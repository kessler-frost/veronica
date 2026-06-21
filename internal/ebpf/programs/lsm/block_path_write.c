//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// block-path-write: deny writes under a path prefix, cgroup-scoped, audit-first.
// Catalog params: { path_prefix: string }. Hooks: file_open (write intent),
// inode_create, path_mkdir.

#include "common_lsm.h"

#define VR_MAX_PREFIX 256

// FMODE_WRITE is a kernel preprocessor macro (include/linux/fs.h), so it is not
// carried in BTF/vmlinux.h and must be defined here. Its value (bit 1) has been
// stable across kernel releases; f_mode is checked for write intent below.
#ifndef FMODE_WRITE
#define FMODE_WRITE 0x2
#endif

// vr_prefix: index 0 holds the NUL-terminated path prefix the daemon writes from
// the policy's path_prefix param.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[VR_MAX_PREFIX]);
} vr_prefix SEC(".maps");

// vr_path_has_prefix returns true if path starts with the configured prefix. An
// empty/unset prefix never matches (so an unarmed policy denies nothing).
static __always_inline int vr_path_has_prefix(const char *path)
{
    __u32 key = 0;
    char *prefix = bpf_map_lookup_elem(&vr_prefix, &key);
    if (!prefix || prefix[0] == 0)
        return 0;

    for (int i = 0; i < VR_MAX_PREFIX; i++) {
        char pc = prefix[i];
        if (pc == 0)
            return 1; // matched the whole prefix
        if (path[i] != pc)
            return 0;
    }
    return 1;
}

// file_open: deny when opening a file under the prefix with write intent.
SEC("lsm/file_open")
int BPF_PROG(vr_block_path_write_open, struct file *file)
{
    char name[VR_MAX_PREFIX];
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    int len = (int)BPF_CORE_READ(dentry, d_name.len);
    if (len <= 0 || len >= VR_MAX_PREFIX)
        return 0;

    // Write intent: FMODE_WRITE in file->f_mode.
    unsigned int fmode = BPF_CORE_READ(file, f_mode);
    if (!(fmode & FMODE_WRITE))
        return 0;

    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));
    if (!vr_path_has_prefix(name))
        return 0;

    VR_DECIDE("path-write file_open");
}

// inode_create: deny creating a new node whose name is under the prefix.
SEC("lsm/inode_create")
int BPF_PROG(vr_block_path_write_create, struct inode *dir,
             struct dentry *dentry, umode_t mode)
{
    char name[VR_MAX_PREFIX];
    int len = (int)BPF_CORE_READ(dentry, d_name.len);
    if (len <= 0 || len >= VR_MAX_PREFIX)
        return 0;

    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));
    if (!vr_path_has_prefix(name))
        return 0;

    VR_DECIDE("path-write inode_create");
}

// path_mkdir: deny creating a directory whose name, OR whose parent directory's
// name, matches the configured prefix. The parent-directory match is what makes
// "block writes under <dir>" work for mkdir: e.g. with path_prefix "volumes",
// dockerd's `mkdir /var/lib/docker/volumes/<name>` is denied because the parent
// dir (`dir` arg) is named "volumes". Matching the new dir's own name as well
// keeps the single-segment-prefix case (mkdir of a dir literally named the
// prefix) working. This is the kernel side of "don't let docker create volumes",
// verified against `docker volume create` (which performs exactly this mkdir).
SEC("lsm/path_mkdir")
int BPF_PROG(vr_block_path_write_mkdir, const struct path *dir,
             struct dentry *dentry, umode_t mode)
{
    char name[VR_MAX_PREFIX];

    // 1. The new directory's own basename.
    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));
    if (vr_path_has_prefix(name))
        VR_DECIDE("path-write path_mkdir (name)");

    // 2. The parent directory's basename (dir->dentry->d_name.name).
    struct dentry *parent = BPF_CORE_READ(dir, dentry);
    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(parent, d_name.name));
    if (vr_path_has_prefix(name))
        VR_DECIDE("path-write path_mkdir (parent)");

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
