//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// block-mount: deny mount operations, cgroup-scoped, audit-first. This is the
// kernel side of "don't let docker create volumes". Catalog params (optional):
// { path_prefix: string } — when set, only mounts whose target path starts with
// the prefix are denied; when unset, all mounts in scope are denied.
// Hooks: sb_mount, move_mount.

#include "common_lsm.h"

#define VR_MAX_PREFIX 256

// vr_mount_prefix: index 0 holds the optional target-path prefix. Empty => match
// every mount in scope.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[VR_MAX_PREFIX]);
} vr_mount_prefix SEC(".maps");

// vr_mount_target_matches: true when no prefix is configured (match-all) or when
// `path` starts with the configured prefix.
static __always_inline int vr_mount_target_matches(const char *path)
{
    __u32 key = 0;
    char *prefix = bpf_map_lookup_elem(&vr_mount_prefix, &key);
    if (!prefix || prefix[0] == 0)
        return 1; // no prefix => block all mounts in scope

    for (int i = 0; i < VR_MAX_PREFIX; i++) {
        char pc = prefix[i];
        if (pc == 0)
            return 1;
        if (path[i] != pc)
            return 0;
    }
    return 1;
}

// sb_mount: the primary mount hook.
//   int sb_mount(const char *dev_name, const struct path *path,
//                const char *type, unsigned long flags, void *data)
SEC("lsm/sb_mount")
int BPF_PROG(vr_block_mount_sb, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data)
{
    char target[VR_MAX_PREFIX];
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    bpf_probe_read_kernel_str(target, sizeof(target),
                              BPF_CORE_READ(dentry, d_name.name));

    if (!vr_mount_target_matches(target))
        return 0;

    VR_DECIDE("mount sb_mount");
}

// move_mount: deny relocating a mount into the scope (e.g. bind-mount moves).
SEC("lsm/move_mount")
int BPF_PROG(vr_block_mount_move, const struct path *from_path,
             const struct path *to_path)
{
    char target[VR_MAX_PREFIX];
    struct dentry *dentry = BPF_CORE_READ(to_path, dentry);
    bpf_probe_read_kernel_str(target, sizeof(target),
                              BPF_CORE_READ(dentry, d_name.name));

    if (!vr_mount_target_matches(target))
        return 0;

    VR_DECIDE("mount move_mount");
}

char LICENSE[] SEC("license") = "GPL";
