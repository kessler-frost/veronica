//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// block-exec: deny execution of named binaries, cgroup-scoped, audit-first.
// Catalog params: { binaries: [string] }. The daemon hashes each binary
// basename (FNV-1a 64-bit) and inserts it into vr_blocked_bins; an exec whose
// basename hash matches is denied. Hook: bprm_check_security.

#include "common_lsm.h"

#define VR_MAX_NAME 256

// vr_blocked_bins: key = FNV-1a hash of the binary basename, value = 1.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} vr_blocked_bins SEC(".maps");

// vr_fnv1a hashes a NUL-terminated string (mirrors the daemon's Go hashing and
// lsm_enforce.c's vr_hash_path so userspace and kernel agree).
static __always_inline __u64 vr_fnv1a(const char *s, int len)
{
    __u64 hash = 14695981039346656037ULL;
    for (int i = 0; i < len && i < VR_MAX_NAME; i++) {
        char c = s[i];
        if (c == 0)
            break;
        hash ^= (__u64)(unsigned char)c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(vr_block_exec_check, struct linux_binprm *bprm)
{
    char name[VR_MAX_NAME];
    // bprm->filename is the full path; we hash the basename to match the
    // daemon, which keys on the binary name (e.g. "nc", "curl").
    const char *filename = BPF_CORE_READ(bprm, filename);
    int len = bpf_probe_read_kernel_str(name, sizeof(name), filename);
    if (len <= 1)
        return 0;

    // Find the basename (last '/').
    int base = 0;
    for (int i = 0; i < VR_MAX_NAME && i < len; i++) {
        if (name[i] == 0)
            break;
        if (name[i] == '/')
            base = i + 1;
    }

    __u64 key = vr_fnv1a(name + base, VR_MAX_NAME);
    __u8 *blocked = bpf_map_lookup_elem(&vr_blocked_bins, &key);
    if (!blocked || *blocked != 1)
        return 0;

    VR_DECIDE("exec bprm_check_security");
}

char LICENSE[] SEC("license") = "GPL";
