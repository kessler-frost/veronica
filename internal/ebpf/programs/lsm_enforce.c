//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// LSM enforcement: deny file open and socket connect based on policy maps.
// Userspace (coordinator) writes policy entries; kernel enforces at call time.
//
// Requires CONFIG_BPF_LSM=y and "bpf" in /sys/kernel/security/lsm.

#include "common.h"

// File policy map: key = FNV-1a hash of filename (u64), value = action (0=allow, 1=deny)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} vr_file_policy SEC(".maps");

// Network policy map: key = IPv4 address in network byte order (u32), value = action (0=allow, 1=deny)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} vr_net_policy SEC(".maps");

// FNV-1a 64-bit hash over a NUL-terminated string (max 256 bytes)
static __always_inline __u64 vr_hash_path(const char *path, int len)
{
    __u64 hash = 14695981039346656037ULL;
    for (int i = 0; i < len && i < 256; i++) {
        char c = path[i];
        if (c == 0)
            break;
        hash ^= (__u64)(unsigned char)c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

// LSM hook: deny file open when the filename hash matches a deny entry.
SEC("lsm/file_open")
int BPF_PROG(vr_lsm_file_open, struct file *file)
{
    char name[MAX_FILENAME_LEN];
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    int len = (int)BPF_CORE_READ(dentry, d_name.len);

    if (len <= 0 || len >= MAX_FILENAME_LEN)
        return 0;

    bpf_probe_read_kernel_str(name, sizeof(name),
                              BPF_CORE_READ(dentry, d_name.name));

    __u64 key = vr_hash_path(name, len);
    __u8 *action = bpf_map_lookup_elem(&vr_file_policy, &key);
    if (action && *action == 1)
        return -EPERM;

    return 0;
}

// LSM hook: deny socket connect when the destination IPv4 matches a deny entry.
// Only inspects AF_INET connections; all other families pass through.
SEC("lsm/socket_connect")
int BPF_PROG(vr_lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    __u16 family = BPF_CORE_READ((struct sockaddr_in *)address, sin_family);
    if (family != AF_INET)
        return 0;

    __u32 ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
    __u8 *action = bpf_map_lookup_elem(&vr_net_policy, &ip);
    if (action && *action == 1)
        return -EPERM;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
