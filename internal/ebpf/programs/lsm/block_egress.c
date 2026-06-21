//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// block-egress: deny outbound IPv4 connections to addresses OUTSIDE the allow
// list, cgroup-scoped, audit-first. Catalog params: { allow_cidrs: [string] }.
// The daemon parses each CIDR and inserts it into vr_allow_cidrs (an LPM trie);
// a connect whose destination is not covered by any allowed prefix is denied.
// Hook: socket_connect.

#include "common_lsm.h"

// AF_INET is a kernel preprocessor macro (include/uapi/linux/socket.h), so it is
// not carried in BTF/vmlinux.h and must be defined here. Its value (2) is part of
// the stable kernel/userspace ABI.
#ifndef AF_INET
#define AF_INET 2
#endif

// LPM trie key: prefixlen + 4-byte IPv4 (network byte order), matching
// BPF_MAP_TYPE_LPM_TRIE's bpf_lpm_trie_key layout. The daemon writes one entry
// per allowed CIDR (value is unused, set to 1).
struct vr_cidr_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct vr_cidr_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} vr_allow_cidrs SEC(".maps");

// vr_egress_allowed: true when the destination IPv4 is covered by an allowed
// CIDR. An empty allow list means nothing is allowed (deny all egress in scope).
static __always_inline int vr_egress_allowed(__u32 daddr_net)
{
    struct vr_cidr_key key = {};
    key.prefixlen = 32;
    __builtin_memcpy(key.addr, &daddr_net, 4);
    return bpf_map_lookup_elem(&vr_allow_cidrs, &key) != 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(vr_block_egress_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    __u16 family = BPF_CORE_READ((struct sockaddr_in *)address, sin_family);
    if (family != AF_INET)
        return 0; // only IPv4 egress is policed in v1

    __u32 daddr = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
    if (vr_egress_allowed(daddr))
        return 0; // destination is allow-listed

    VR_DECIDE("egress socket_connect");
}

char LICENSE[] SEC("license") = "GPL";
