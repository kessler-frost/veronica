//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// TODO: Not yet compiled or loaded. Will replace shell-based iptables
// enforcement with wire-speed XDP packet filtering.
//
// XDP packet filter: drop packets from/to blocked IPv4 addresses before they
// reach the kernel network stack. Runs at the NIC driver level for minimum
// overhead. Daemon populates vr_xdp_blocklist; the kernel drops at wire speed.

#include "common.h"
#include <bpf/bpf_endian.h>

// Blocked IPs map: key = IPv4 address (network byte order), value = 1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} vr_xdp_blocklist SEC(".maps");

// Stats: index 0 = dropped packets, index 1 = passed packets (per-CPU for lock-free updates)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} vr_xdp_stats SEC(".maps");

static __always_inline void vr_xdp_inc_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&vr_xdp_stats, &idx);
    if (count)
        (*count)++;
}

SEC("xdp")
int vr_xdp_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Bounds-check Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        vr_xdp_inc_stat(1);
        return XDP_PASS;
    }

    // Only process IPv4; pass everything else up the stack
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        vr_xdp_inc_stat(1);
        return XDP_PASS;
    }

    // Bounds-check IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        vr_xdp_inc_stat(1);
        return XDP_PASS;
    }

    // Drop packets whose source IP is blocked (inbound traffic from bad actor)
    __u8 *blocked = bpf_map_lookup_elem(&vr_xdp_blocklist, &ip->saddr);
    if (blocked && *blocked == 1) {
        vr_xdp_inc_stat(0);
        return XDP_DROP;
    }

    // Drop packets whose destination IP is blocked (outbound to blocked host).
    // Effective when XDP is attached on the egress path or a loopback interface.
    blocked = bpf_map_lookup_elem(&vr_xdp_blocklist, &ip->daddr);
    if (blocked && *blocked == 1) {
        vr_xdp_inc_stat(0);
        return XDP_DROP;
    }

    vr_xdp_inc_stat(1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
