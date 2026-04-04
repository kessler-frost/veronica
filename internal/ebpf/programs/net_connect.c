//go:build ignore

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int trace_connect(struct pt_regs *ctx)
{
    struct vr_net_connect_event *e;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EVENT_NET_CONNECT;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->hdr.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
    e->dport = __builtin_bswap16(e->dport);
    BPF_CORE_READ_INTO(&e->family, sk, __sk_common.skc_family);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
