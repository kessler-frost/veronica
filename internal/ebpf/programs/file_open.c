//go:build ignore

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int trace_file_open(struct pt_regs *ctx)
{
    struct vr_file_open_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EVENT_FILE_OPEN;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->hdr.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    const char *fname = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);

    struct open_how *how = (struct open_how *)PT_REGS_PARM3(ctx);
    bpf_probe_read_kernel(&e->flags, sizeof(e->flags), &how->flags);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
