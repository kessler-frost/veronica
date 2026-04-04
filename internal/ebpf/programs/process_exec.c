//go:build ignore

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct vr_process_exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EVENT_PROCESS_EXEC;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->hdr.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);

    // Read argv from current process mm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    unsigned long arg_start = 0, arg_end = 0;
    BPF_CORE_READ_INTO(&arg_start, task, mm, arg_start);
    BPF_CORE_READ_INTO(&arg_end, task, mm, arg_end);

    unsigned long arg_len = arg_end - arg_start;
    if (arg_len > MAX_ARGS_LEN)
        arg_len = MAX_ARGS_LEN;
    if (arg_len > 0)
        bpf_probe_read_user(&e->args, arg_len, (void *)arg_start);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
