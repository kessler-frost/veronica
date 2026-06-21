//go:build ignore

#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Observe mount operations for the target cgroup. path_mount() is the modern
// (kernel 5.9+) common entry for the mount(2) syscall:
//   int path_mount(const char *dev_name, struct path *path,
//                  const char *type_page, unsigned long flags, void *data)
// PARM1 = dev_name (the source), PARM3 = type_page. The target path lives in a
// struct path that needs d_path-style resolution; for observation we record the
// device/source and the filesystem type as the "target" hint, which is enough
// to surface "docker created a volume mount" in an Activity snapshot. The
// enforcement side (lsm/block_mount.c) uses the sb_mount LSM hook instead.
SEC("kprobe/path_mount")
int trace_mount(struct pt_regs *ctx)
{
    struct vr_mount_event *e;

    if (!vr_cgroup_observed())
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EVENT_MOUNT;
    e->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    e->hdr.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->hdr.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->hdr.comm, sizeof(e->hdr.comm));

    const char *dev_name = (const char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(&e->source, sizeof(e->source), dev_name);

    const char *type = (const char *)PT_REGS_PARM3(ctx);
    bpf_probe_read_user_str(&e->target, sizeof(e->target), type);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
