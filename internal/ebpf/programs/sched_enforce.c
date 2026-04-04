//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// sched_ext priority scheduler skeleton.
//
// Reads per-PID priority from vr_sched_priority; higher values mean the process
// is dispatched before others. This is a SKELETON — the sched_ext struct_ops API
// is kernel-version-specific and requires testing against kernel 6.17.
//
// Key differences from earlier kernels that may need adjustment:
//   - scx_bpf_dispatch() signature changes across kernel versions
//   - SCX_DSQ_GLOBAL / SCX_SLICE_DFL constant names may differ
//   - struct sched_ext_ops field names evolve between rc versions
//
// The Go side registers this via cilium/ebpf struct_ops loading (not auto-attach).
// See internal/ebpf/manager.go for the attachment point.

#include "common.h"

// Priority map: key = PID (u32), value = priority (u32, higher = scheduled sooner)
// Userspace writes priorities here when the LLM decides a process needs preference.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u32);
} vr_sched_priority SEC(".maps");

// Stats: index 0 = enqueues where a priority entry was found (per-CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} vr_sched_stats SEC(".maps");

// select_cpu: called before enqueue to optionally pin a task to a specific CPU.
// Default: return prev_cpu (no migration).
SEC("struct_ops/vr_select_cpu")
s32 BPF_PROG(vr_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    return prev_cpu;
}

// enqueue: called when a task becomes runnable.
// Tasks with a vr_sched_priority entry are dispatched to the global DSQ normally
// but the stat counter lets userspace observe how many prioritised tasks are active.
// TODO(kernel-6.17): if sched_ext gains per-DSQ priorities, dispatch high-priority
// tasks to a dedicated high-priority DSQ created in vr_sched_init instead.
SEC("struct_ops/vr_enqueue")
void BPF_PROG(vr_enqueue, struct task_struct *p, u64 enq_flags)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u32 *prio = bpf_map_lookup_elem(&vr_sched_priority, &pid);

    if (prio && *prio > 0) {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&vr_sched_stats, &key);
        if (count)
            (*count)++;
    }

    scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

// dispatch: called when a CPU is idle and needs work from the global DSQ.
SEC("struct_ops/vr_dispatch")
void BPF_PROG(vr_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_consume(SCX_DSQ_GLOBAL);
}

// running: called just before a task starts executing on a CPU (optional hook).
SEC("struct_ops/vr_running")
void BPF_PROG(vr_running, struct task_struct *p)
{
}

// stopping: called just after a task stops executing (optional hook).
SEC("struct_ops/vr_stopping")
void BPF_PROG(vr_stopping, struct task_struct *p, bool runnable)
{
}

// enable: called when the scheduler is enabled for a task.
SEC("struct_ops/vr_enable")
void BPF_PROG(vr_enable, struct task_struct *p)
{
}

char LICENSE[] SEC("license") = "GPL";
