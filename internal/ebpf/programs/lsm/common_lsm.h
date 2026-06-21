#ifndef __VERONICA_COMMON_LSM_H
#define __VERONICA_COMMON_LSM_H

// Shared scaffolding for the veronica LSM enforcement primitives. Each primitive
// program (block_path_write, block_mount, block_egress, block_exec,
// drop_capability) includes this for the common mode/cgroup-scope/self-protection
// machinery so the catalog's audit-first + cgroup-scope + guard-list guarantees
// are enforced identically in every program.
//
// Build: VM-only. Requires CONFIG_BPF_LSM=y and "bpf" in the active LSM list
// (boot param lsm=...,bpf). See scripts/vm/test_preconditions.sh.

#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef EPERM
#define EPERM 1
#endif

#define VR_MODE_AUDIT   0
#define VR_MODE_ENFORCE 1

// vr_mode: single-entry array, index 0 holds the enforcement mode (audit vs
// enforce). The daemon flips this from audit to enforce after the human confirms
// the audit report — the kernel-side half of the audit-first lifecycle.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} vr_mode SEC(".maps");

// vr_scope: a cgroup array. Index 0 holds the target cgroup (the daemon updates
// it with the resolved app's cgroup fd). bpf_current_task_under_cgroup(&vr_scope,
// 0) is true only for tasks inside that cgroup, so enforcement is cgroup-scoped.
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} vr_scope SEC(".maps");

// vr_audit_count: per-CPU counter, index 0. Incremented on every would-block in
// audit mode so the daemon can report AuditCount before the operator confirms.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} vr_audit_count SEC(".maps");

// vr_mode_value reads the current enforcement mode (defaults to audit when the
// map is unset, so a freshly loaded program never denies before it is armed).
static __always_inline __u8 vr_mode_value(void)
{
    __u32 key = 0;
    __u8 *m = bpf_map_lookup_elem(&vr_mode, &key);
    if (!m)
        return VR_MODE_AUDIT;
    return *m;
}

// vr_in_scope reports whether the current task is inside the target cgroup.
// Returns false (out of scope) when the scope array has no cgroup installed yet,
// so an unarmed program is a no-op rather than a global deny.
static __always_inline int vr_in_scope(void)
{
    long r = bpf_current_task_under_cgroup(&vr_scope, 0);
    return r == 1;
}

// vr_self_protected guards the daemon, PID 1, and the login/service plumbing so
// a policy can never wedge the VM. This is the kernel-side mirror of the policy
// store's guard list (internal/control/lifecycle.go guardedComms).
static __always_inline int vr_self_protected(void)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 1)
        return 1;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Compare against guarded comms. comm is NUL-padded to 16 bytes.
    static const char guarded[][16] = {
        "veronicad",
        "systemd",
        "sshd",
        "init",
    };
    for (int g = 0; g < 4; g++) {
        int match = 1;
        for (int i = 0; i < 16; i++) {
            if (comm[i] != guarded[g][i]) {
                match = 0;
                break;
            }
            if (comm[i] == 0)
                break;
        }
        if (match)
            return 1;
    }
    return 0;
}

// vr_count_audit bumps the would-block counter (audit-mode bookkeeping).
static __always_inline void vr_count_audit(void)
{
    __u32 key = 0;
    __u64 *c = bpf_map_lookup_elem(&vr_audit_count, &key);
    if (c)
        (*c)++;
}

// VR_DECIDE is the shared decision tail for every primitive: called once the
// program has determined the current operation matches the policy. It applies
// scope + self-protection, then audit-vs-enforce. In audit mode it counts and
// logs but allows (returns 0); in enforce mode it denies with -EPERM. `what` is
// a short literal naming the primitive for the trace log.
#define VR_DECIDE(what)                                                       \
    do {                                                                      \
        if (!vr_in_scope())                                                   \
            return 0;                                                         \
        if (vr_self_protected())                                             \
            return 0;                                                         \
        if (vr_mode_value() == VR_MODE_ENFORCE) {                            \
            bpf_printk("veronica enforce: deny " what);                       \
            return -EPERM;                                                    \
        }                                                                     \
        vr_count_audit();                                                     \
        bpf_printk("veronica audit: would deny " what);                      \
        return 0;                                                             \
    } while (0)

#endif
