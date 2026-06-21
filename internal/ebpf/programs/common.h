#ifndef __VERONICA_COMMON_H
#define __VERONICA_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 64
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 256
#define MAX_MOUNT_LEN 256

#define EVENT_PROCESS_EXEC  1
#define EVENT_FILE_OPEN     2
#define EVENT_NET_CONNECT   3
#define EVENT_PROCESS_EXIT  4
#define EVENT_MOUNT         5

struct vr_event_header {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u32 _pad;
    __u64 timestamp;
    char comm[MAX_COMM_LEN];
};

struct vr_process_exec_event {
    struct vr_event_header hdr;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
};

struct vr_file_open_event {
    struct vr_event_header hdr;
    char filename[MAX_FILENAME_LEN];
    __s32 flags;
    __u32 _pad;
};

struct vr_net_connect_event {
    struct vr_event_header hdr;
    __u32 daddr;
    __u16 dport;
    __u16 family;
};

struct vr_process_exit_event {
    struct vr_event_header hdr;
    __s32 exit_code;
    __u32 _pad;
};

struct vr_mount_event {
    struct vr_event_header hdr;
    char source[MAX_MOUNT_LEN];
    char target[MAX_MOUNT_LEN];
};

// Target-cgroup observation filter. The daemon writes the resolved app's
// cgroup v2 id (the value of bpf_get_current_cgroup_id() inside that cgroup)
// as a key with value 1; the observation programs emit an event only when the
// current task's cgroup id is present here. An empty map means "observe
// everything" so the probes are still useful before a target is set.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} vr_target_cgroup SEC(".maps");

// vr_cgroup_observed reports whether the current task belongs to the observed
// cgroup. Returns true when the target map is empty (observe-all) or when the
// current cgroup id is an explicit target. Kept __always_inline so each program
// that includes common.h gets its own copy referencing its own map instance.
static __always_inline int vr_cgroup_observed(void)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *hit = bpf_map_lookup_elem(&vr_target_cgroup, &cgid);
    if (hit)
        return 1;

    // No explicit hit: observe-all only while the target map carries the
    // sentinel "unset" marker (key 0). The daemon deletes key 0 once it sets a
    // real target, flipping these probes into cgroup-scoped mode.
    __u64 unset = 0;
    return bpf_map_lookup_elem(&vr_target_cgroup, &unset) != 0;
}

#endif
