//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// drop-capability: deny use of named Linux capabilities, cgroup-scoped,
// audit-first. Catalog params: { caps: [string] }. The daemon maps each name
// (e.g. "CAP_SYS_ADMIN") to its integer capability number and inserts it into
// vr_dropped_caps; a capability check for a dropped cap is denied.
// Hook: capable (the generic capability LSM hook).

#include "common_lsm.h"

// vr_dropped_caps: key = capability number (int, e.g. CAP_SYS_ADMIN=21),
// value = 1. Empty => no caps dropped.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __s32);
    __type(value, __u8);
} vr_dropped_caps SEC(".maps");

// capable hook:
//   int capable(const struct cred *cred, struct user_namespace *ns,
//               int cap, unsigned int opts)
SEC("lsm/capable")
int BPF_PROG(vr_drop_capability_check, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts)
{
    __u8 *dropped = bpf_map_lookup_elem(&vr_dropped_caps, &cap);
    if (!dropped || *dropped != 1)
        return 0;

    VR_DECIDE("capability capable");
}

char LICENSE[] SEC("license") = "GPL";
