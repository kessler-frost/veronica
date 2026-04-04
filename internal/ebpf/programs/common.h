#ifndef __VERONICA_COMMON_H
#define __VERONICA_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 64
#define MAX_FILENAME_LEN 256

#define EVENT_PROCESS_EXEC  1
#define EVENT_FILE_OPEN     2
#define EVENT_NET_CONNECT   3

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

#endif
