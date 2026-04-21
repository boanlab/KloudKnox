// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// go:build ignore

#pragma once

#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../common/metadata.h"
#include "../common/network.h"
#include "../common/path.h"
#include "syscalls.h"
// clang-format on

// Definitions

typedef struct __attribute__((packed)) event {
    __u64 ts;
    __u32 cpu_id;
    __u32 seq_num;

    __u32 pid_ns_id;
    __u32 mnt_ns_id;

    __s32 host_ppid;
    __s32 host_pid;
    __s32 host_tid;

    __s32 ppid;
    __s32 pid;
    __s32 tid;

    __u32 uid;
    __u32 gid;

    __s16 event_id;
    __s8 event_type;
    __s8 arg_num;
    __s32 ret_val;
} event_t;

enum {
    EVENT_UNARY = 0,
    EVENT_ENTER,
    EVENT_EXIT,
};

enum {
    __SCHED_PROCESS_EXIT = 1000,
    __SECURITY_BPRM_CHECK,
    __SECURITY_TASK_KILL,
    __SECURITY_PATH_CHROOT,
    __SECURITY_FILE_OPEN,
    __FILP_CLOSE,
    __SECURITY_PATH_CHOWN,
    __SECURITY_PATH_CHMOD,
    __SECURITY_PATH_UNLINK,
    __SECURITY_PATH_RENAME,
    __SECURITY_PATH_LINK,
    __SECURITY_PATH_MKDIR,
    __SECURITY_PATH_RMDIR,
    __KRETPROBE_INET_CSK_ACCEPT,     // 1013: patches accept/accept4 ENTER with peer addr:port
    __SECURITY_CAPABLE,              // 1014: kprobe on cap_capable — capability usage attempts
    __SECURITY_UNIX_STREAM_CONNECT,  // 1015: kprobe — unix-socket client-side connect
    __SECURITY_UNIX_MAY_SEND,        // 1016: kprobe — datagram unix-socket sendmsg
    __SECURITY_PTRACE_ACCESS_CHECK,  // 1017: kprobe — ptrace tracer/tracee relationship
    // NOTE: __SECURITY_TASK_KILL (1002) covers both syscall-driven and signal
    // LSM attempts, so no separate id is needed for signals.
};

enum {
    TYPE_NONE = 0,
    TYPE_INT,
    TYPE_UINT,
    TYPE_ULONG,
    TYPE_STR,
    TYPE_STR_ARR,
    TYPE_SRC,
    TYPE_RES,
};

// Event Management

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} st_seq_map SEC(".maps");

static __always_inline __u32 get_sequence_number() {
    __u32 index = 0;

    __u32 *seq_num = bpf_map_lookup_elem(&st_seq_map, &index);
    if (!seq_num) return 0;

    return ++(*seq_num);
}

static __always_inline void init_event(event_t *ev, __s16 event_id, __s8 event_type, __s8 arg_num) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u64 tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    ev->ts = bpf_ktime_get_ns();
    ev->cpu_id = bpf_get_smp_processor_id();
    ev->seq_num = get_sequence_number();

    ev->pid_ns_id = get_pid_ns_id(task);
    ev->mnt_ns_id = get_mnt_ns_id(task);

    ev->host_ppid = get_task_ppid(task);
    ev->host_pid = tgid >> 32;
    ev->host_tid = tgid & 0xFFFFFFFF;

    ev->ppid = get_task_ns_ppid(task);
    ev->pid = get_task_ns_tgid(task);
    ev->tid = get_task_ns_tid(task);

    ev->uid = uid_gid >> 32;
    ev->gid = uid_gid & 0xFFFFFFFF;

    ev->event_id = event_id;
    ev->event_type = event_type;
    ev->arg_num = arg_num;
    ev->ret_val = 0;
}

// NS Filtering

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} st_skip_ns_map SEC(".maps");

static __always_inline __u32 should_monitor() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 ns_id = ((__u64)get_pid_ns_id(task) << 32) | (__u64)get_mnt_ns_id(task);
    return !bpf_map_lookup_elem(&st_skip_ns_map, &ns_id);
}

// Source Filtering

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 65536);
} st_src_map SEC(".maps");

static __always_inline __u32 known_source(__u32 host_pid) {
    return bpf_map_lookup_elem(&st_src_map, &host_pid) != NULL;
}

static __always_inline void delete_source(__u32 host_pid) { bpf_map_delete_elem(&st_src_map, &host_pid); }

// Buffer Management

#define MAX_BUF_LEN 8192

typedef struct __attribute__((packed)) buffer {
    __u8 buf[MAX_BUF_LEN];
} buf_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(buf_t));
    __uint(max_entries, 1);
} st_buf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} st_buf_offset_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(buf_t));
    __uint(max_entries, 1);
} st_tmp_buf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} st_critical_event_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} st_non_critical_event_rb SEC(".maps");

static __always_inline buf_t *get_buffer() {
    __u32 index = 0;

    buf_t *buf = bpf_map_lookup_elem(&st_buf_map, &index);
    if (!buf) return NULL;

    // initialize write cursor to just after the event header
    __u32 offset = sizeof(event_t);
    bpf_map_update_elem(&st_buf_offset_map, &index, &offset, BPF_ANY);

    return buf;
}

static __always_inline int submit_buffer(buf_t *buf, __u32 critical) {
    __u32 index = 0;

    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return 0;

    __u32 buf_len = (*offset_ptr) & (MAX_BUF_LEN - 1);

    if (critical) {
        bpf_ringbuf_output(&st_critical_event_rb, buf, buf_len, 0);
    } else {
        bpf_ringbuf_output(&st_non_critical_event_rb, buf, buf_len, 0);
    }

    return 0;
}

static __always_inline int submit_event(event_t *ev, __u32 critical) {
    if (critical) {
        bpf_ringbuf_output(&st_critical_event_rb, ev, sizeof(event_t), 0);
    } else {
        bpf_ringbuf_output(&st_non_critical_event_rb, ev, sizeof(event_t), 0);
    }
    return 0;
}

#include "buffer_helpers.h"
