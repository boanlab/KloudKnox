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
// clang-format on

// Definitions

typedef struct __attribute__((packed)) network_event {
    __u64 ts;

    __u32 pid_ns_id;
    __u32 mnt_ns_id;

    __s32 host_ppid;
    __s32 host_pid;
    __s32 host_tid;

    __s32 ppid;
    __s32 pid;
    __s32 tid;

    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;

    __u16 proto;
    __u16 event_id;

    __u32 policy_id;
    __s32 ret_val;
} network_event_t;

enum {
    __INET_STREAM_CONNECT = 0,
    __INET_CSK_ACCEPT,
    __UDP_SENDMSG,
    __UDP_RECVMSG,
    __CGROUP_SKB_EGRESS,
    __CGROUP_SKB_INGRESS,
};

// Event Management

static __always_inline void init_event(network_event_t *ev, __u16 event_id) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u64 tgid = bpf_get_current_pid_tgid();

    ev->ts = bpf_ktime_get_ns();

    ev->pid_ns_id = get_pid_ns_id(task);
    ev->mnt_ns_id = get_mnt_ns_id(task);

    ev->host_ppid = get_task_ppid(task);
    ev->host_pid = tgid >> 32;
    ev->host_tid = tgid & 0xFFFFFFFF;

    ev->ppid = get_task_ns_ppid(task);
    ev->pid = get_task_ns_tgid(task);
    ev->tid = get_task_ns_tid(task);

    ev->event_id = event_id;
    ev->ret_val = 0;
}

// Buffer Management

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} ne_event_rb SEC(".maps");

static __always_inline int submit_event(network_event_t *ev) {
    bpf_ringbuf_output(&ne_event_rb, ev, sizeof(network_event_t), 0);
    return 0;
}

// NS Filtering

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} ne_skip_ns_map SEC(".maps");

static __always_inline __u32 should_monitor() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 ns_id = ((__u64)get_pid_ns_id(task) << 32) | (__u64)get_mnt_ns_id(task);
    return !bpf_map_lookup_elem(&ne_skip_ns_map, &ns_id);
}

// Submodules

// clang-format off
#include "inode_mgmt.h"
#include "policy.h"
#include "dns.h"
#include "socket_mgmt.h"
// clang-format on
