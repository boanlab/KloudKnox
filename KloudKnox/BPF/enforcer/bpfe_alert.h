// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by bpf_enforcer.bpf.c — do not compile standalone.

#pragma once

#include "bpfe_maps.h"

// Alert Event Structure

// bpfe_alert_t mirrors the C struct written to bpfe_alerts_rb.
// Fields are in host byte order. Layout must match the Go struct
// in enforcer/bpfAlertHandler.go.
typedef struct __attribute__((packed)) bpfe_alert {
    __u64 ts;
    __u64 cgid;

    __u32 pid_ns_id;
    __u32 mnt_ns_id;

    __s32 host_ppid;
    __s32 host_pid;
    __s32 host_tid;

    __s32 ppid;
    __s32 pid;
    __s32 tid;

    __u64 src_inode;
    __u64 target_inode;

    __u8  domain;      // DOMAIN_* constant
    __u8  action;      // ACTION_AUDIT | ACTION_BLOCK
    __u16 event_id;    // domain-specific sub-type (cap_id, signal, etc.)
    __u32 policy_id;

    __s32 ret_val;     // -EACCES (-13) or 0
    __u32 extra;       // reserved / domain-specific
} bpfe_alert_t;

// Alert Submit Helper

// submit_alert reserves a slot in the alert ring buffer and submits it.
// If the ring buffer is full (reserve returns NULL) the event is silently
// dropped — enforcement is not affected.
static __always_inline void submit_alert(__u64 cgid, __u64 src_inode,
                                         __u64 target_inode, __u8 domain,
                                         __u8 action, __u16 event_id,
                                         __u32 policy_id, __s32 ret_val) {
    bpfe_alert_t *al = bpf_ringbuf_reserve(&bpfe_alerts_rb,
                                            sizeof(bpfe_alert_t), 0);
    if (!al)
        return;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 tgid = bpf_get_current_pid_tgid();

    al->ts         = bpf_ktime_get_ns();
    al->cgid       = cgid;
    al->pid_ns_id  = get_pid_ns_id(task);
    al->mnt_ns_id  = get_mnt_ns_id(task);
    al->host_ppid  = (__s32)get_task_ppid(task);
    al->host_pid   = (__s32)(tgid >> 32);
    al->host_tid   = (__s32)(tgid & 0xFFFFFFFF);
    al->ppid       = (__s32)get_task_ns_ppid(task);
    al->pid        = (__s32)get_task_ns_tgid(task);
    al->tid        = (__s32)get_task_ns_tid(task);
    al->src_inode  = src_inode;
    al->target_inode = target_inode;
    al->domain     = domain;
    al->action     = action;
    al->event_id   = event_id;
    al->policy_id  = policy_id;
    al->ret_val    = ret_val;
    al->extra      = 0;

    bpf_ringbuf_submit(al, 0);
}
