// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by BPF program headers — do not compile standalone.

#pragma once

#include <bpf/bpf_core_read.h>

#include "vmlinux.h"

// System Metadata

static __always_inline __u32 get_pid_ns_id(struct task_struct *task) {
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;

    struct pid_namespace *pidns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
    if (!pidns) return 0;

    return BPF_CORE_READ(pidns, ns.inum);
}

static __always_inline __u32 get_mnt_ns_id(struct task_struct *task) {
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;

    struct mnt_namespace *mntns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mntns) return 0;

    return BPF_CORE_READ(mntns, ns.inum);
}

static __always_inline __u32 get_task_ppid(struct task_struct *task) {
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) return 0;

    return BPF_CORE_READ(parent, pid);
}

static __always_inline __u32 get_task_ns_ppid(struct task_struct *task) {
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) return 0;

    struct pid *ppid_struct = BPF_CORE_READ(parent, thread_pid);
    if (!ppid_struct) return 0;

    unsigned int level = BPF_CORE_READ(ppid_struct, level);

    struct upid parent_upid;
    bpf_core_read(&parent_upid, sizeof(parent_upid), &ppid_struct->numbers[level]);

    return parent_upid.nr;
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task) {
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader) return 0;

    struct pid *leader_pid = BPF_CORE_READ(leader, thread_pid);
    if (!leader_pid) return 0;

    unsigned int level = BPF_CORE_READ(leader_pid, level);

    struct upid leader_upid = {};
    bpf_core_read(&leader_upid, sizeof(leader_upid), &leader_pid->numbers[level]);

    return leader_upid.nr;
}

static __always_inline u32 get_task_ns_tid(struct task_struct *task) {
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    if (!pid) return 0;

    unsigned int level = BPF_CORE_READ(pid, level);

    struct upid up = {};
    bpf_core_read(&up, sizeof(up), &pid->numbers[level]);

    return up.nr;
}
