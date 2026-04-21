// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Signal enforcement — SEC("lsm/task_kill").

#pragma once

#include "bpfe_lookup.h"

SEC("lsm/task_kill")
int BPF_PROG(bpfe_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig,
             const struct cred *cred)
{
    // sig=0 is an existence-check probe; never block it.
    if (sig <= 0 || sig > 31)
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 src = current_exe_inode();
    __u64 tgt = task_exe_inode(p);

    // 4-way fallback: (pod, src, tgt) → (pod, 0, tgt) → (pod, src, 0) → (pod, 0, 0)
    struct bpfe_signal_key k = { cgid, src, tgt, 0 };
    struct bpfe_signal_val *v = bpf_map_lookup_elem(&bpfe_signal_rules, &k);
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_signal_rules, &k); }
    if (!v) { k.src_inode = src; k.target_inode = 0; v = bpf_map_lookup_elem(&bpfe_signal_rules, &k); }
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_signal_rules, &k); }

    if (!v)
        return fallback_posture(cgid, src, 0, DOMAIN_SIGNAL);

    __u32 bit = 1u << ((__u32)sig - 1);

    if (v->block_mask & bit) {
        submit_alert(cgid, src, tgt, DOMAIN_SIGNAL, ACTION_BLOCK,
                     (__u16)sig, v->policy_id, -EACCES);
        return -EACCES;
    }
    if (v->audit_mask & bit) {
        submit_alert(cgid, src, tgt, DOMAIN_SIGNAL, ACTION_AUDIT,
                     (__u16)sig, v->policy_id, 0);
        return 0;
    }

    // Rule exists but this signal is not covered — treat as allow.
    return 0;
}
