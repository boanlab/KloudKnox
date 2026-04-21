// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Ptrace enforcement — SEC("lsm/ptrace_access_check") + ptrace_traceme.

#pragma once

#include "bpfe_lookup.h"

// From linux/ptrace.h — not in vmlinux.h enum/define section
#define BPFE_PTRACE_MODE_READ    0x01
#define BPFE_PTRACE_MODE_ATTACH  0x02

// max_action: returns ACTION_BLOCK if either is BLOCK, then ACTION_AUDIT if either
// is AUDIT, otherwise ACTION_ALLOW.
static __always_inline __u8 max_action(__u8 a, __u8 b) {
    if (a == ACTION_BLOCK || b == ACTION_BLOCK)
        return ACTION_BLOCK;
    if (a == ACTION_AUDIT || b == ACTION_AUDIT)
        return ACTION_AUDIT;
    return ACTION_ALLOW;
}

// ptrace_access_check: tracer (current) requests access to tracee (child).
// mode & BPFE_PTRACE_MODE_ATTACH → "trace", mode & BPFE_PTRACE_MODE_READ → "read".
SEC("lsm/ptrace_access_check")
int BPF_PROG(bpfe_ptrace_access, struct task_struct *child, unsigned int mode)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 src = current_exe_inode();        // tracer exe
    __u64 tgt = task_exe_inode(child);      // tracee exe

    // 4-way fallback lookup
    struct bpfe_ptrace_key k = { cgid, src, tgt };
    struct bpfe_ptrace_val *v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k);
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k); }
    if (!v) { k.src_inode = src; k.target_inode = 0; v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k); }
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k); }

    if (!v)
        return fallback_posture(cgid, src, 0, DOMAIN_PTRACE);

    __u8 action;
    if (mode & BPFE_PTRACE_MODE_ATTACH)
        action = v->action_trace;
    else
        action = v->action_read;

    if (action == ACTION_ALLOW)
        return 0;

    __s32 ret = (action == ACTION_BLOCK) ? -EACCES : 0;
    submit_alert(cgid, src, tgt, DOMAIN_PTRACE, action,
                 (__u16)(mode & 0x3), v->policy_id, ret);
    return ret;
}

// ptrace_traceme: tracee (current) grants trace permission to tracer (parent).
// Evaluates traceby/readby rules on the tracee side.
SEC("lsm/ptrace_traceme")
int BPF_PROG(bpfe_ptrace_traceme, struct task_struct *parent)
{
    __u64 cgid = bpf_get_current_cgroup_id();   // tracee cgroup
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 src = current_exe_inode();             // tracee exe (policy subject)
    __u64 tgt = task_exe_inode(parent);          // tracer exe

    struct bpfe_ptrace_key k = { cgid, src, tgt };
    struct bpfe_ptrace_val *v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k);
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k); }
    if (!v) { k.src_inode = src; k.target_inode = 0; v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k); }
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_ptrace_rules, &k); }

    if (!v)
        return fallback_posture(cgid, src, 0, DOMAIN_PTRACE);

    // traceme has no mode argument — take the stricter of traceby/readby.
    __u8 action = max_action(v->action_traceby, v->action_readby);
    if (action == ACTION_ALLOW)
        return 0;

    __s32 ret = (action == ACTION_BLOCK) ? -EACCES : 0;
    submit_alert(cgid, src, tgt, DOMAIN_PTRACE, action, 0, v->policy_id, ret);
    return ret;
}
