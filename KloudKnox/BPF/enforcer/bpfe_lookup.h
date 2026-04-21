// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by bpf_enforcer.bpf.c — do not compile standalone.

#pragma once

#include "bpfe_alert.h"

// Exe-inode Helpers

// task_exe_inode returns the exe inode of any task_struct (NULL-safe).
static __always_inline __u64 task_exe_inode(struct task_struct *task) {
    if (!task)
        return 0;
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;
    struct file *exe = BPF_CORE_READ(mm, exe_file);
    if (!exe)
        return 0;
    struct dentry *dent = BPF_CORE_READ(exe, f_path.dentry);
    if (!dent)
        return 0;
    struct inode *ino = BPF_CORE_READ(dent, d_inode);
    if (!ino)
        return 0;
    return BPF_CORE_READ(ino, i_ino);
}

// current_exe_inode returns the inode number of the current task's executable.
static __always_inline __u64 current_exe_inode(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return task_exe_inode(task);
}

// Posture Fallback

// fallback_posture looks up the default posture for (cgid, src, domain).
// If posture is Block it emits an alert with the actual target_inode and
// returns -EACCES. Otherwise returns 0 (Allow).
static __always_inline int fallback_posture(__u64 cgid, __u64 src_inode,
                                             __u64 target_inode, __u8 domain) {
    struct bpfe_posture_key pk = {
        .pod_inode = cgid,
        .src_inode = src_inode,
        .domain    = domain,
        ._pad      = 0,
    };

    struct bpfe_posture_val *pv =
        bpf_map_lookup_elem(&bpfe_posture, &pk);

    // Try (cgid, 0, domain) if per-source lookup missed
    if (!pv) {
        pk.src_inode = 0;
        pv = bpf_map_lookup_elem(&bpfe_posture, &pk);
    }

    if (pv && pv->action == ACTION_BLOCK) {
        submit_alert(cgid, src_inode, target_inode, domain, ACTION_BLOCK,
                     (__u16)domain, pv->policy_id, -EACCES);
        return -EACCES;
    }

    return 0;
}

// apply_action helper

// apply_action emits an alert (when action != ALLOW) and returns the appropriate
// return code.  All enforcement hooks share this pattern.
static __always_inline int apply_action(__u64 cgid, __u64 src_inode,
                                         __u64 target_inode, __u8 domain,
                                         __u16 event_id,
                                         const struct bpfe_rule_val *v) {
    __s32 ret = (v->action == ACTION_BLOCK) ? -EACCES : 0;

    if (v->action != ACTION_ALLOW)
        submit_alert(cgid, src_inode, target_inode, domain, v->action,
                     event_id, v->policy_id, ret);

    return ret;
}
