// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Process exec enforcement — SEC("lsm/bprm_check_security") (M5).

#pragma once

#include "bpfe_lookup.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(bpfe_bprm_check, struct linux_binprm *bprm)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 src = current_exe_inode();

    // Target: the executable being loaded into the new address space
    struct file *f = BPF_CORE_READ(bprm, file);
    if (!f)
        return 0;
    struct dentry *dent = BPF_CORE_READ(f, f_path.dentry);
    if (!dent)
        return 0;
    struct inode *ino = BPF_CORE_READ(dent, d_inode);
    if (!ino)
        return 0;
    __u64 tgt = BPF_CORE_READ(ino, i_ino);

    // 4-way fallback: (pod,src,tgt) → (pod,0,tgt) → (pod,src,0) → (pod,0,0)
    struct bpfe_proc_key k = { cgid, src, tgt };
    struct bpfe_rule_val *v = bpf_map_lookup_elem(&bpfe_proc_rules, &k);
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_proc_rules, &k); }
    if (!v) { k.src_inode = src; k.tgt_inode = 0; v = bpf_map_lookup_elem(&bpfe_proc_rules, &k); }
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_proc_rules, &k); }

    if (!v)
        return fallback_posture(cgid, src, tgt, DOMAIN_PROC);

    return apply_action(cgid, src, tgt, DOMAIN_PROC, 0, v);
}
