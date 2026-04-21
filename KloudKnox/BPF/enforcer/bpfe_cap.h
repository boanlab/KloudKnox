// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Capability enforcement — SEC("lsm/capable").

#pragma once

#include "bpfe_lookup.h"

SEC("lsm/capable")
int BPF_PROG(bpfe_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 src = current_exe_inode();

    // Lookup (pod_cgid, src_inode, cap_id) — exact source match
    struct bpfe_cap_key k = {
        .pod_inode = cgid,
        .src_inode = src,
        .cap_id    = (__u32)cap,
        ._pad      = 0,
    };
    struct bpfe_rule_val *v = bpf_map_lookup_elem(&bpfe_cap_rules, &k);

    // Fallback to "default" source (src_inode = 0)
    if (!v) {
        k.src_inode = 0;
        v = bpf_map_lookup_elem(&bpfe_cap_rules, &k);
    }

    if (!v)
        return fallback_posture(cgid, src, (__u64)cap, DOMAIN_CAP);

    return apply_action(cgid, src, (__u64)cap, DOMAIN_CAP, (__u16)cap, v);
}
