// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by net_enforcer.bpf.h — do not compile standalone.

// Inode Management

static __always_inline __u64 get_exe_file_inode() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return 0;

    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) return 0;

    struct inode *inode = BPF_CORE_READ(exe_file, f_inode);
    if (!inode) return 0;

    return BPF_CORE_READ(inode, i_ino);
}

struct inode_key {
    __u64 cgroup_id;
    __u32 protocol;  // u8 -> u32 due to padding
    __u32 port;      // u16 -> u32 due to padding
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct inode_key);
    __type(value, __u64);  // inode
    __uint(max_entries, 65536);
} ne_inode_map SEC(".maps");

static __always_inline void bind_port_to_inode(__u8 proto, __u16 port) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct inode_key key = {.cgroup_id = cgid, .protocol = proto, .port = port};
    __u64 val = get_exe_file_inode();
    bpf_map_update_elem(&ne_inode_map, &key, &val, BPF_ANY);
}

static __always_inline __u64 get_inode_from_port(struct __sk_buff *skb, __u8 proto, __u16 port) {
    __u64 cgid = bpf_skb_cgroup_id(skb);
    struct inode_key key = {.cgroup_id = cgid, .protocol = proto, .port = port};
    __u64 *pval = bpf_map_lookup_elem(&ne_inode_map, &key);

    if (pval) return *pval;
    return 0;
}

static __always_inline void delete_port_bound_to_inode(__u64 cgid, __u8 proto, __u16 port) {
    struct inode_key key = {.cgroup_id = cgid, .protocol = proto, .port = port};
    bpf_map_delete_elem(&ne_inode_map, &key);
}
