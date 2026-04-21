// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by net_enforcer.bpf.h — do not compile standalone.

// Socket Management

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  // TGID
    __uint(value_size, sizeof(struct socket *));
    __uint(max_entries, 65536);
} ne_bind_socket_map SEC(".maps");

static __always_inline void push_bind_socket(struct socket *sock) {
    __u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ne_bind_socket_map, &tgid, &sock, BPF_ANY);
}

static __always_inline struct socket *pop_bind_socket() {
    __u64 tgid = bpf_get_current_pid_tgid();

    struct socket **psock = bpf_map_lookup_elem(&ne_bind_socket_map, &tgid);
    if (!psock) return NULL;

    bpf_map_delete_elem(&ne_bind_socket_map, &tgid);

    return *psock;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  // TGID
    __uint(value_size, sizeof(struct sock *));
    __uint(max_entries, 65536);
} ne_connect_sock_map SEC(".maps");

static __always_inline void push_connect_sock(struct sock *sk) {
    __u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ne_connect_sock_map, &tgid, &sk, BPF_ANY);
}

static __always_inline struct sock *pop_connect_sock() {
    __u64 tgid = bpf_get_current_pid_tgid();

    struct sock **psk = bpf_map_lookup_elem(&ne_connect_sock_map, &tgid);
    if (!psk) return NULL;

    bpf_map_delete_elem(&ne_connect_sock_map, &tgid);

    return *psk;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  // TGID
    __uint(value_size, sizeof(struct sock *));
    __uint(max_entries, 65536);
} ne_autobind_map SEC(".maps");

static __always_inline void push_autobind_sock(struct sock *sk) {
    __u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ne_autobind_map, &tgid, &sk, BPF_ANY);
}

static __always_inline struct sock *pop_autobind_sock() {
    __u64 tgid = bpf_get_current_pid_tgid();
    struct sock **psk = bpf_map_lookup_elem(&ne_autobind_map, &tgid);
    if (!psk) return NULL;
    struct sock *sk = *psk;
    bpf_map_delete_elem(&ne_autobind_map, &tgid);
    return sk;
}

struct msg_args {
    struct sock *sk;
    struct msghdr *msg;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));  // TGID
    __uint(value_size, sizeof(struct msg_args));
    __uint(max_entries, 65536);
} ne_msg_map SEC(".maps");

static __always_inline void push_msg_args(struct sock *sk, struct msghdr *msg) {
    __u64 tgid = bpf_get_current_pid_tgid();
    struct msg_args args = {.sk = sk, .msg = msg};
    bpf_map_update_elem(&ne_msg_map, &tgid, &args, BPF_ANY);
}

static __always_inline struct msg_args *peek_msg_args() {
    __u64 tgid = bpf_get_current_pid_tgid();
    return bpf_map_lookup_elem(&ne_msg_map, &tgid);
}

static __always_inline int pop_msg_args() {
    __u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ne_msg_map, &tgid);
    return 0;
}
