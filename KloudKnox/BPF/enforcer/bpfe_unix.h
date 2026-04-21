// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Unix-socket IPC enforcement (M4).
// Named AF_UNIX sockets only; abstract and anonymous sockets pass through.
// Paths longer than UNIX_HASH_LEN bytes are hashed by their prefix only.

#pragma once

#include "bpfe_lookup.h"

// FNV-1a hash of the first UNIX_HASH_LEN bytes of a null-terminated path.
// Must match Go-side fnv1aUnixPath() exactly.
// Loop is not unrolled to stay within the BPF 512-byte stack limit.
static __always_inline __u32 bpfe_unix_hash(const char *path) {
    __u32 h = 2166136261u;
    for (int i = 0; i < UNIX_HASH_LEN; i++) {
        __u8 c = ((unsigned char *)path)[i];
        if (!c)
            break;
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

// 4-way fallback lookup on bpfe_unix_rules:
//   (pod, src, hash, type, perm) → (pod, 0, hash, type, perm)
//   → (pod, src, 0, 0, perm) → (pod, 0, 0, 0, perm)
static __always_inline struct bpfe_rule_val *
bpfe_unix_lookup(__u64 cgid, __u64 src, __u32 hash, __u8 sock_type, __u8 perm)
{
    struct bpfe_unix_key k = {
        .pod_inode  = cgid,
        .src_inode  = src,
        .path_hash  = hash,
        .sock_type  = sock_type,
        .permission = perm,
    };
    struct bpfe_rule_val *v = bpf_map_lookup_elem(&bpfe_unix_rules, &k);
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_unix_rules, &k); }
    if (!v) { k.src_inode = src; k.path_hash = 0; k.sock_type = 0;
              v = bpf_map_lookup_elem(&bpfe_unix_rules, &k); }
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_unix_rules, &k); }
    return v;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(bpfe_unix_stream_connect, struct socket *sock,
             struct socket *other, struct socket *newsk)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    struct sock *srv_sk = BPF_CORE_READ(other, sk);
    if (!srv_sk)
        return 0;
    __u64 srv_key = (__u64)(unsigned long)srv_sk;
    struct bpfe_unix_sk_ctx *sk_ctx = bpf_map_lookup_elem(&bpfe_unix_sk_map, &srv_key);
    if (!sk_ctx || sk_ctx->path_hash == 0)
        return 0;   // server not bound to a named path

    __u64 src = current_exe_inode();
    struct bpfe_rule_val *v = bpfe_unix_lookup(cgid, src, sk_ctx->path_hash,
                                                sk_ctx->sock_type, PERM_UNIX_CONNECT);
    if (!v)
        return fallback_posture(cgid, src, 0, DOMAIN_UNIX);
    return apply_action(cgid, src, 0, DOMAIN_UNIX, (__u16)PERM_UNIX_CONNECT, v);
}

SEC("lsm/unix_may_send")
int BPF_PROG(bpfe_unix_may_send, struct socket *sock, struct socket *other)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    struct sock *dst_sk = BPF_CORE_READ(other, sk);
    if (!dst_sk)
        return 0;
    __u64 dst_key = (__u64)(unsigned long)dst_sk;
    struct bpfe_unix_sk_ctx *sk_ctx = bpf_map_lookup_elem(&bpfe_unix_sk_map, &dst_key);
    if (!sk_ctx || sk_ctx->path_hash == 0)
        return 0;

    __u64 src = current_exe_inode();
    struct bpfe_rule_val *v = bpfe_unix_lookup(cgid, src, sk_ctx->path_hash,
                                                sk_ctx->sock_type, PERM_UNIX_SEND);
    if (!v)
        return fallback_posture(cgid, src, 0, DOMAIN_UNIX);
    return apply_action(cgid, src, 0, DOMAIN_UNIX, (__u16)PERM_UNIX_SEND, v);
}

// socket_post_create: register AF_UNIX socket in sidecar with path_hash=0.
// The path hash is updated at socket_bind time.
SEC("lsm/socket_post_create")
int BPF_PROG(bpfe_socket_post_create, struct socket *sock, int family,
             int type, int protocol, int kern)
{
    if (family != AF_UNIX || kern)
        return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;
    __u64 sk_key = (__u64)(unsigned long)sk;
    struct bpfe_unix_sk_ctx sk_ctx = {
        .cgid      = cgid,
        .path_hash = 0,
        .sock_type = (__u8)type,
    };
    bpf_map_update_elem(&bpfe_unix_sk_map, &sk_key, &sk_ctx, BPF_ANY);
    return 0;
}

// sk_free_security: remove socket from sidecar on destruction.
SEC("lsm/sk_free_security")
int BPF_PROG(bpfe_sk_free, struct sock *sk)
{
    if (!sk)
        return 0;
    __u64 sk_key = (__u64)(unsigned long)sk;
    bpf_map_delete_elem(&bpfe_unix_sk_map, &sk_key);
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(bpfe_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    if (!sock || !address)
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    // Read sa_family to check if AF_UNIX
    __u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), address) < 0)
        return 0;
    if (family != AF_UNIX)
        return 0;

    // sockaddr_un layout: sa_family(2) + sun_path(108)
    // Read first byte of sun_path to detect abstract sockets
    char first = 0;
    if (bpf_probe_read_kernel(&first, 1, (char *)address + 2) < 0)
        return 0;
    if (!first)
        return 0;  // abstract socket ('\0'-prefixed) — skip

    // Read up to UNIX_HASH_LEN bytes of path for hashing
    char path[UNIX_HASH_LEN];
    __builtin_memset(path, 0, sizeof(path));
    bpf_probe_read_kernel(path, sizeof(path), (char *)address + 2);

    __u32 hash = bpfe_unix_hash(path);

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;
    __u64 sk_key = (__u64)(unsigned long)sk;
    __u16 stype = BPF_CORE_READ(sock, type);

    struct bpfe_unix_sk_ctx sk_ctx = {
        .cgid      = cgid,
        .path_hash = hash,
        .sock_type = (__u8)stype,
    };
    bpf_map_update_elem(&bpfe_unix_sk_map, &sk_key, &sk_ctx, BPF_ANY);

    __u64 src = current_exe_inode();
    struct bpfe_rule_val *v = bpfe_unix_lookup(cgid, src, hash,
                                                (__u8)stype, PERM_UNIX_BIND);
    if (!v)
        return fallback_posture(cgid, src, 0, DOMAIN_UNIX);
    return apply_action(cgid, src, 0, DOMAIN_UNIX, (__u16)PERM_UNIX_BIND, v);
}

SEC("lsm/socket_listen")
int BPF_PROG(bpfe_socket_listen, struct socket *sock, int backlog)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;
    __u64 sk_key = (__u64)(unsigned long)sk;
    struct bpfe_unix_sk_ctx *sk_ctx = bpf_map_lookup_elem(&bpfe_unix_sk_map, &sk_key);
    if (!sk_ctx || sk_ctx->path_hash == 0)
        return 0;  // not a named AF_UNIX socket

    __u64 src = current_exe_inode();
    struct bpfe_rule_val *v = bpfe_unix_lookup(cgid, src, sk_ctx->path_hash,
                                                sk_ctx->sock_type, PERM_UNIX_LISTEN);
    if (!v)
        return fallback_posture(cgid, src, 0, DOMAIN_UNIX);
    return apply_action(cgid, src, 0, DOMAIN_UNIX, (__u16)PERM_UNIX_LISTEN, v);
}
