// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by bpf_enforcer.bpf.c — do not compile standalone.

#pragma once

#include "bpf_enforcer.bpf.h"
#include "../common/network.h"

// Errno / Action

#ifndef EACCES
#define EACCES 13
#endif

// Domain/Action

#define DOMAIN_PROC   0
#define DOMAIN_FILE   1
#define DOMAIN_CAP    2
#define DOMAIN_UNIX   3
#define DOMAIN_SIGNAL 4
#define DOMAIN_PTRACE 5

#define ACTION_ALLOW 0
#define ACTION_AUDIT 1
#define ACTION_BLOCK 2

// Common Key/Value

// Generic rule value used by cap/file/proc maps
struct bpfe_rule_val {
    __u8  action;    // ACTION_AUDIT or ACTION_BLOCK
    __u8  _pad[3];
    __u32 policy_id;
};

// Default posture (per pod+src+domain)
struct bpfe_posture_key {
    __u64 pod_inode;
    __u64 src_inode;
    __u32 domain;
    __u32 _pad;
};

struct bpfe_posture_val {
    __u8  action;     // ACTION_ALLOW or ACTION_BLOCK
    __u8  _pad[3];
    __u32 policy_id;  // policy that created this posture entry (0 = unknown)
};

// Managed Cgroups

// Cgroup IDs that are under BPF-LSM enforcement.
// Registered by UpdateBPFMaps after all rules are in place.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, 4096);
} bpfe_managed_cgroups SEC(".maps");

// Alert Ring Buffer

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} bpfe_alerts_rb SEC(".maps");

// Posture Map

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpfe_posture_key);
    __type(value, struct bpfe_posture_val);
    __uint(max_entries, 65536);
} bpfe_posture SEC(".maps");

// Capability Rules

struct bpfe_cap_key {
    __u64 pod_inode;
    __u64 src_inode;
    __u32 cap_id;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpfe_cap_key);
    __type(value, struct bpfe_rule_val);
    __uint(max_entries, 65536);
} bpfe_cap_rules SEC(".maps");

// Signal Rules

struct bpfe_signal_key {
    __u64 pod_inode;
    __u64 src_inode;
    __u64 target_inode;  // receiver exe inode; 0 = any
    __u32 _pad;
};

struct bpfe_signal_val {
    __u32 block_mask;  // bit(sig-1) set → Block
    __u32 audit_mask;  // bit(sig-1) set → Audit
    __u32 policy_id;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpfe_signal_key);
    __type(value, struct bpfe_signal_val);
    __uint(max_entries, 65536);
} bpfe_signal_rules SEC(".maps");

// Ptrace Rules

struct bpfe_ptrace_key {
    __u64 pod_inode;
    __u64 src_inode;
    __u64 target_inode;
};

struct bpfe_ptrace_val {
    __u8  action_trace;    // tracer→tracee ATTACH
    __u8  action_read;     // tracer→tracee READ
    __u8  action_traceby;  // tracee side ATTACH (PTRACE_TRACEME)
    __u8  action_readby;   // tracee side READ  (PTRACE_TRACEME)
    __u32 policy_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpfe_ptrace_key);
    __type(value, struct bpfe_ptrace_val);
    __uint(max_entries, 65536);
} bpfe_ptrace_rules SEC(".maps");

// File Rules

#define PERM_FILE_READ   0
#define PERM_FILE_WRITE  1

struct bpfe_file_key {
    __u64 pod_inode;
    __u64 src_inode;
    __u64 tgt_inode;   // target file/dir inode; 0 = any
    __u8  permission;  // PERM_FILE_READ or PERM_FILE_WRITE
    __u8  _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpfe_file_key);
    __type(value, struct bpfe_rule_val);
    __uint(max_entries, 65536);
} bpfe_file_rules SEC(".maps");

// Process Exec Rules

struct bpfe_proc_key {
    __u64 pod_inode;
    __u64 src_inode;  // executer exe inode; 0 = any
    __u64 tgt_inode;  // target exe inode; 0 = any
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpfe_proc_key);
    __type(value, struct bpfe_rule_val);
    __uint(max_entries, 65536);
} bpfe_proc_rules SEC(".maps");

// Unix IPC Rules

#define UNIX_PATH_MAX     108
#define UNIX_HASH_LEN      64   // bytes hashed (BPF stack budget); paths >64 bytes are hashed by prefix

#define PERM_UNIX_CONNECT  0
#define PERM_UNIX_SEND     1
#define PERM_UNIX_RECEIVE  2
#define PERM_UNIX_BIND     3
#define PERM_UNIX_LISTEN   4

// Per-socket state keyed by (struct sock *) cast to __u64.
// Populated at socket_bind; cleaned up at sk_free_security.
struct bpfe_unix_sk_ctx {
    __u64 cgid;
    __u32 path_hash;   // FNV-1a of sun_path; 0 = not yet bound to a named path
    __u8  sock_type;   // SOCK_STREAM=1 or SOCK_DGRAM=2
    __u8  _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct bpfe_unix_sk_ctx);
    __uint(max_entries, 4096);
} bpfe_unix_sk_map SEC(".maps");

struct bpfe_unix_key {
    __u64 pod_inode;
    __u64 src_inode;
    __u32 path_hash;   // FNV-1a of sun_path; 0 = any path
    __u8  sock_type;   // 0 = any, 1 = SOCK_STREAM, 2 = SOCK_DGRAM
    __u8  permission;  // PERM_UNIX_*
    __u8  _pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpfe_unix_key);
    __type(value, struct bpfe_rule_val);
    __uint(max_entries, 65536);
} bpfe_unix_rules SEC(".maps");
