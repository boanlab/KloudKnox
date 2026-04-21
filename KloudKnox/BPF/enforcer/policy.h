// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by net_enforcer.bpf.h — do not compile standalone.

// Policy Action Cache

struct session_key {
    __u32 proto;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
} __attribute__((packed));

struct ret_val {
    __s32 action;
    __u32 policy_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct session_key);
    __type(value, struct ret_val);
    __uint(max_entries, 65536);
} ne_sk_cache SEC(".maps");

static __always_inline void cache_policy_action(struct session_key *key, struct ret_val *res) {
    bpf_map_update_elem(&ne_sk_cache, key, res, BPF_ANY);
}

static __always_inline struct ret_val *cached_policy_action(struct session_key *key) {
    struct ret_val *ret = bpf_map_lookup_elem(&ne_sk_cache, key);
    return ret;
}

static __always_inline void delete_cached_policy_action(struct session_key *key) {
    bpf_map_delete_elem(&ne_sk_cache, key);
}

// Policy Management

struct policy_key {
    __u64 inode;
    __u32 saddr;
    __u32 daddr;
    __u32 proto;  // u8 -> u32 due to padding
    __u32 port;   // u16 -> u32 due to padding
};

struct lpm_key {
    __u32 prefixlen;
    __u32 laddr;  // fixed
    __u64 inode;  // fixed
    __u16 proto;  // fixed, u8 -> u16 due to padding
    __u16 port;   // fixed
    __u32 raddr;  // target for LPM
} __attribute__((packed));

struct policy_val {
    __u64 inode;
    __u16 port;
    __u8 proto;
    __s8 action;
    __u32 policy_id;
};

struct default_posture_key {
    __u64 inode;
    __u64 addr;  // u32 -> u64 due to padding
};

// FQDN Definitions

#define FQDN_KEY_LEN 64      // rule key & per-CPU scratch buffer length
#define FQDN_NOTIFY_LEN 256  // ring-buffer notify event reversed field (matches Go)
// DNS_MAX_LABELS capped far below the spec's 127: real FQDNs are 2–4 labels
// (e.g. "api.example.com" = 3), so 4 covers the common case with headroom.
#define DNS_MAX_LABELS 4
#define DNS_MAX_ANSWERS 16
#define DNS_RAW_BUF_LEN 512
// reversed-FQDN assembly scratch. The buffer (FQDN_TMP_LEN) must be larger
// than the effective write range (FQDN_TMP_WRITE_LEN) by at least one max
// label size (63): the verifier sums (max masked offset) + (max masked size)
// for each bpf_probe_read_kernel and requires the result ≤ buffer size.
// Writes target [0, FQDN_TMP_WRITE_LEN); the extra tail bytes are padding
// that keeps variable (offset, size) combinations inside the buffer bound.
#define FQDN_TMP_LEN 256
#define FQDN_TMP_WRITE_LEN 128

// FQDN notify event types (must match constants in Go fqdnResolver.go).
#define FQDN_NOTIFY_IP_INSTALLED 0
#define FQDN_NOTIFY_DNS_QUERY 1
#define FQDN_NOTIFY_DNS_RESPONSE 2

// DNS pending query correlation key (LRU hash).
struct dns_pending_key {
    __u32 querier_ip;     // network byte order
    __u32 dns_server_ip;  // network byte order
    __u16 querier_port;   // host order
    __u16 txid;           // host order
} __attribute__((packed));

struct dns_pending_val {
    __u64 ts;
    __u32 pid_ns_id;
    __u32 mnt_ns_id;
    char reversed[FQDN_KEY_LEN];
};

// FQDN rule map key/value.
struct fqdn_rule_key {
    char reversed[FQDN_KEY_LEN];
};

struct fqdn_rule_val {
    __u64 inode;
    __s8 action;
    __u8 direction;  // 0=egress, 1=ingress
    __u16 _pad;
    __u32 policy_id;
};

// FQDN IP lookup key: (inode, addr) → policy_val.
struct fqdn_ip_key {
    __u64 inode;
    __u32 addr;  // network byte order
    __u32 _pad;
};

// Per-CPU scratch for right-aligned reversed-FQDN assembly. Mirrors the
// prepend_path pattern in common/path.h: labels are written from the right
// with bpf_probe_read (one helper call per label), then the start offset is
// returned so callers can bpf_probe_read_str into the left-aligned key/event
// field — the NUL-terminated copy replaces any manual shift loop.
struct fqdn_tmp_buf {
    char buf[FQDN_TMP_LEN];
};

// Per-CPU raw DNS payload buffer.
struct dns_raw_buf {
    __u8 data[DNS_RAW_BUF_LEN];
};

// Notify ring buffer event. Allocated via bpf_ringbuf_reserve (not on BPF stack),
// so the 256-byte reversed field is safe. Must match Go fqdnNotifyEvent exactly.
struct fqdn_notify_event {
    __u64 ts;
    __u8 event_type;
    __u8 direction;
    __u8 _pad[2];
    __u32 pid_ns_id;
    __u32 mnt_ns_id;
    __u32 querier_ip;
    __u32 dns_server_ip;
    __u16 querier_port;
    __u16 txid;
    __u32 resolved_ip;
    __s8 policy_action;
    __u8 _pad2[3];
    __u32 policy_id;
    char reversed[FQDN_NOTIFY_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fqdn_ip_key);
    __type(value, struct policy_val);
    __uint(max_entries, 8192);
} ne_fqdn_egress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fqdn_ip_key);
    __type(value, struct policy_val);
    __uint(max_entries, 8192);
} ne_fqdn_ingress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fqdn_rule_key);
    __type(value, struct fqdn_rule_val);
    __uint(max_entries, 4096);
} ne_fqdn_rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ne_fqdn_notify_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct dns_pending_key);
    __type(value, struct dns_pending_val);
    __uint(max_entries, 1024);
} ne_dns_pending_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct fqdn_tmp_buf);
    __uint(max_entries, 1);
} ne_fqdn_tmp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct dns_raw_buf);
    __uint(max_entries, 1);
} ne_dns_raw_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct fqdn_rule_key);
    __uint(max_entries, 1);
} ne_fqdn_key_scratch_map SEC(".maps");

static __always_inline struct policy_val *lookup_fqdn_ip(__u8 direction, __u64 inode, __u32 addr) {
    struct fqdn_ip_key k = {.inode = inode, .addr = addr, ._pad = 0};
    if (direction == 0) return bpf_map_lookup_elem(&ne_fqdn_egress_map, &k);
    return bpf_map_lookup_elem(&ne_fqdn_ingress_map, &k);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_key);
    __type(value, struct policy_val);
    __uint(max_entries, 16384);
} ne_ingress_policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct policy_val);
    __uint(max_entries, 8192);
} ne_ingress_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct default_posture_key);
    __type(value, struct ret_val);
    __uint(max_entries, 8192);
} ne_ingress_default_posture_map SEC(".maps");

static __always_inline struct ret_val ingress_policy_match(struct __sk_buff *skb, struct session_key *key) {
    __u64 ino = 0;
    struct policy_val *val = NULL;
    struct ret_val *res = NULL;

    if (!skb)
        ino = get_exe_file_inode();
    else
        ino = get_inode_from_port(skb, key->proto, key->dport);

    // Step 0: FQDN IP match (inode-specific). Go stores addr as
    // binary.BigEndian.Uint32(ip_bytes); bpf_ntohl converts our LE value to match.
    __u32 ingress_remote = bpf_ntohl(key->saddr);
    val = lookup_fqdn_ip(1, ino, ingress_remote);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 0b: FQDN IP match (wildcard inode — applies to all processes)
    if (ino != 0) {
        val = lookup_fqdn_ip(1, 0, ingress_remote);
        if (val) return (struct ret_val){val->action, val->policy_id};
    }

    // Step 1: Try exact matching with inode + source IP + destination port
    struct policy_key p_key = {
        .inode = ino, .saddr = key->saddr, .daddr = key->daddr, .proto = key->proto, .port = key->dport};

    val = bpf_map_lookup_elem(&ne_ingress_policy_map, &p_key);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 2: Try exact matching with inode + source IP (port wildcard)
    p_key.proto = 0;
    p_key.port = 0;

    val = bpf_map_lookup_elem(&ne_ingress_policy_map, &p_key);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 3: Try LPM matching with inode + CIDR + destination port
    struct lpm_key lpm_k = {.prefixlen = 160,
                            .inode = ino,
                            .laddr = key->daddr,
                            .proto = key->proto,
                            .port = key->dport,
                            .raddr = key->saddr};

    val = bpf_map_lookup_elem(&ne_ingress_lpm_map, &lpm_k);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 4: Try LPM matching with inode + CIDR (port wildcard)
    lpm_k.proto = 0;
    lpm_k.port = 0;

    val = bpf_map_lookup_elem(&ne_ingress_lpm_map, &lpm_k);
    if (val) return (struct ret_val){val->action, val->policy_id};

    if (ino != 0) {
        // Step 5: Try exact matching with wildcard inode + source IP + destination port
        struct policy_key p_key = {
            .inode = 0, .saddr = key->saddr, .daddr = key->daddr, .proto = key->proto, .port = key->dport};

        val = bpf_map_lookup_elem(&ne_ingress_policy_map, &p_key);
        if (val) return (struct ret_val){val->action, val->policy_id};

        // Step 6: Try exact matching with wildcard inode + source IP (port wildcard)
        p_key.proto = 0;
        p_key.port = 0;

        val = bpf_map_lookup_elem(&ne_ingress_policy_map, &p_key);
        if (val) return (struct ret_val){val->action, val->policy_id};

        // Step 7: Try LPM matching with wildcard inode + CIDR + destination port
        struct lpm_key lpm_k = {.prefixlen = 160,
                                .inode = 0,
                                .laddr = key->daddr,
                                .proto = key->proto,
                                .port = key->dport,
                                .raddr = key->saddr};

        val = bpf_map_lookup_elem(&ne_ingress_lpm_map, &lpm_k);
        if (val) return (struct ret_val){val->action, val->policy_id};

        // Step 8: Try LPM matching with wildcard inode + CIDR (port wildcard)
        lpm_k.proto = 0;
        lpm_k.port = 0;

        val = bpf_map_lookup_elem(&ne_ingress_lpm_map, &lpm_k);
        if (val) return (struct ret_val){val->action, val->policy_id};
    }

    struct default_posture_key dp_key = {
        .inode = ino,
        .addr = key->daddr,
    };

    // Step 9: Default posture for this specific inode
    res = bpf_map_lookup_elem(&ne_ingress_default_posture_map, &dp_key);
    if (res) return *res;

    if (ino != 0) {
        // Step 10: Fall back to global default posture (wildcard inode)
        dp_key.inode = 0;

        res = bpf_map_lookup_elem(&ne_ingress_default_posture_map, &dp_key);
        if (res) return *res;
    }

    return (struct ret_val){0, 0};
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct policy_key);
    __type(value, struct policy_val);
    __uint(max_entries, 16384);
} ne_egress_policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct policy_val);
    __uint(max_entries, 8192);
} ne_egress_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct default_posture_key);
    __type(value, struct ret_val);
    __uint(max_entries, 8192);
} ne_egress_default_posture_map SEC(".maps");

static __always_inline struct ret_val egress_policy_match(struct __sk_buff *skb, struct session_key *key) {
    __u64 ino = 0;
    struct policy_val *val = NULL;
    struct ret_val *res = NULL;

    if (!skb)
        ino = get_exe_file_inode();
    else
        ino = get_inode_from_port(skb, key->proto, key->sport);

    // Step 0: FQDN IP match (inode-specific). Go stores addr as
    // binary.BigEndian.Uint32(ip_bytes); bpf_ntohl converts our LE value to match.
    __u32 egress_remote = bpf_ntohl(key->daddr);
    val = lookup_fqdn_ip(0, ino, egress_remote);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 0b: FQDN IP match (wildcard inode — applies to all processes)
    if (ino != 0) {
        val = lookup_fqdn_ip(0, 0, egress_remote);
        if (val) return (struct ret_val){val->action, val->policy_id};
    }

    // Step 1: Try exact matching with inode + destination IP + destination port
    struct policy_key p_key = {
        .inode = ino, .saddr = key->saddr, .daddr = key->daddr, .proto = key->proto, .port = key->dport};

    val = bpf_map_lookup_elem(&ne_egress_policy_map, &p_key);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 2: Try exact matching with inode + destination IP (port wildcard)
    p_key.proto = 0;
    p_key.port = 0;

    val = bpf_map_lookup_elem(&ne_egress_policy_map, &p_key);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 3: Try LPM matching with inode + CIDR + destination port
    struct lpm_key lpm_k = {.prefixlen = 160,
                            .inode = ino,
                            .laddr = key->saddr,
                            .proto = key->proto,
                            .port = key->dport,
                            .raddr = key->daddr};

    val = bpf_map_lookup_elem(&ne_egress_lpm_map, &lpm_k);
    if (val) return (struct ret_val){val->action, val->policy_id};

    // Step 4: Try LPM matching with inode + CIDR (port wildcard)
    lpm_k.proto = 0;
    lpm_k.port = 0;

    val = bpf_map_lookup_elem(&ne_egress_lpm_map, &lpm_k);
    if (val) return (struct ret_val){val->action, val->policy_id};

    if (ino != 0) {
        // Step 5: Try matching with destination IP + destination port (inode wildcard)
        struct policy_key p_key = {
            .inode = 0, .saddr = key->saddr, .daddr = key->daddr, .proto = key->proto, .port = key->dport};

        val = bpf_map_lookup_elem(&ne_egress_policy_map, &p_key);
        if (val) return (struct ret_val){val->action, val->policy_id};

        // Step 6: Try matching with destination IP only (inode and port wildcards)
        p_key.proto = 0;
        p_key.port = 0;

        val = bpf_map_lookup_elem(&ne_egress_policy_map, &p_key);
        if (val) return (struct ret_val){val->action, val->policy_id};

        // Step 7: Try LPM matching with wildcard inode + CIDR + destination port
        struct lpm_key lpm_k = {.prefixlen = 160,
                                .inode = 0,
                                .laddr = key->saddr,
                                .proto = key->proto,
                                .port = key->dport,
                                .raddr = key->daddr};

        val = bpf_map_lookup_elem(&ne_egress_lpm_map, &lpm_k);
        if (val) return (struct ret_val){val->action, val->policy_id};

        // Step 8: Try LPM matching with wildcard inode + CIDR (port wildcard)
        lpm_k.proto = 0;
        lpm_k.port = 0;

        val = bpf_map_lookup_elem(&ne_egress_lpm_map, &lpm_k);
        if (val) return (struct ret_val){val->action, val->policy_id};
    }

    struct default_posture_key dp_key = {
        .inode = ino,
        .addr = key->saddr,
    };

    // Step 9: Default posture for this specific inode
    res = bpf_map_lookup_elem(&ne_egress_default_posture_map, &dp_key);
    if (res) return *res;

    if (ino != 0) {
        // Step 10: Fall back to global default posture (wildcard inode)
        dp_key.inode = 0;

        res = bpf_map_lookup_elem(&ne_egress_default_posture_map, &dp_key);
        if (res) return *res;
    }

    return (struct ret_val){0, 0};
}
