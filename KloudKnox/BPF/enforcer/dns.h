// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by net_enforcer.bpf.h — do not compile standalone.

// DNS Helpers

// Read a single byte from the raw DNS buffer. Caller is responsible for
// bounding `off`; we still mask to keep the load in-bounds of the 512-byte
// map value even if a new call site forgets to check.
static __always_inline __u8 raw_byte(struct dns_raw_buf *raw, __u32 off) {
    // barrier_var(off) prevents clang from proving `off & (DNS_RAW_BUF_LEN-1) == off`
    // via a caller-side bound check and stripping the AND — the verifier needs
    // the mask to keep `pos` registers bounded across loop back-edges.
    barrier_var(off);
    return raw->data[off & (DNS_RAW_BUF_LEN - 1)];
}

// Extract 16-bit big-endian value from raw buffer at offset.
static __always_inline __u16 raw_read16(struct dns_raw_buf *raw, __u32 off) {
    return ((__u16)raw_byte(raw, off) << 8) | (__u16)raw_byte(raw, off + 1);
}

// Extract 32-bit big-endian value from raw buffer at offset.
static __always_inline __u32 raw_read32(struct dns_raw_buf *raw, __u32 off) {
    return ((__u32)raw_byte(raw, off) << 24) | ((__u32)raw_byte(raw, off + 1) << 16) |
           ((__u32)raw_byte(raw, off + 2) << 8) | (__u32)raw_byte(raw, off + 3);
}

// Assemble a DNS wire-format name from `raw->data[]` (starting at `offset`) as
// a reversed dotted string, right-aligned into `tmp->buf`. Mirrors
// prepend_path() in common/path.h: iterate labels forward, write each with a
// single bpf_probe_read() into decreasing positions in tmp. Because every
// per-label copy is a single helper call (not a byte-wise C loop), the
// verifier does not multiply (pos, out, j) scalar state across iterations —
// cross-iteration state reduces to `pos` and `out` only.
//
// Returns the starting offset in tmp->buf where the NUL-terminated reversed
// string begins, or -1 on parse failure. Compression pointers are supported
// (jump limit 2), but at most DNS_MAX_LABELS total labels are emitted.
//
// __noinline so each invocation has its own bounded verifier cost — inlining
// into cgroup_skb__egress_dns would re-expand the loop state at the call site.
static __noinline int prepend_fqdn_reversed(struct dns_raw_buf *raw, __u32 raw_len, __u32 offset,
                                            struct fqdn_tmp_buf *tmp) {
    int out = FQDN_TMP_WRITE_LEN - 1;
    // Trailing NUL — becomes the string terminator after all labels are prepended.
    // Direct write into the map value: cgroup_skb can't call bpf_probe_read(#4),
    // and a single-byte store needs no helper anyway.
    tmp->buf[out & (FQDN_TMP_WRITE_LEN - 1)] = '\0';

    __u32 pos = offset;
    __u32 end_pos = 0;
    int jumps = 0;
    int labels = 0;

    for (int i = 0; i < DNS_MAX_LABELS; i++) {
        barrier_var(pos);
        if (pos >= raw_len || pos >= DNS_RAW_BUF_LEN) break;

        __u8 lb = raw_byte(raw, pos);

        if (lb == 0) {
            pos++;
            break;
        }

        if ((lb & 0xC0) == 0xC0) {
            if (jumps++ >= 2) break;
            if (pos + 1 >= raw_len || pos + 1 >= DNS_RAW_BUF_LEN) break;
            __u8 lb2 = raw_byte(raw, pos + 1);
            if (end_pos == 0) end_pos = pos + 2;
            __u32 np = (((__u32)(lb & 0x3F)) << 8) | (__u32)lb2;
            if (np >= DNS_RAW_BUF_LEN) break;
            pos = np;
            continue;
        }

        if (lb > 63) break;
        __u32 llen = lb;
        pos++;

        // Prepend '.' separator before every label except the first-written
        // (which is the right-most label in the output — no separator follows it).
        if (labels > 0) {
            if (out <= 0) break;
            out--;
            tmp->buf[out & (FQDN_TMP_WRITE_LEN - 1)] = '.';
        }

        if (out - (int)llen < 0) break;
        out -= llen;

        // One helper call per label — verifier sees a single copy regardless
        // of llen. This is the key behaviour that keeps the prepend pattern
        // within the 1M-insn budget even with DNS_MAX_LABELS unrolled.
        // bpf_probe_read_kernel(#113) is permitted for cgroup_skb with CAP_BPF
        // (the legacy bpf_probe_read(#4) is not).
        //
        // Masks: offset into [0, FQDN_TMP_WRITE_LEN) and size into [0, 64) (DNS
        // label max 63 per RFC). Their sum (≤ 127 + 63 = 190) stays below
        // FQDN_TMP_LEN (256), which is the verifier's acceptance condition for
        // variable (offset, size) stores into a map value.
        bpf_probe_read_kernel(&tmp->buf[out & (FQDN_TMP_WRITE_LEN - 1)], llen & 63,
                              &raw->data[pos & (DNS_RAW_BUF_LEN - 1)]);
        pos += llen;
        labels++;
    }
    (void)end_pos;

    if (labels == 0) return -1;
    return out;
}

// Advance past a DNS wire-format name without building a string. Cheap
// counterpart to prepend_fqdn_reversed() used in the response path where the
// matching key comes from pv->reversed (saved at query time) — answer-record
// NAMEs never need reconstruction.
// Returns the offset AFTER the name, or -1.
static __noinline int dns_skip_name(struct dns_raw_buf *raw, __u32 raw_len, __u32 offset) {
    __u32 pos = offset;
    for (int i = 0; i < DNS_MAX_LABELS + 1; i++) {
        barrier_var(pos);
        if (pos >= raw_len || pos >= DNS_RAW_BUF_LEN) return -1;
        __u8 lb = raw_byte(raw, pos);
        if (lb == 0) return (int)(pos + 1);
        if ((lb & 0xC0) == 0xC0) {
            if (pos + 1 >= raw_len) return -1;
            return (int)(pos + 2);
        }
        if (lb > 63) return -1;
        pos += 1 + (__u32)lb;
    }
    return -1;
}

// Emit an fqdn_notify_event to the ring buffer. `reversed` points to a
// NUL-terminated reversed FQDN (≤ FQDN_KEY_LEN bytes). bpf_probe_read_str
// stops at NUL → the copy is auto left-aligned in ev->reversed with no manual
// shift required.
static __always_inline void emit_fqdn_notify(__u8 event_type, __u8 direction, __u32 pid_ns_id, __u32 mnt_ns_id,
                                             __u32 querier_ip, __u32 dns_server_ip, __u16 querier_port, __u16 txid,
                                             __u32 resolved_ip, __s8 policy_action, __u32 policy_id,
                                             const char *reversed) {
    struct fqdn_notify_event *ev = bpf_ringbuf_reserve(&ne_fqdn_notify_rb, sizeof(*ev), 0);
    if (!ev) return;

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->ts = bpf_ktime_get_ns();
    ev->event_type = event_type;
    ev->direction = direction;
    ev->pid_ns_id = pid_ns_id;
    ev->mnt_ns_id = mnt_ns_id;
    ev->querier_ip = querier_ip;
    ev->dns_server_ip = dns_server_ip;
    ev->querier_port = querier_port;
    ev->txid = txid;
    ev->resolved_ip = resolved_ip;
    ev->policy_action = policy_action;
    ev->policy_id = policy_id;
    bpf_probe_read_kernel_str(ev->reversed, FQDN_KEY_LEN, reversed);

    bpf_ringbuf_submit(ev, 0);
}

// Handle outgoing DNS query (UDP dport=53). Called from cgroup_skb/egress_dns.
// Builds the reversed FQDN in per-CPU tmp scratch, records pending state for
// the response correlation, emits DNS_QUERY notify event.
// saddr_net/daddr_net are network byte order (from iphdr); sport_host is host order.
static __always_inline void handle_dns_query(struct __sk_buff *skb, __u32 dns_offset, __u32 dns_len, __u32 saddr_net,
                                             __u32 daddr_net, __u16 sport_host) {
    if (dns_len < 12 || dns_len > DNS_RAW_BUF_LEN) return;

    __u32 zero = 0;
    struct dns_raw_buf *raw = bpf_map_lookup_elem(&ne_dns_raw_map, &zero);
    struct fqdn_tmp_buf *tmp = bpf_map_lookup_elem(&ne_fqdn_tmp_map, &zero);
    struct fqdn_rule_key *rkey = bpf_map_lookup_elem(&ne_fqdn_key_scratch_map, &zero);
    if (!raw || !tmp || !rkey) return;

    if (bpf_skb_load_bytes(skb, dns_offset, raw->data, dns_len) < 0) return;

    __u16 flags = raw_read16(raw, 2);
    if (flags & 0x8000) return;           // not a query
    if (raw_read16(raw, 4) == 0) return;  // qdcount == 0

    __u16 txid = raw_read16(raw, 0);

    int s = prepend_fqdn_reversed(raw, dns_len, 12, tmp);
    if (s < 0) return;

    // Stage reversed FQDN into the rule-key scratch, then look up any rule
    // so the query notify can carry its policy info.
    __builtin_memset(rkey, 0, sizeof(*rkey));
    bpf_probe_read_kernel_str(rkey->reversed, FQDN_KEY_LEN, &tmp->buf[s & (FQDN_TMP_WRITE_LEN - 1)]);
    struct fqdn_rule_val *rv = bpf_map_lookup_elem(&ne_fqdn_rules_map, rkey);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 pns = get_pid_ns_id(task);
    __u32 mns = get_mnt_ns_id(task);

    struct dns_pending_key pk = {
        .querier_ip = bpf_ntohl(saddr_net),
        .dns_server_ip = bpf_ntohl(daddr_net),
        .querier_port = sport_host,
        .txid = txid,
    };
    struct dns_pending_val pv;
    __builtin_memset(&pv, 0, sizeof(pv));
    pv.ts = bpf_ktime_get_ns();
    pv.pid_ns_id = pns;
    pv.mnt_ns_id = mns;
    bpf_probe_read_kernel_str(pv.reversed, FQDN_KEY_LEN, &tmp->buf[s & (FQDN_TMP_WRITE_LEN - 1)]);

    bpf_map_update_elem(&ne_dns_pending_map, &pk, &pv, BPF_ANY);

    emit_fqdn_notify(FQDN_NOTIFY_DNS_QUERY, rv ? rv->direction : 0, pns, mns, pk.querier_ip, pk.dns_server_ip,
                     sport_host, txid, 0, rv ? rv->action : 0, rv ? rv->policy_id : 0, pv.reversed);
}

// Per-answer state for the bpf_loop callback below. All fields that need to
// survive across iterations (notably `pos`) live here; the callback reads and
// writes them through the ctx pointer.
struct dns_answer_ctx {
    struct dns_raw_buf *raw;
    struct fqdn_rule_val *rv;    // may be NULL (no rule for this FQDN)
    struct dns_pending_val *pv;  // non-NULL (caller verified)
    __u32 dns_len;
    __u32 pos;  // advances past each answer
    __u32 querier_ip;
    __u32 dns_server_ip;
    __u16 dport_host;
    __u16 txid;
    __u16 ancount;
};

// bpf_loop callback: parse one DNS answer record. Returns 1 to stop early, 0 to continue.
// Name reconstruction is NOT performed here — the matching key was captured at
// query time (pv->reversed). Answer NAMEs are advanced past with dns_skip_name
// (zero writes, single scalar across iterations), which is what lets the
// per-answer loop stay inside the verifier's state-pruning threshold.
static long dns_answer_cb(__u32 k, void *ctx_) {
    struct dns_answer_ctx *ctx = ctx_;
    if ((__u16)k >= ctx->ancount) return 1;

    __u32 pos = ctx->pos;
    __u32 dns_len = ctx->dns_len;
    if (pos >= dns_len || pos >= DNS_RAW_BUF_LEN) return 1;

    int after_name = dns_skip_name(ctx->raw, dns_len, pos);
    if (after_name < 0) return 1;
    pos = (__u32)after_name;
    if (pos + 10 > dns_len || pos + 10 > DNS_RAW_BUF_LEN) return 1;

    __u16 rtype = raw_read16(ctx->raw, pos);
    __u16 rclass = raw_read16(ctx->raw, pos + 2);
    __u16 rdlen = raw_read16(ctx->raw, pos + 8);
    pos += 10;

    if (rtype == 1 && rclass == 1 && rdlen == 4 && pos + 4 <= dns_len && pos + 4 <= DNS_RAW_BUF_LEN) {
        __u32 ip_be = raw_read32(ctx->raw, pos);
        struct fqdn_rule_val *rv = ctx->rv;
        struct dns_pending_val *pv = ctx->pv;

        if (rv) {
            struct fqdn_ip_key fk = {.inode = rv->inode, .addr = ip_be, ._pad = 0};
            struct policy_val pval;
            __builtin_memset(&pval, 0, sizeof(pval));
            pval.inode = rv->inode;
            pval.action = rv->action;
            pval.policy_id = rv->policy_id;

            if (rv->direction == 0)
                bpf_map_update_elem(&ne_fqdn_egress_map, &fk, &pval, BPF_ANY);
            else
                bpf_map_update_elem(&ne_fqdn_ingress_map, &fk, &pval, BPF_ANY);

            emit_fqdn_notify(FQDN_NOTIFY_IP_INSTALLED, rv->direction, pv->pid_ns_id, pv->mnt_ns_id, ctx->querier_ip,
                             ctx->dns_server_ip, ctx->dport_host, ctx->txid, ip_be, rv->action, rv->policy_id,
                             pv->reversed);
        }

        emit_fqdn_notify(FQDN_NOTIFY_DNS_RESPONSE, rv ? rv->direction : 0, pv->pid_ns_id, pv->mnt_ns_id, ctx->querier_ip,
                         ctx->dns_server_ip, ctx->dport_host, ctx->txid, ip_be, rv ? rv->action : 0,
                         rv ? rv->policy_id : 0, pv->reversed);
    }

    if (pos + ((__u32)rdlen) > DNS_RAW_BUF_LEN) return 1;
    ctx->pos = pos + (__u32)rdlen;
    return 0;
}

// Handle incoming DNS response (UDP sport=53). Called from cgroup_skb/ingress_dns.
// Correlates with pending query via (querier, server, port, txid) → pv. Uses
// pv->reversed directly as the rule-map key (no answer-name parsing), scans A
// records, installs FQDN IPs, emits events.
// saddr_net/daddr_net are network byte order (from iphdr); dport_host is host order.
static __always_inline void handle_dns_response(struct __sk_buff *skb, __u32 dns_offset, __u32 dns_len,
                                                __u32 saddr_net, __u32 daddr_net, __u16 dport_host) {
    if (dns_len < 12 || dns_len > DNS_RAW_BUF_LEN) return;

    __u32 zero = 0;
    struct dns_raw_buf *raw = bpf_map_lookup_elem(&ne_dns_raw_map, &zero);
    struct fqdn_rule_key *rkey = bpf_map_lookup_elem(&ne_fqdn_key_scratch_map, &zero);
    if (!raw || !rkey) return;

    if (bpf_skb_load_bytes(skb, dns_offset, raw->data, dns_len) < 0) return;

    __u16 flags = raw_read16(raw, 2);
    if ((flags & 0x8000) == 0) return;  // not a response
    if ((flags & 0x000F) != 0) return;  // rcode != NOERROR
    __u16 ancount = raw_read16(raw, 6);
    if (raw_read16(raw, 4) == 0 || ancount == 0) return;

    __u16 txid = raw_read16(raw, 0);

    struct dns_pending_key pk = {
        .querier_ip = bpf_ntohl(daddr_net),
        .dns_server_ip = bpf_ntohl(saddr_net),
        .querier_port = dport_host,
        .txid = txid,
    };
    struct dns_pending_val *pv = bpf_map_lookup_elem(&ne_dns_pending_map, &pk);
    if (!pv) return;

    __builtin_memcpy(rkey->reversed, pv->reversed, FQDN_KEY_LEN);
    struct fqdn_rule_val *rv = bpf_map_lookup_elem(&ne_fqdn_rules_map, rkey);

    // Skip question section: QNAME + QTYPE(2) + QCLASS(2).
    int after_q = dns_skip_name(raw, dns_len, 12);
    if (after_q < 0 || ((__u32)after_q + 4) > dns_len) return;
    __u32 pos = (__u32)after_q + 4;

    struct dns_answer_ctx actx = {
        .raw = raw,
        .rv = rv,
        .pv = pv,
        .dns_len = dns_len,
        .pos = pos,
        .querier_ip = pk.querier_ip,
        .dns_server_ip = pk.dns_server_ip,
        .dport_host = dport_host,
        .txid = txid,
        .ancount = ancount,
    };
    bpf_loop(DNS_MAX_ANSWERS, dns_answer_cb, &actx, 0);

    bpf_map_delete_elem(&ne_dns_pending_map, &pk);
}
