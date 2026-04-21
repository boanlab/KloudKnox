// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// go:build ignore

#include "net_enforcer.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Port-to-Inode

// save socket pointer before bind; kretprobe reads bound port after syscall returns
SEC("kprobe/inet_bind")
int kprobe__inet_bind(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    if (!sock) return 0;

    push_bind_socket(sock);

    return 0;
}

// record listen port → inode mapping after bind succeeds
SEC("kretprobe/inet_bind")
int kretprobe__inet_bind(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct socket *sock = pop_bind_socket();
    if (!sock) return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);

    if (skc.skc_family != AF_INET) return 0;

    __u8 proto = BPF_CORE_READ(sk, sk_protocol);
    __u16 dport = skc.skc_num;  // host order

    if (dport != 0) {
        bind_port_to_inode(proto, dport);
    }

    return 0;
}

// save sock pointer before TCP autobind; kretprobe reads assigned ephemeral port
SEC("kprobe/inet_hash_connect")
int kprobe__inet_hash_connect(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM2(ctx);
    if (!sk) return 0;

    push_autobind_sock(sk);

    return 0;
}

// record TCP ephemeral source port → inode mapping after port is assigned
SEC("kretprobe/inet_hash_connect")
int kretprobe__inet_hash_connect(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = pop_autobind_sock();
    if (!sk) return 0;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);
    if (skc.skc_family != AF_INET) return 0;

    __u8 proto = BPF_CORE_READ(sk, sk_protocol);
    __u16 sport = skc.skc_num;  // host order

    if (sport != 0) {
        bind_port_to_inode(proto, sport);
    }

    return 0;
}

// Clean up map entries when TCP connection closes
SEC("tp/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->newstate != 7) return 0;  // TCP_CLOSE (7)

    struct sock *sk = (struct sock *)ctx->skaddr;
    if (!sk) return 0;

    // We only care about IPv4 for now
    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);
    if (skc.skc_family != AF_INET) return 0;

    __u16 sport = skc.skc_num;  // host order

    if (sport != 0) {
        __u64 cgid = bpf_get_current_cgroup_id();
        delete_port_bound_to_inode(cgid, IPPROTO_TCP, sport);

        struct session_key key = {.proto = IPPROTO_TCP,
                                  .saddr = skc.skc_rcv_saddr,
                                  .sport = sport,
                                  .daddr = skc.skc_daddr,
                                  .dport = bpf_ntohs(skc.skc_dport)};
        delete_cached_policy_action(&key);
    }

    return 0;
}

// save sock pointer before UDP autobind; kretprobe reads assigned ephemeral port
SEC("kprobe/inet_autobind")
int kprobe__inet_autobind(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    push_autobind_sock(sk);

    return 0;
}

// record UDP ephemeral source port → inode mapping after port is assigned
SEC("kretprobe/inet_autobind")
int kretprobe__inet_autobind(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = pop_autobind_sock();
    if (!sk) return 0;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);
    if (skc.skc_family != AF_INET) return 0;

    __u8 proto = BPF_CORE_READ(sk, sk_protocol);
    __u16 sport = skc.skc_num;  // host order

    if (sport != 0) {
        bind_port_to_inode(proto, sport);
    }

    return 0;
}

// Clean up map entries when UDP socket is destroyed
SEC("kprobe/udp_destroy_sock")
int kprobe__udp_destroy_sock(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);
    if (skc.skc_family != AF_INET) return 0;

    __u16 sport = skc.skc_num;  // host order

    if (sport != 0) {
        __u64 cgid = bpf_get_current_cgroup_id();
        delete_port_bound_to_inode(cgid, IPPROTO_UDP, sport);

        struct session_key key = {.proto = IPPROTO_UDP,
                                  .saddr = skc.skc_rcv_saddr,
                                  .sport = sport,
                                  .daddr = skc.skc_daddr,
                                  .dport = bpf_ntohs(skc.skc_dport)};
        delete_cached_policy_action(&key);
    }

    return 0;
}

// Network Events

SEC("kprobe/inet_stream_connect")
int kprobe__inet_stream_connect(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    if (!sock) return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;

    push_connect_sock(sk);

    return 0;
}

SEC("kretprobe/inet_stream_connect")
int kretprobe__inet_stream_connect(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = pop_connect_sock();
    if (!sk) return 0;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);

    if (skc.skc_family != AF_INET) return 0;

    struct session_key key = {
        .proto = BPF_CORE_READ(sk, sk_protocol),
        .saddr = skc.skc_rcv_saddr,        // network order
        .sport = skc.skc_num,              // host order
        .daddr = skc.skc_daddr,            // network order
        .dport = bpf_ntohs(skc.skc_dport)  // host order
    };

    // use network-ordered destination address and host-ordered port for policy matching
    struct ret_val res = egress_policy_match(NULL, &key);

    // cache the result of the policy match for future packets in the same session
    cache_policy_action(&key, &res);

    if (res.action != 0) {
        network_event_t ev = {0};
        init_event(&ev, __INET_STREAM_CONNECT);

        ev.saddr = bpf_ntohl(key.saddr);
        ev.daddr = bpf_ntohl(key.daddr);
        ev.sport = key.sport;
        ev.dport = key.dport;

        ev.proto = key.proto;

        ev.policy_id = res.policy_id;
        ev.ret_val = res.action;  // AUDIT(1) or BLOCK(-1)

        return submit_event(&ev);
    }

    return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);

    if (skc.skc_family != AF_INET) return 0;

    struct session_key key = {
        .proto = BPF_CORE_READ(sk, sk_protocol),
        .saddr = skc.skc_daddr,             // network order
        .sport = bpf_ntohs(skc.skc_dport),  // host order
        .daddr = skc.skc_rcv_saddr,         // network order
        .dport = skc.skc_num                // host order
    };

    struct ret_val *cached_val = cached_policy_action(&key);
    if (cached_val != NULL) {
        if (cached_val->action != 0) {
            network_event_t ev = {0};
            init_event(&ev, __INET_CSK_ACCEPT);

            ev.saddr = bpf_ntohl(key.saddr);
            ev.daddr = bpf_ntohl(key.daddr);
            ev.sport = key.sport;
            ev.dport = key.dport;

            ev.proto = key.proto;

            ev.policy_id = cached_val->policy_id;
            ev.ret_val = cached_val->action;  // AUDIT(1) or BLOCK(-1)

            return submit_event(&ev);
        }
        return 1;  // PASS
    }

    // use network-ordered address and host-ordered ports for policy matching
    struct ret_val res = ingress_policy_match(NULL, &key);
    if (res.action != 0) {
        network_event_t ev = {0};
        init_event(&ev, __INET_CSK_ACCEPT);

        ev.saddr = bpf_ntohl(key.saddr);
        ev.daddr = bpf_ntohl(key.daddr);
        ev.sport = key.sport;
        ev.dport = key.dport;

        ev.proto = key.proto;

        ev.policy_id = res.policy_id;
        ev.ret_val = res.action;  // AUDIT(1) or BLOCK(-1)

        return submit_event(&ev);
    }

    return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!msg) return 0;

    push_msg_args(sk, msg);

    return 0;
}

SEC("kretprobe/udp_sendmsg")
int kretprobe__udp_sendmsg(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct msg_args *args = peek_msg_args();
    if (!args) return 0;

    struct sock *sk = args->sk;
    struct msghdr *msg = args->msg;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);

    if (skc.skc_family != AF_INET) return 0;

    struct session_key key = {
        .proto = BPF_CORE_READ(sk, sk_protocol),
        .saddr = skc.skc_rcv_saddr,        // network order
        .sport = skc.skc_num,              // host order
        .daddr = skc.skc_daddr,            // network order
        .dport = bpf_ntohs(skc.skc_dport)  // host order
    };

    if (msg) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name) {
            struct sockaddr_in usin;
            if (bpf_probe_read_kernel(&usin, sizeof(usin), msg_name) == 0 ||
                bpf_probe_read_user(&usin, sizeof(usin), msg_name) == 0) {
                if (usin.sin_family == AF_INET) {
                    key.daddr = usin.sin_addr.s_addr;
                    key.dport = bpf_ntohs(usin.sin_port);
                }
            }
        }
    }

    pop_msg_args();

    // use network-ordered address and host-ordered port for policy matching
    struct ret_val res = egress_policy_match(NULL, &key);

    // cache the result of the policy match for future packets in the same session
    cache_policy_action(&key, &res);

    if (res.action != 0) {
        network_event_t ev = {0};
        init_event(&ev, __UDP_SENDMSG);

        ev.saddr = bpf_ntohl(key.saddr);
        ev.daddr = bpf_ntohl(key.daddr);
        ev.sport = key.sport;
        ev.dport = key.dport;

        ev.proto = key.proto;

        ev.policy_id = res.policy_id;
        ev.ret_val = res.action;  // AUDIT(1) or BLOCK(-1)

        return submit_event(&ev);
    }

    return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!msg) return 0;

    push_msg_args(sk, msg);

    return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct msg_args *args = peek_msg_args();
    if (!args) return 0;

    struct sock *sk = args->sk;
    struct msghdr *msg = args->msg;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);

    if (skc.skc_family != AF_INET) return pop_msg_args();

    struct session_key key = {
        .proto = BPF_CORE_READ(sk, sk_protocol),
        .saddr = skc.skc_daddr,             // network order
        .sport = bpf_ntohs(skc.skc_dport),  // host order
        .daddr = skc.skc_rcv_saddr,         // network order
        .dport = skc.skc_num                // host order
    };

    if (msg) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name) {
            struct sockaddr_in usin;
            if (bpf_probe_read_kernel(&usin, sizeof(usin), msg_name) == 0 ||
                bpf_probe_read_user(&usin, sizeof(usin), msg_name) == 0) {
                if (usin.sin_family == AF_INET) {
                    key.saddr = usin.sin_addr.s_addr;
                    key.sport = bpf_ntohs(usin.sin_port);
                }
            }
        }
    }

    pop_msg_args();

    struct ret_val *cached_val = cached_policy_action(&key);
    if (cached_val != NULL) {
        if (cached_val->action != 0) {
            network_event_t ev = {0};
            init_event(&ev, __UDP_RECVMSG);

            ev.saddr = bpf_ntohl(key.saddr);
            ev.daddr = bpf_ntohl(key.daddr);
            ev.sport = key.sport;
            ev.dport = key.dport;

            ev.proto = key.proto;

            ev.policy_id = cached_val->policy_id;
            ev.ret_val = cached_val->action;  // AUDIT(1) or BLOCK(-1)

            return submit_event(&ev);
        }
        return 1;  // PASS
    }

    // use network-ordered address and host-ordered ports for policy matching
    struct ret_val res = ingress_policy_match(NULL, &key);
    if (res.action != 0) {
        network_event_t ev = {0};
        init_event(&ev, __UDP_RECVMSG);

        ev.saddr = bpf_ntohl(key.saddr);
        ev.daddr = bpf_ntohl(key.daddr);
        ev.sport = key.sport;
        ev.dport = key.dport;

        ev.proto = key.proto;

        ev.policy_id = res.policy_id;
        ev.ret_val = res.action;  // AUDIT(1) or BLOCK(-1)

        return submit_event(&ev);
    }

    return 0;
}

// Network Traffic

SEC("cgroup_skb/egress")
int cgroup_skb__egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end) return 1;  // PASS

    if (ip->version != 4) return 1;  // Only handle IPv4

    struct session_key key = {.proto = ip->protocol, .saddr = ip->saddr, .sport = 0, .daddr = ip->daddr, .dport = 0};

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr)) return 1;  // PASS

    if (key.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end) return 1;  // PASS

        key.sport = bpf_ntohs(tcp->source);
        key.dport = bpf_ntohs(tcp->dest);
    } else if (key.proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) > data_end) return 1;  // PASS

        key.sport = bpf_ntohs(udp->source);
        key.dport = bpf_ntohs(udp->dest);
    } else {
        return 1;  // PASS
    }

    struct ret_val *cached_val = cached_policy_action(&key);
    if (cached_val != NULL) {
        if (cached_val->action < 0) {
            return 0;  // DROP
        } else {
            return 1;  // PASS
        }
    }

    // use network-ordered destination address and host-ordered port for policy matching
    struct ret_val res = egress_policy_match(skb, &key);

    // cache the result of the policy match for future packets in the same session
    cache_policy_action(&key, &res);

    if (res.action < 0) {
        return 0;  // DROP
    }

    return 1;  // PASS
}

SEC("cgroup_skb/ingress")
int cgroup_skb__ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end) return 1;  // PASS

    if (ip->version != 4) return 1;  // Only handle IPv4

    struct session_key key = {.proto = ip->protocol, .saddr = ip->saddr, .sport = 0, .daddr = ip->daddr, .dport = 0};

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr)) return 1;  // PASS

    if (key.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end) return 1;  // PASS

        key.sport = bpf_ntohs(tcp->source);
        key.dport = bpf_ntohs(tcp->dest);
    } else if (key.proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) > data_end) return 1;  // PASS

        key.sport = bpf_ntohs(udp->source);
        key.dport = bpf_ntohs(udp->dest);
    } else {
        return 1;  // PASS
    }

    // use network-ordered address and host-ordered ports for policy matching
    struct ret_val res = ingress_policy_match(skb, &key);

    // cache the result of the policy match for future packets in the same session
    cache_policy_action(&key, &res);

    if (res.action < 0) {
        network_event_t ev = {0};

        ev.ts = bpf_ktime_get_ns();
        ev.event_id = __CGROUP_SKB_INGRESS;

        ev.saddr = bpf_ntohl(key.saddr);
        ev.daddr = bpf_ntohl(key.daddr);
        ev.sport = key.sport;
        ev.dport = key.dport;

        ev.proto = key.proto;

        ev.policy_id = res.policy_id;
        ev.ret_val = res.action;  // BLOCK(-1)

        return submit_event(&ev);  // DROP
    }

    return 1;  // PASS
}

// DNS Programs (separate)
// Split out from the enforcer because combining DNS parsing with policy
// matching in a single cgroup_skb program exceeds BPF_COMPLEXITY_LIMIT_INSNS.
// Each program gets its own 1M-instruction verifier budget, and maps are
// shared automatically via the same .o file.
// These programs always return 1 (PASS); drop decisions are made by the
// enforcer programs under BPF_F_ALLOW_MULTI.

SEC("cgroup_skb/egress")
int cgroup_skb__egress_dns(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end) return 1;

    if (ip->version != 4) return 1;
    if (ip->protocol != IPPROTO_UDP) return 1;

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr)) return 1;

    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end) return 1;

    __u16 dport = bpf_ntohs(udp->dest);
    if (dport != 53) return 1;

    __u16 sport = bpf_ntohs(udp->source);
    __u32 dns_off = ihl + sizeof(struct udphdr);
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len > sizeof(struct udphdr)) {
        __u32 dns_len = (__u32)(udp_len - sizeof(struct udphdr));
        handle_dns_query(skb, dns_off, dns_len, ip->saddr, ip->daddr, sport);
    }

    return 1;
}

SEC("cgroup_skb/ingress")
int cgroup_skb__ingress_dns(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end) return 1;

    if (ip->version != 4) return 1;
    if (ip->protocol != IPPROTO_UDP) return 1;

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr)) return 1;

    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end) return 1;

    __u16 sport = bpf_ntohs(udp->source);
    if (sport != 53) return 1;

    __u16 dport = bpf_ntohs(udp->dest);
    __u32 dns_off = ihl + sizeof(struct udphdr);
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len > sizeof(struct udphdr)) {
        __u32 dns_len = (__u32)(udp_len - sizeof(struct udphdr));
        handle_dns_response(skb, dns_off, dns_len, ip->saddr, ip->daddr, dport);
    }

    return 1;
}
