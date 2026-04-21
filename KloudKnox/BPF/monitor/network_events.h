// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by system_events.bpf.c — do not compile standalone.

// Network events

SEC("tp/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    int family = ctx->args[0];
    int type = ctx->args[1];
    int protocol = ctx->args[2];

    if (family == AF_UNIX || family == AF_INET || family == AF_PACKET) {
        buf_t *buf = get_buffer();
        if (!buf) return 0;

        event_t *ev = (event_t *)&buf->buf[0];
        init_event(ev, ctx->id, EVENT_ENTER, 4);

        if (save_int_to_buffer(buf, family) < 0) return 0;    // save family
        if (save_int_to_buffer(buf, type) < 0) return 0;      // save type/flags
        if (save_int_to_buffer(buf, protocol) < 0) return 0;  // save protocol
        if (save_src_to_buffer(buf, 0) < 0) return 0;         // save source if unknown

        return submit_buffer(buf, 1);
    }

    return 0;
}
TRACEPOINT_SYSCALL_EXIT(socket, __NR_socket, 1)

SEC("tp/syscalls/sys_enter_bind")
int tracepoint__syscalls__sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    struct sockaddr sa = {};
    bpf_probe_read(&sa, sizeof(sa), (void *)ctx->args[1]);

    int family = sa.sa_family;

    if (family == AF_UNIX || family == AF_INET || family == AF_PACKET) {
        buf_t *buf = get_buffer();
        if (!buf) return 0;

        event_t *ev = (event_t *)&buf->buf[0];
        init_event(ev, ctx->id, EVENT_ENTER, 5);

        if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fd
        if (save_int_to_buffer(buf, family) < 0) return 0;        // save family

        int addrlen = (int)ctx->args[2];

        switch (family) {
            case AF_UNIX:
                if (addrlen >= sizeof(struct sockaddr_un)) {
                    struct sockaddr_un sun = {};
                    bpf_probe_read(&sun, sizeof(sun), (void *)ctx->args[1]);

                    __u8 unix_path[108];
                    bpf_probe_read(&unix_path, sizeof(unix_path), (void *)sun.sun_path);
                    unix_path[107] = '\0';

                    if (save_str_to_buffer(buf, (char *)unix_path) < 0) return 0;  // save unix path
                    if (save_int_to_buffer(buf, 0) < 0) return 0;                  // save padding (not used)
                }
                break;

            case AF_INET:
                if (addrlen >= sizeof(struct sockaddr_in)) {
                    struct sockaddr_in sin = {};
                    bpf_probe_read(&sin, sizeof(sin), (void *)ctx->args[1]);

                    __u32 addr = 0;
                    __u16 port = 0;
                    bpf_probe_read(&addr, sizeof(addr), &sin.sin_addr.s_addr);
                    bpf_probe_read(&port, sizeof(port), &sin.sin_port);

                    if (save_uint_to_buffer(buf, bpf_ntohl(addr)) < 0) return 0;  // save addr
                    if (save_uint_to_buffer(buf, bpf_ntohs(port)) < 0) return 0;  // save port
                }
                break;

            case AF_PACKET:
                if (addrlen >= sizeof(struct sockaddr_ll)) {
                    struct sockaddr_ll ll = {};
                    bpf_probe_read(&ll, sizeof(ll), (void *)ctx->args[1]);

                    if (save_int_to_buffer(buf, ll.sll_protocol) < 0) return 0;  // save ethertype
                    if (save_uint_to_buffer(buf, ll.sll_ifindex) < 0) return 0;  // save ifindex
                }
                break;
        }

        if (save_src_to_buffer(buf, 0) < 0) return 0;  // save source if unknown

        return submit_buffer(buf, 1);
    }

    return 0;
}
TRACEPOINT_SYSCALL_EXIT(bind, __NR_bind, 1)

SEC("tp/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    struct sockaddr sa = {};
    bpf_probe_read(&sa, sizeof(sa), (void *)ctx->args[1]);

    int family = sa.sa_family;

    if (family == AF_UNIX || family == AF_INET) {
        buf_t *buf = get_buffer();
        if (!buf) return 0;

        event_t *ev = (event_t *)&buf->buf[0];
        init_event(ev, ctx->id, EVENT_ENTER, 5);

        if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fd
        if (save_int_to_buffer(buf, family) < 0) return 0;        // save family

        int addrlen = (int)ctx->args[2];

        switch (family) {
            case AF_UNIX:
                if (addrlen >= sizeof(struct sockaddr_un)) {
                    struct sockaddr_un sun = {};
                    bpf_probe_read(&sun, sizeof(sun), (void *)ctx->args[1]);

                    __u8 unix_path[108];
                    bpf_probe_read(&unix_path, sizeof(unix_path), (void *)sun.sun_path);
                    unix_path[107] = '\0';

                    if (save_str_to_buffer(buf, (char *)unix_path) < 0) return 0;  // save unix path
                    if (save_int_to_buffer(buf, 0) < 0) return 0;                  // save padding (not used)
                }
                break;

            case AF_INET:
                if (addrlen >= sizeof(struct sockaddr_in)) {
                    struct sockaddr_in sin = {};
                    bpf_probe_read(&sin, sizeof(sin), (void *)ctx->args[1]);

                    __u32 addr = 0;
                    __u16 port = 0;
                    bpf_probe_read(&addr, sizeof(addr), &sin.sin_addr.s_addr);
                    bpf_probe_read(&port, sizeof(port), &sin.sin_port);

                    if (save_uint_to_buffer(buf, bpf_ntohl(addr)) < 0) return 0;  // save dstip
                    if (save_uint_to_buffer(buf, bpf_ntohs(port)) < 0) return 0;  // save dport
                }
                break;
        }

        if (save_src_to_buffer(buf, 0) < 0) return 0;  // save source if unknown

        return submit_buffer(buf, 1);
    }

    return 0;
}
TRACEPOINT_SYSCALL_EXIT(connect, __NR_connect, 1)

SEC("tp/syscalls/sys_enter_listen")
int tracepoint__syscalls__sys_enter_listen(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fd
    if (save_int_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save backlog
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(listen, __NR_listen, 0)

SEC("tp/syscalls/sys_enter_accept")
int tracepoint__syscalls__sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fd
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(accept, __NR_accept, 1)

SEC("tp/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fd
    if (save_int_to_buffer(buf, ctx->args[3]) < 0) return 0;  // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(accept4, __NR_accept4, 1)

// D-3: capture peer (client) address from accepted TCP connection.
// The sys_enter_accept tracepoint fires before the kernel fills the sockaddr
// buffer, so peer info is unavailable there. This kretprobe on inet_csk_accept
// fires after the kernel has accepted the connection and returns the fully
// populated sock struct. We emit a UNARY event (ID 1013) with peer_ip and
// peer_port so that eventParser.go can patch the corresponding accept/accept4
// ENTER entry in evMapShards.
SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept_monitor(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;

    struct sock_common skc = BPF_CORE_READ(sk, __sk_common);
    if (skc.skc_family != AF_INET) return 0;  // IPv4 only for now

    __u32 peer_ip = bpf_ntohl(skc.skc_daddr);    // host order
    __u32 peer_port = bpf_ntohs(skc.skc_dport);  // host order

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __KRETPROBE_INET_CSK_ACCEPT, EVENT_UNARY, 2);

    if (save_uint_to_buffer(buf, peer_ip) < 0) return 0;    // args[0]: peer IP (host order)
    if (save_uint_to_buffer(buf, peer_port) < 0) return 0;  // args[1]: peer port (host order)

    return submit_buffer(buf, 0);
}
