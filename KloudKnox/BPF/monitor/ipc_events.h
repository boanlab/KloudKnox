// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by system_events.bpf.c — do not compile standalone.

// IPC events

// save_task_exe_to_buffer writes task's exe path via save_res_to_buffer,
// falling back to "" when mm/exe_file is unavailable (kernel threads, exit).
static __always_inline int save_task_exe_to_buffer(buf_t *buf, struct task_struct *task) {
    char empty[] = "";
    if (!task) return save_str_to_buffer(buf, (void *)empty);
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return save_str_to_buffer(buf, (void *)empty);
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) return save_str_to_buffer(buf, (void *)empty);
    struct path path = BPF_CORE_READ(exe_file, f_path);
    return save_res_to_buffer(buf, &path);
}

// Emit the unix peer sun_path as a string. Three cases:
//   - filesystem socket ("/run/foo.sock"): emit as-is
//   - abstract socket (sun_path[0] == '\0', name follows): emit as "@name"
//   - anonymous / unresolved peer: emit ""
//
// The abstract-socket rewrite matches the notation expected by
// eventParser.go::security_unix_* and by AppArmor's `addr=@name` syntax, so
// the same string can be hashed once and compared against both sides.
static __always_inline int save_unix_peer_to_buffer(buf_t *buf, struct sock *peer_sk) {
    char empty[] = "";
    if (!peer_sk) return save_str_to_buffer(buf, (void *)empty);

    struct unix_sock *u = (struct unix_sock *)peer_sk;
    struct unix_address *addr = BPF_CORE_READ(u, addr);
    if (!addr) return save_str_to_buffer(buf, (void *)empty);

    int addr_len = 0;
    bpf_probe_read_kernel(&addr_len, sizeof(addr_len), &addr->len);
    int payload = addr_len - (int)sizeof(short);  // sizeof(sa_family_t) == 2
    if (payload <= 0) return save_str_to_buffer(buf, (void *)empty);
    if (payload > 107) payload = 107;  // sun_path is char[108]
    payload &= 0x7F;                   // bound for the verifier

    __u32 zero = 0;
    buf_t *tmp = bpf_map_lookup_elem(&st_tmp_buf_map, &zero);
    if (!tmp) return save_str_to_buffer(buf, (void *)empty);

    // Read sun_path into tmp->buf[1..], leaving tmp->buf[0] as a scratch slot.
    bpf_probe_read_kernel(&tmp->buf[1], payload,
                          ((char *)addr) + __builtin_offsetof(struct unix_address, name)
                              + __builtin_offsetof(struct sockaddr_un, sun_path));
    tmp->buf[1 + payload] = '\0';

    if (tmp->buf[1] == '\0') {
        // Abstract socket: the leading '\0' marks the family; overwrite it
        // with '@' so bpf_probe_read_str inside save_str_to_buffer can read
        // the full "@name" without stopping on the null.
        tmp->buf[1] = '@';
    }

    return save_str_to_buffer(buf, (void *)&tmp->buf[1]);
}

// security_unix_stream_connect(struct sock *sock, struct sock *other,
//                              struct sock *newsk)
// Fires at SOCK_STREAM / SOCK_SEQPACKET client-side connect() before the
// listener accepts. We report the peer (other) sun_path and the connecting
// process's exe path.
SEC("kprobe/security_unix_stream_connect")
int kprobe__security_unix_stream_connect(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct sock *other = (struct sock *)PT_REGS_PARM2(ctx);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_UNIX_STREAM_CONNECT, EVENT_UNARY, 2);

    if (save_unix_peer_to_buffer(buf, other) < 0) return 0;  // peer sun_path
    if (save_src_to_buffer(buf, 1) < 0) return 0;            // caller exe path

    return submit_buffer(buf, 0);
}

// security_unix_may_send(struct socket *sock, struct socket *other)
// Fires per-datagram on unix SOCK_DGRAM sendmsg. Same shape as stream_connect.
SEC("kprobe/security_unix_may_send")
int kprobe__security_unix_may_send(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct socket *other_sock = (struct socket *)PT_REGS_PARM2(ctx);
    if (!other_sock) return 0;
    struct sock *other = BPF_CORE_READ(other_sock, sk);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_UNIX_MAY_SEND, EVENT_UNARY, 2);

    if (save_unix_peer_to_buffer(buf, other) < 0) return 0;  // peer sun_path
    if (save_src_to_buffer(buf, 1) < 0) return 0;            // caller exe path

    return submit_buffer(buf, 0);
}

// security_ptrace_access_check(struct task_struct *child, unsigned int mode)
// Fires when a tracer asks the kernel whether it may attach/peek at `child`.
// We report PTRACE_MODE_* and the child's exe path; the tracer's exe is the
// standard src field.
SEC("kprobe/security_ptrace_access_check")
int kprobe__security_ptrace_access_check(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct task_struct *child = (struct task_struct *)PT_REGS_PARM1(ctx);
    __u32 mode = (__u32)PT_REGS_PARM2(ctx);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PTRACE_ACCESS_CHECK, EVENT_UNARY, 3);

    if (save_uint_to_buffer(buf, mode) < 0) return 0;  // PTRACE_MODE_*
    if (save_task_exe_to_buffer(buf, child) < 0) return 0;  // child exe path
    if (save_src_to_buffer(buf, 1) < 0) return 0;           // caller exe path

    return submit_buffer(buf, 0);
}
