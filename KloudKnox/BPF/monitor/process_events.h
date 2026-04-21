// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by system_events.bpf.c — do not compile standalone.

// Process events

SEC("tp/syscalls/sys_enter_clone")
int tracepoint__syscalls__sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_ulong_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;               // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(clone, __NR_clone, 1)

SEC("tp/syscalls/sys_enter_clone3")
int tracepoint__syscalls__sys_enter_clone3(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    struct clone_args args;
    void *args_ptr = (void *)ctx->args[0];
    bpf_probe_read_user(&args, sizeof(args),
                        args_ptr);  // B-1 fix: read from userspace pointer, not stack

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_ulong_to_buffer(buf, args.flags) < 0) return 0;  // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(clone3, __NR_clone3, 1)

SEC("tp/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];
    const char *const *envp = (const char *const *)ctx->args[2];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_str_arr_to_buffer(buf, argv) < 0) return 0;          // save argv
    if (save_str_arr_to_buffer(buf, envp) < 0) return 0;          // save envp
    if (save_src_to_buffer(buf, 1) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(execve, __NR_execve, 1)

SEC("tp/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[1];
    const char *const *argv = (const char *const *)ctx->args[2];
    const char *const *envp = (const char *const *)ctx->args[3];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 6);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;      // save dirfd
    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_str_arr_to_buffer(buf, argv) < 0) return 0;          // save argv
    if (save_str_arr_to_buffer(buf, envp) < 0) return 0;          // save envp
    if (save_int_to_buffer(buf, ctx->args[4]) < 0) return 0;      // save flags
    if (save_src_to_buffer(buf, 1) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(execveat, __NR_execveat, 1)

SEC("kprobe/security_bprm_check")
int kprobe__security_bprm_check(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    if (!bprm) return 0;

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file) return 0;

    struct path path = BPF_CORE_READ(file, f_path);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_BPRM_CHECK, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, &path) < 0) return 0;  // save path

    return submit_buffer(buf, 1);
}

SEC("tp/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save error code (status)
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(exit, __NR_exit, 1)

SEC("tp/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save error code (status)
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(exit_group, __NR_exit_group, 1)

SEC("tp/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SCHED_PROCESS_EXIT, EVENT_UNARY, 1);

    if (save_src_to_buffer(buf, 0) < 0) return 0;  // save source if unknown

    // no longer valid
    delete_source(ev->host_pid);

    return submit_buffer(buf, 1);
}

SEC("tp/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save uid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setuid, __NR_setuid, 0)

SEC("tp/syscalls/sys_enter_setreuid")
int tracepoint__syscalls__sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save ruid
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save euid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setreuid, __NR_setreuid, 0)

SEC("tp/syscalls/sys_enter_setresuid")
int tracepoint__syscalls__sys_enter_setresuid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save ruid
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save euid
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;  // save suid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setresuid, __NR_setresuid, 0)

SEC("tp/syscalls/sys_enter_setfsuid")
int tracepoint__syscalls__sys_enter_setfsuid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fsuid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setfsuid, __NR_setfsuid, 0)

SEC("tp/syscalls/sys_enter_setgid")
int tracepoint__syscalls__sys_enter_setgid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save gid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setgid, __NR_setgid, 0)

SEC("tp/syscalls/sys_enter_setregid")
int tracepoint__syscalls__sys_enter_setregid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save rgid
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save egid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setregid, __NR_setregid, 0)

SEC("tp/syscalls/sys_enter_setresgid")
int tracepoint__syscalls__sys_enter_setresgid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save rgid
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save egid
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;  // save sgid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setresgid, __NR_setresgid, 0)

SEC("tp/syscalls/sys_enter_setfsgid")
int tracepoint__syscalls__sys_enter_setfsgid(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fsgid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setfsgid, __NR_setfsgid, 0)

SEC("tp/syscalls/sys_enter_kill")
int tracepoint__syscalls__sys_enter_kill(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save pid
    if (save_int_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save sig
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(kill, __NR_kill, 0)

SEC("tp/syscalls/sys_enter_tgkill")
int tracepoint__syscalls__sys_enter_tgkill(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save pid
    if (save_int_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save tid
    if (save_int_to_buffer(buf, ctx->args[2]) < 0) return 0;  // save sig
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(tgkill, __NR_tgkill, 0)

SEC("kprobe/security_task_kill")
int kprobe__security_task_kill(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    if (!task) return 0;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return 0;

    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) return 0;

    struct path path = BPF_CORE_READ(exe_file, f_path);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_TASK_KILL, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, &path) < 0) return 0;  // save path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_unshare")
int tracepoint__syscalls__sys_enter_unshare(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(unshare, __NR_unshare, 0)

SEC("tp/syscalls/sys_enter_setns")
int tracepoint__syscalls__sys_enter_setns(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fd
    if (save_int_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save nstype
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setns, __NR_setns, 0)

struct rlimit_t {
    __u64 rlim_cur;
    __u64 rlim_max;
};

SEC("tp/syscalls/sys_enter_setrlimit")
int tracepoint__syscalls__sys_enter_setrlimit(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    struct rlimit_t rlim;
    void *rlim_ptr = (void *)ctx->args[1];
    bpf_probe_read_user(&rlim, sizeof(rlim), rlim_ptr);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_uint_to_buffer(buf, ctx->args[0]) < 0) return 0;    // save resource
    if (save_ulong_to_buffer(buf, rlim.rlim_cur) < 0) return 0;  // save rlim_cur
    if (save_ulong_to_buffer(buf, rlim.rlim_max) < 0) return 0;  // save rlim_max
    if (save_src_to_buffer(buf, 0) < 0) return 0;                // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(setrlimit, __NR_setrlimit, 0)

SEC("tp/syscalls/sys_enter_chroot")
int tracepoint__syscalls__sys_enter_chroot(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[0];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(chroot, __NR_chroot, 0)

SEC("kprobe/security_path_chroot")
int kprobe__security_path_chroot(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    if (!path) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_CHROOT, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, path) < 0) return 0;  // save path

    return submit_buffer(buf, 0);
}

struct bpf_cap_user_header_t {
    __u32 version;
    __s32 pid;
};

struct bpf_cap_user_data_t {
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
};

SEC("tp/syscalls/sys_enter_capset")
int tracepoint__syscalls__sys_enter_capset(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    void *hdr_ptr = (void *)ctx->args[0];
    if (!hdr_ptr) return 0;

    // Read header
    struct bpf_cap_user_header_t hdr;
    bpf_probe_read_user(&hdr, sizeof(hdr), hdr_ptr);

    void *data_ptr = (void *)ctx->args[1];
    if (!data_ptr) return 0;

    // Read first element of data (index 0)
    struct bpf_cap_user_data_t data;
    bpf_probe_read_user(&data, sizeof(data), data_ptr);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 5);

    if (save_int_to_buffer(buf, hdr.pid) < 0) return 0;            // save pid
    if (save_uint_to_buffer(buf, data.effective) < 0) return 0;    // save effective
    if (save_uint_to_buffer(buf, data.permitted) < 0) return 0;    // save permitted
    if (save_uint_to_buffer(buf, data.inheritable) < 0) return 0;  // save inheritable
    if (save_src_to_buffer(buf, 0) < 0) return 0;                  // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(capset, __NR_capset, 0)

// kprobe on cap_capable — visibility into capability usage attempts even when
// BPF LSM is unavailable. cap_capable(cred, ns, cap, audit) is called whenever
// the kernel checks a capability; `audit != 0` indicates the caller wants the
// check logged on denial.
SEC("kprobe/cap_capable")
int kprobe__cap_capable(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    int cap = (int)PT_REGS_PARM3(ctx);
    int audit = (int)PT_REGS_PARM4(ctx);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_CAPABLE, EVENT_UNARY, 3);

    if (save_int_to_buffer(buf, cap) < 0) return 0;
    if (save_int_to_buffer(buf, audit) < 0) return 0;
    if (save_src_to_buffer(buf, 1) < 0) return 0;

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save request
    if (save_int_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save pid
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(ptrace, __NR_ptrace, 0)
