// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by system_events.bpf.c — do not compile standalone.

// File events

SEC("tp/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[0];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_int_to_buffer(buf, ctx->args[1]) < 0) return 0;      // save flags
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;     // save mode
    if (save_src_to_buffer(buf, 1) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(open, __NR_open, 1)

SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[1];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 5);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;      // save dirfd
    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_int_to_buffer(buf, ctx->args[2]) < 0) return 0;      // save flags
    if (save_uint_to_buffer(buf, ctx->args[3]) < 0) return 0;     // save mode
    if (save_src_to_buffer(buf, 1) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(openat, __NR_openat, 1)

SEC("tp/syscalls/sys_enter_openat2")
int tracepoint__syscalls__sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[1];

    struct open_how how;
    void *how_ptr = (void *)ctx->args[2];
    bpf_probe_read_user(&how, sizeof(how), how_ptr);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 6);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;             // save dirfd
    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;         // save filename
    if (save_int_to_buffer(buf, (int)how.flags) < 0) return 0;           // save flags
    if (save_uint_to_buffer(buf, (unsigned int)how.mode) < 0) return 0;  // save mode
    if (save_ulong_to_buffer(buf, how.resolve) < 0) return 0;            // save resolve
    if (save_src_to_buffer(buf, 1) < 0) return 0;                        // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(openat2, __NR_openat2, 1)

SEC("kprobe/security_file_open")
int kprobe__security_file_open(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file) return 0;

    struct path path = BPF_CORE_READ(file, f_path);

    struct super_block *sb = BPF_CORE_READ(path.mnt, mnt_sb);
    if (!sb) return 0;

    struct file_system_type *fstype = BPF_CORE_READ(sb, s_type);
    if (!fstype) return 0;

    const char *fsname_ptr = BPF_CORE_READ(fstype, name);
    if (!fsname_ptr) return 0;

    char fsname[16] = {0};
    bpf_probe_read_str(&fsname, sizeof(fsname), fsname_ptr);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_FILE_OPEN, EVENT_UNARY, 2);

    if (save_str_to_buffer(buf, fsname) < 0) return 0;  // save file system type
    if (save_res_to_buffer(buf, &path) < 0) return 0;   // save path

    return submit_buffer(buf, 1);
}

SEC("tp/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;  // save fd
    if (save_src_to_buffer(buf, 0) < 0) return 0;             // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(close, __NR_close, 1)

SEC("kprobe/filp_close")
int kprobe__filp_close(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file) return 0;

    struct path path = BPF_CORE_READ(file, f_path);

    struct super_block *sb = BPF_CORE_READ(path.mnt, mnt_sb);
    if (!sb) return 0;

    struct file_system_type *fstype = BPF_CORE_READ(sb, s_type);
    if (!fstype) return 0;

    const char *fsname_ptr = BPF_CORE_READ(fstype, name);
    if (!fsname_ptr) return 0;

    char fsname[16] = {0};
    bpf_probe_read_str(&fsname, sizeof(fsname), fsname_ptr);

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __FILP_CLOSE, EVENT_UNARY, 2);

    if (save_str_to_buffer(buf, fsname) < 0) return 0;  // save file system type
    if (save_res_to_buffer(buf, &path) < 0) return 0;   // save path

    return submit_buffer(buf, 1);
}

SEC("tp/syscalls/sys_enter_chown")
int tracepoint__syscalls__sys_enter_chown(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[0];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;     // save uid
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;     // save gid
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(chown, __NR_chown, 0)

SEC("tp/syscalls/sys_enter_fchown")
int tracepoint__syscalls__sys_enter_fchown(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;   // save fd
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save uid
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;  // save gid
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(fchown, __NR_fchown, 0)

SEC("tp/syscalls/sys_enter_fchownat")
int tracepoint__syscalls__sys_enter_fchownat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[1];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 6);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;      // save dirfd
    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;     // save uid
    if (save_uint_to_buffer(buf, ctx->args[3]) < 0) return 0;     // save gid
    if (save_int_to_buffer(buf, ctx->args[4]) < 0) return 0;      // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(fchownat, __NR_fchownat, 0)

SEC("kprobe/security_path_chown")
int kprobe__security_path_chown(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    if (!path) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_CHOWN, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, path) < 0) return 0;  // save path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_chmod")
int tracepoint__syscalls__sys_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[0];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;     // save mode
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(chmod, __NR_chmod, 0)

SEC("tp/syscalls/sys_enter_fchmod")
int tracepoint__syscalls__sys_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;   // save fd
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;  // save mode
    if (save_src_to_buffer(buf, 0) < 0) return 0;              // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(fchmod, __NR_fchmod, 0)

SEC("tp/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[1];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;      // save dirfd
    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;     // save mode
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(fchmodat, __NR_fchmodat, 0)

SEC("kprobe/security_path_chmod")
int kprobe__security_path_chmod(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    if (!path) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_CHMOD, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, path) < 0) return 0;  // save path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
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
TRACEPOINT_SYSCALL_EXIT(unlink, __NR_unlink, 0)

SEC("tp/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *filename = (const char *)ctx->args[1];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;      // save dirfd
    if (save_str_to_buffer(buf, (void *)filename) < 0) return 0;  // save filename
    if (save_int_to_buffer(buf, ctx->args[2]) < 0) return 0;      // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(unlinkat, __NR_unlinkat, 0)

SEC("kprobe/security_path_unlink")
int kprobe__security_path_unlink(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct path *path;
    bpf_probe_read(&path, sizeof(path), (void *)&PT_REGS_PARM1(ctx));
    if (!path) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_UNLINK, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, path) < 0) return 0;  // save path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *old_filename = (const char *)ctx->args[0];
    const char *new_filename = (const char *)ctx->args[1];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_str_to_buffer(buf, (void *)old_filename) < 0) return 0;  // save old filename
    if (save_str_to_buffer(buf, (void *)new_filename) < 0) return 0;  // save new filename
    if (save_src_to_buffer(buf, 0) < 0) return 0;                     // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(rename, __NR_rename, 0)

SEC("tp/syscalls/sys_enter_renameat")
int tracepoint__syscalls__sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    // ctx->args[0] : oldfd
    const char *old_filename = (const char *)ctx->args[1];
    // ctx->args[2] : newfd
    const char *new_filename = (const char *)ctx->args[3];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_str_to_buffer(buf, (void *)old_filename) < 0) return 0;  // save old filename
    if (save_str_to_buffer(buf, (void *)new_filename) < 0) return 0;  // save new filename
    if (save_src_to_buffer(buf, 0) < 0) return 0;                     // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(renameat, __NR_renameat, 0)

SEC("tp/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    // ctx->args[0] : oldfd
    const char *old_filename = (const char *)ctx->args[1];
    // ctx->args[2] : newfd
    const char *new_filename = (const char *)ctx->args[3];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_str_to_buffer(buf, (void *)old_filename) < 0) return 0;  // save old filename
    if (save_str_to_buffer(buf, (void *)new_filename) < 0) return 0;  // save new filename
    if (save_uint_to_buffer(buf, ctx->args[4]) < 0) return 0;         // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;                     // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(renameat2, __NR_renameat2, 0)

SEC("kprobe/security_path_rename")
int kprobe__security_path_rename(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    // old path

    struct path *old_dir;
    bpf_probe_read(&old_dir, sizeof(old_dir), (void *)&PT_REGS_PARM1(ctx));
    if (!old_dir) return 0;

    struct dentry *old_dentry;
    bpf_probe_read(&old_dentry, sizeof(old_dentry), (void *)&PT_REGS_PARM2(ctx));
    if (!old_dentry) return 0;

    struct path old_dir_val;
    bpf_probe_read(&old_dir_val, sizeof(old_dir_val), old_dir);

    struct path old_path = {
        .mnt = old_dir_val.mnt,
        .dentry = old_dentry,
    };

    // new path

    struct path *new_dir;
    bpf_probe_read(&new_dir, sizeof(new_dir), (void *)&PT_REGS_PARM3(ctx));
    if (!new_dir) return 0;

    struct dentry *new_dentry;
    bpf_probe_read(&new_dentry, sizeof(new_dentry), (void *)&PT_REGS_PARM4(ctx));
    if (!new_dentry) return 0;

    struct path new_dir_val;
    bpf_probe_read(&new_dir_val, sizeof(new_dir_val), new_dir);

    struct path new_path = {
        .mnt = new_dir_val.mnt,
        .dentry = new_dentry,
    };

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_RENAME, EVENT_UNARY, 2);

    if (save_res_to_buffer(buf, &old_path) < 0) return 0;  // save old path
    if (save_res_to_buffer(buf, &new_path) < 0) return 0;  // save new path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_link")
int tracepoint__syscalls__sys_enter_link(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    const char *old_filename = (const char *)ctx->args[0];
    const char *new_filename = (const char *)ctx->args[1];

    if (save_str_to_buffer(buf, (void *)old_filename) < 0) return 0;  // save old filename
    if (save_str_to_buffer(buf, (void *)new_filename) < 0) return 0;  // save new filename
    if (save_src_to_buffer(buf, 0) < 0) return 0;                     // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(link, __NR_link, 0)

SEC("tp/syscalls/sys_enter_linkat")
int tracepoint__syscalls__sys_enter_linkat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    // ctx->args[0] : oldfd
    const char *old_filename = (const char *)ctx->args[1];
    // ctx->args[2] : newfd
    const char *new_filename = (const char *)ctx->args[3];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_str_to_buffer(buf, (void *)old_filename) < 0) return 0;  // save old filename
    if (save_str_to_buffer(buf, (void *)new_filename) < 0) return 0;  // save new filename
    if (save_int_to_buffer(buf, ctx->args[4]) < 0) return 0;          // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;                     // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(linkat, __NR_linkat, 0)

SEC("kprobe/security_path_link")
int kprobe__security_path_link(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    // old path

    struct path *old_path;
    bpf_probe_read(&old_path, sizeof(old_path), (void *)&PT_REGS_PARM1(ctx));
    if (!old_path) return 0;

    // new path

    struct path *new_dir;
    bpf_probe_read(&new_dir, sizeof(new_dir), (void *)&PT_REGS_PARM2(ctx));
    if (!new_dir) return 0;

    struct dentry *new_dentry;
    bpf_probe_read(&new_dentry, sizeof(new_dentry), (void *)&PT_REGS_PARM3(ctx));
    if (!new_dentry) return 0;

    struct path new_path;
    bpf_probe_read(&new_path, sizeof(new_path), new_dir);
    new_path.dentry = new_dentry;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_LINK, EVENT_UNARY, 2);

    if (save_res_to_buffer(buf, old_path) < 0) return 0;   // save old path
    if (save_res_to_buffer(buf, &new_path) < 0) return 0;  // save new path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_symlink")
int tracepoint__syscalls__sys_enter_symlink(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *target_filename = (const char *)ctx->args[0];
    const char *link_filename = (const char *)ctx->args[1];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_str_to_buffer(buf, (void *)target_filename) < 0) return 0;  // save target filename
    if (save_str_to_buffer(buf, (void *)link_filename) < 0) return 0;    // save link filename
    if (save_src_to_buffer(buf, 0) < 0) return 0;                        // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(symlink, __NR_symlink, 0)

SEC("tp/syscalls/sys_enter_symlinkat")
int tracepoint__syscalls__sys_enter_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *target_filename = (const char *)ctx->args[0];
    // ctx->args[1] : newdirfd
    const char *link_filename = (const char *)ctx->args[2];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_str_to_buffer(buf, (void *)target_filename) < 0) return 0;  // save target filename
    if (save_str_to_buffer(buf, (void *)link_filename) < 0) return 0;    // save link filename
    if (save_src_to_buffer(buf, 0) < 0) return 0;                        // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(symlinkat, __NR_symlinkat, 0)

SEC("tp/syscalls/sys_enter_mkdir")
int tracepoint__syscalls__sys_enter_mkdir(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *pathname = (const char *)ctx->args[0];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_str_to_buffer(buf, (void *)pathname) < 0) return 0;  // save pathname
    if (save_uint_to_buffer(buf, ctx->args[1]) < 0) return 0;     // save mode
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(mkdir, __NR_mkdir, 0)

SEC("tp/syscalls/sys_enter_mkdirat")
int tracepoint__syscalls__sys_enter_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *pathname = (const char *)ctx->args[1];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 4);

    if (save_int_to_buffer(buf, ctx->args[0]) < 0) return 0;      // save dirfd
    if (save_str_to_buffer(buf, (void *)pathname) < 0) return 0;  // save pathname
    if (save_uint_to_buffer(buf, ctx->args[2]) < 0) return 0;     // save mode
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 1);
}
TRACEPOINT_SYSCALL_EXIT(mkdirat, __NR_mkdirat, 0)

SEC("kprobe/security_path_mkdir")
int kprobe__security_path_mkdir(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct path *dir;
    bpf_probe_read(&dir, sizeof(dir), (void *)&PT_REGS_PARM1(ctx));
    if (!dir) return 0;

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), (void *)&PT_REGS_PARM2(ctx));
    if (!dentry) return 0;

    struct path dir_val;
    bpf_probe_read(&dir_val, sizeof(dir_val), dir);

    struct path path = {
        .mnt = dir_val.mnt,
        .dentry = dentry,
    };

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_MKDIR, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, &path) < 0) return 0;  // save path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_rmdir")
int tracepoint__syscalls__sys_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 2);

    const char *pathname = (const char *)ctx->args[0];

    if (save_str_to_buffer(buf, (void *)pathname) < 0) return 0;  // save pathname
    if (save_src_to_buffer(buf, 0) < 0) return 0;                 // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(rmdir, __NR_rmdir, 0)

SEC("kprobe/security_path_rmdir")
int kprobe__security_path_rmdir(struct pt_regs *ctx) {
    if (!should_monitor()) return 0;

    struct path *dir;
    bpf_probe_read(&dir, sizeof(dir), (void *)&PT_REGS_PARM1(ctx));
    if (!dir) return 0;

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), (void *)&PT_REGS_PARM2(ctx));
    if (!dentry) return 0;

    struct path dir_val;
    bpf_probe_read(&dir_val, sizeof(dir_val), dir);

    struct path path = {
        .mnt = dir_val.mnt,
        .dentry = dentry,
    };

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, __SECURITY_PATH_RMDIR, EVENT_UNARY, 1);

    if (save_res_to_buffer(buf, &path) < 0) return 0;  // save path

    return submit_buffer(buf, 0);
}

SEC("tp/syscalls/sys_enter_mount")
int tracepoint__syscalls__sys_enter_mount(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *source_dev_name = (const char *)ctx->args[0];
    const char *target_dir_name = (const char *)ctx->args[1];
    const char *filesystem_type = (const char *)ctx->args[2];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 5);

    if (save_str_to_buffer(buf, (void *)source_dev_name) < 0) return 0;  // save source dev name
    if (save_str_to_buffer(buf, (void *)target_dir_name) < 0) return 0;  // save target dir name
    if (save_str_to_buffer(buf, (void *)filesystem_type) < 0) return 0;  // save filesystem type
    if (save_ulong_to_buffer(buf, ctx->args[3]) < 0) return 0;           // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;                        // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(mount, __NR_mount, 0)

// sys_enter_umount tracepoint is used for umount2()
// ctx->id corresponds to the __NR_umount2 syscall
SEC("tp/syscalls/sys_enter_umount")
int tracepoint__syscalls__sys_enter_umount(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor()) return 0;

    const char *target_dir_name = (const char *)ctx->args[0];

    buf_t *buf = get_buffer();
    if (!buf) return 0;

    event_t *ev = (event_t *)&buf->buf[0];
    init_event(ev, ctx->id, EVENT_ENTER, 3);

    if (save_str_to_buffer(buf, (void *)target_dir_name) < 0) return 0;  // save target dir name
    if (save_ulong_to_buffer(buf, ctx->args[1]) < 0) return 0;           // save flags
    if (save_src_to_buffer(buf, 0) < 0) return 0;                        // save source if unknown

    return submit_buffer(buf, 0);
}
TRACEPOINT_SYSCALL_EXIT(umount, __NR_umount2, 0)
