// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by system_events.bpf.h — do not compile standalone.

// Save Values

static __always_inline int save_type_to_buffer(buf_t *buf, __u32 type) {
    __u32 index = 0;
    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return -1;

    __u32 cur = *offset_ptr;
    if (cur + sizeof(__u32) > MAX_BUF_LEN) return -1;
    *(__u32 *)&buf->buf[cur] = type;
    cur += sizeof(__u32);

    bpf_map_update_elem(&st_buf_offset_map, &index, &cur, BPF_ANY);

    return cur;
}

static __always_inline int save_int_to_buffer(buf_t *buf, __s32 val) {
    save_type_to_buffer(buf, TYPE_INT);

    __u32 index = 0;
    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return -1;

    __u32 cur = *offset_ptr;
    if (cur + sizeof(__s32) > MAX_BUF_LEN) return -1;
    *(__s32 *)&buf->buf[cur] = val;
    cur += sizeof(__s32);

    bpf_map_update_elem(&st_buf_offset_map, &index, &cur, BPF_ANY);

    return cur;
}

static __always_inline int save_uint_to_buffer(buf_t *buf, __u32 val) {
    save_type_to_buffer(buf, TYPE_UINT);

    __u32 index = 0;
    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return -1;

    __u32 cur = *offset_ptr;
    if (cur + sizeof(__u32) > MAX_BUF_LEN) return -1;
    *(__u32 *)&buf->buf[cur] = val;
    cur += sizeof(__u32);

    bpf_map_update_elem(&st_buf_offset_map, &index, &cur, BPF_ANY);

    return cur;
}

static __always_inline int save_ulong_to_buffer(buf_t *buf, __u64 val) {
    save_type_to_buffer(buf, TYPE_ULONG);

    __u32 index = 0;
    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return -1;

    __u32 cur = *offset_ptr;
    if (cur + sizeof(__u64) > MAX_BUF_LEN) return -1;
    *(__u64 *)&buf->buf[cur] = val;
    cur += sizeof(__u64);

    bpf_map_update_elem(&st_buf_offset_map, &index, &cur, BPF_ANY);

    return cur;
}

#define MAX_STR_LEN 2048

static __always_inline int save_str_to_buffer(buf_t *buf, void *str) {
    save_type_to_buffer(buf, TYPE_STR);

    __u32 index = 0;
    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return -1;

    __u32 offset = *offset_ptr;

    // Two-step bound: derive safe_off = offset + 4, then check it directly so
    // the verifier has a single tight variable.  Computing index from 'offset'
    // alone after one conditional can lose the map-value bound in kernel 6.x.
#define SAVE_STR_MAX_OFFSET (MAX_BUF_LEN - 4 - MAX_STR_LEN)  /* = 6140 */
    if (offset >= SAVE_STR_MAX_OFFSET) return -1;
    __u32 safe_off = offset + 4;
    // Explicit re-check on safe_off: verifier now has a tight range on the
    // actual destination index rather than re-deriving it via arithmetic.
    if (safe_off >= MAX_BUF_LEN - MAX_STR_LEN) return -1;  /* safe_off < 6144 */

    // Zero the length slot (in case bpf_probe_read_str fails); direct store so
    // the verifier tracks bounds inline rather than losing them through a CALL.
    *(__u32 *)&buf->buf[offset] = 0;

    int len = bpf_probe_read_str(&buf->buf[safe_off], MAX_STR_LEN, str);

    // bpf_probe_read_str is a helper CALL that clobbers R1-R5.  On kernel 6.17
    // the verifier loses the scalar range of stack-spilled locals across calls,
    // so `offset` is treated as unbounded on reload.  Re-establish its range:
    // mask gives verifier tight [0, MAX_BUF_LEN-1] bound, then re-check bound.
    offset &= (MAX_BUF_LEN - 1);
    if (offset >= SAVE_STR_MAX_OFFSET) return -1;

    if (len <= 0 || offset + sizeof(__u32) + len > MAX_BUF_LEN) {
        offset += sizeof(__u32);
        bpf_map_update_elem(&st_buf_offset_map, &index, &offset, BPF_ANY);
        return -1;
    }

    *(__u32 *)&buf->buf[offset] = (__u32)len;

    offset += sizeof(__u32) + len;
    if (offset > MAX_BUF_LEN) return -1;
    bpf_map_update_elem(&st_buf_offset_map, &index, &offset, BPF_ANY);

    return offset;
}

#define MAX_STR_ARR_ELEM 16

static __always_inline int save_str_arr_to_buffer(buf_t *buf, const char *const *ptr) {
    save_type_to_buffer(buf, TYPE_STR_ARR);

    _Pragma("unroll") for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *arg = NULL;
        bpf_probe_read(&arg, sizeof(arg), (void *)&ptr[i]);
        if (!arg) goto out;
        save_str_to_buffer(buf, (void *)arg);
    }

    char ellipsis[] = "...";
    save_str_to_buffer(buf, (void *)ellipsis);

out:
    save_type_to_buffer(buf, TYPE_NONE);
    return 0;
}

static __always_inline int save_src_to_buffer(buf_t *buf, int force) {
    __u32 host_pid = bpf_get_current_pid_tgid() >> 32;

    if (!force && known_source(host_pid)) {
        // source path already cached; emit zero-length placeholder
        save_type_to_buffer(buf, TYPE_SRC);

        __u32 index = 0;
        __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
        if (!offset_ptr) return -1;

        __u32 offset = *offset_ptr;
        if (offset + sizeof(__u32) > MAX_BUF_LEN) return -1;

        *(__u32 *)&buf->buf[offset] = 0;
        *offset_ptr += sizeof(__u32);

        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return -1;

    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file) return -1;

    struct path path = BPF_CORE_READ(exe_file, f_path);

    __u32 index = 0;
    buf_t *tmp_buf = bpf_map_lookup_elem(&st_tmp_buf_map, &index);
    if (!tmp_buf) return -1;

    int tmp_offset = prepend_path(&path, tmp_buf);
    if (tmp_offset < 0) return -1;

    char *path_ptr = (char *)&tmp_buf->buf[(tmp_offset) & (MAX_PATH_SIZE - 1)];
    if (!path_ptr) return -1;

    save_type_to_buffer(buf, TYPE_SRC);

    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return -1;

    __u32 offset = *offset_ptr;
    if (offset >= SAVE_STR_MAX_OFFSET) return -1;
    __u32 safe_off = offset + 4;
    if (safe_off >= MAX_BUF_LEN - MAX_STR_LEN) return -1;

    // reserve 4 bytes for length, then write the path string
    int len = bpf_probe_read_str(&buf->buf[safe_off], MAX_STR_LEN, path_ptr);

    // Re-establish verifier range for offset after the helper CALL.
    offset &= (MAX_BUF_LEN - 1);
    if (offset >= SAVE_STR_MAX_OFFSET) return -1;

    if (len <= 0) {
        offset += sizeof(__u32);
        bpf_map_update_elem(&st_buf_offset_map, &index, &offset, BPF_ANY);
        return -1;
    }

    *(__u32 *)&buf->buf[offset] = len;
    offset += sizeof(__u32) + len;
    bpf_map_update_elem(&st_buf_offset_map, &index, &offset, BPF_ANY);

    bpf_map_update_elem(&st_src_map, &host_pid, &host_pid, BPF_ANY);

    return 0;
}

static __always_inline int save_res_to_buffer(buf_t *buf, struct path *path) {
    __u32 index = 0;
    buf_t *tmp_buf = bpf_map_lookup_elem(&st_tmp_buf_map, &index);
    if (!tmp_buf) return -1;

    int tmp_offset = prepend_path(path, tmp_buf);
    if (tmp_offset < 0) return -1;

    char *path_ptr = (char *)&tmp_buf->buf[(tmp_offset) & (MAX_PATH_SIZE - 1)];
    if (!path_ptr) return -1;

    save_type_to_buffer(buf, TYPE_RES);

    __u32 *offset_ptr = bpf_map_lookup_elem(&st_buf_offset_map, &index);
    if (!offset_ptr) return -1;

    __u32 offset = *offset_ptr;
    if (offset >= SAVE_STR_MAX_OFFSET) return -1;
    __u32 safe_off = offset + 4;
    if (safe_off >= MAX_BUF_LEN - MAX_STR_LEN) return -1;

    // reserve 4 bytes for length, then write the path string
    int len = bpf_probe_read_str(&buf->buf[safe_off], MAX_STR_LEN, path_ptr);

    // Re-establish verifier range for offset after the helper CALL.
    offset &= (MAX_BUF_LEN - 1);
    if (offset >= SAVE_STR_MAX_OFFSET) return -1;

    if (len <= 0) {
        offset += sizeof(__u32);
        bpf_map_update_elem(&st_buf_offset_map, &index, &offset, BPF_ANY);
        return -1;
    }

    *(__u32 *)&buf->buf[offset] = len;
    offset += sizeof(__u32) + len;
    bpf_map_update_elem(&st_buf_offset_map, &index, &offset, BPF_ANY);

    return 0;
}

// Tracepoint macros

#define TRACEPOINT_SYSCALL_EXIT(syscall_name, event_id_val, flag)                             \
    SEC("tp/syscalls/sys_exit_" #syscall_name)                                                \
    int tracepoint__syscalls__sys_exit_##syscall_name(struct trace_event_raw_sys_exit *ctx) { \
        if (!should_monitor()) return 0;                                                      \
        event_t ev = {0};                                                                     \
        init_event(&ev, event_id_val, EVENT_EXIT, 0);                                         \
        ev.ret_val = ctx->ret;                                                                \
        return submit_event(&ev, flag);                                                       \
    }
