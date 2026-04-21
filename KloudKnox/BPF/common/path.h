// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by BPF program headers — do not compile standalone.

#pragma once

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "vmlinux.h"

// Path Extraction

#define MAX_PATH_SIZE 4096
#define MAX_LOOP_LIMIT 16

// buf_t is defined in each BPF program's header; avoid redefinition here

static inline struct mount *real_mount(struct vfsmount *mnt) {
    struct mount *m = NULL;
    bpf_probe_read(&m, sizeof(m), mnt);
    return m;
}

// Builds the path backwards from MAX_PATH_SIZE; returns offset to path start, or -1 on error.
static int prepend_path(struct path *path, void *buf_ptr) {
    if (!path || !buf_ptr) return -1;

    __u8 *buf = (__u8 *)buf_ptr;

    int offset = MAX_PATH_SIZE;
    char slash = '/';
    char null = '\0';

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    struct mount *mnt = real_mount(vfsmnt);

    struct dentry *parent = NULL;
    struct dentry *mnt_root = NULL;
    struct mount *mnt_parent = NULL;
    struct qstr d_name;

    for (int i = 0; i < MAX_LOOP_LIMIT; i++) {
        if (!dentry) break;

        mnt = real_mount(vfsmnt);
        mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
        parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == mnt_root) {
            mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
            if (mnt != mnt_parent) {
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt = BPF_CORE_READ(mnt, mnt_parent);
                struct vfsmount mnt_val = BPF_CORE_READ(mnt, mnt);
                vfsmnt = &mnt_val;
                continue;
            }
            break;
        }

        if (dentry == parent) break;

        d_name = BPF_CORE_READ(dentry, d_name);

        offset -= (d_name.len + 1);
        if (offset < 0) break;

        int len = bpf_probe_read_str(&(buf[(offset) & (MAX_PATH_SIZE - 1)]), (d_name.len + 1) & (MAX_PATH_SIZE - 1),
                                     d_name.name);
        if (len > 1) {
            bpf_probe_read(&buf[(offset + d_name.len) & (MAX_PATH_SIZE - 1)], 1, &slash);
        } else {
            offset += (d_name.len + 1);
        }

        dentry = parent;
    }

    if (offset == MAX_PATH_SIZE) return -1;

    // insert null terminator and leading slash
    bpf_probe_read(&(buf[MAX_PATH_SIZE - 1]), 1, &null);
    offset--;

    bpf_probe_read(&(buf[offset & (MAX_PATH_SIZE - 1)]), 1, &slash);

    return offset;
}
