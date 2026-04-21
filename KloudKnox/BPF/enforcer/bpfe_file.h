// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// File R/W enforcement — SEC("lsm/file_*") and SEC("lsm/path_*") (M6).
// Enforces read and write permissions on regular files and directories.

#pragma once

#include "bpfe_lookup.h"

// Linux open/mmap/permission flags not always in vmlinux.h as plain #defines
#ifndef O_RDONLY
#define O_ACCMODE  03
#define O_RDONLY   00
#define O_WRONLY   01
#define O_RDWR     02
#define O_CREAT  0100
#define O_TRUNC  01000
#endif

#ifndef MAY_WRITE
#define MAY_EXEC   0x00000001
#define MAY_WRITE  0x00000002
#define MAY_READ   0x00000004
#endif

#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif

// Private (copy-on-write) mappings never write back to the underlying file
// even when PROT_WRITE is set — only MAP_SHARED writes do. Distinguish them so
// mmap_file enforcement only fires for shared writable mappings.
#ifndef MAP_SHARED
#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02
#endif

// S_IFMT / S_IFREG / S_IFDIR
#define BPFE_S_IFMT   0xF000
#define BPFE_S_IFREG  0x8000
#define BPFE_S_IFDIR  0x4000

// Filesystems whose "regular" inodes should be exempt from file enforcement.
// procfs/sysfs/devtmpfs/cgroup2 are pseudo-fs that the container runtime reads
// during exec setup. tmpfs is NOT exempted: containers mount service-account
// tokens and other policy-controlled files on tmpfs, and those must be enforceable.
#define PROC_SUPER_MAGIC    0x9fa0
#define SYSFS_MAGIC         0x62656572
#define DEVTMPFS_MAGIC      0x1373
#define CGROUP2_SUPER_MAGIC 0x63677270

// inode_from_file returns the inode number of a regular file, or 0 for all
// other file types (sockets, pipes, /proc entries, etc.) and for files on
// pseudo-filesystems (procfs, sysfs, devtmpfs, cgroup2).
static __always_inline __u64 inode_from_file(struct file *file) {
    if (!file)
        return 0;
    struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
    if (!d)
        return 0;
    struct inode *i = BPF_CORE_READ(d, d_inode);
    if (!i)
        return 0;
    __u16 mode = BPF_CORE_READ(i, i_mode);
    if ((mode & BPFE_S_IFMT) != BPFE_S_IFREG)
        return 0;   // only enforce on regular files
    struct super_block *sb = BPF_CORE_READ(i, i_sb);
    if (sb) {
        unsigned long magic = BPF_CORE_READ(sb, s_magic);
        if (magic == PROC_SUPER_MAGIC || magic == SYSFS_MAGIC ||
            magic == DEVTMPFS_MAGIC || magic == CGROUP2_SUPER_MAGIC)
            return 0;
    }
    return BPF_CORE_READ(i, i_ino);
}

// inode_from_path returns the inode number of a regular file or directory.
static __always_inline __u64 inode_from_path(const struct path *path) {
    if (!path)
        return 0;
    struct dentry *d = BPF_CORE_READ(path, dentry);
    if (!d)
        return 0;
    struct inode *i = BPF_CORE_READ(d, d_inode);
    if (!i)
        return 0;
    __u16 mode = BPF_CORE_READ(i, i_mode);
    if ((mode & BPFE_S_IFMT) != BPFE_S_IFREG &&
        (mode & BPFE_S_IFMT) != BPFE_S_IFDIR)
        return 0;
    return BPF_CORE_READ(i, i_ino);
}

// inode_from_dentry returns the inode number of a regular file or directory.
static __always_inline __u64 inode_from_dentry(struct dentry *dent) {
    if (!dent)
        return 0;
    struct inode *i = BPF_CORE_READ(dent, d_inode);
    if (!i)
        return 0;
    __u16 mode = BPF_CORE_READ(i, i_mode);
    if ((mode & BPFE_S_IFMT) != BPFE_S_IFREG &&
        (mode & BPFE_S_IFMT) != BPFE_S_IFDIR)
        return 0;
    return BPF_CORE_READ(i, i_ino);
}

// bpfe_file_check performs a 4-way fallback lookup on bpfe_file_rules:
//   (pod, src, tgt, perm) → (pod, 0, tgt, perm) →
//   (pod, src, 0, perm) → (pod, 0, 0, perm)
// then falls back to posture.
//
// __noinline gives this its own BPF stack frame so the arguments (cgid/src/tgt)
// live in R1-R4 at call time and are not subject to register clobbering from
// the helper calls inside bpfe_file_open.  Inlining all the map lookups into
// the caller makes the register allocator reuse slots unpredictably across
// bpf_get_current_task() helper calls, causing intermittent wrong-action reads.
__attribute__((noinline)) static int
bpfe_file_check(__u64 cgid, __u64 src, __u64 tgt, __u8 perm)
{
    struct bpfe_file_key k = {
        .pod_inode  = cgid,
        .src_inode  = src,
        .tgt_inode  = tgt,
        .permission = perm,
    };
    struct bpfe_rule_val *v = bpf_map_lookup_elem(&bpfe_file_rules, &k);
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_file_rules, &k); }
    if (!v) { k.src_inode = src; k.tgt_inode = 0;
              v = bpf_map_lookup_elem(&bpfe_file_rules, &k); }
    if (!v) { k.src_inode = 0; v = bpf_map_lookup_elem(&bpfe_file_rules, &k); }

    if (!v)
        return fallback_posture(cgid, src, tgt, DOMAIN_FILE);

    return apply_action(cgid, src, tgt, DOMAIN_FILE, (__u16)perm, v);
}

// file_open: read permission on read-only opens; write permission when
// O_WRONLY, O_RDWR, O_CREAT, or O_TRUNC is set.
SEC("lsm/file_open")
int BPF_PROG(bpfe_file_open, struct file *file)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_file(file);
    if (!tgt)
        return 0;

    // Read f_flags here — after inode_from_file (pure direct loads, file
    // pointer still valid) but BEFORE current_exe_inode, which calls
    // bpf_get_current_task() (a helper).  That helper call pressures the
    // register allocator into reusing the slot that holds 'file', so any
    // BPF_CORE_READ(file, ...) after current_exe_inode reads the wrong address.
    unsigned int flags = BPF_CORE_READ(file, f_flags);
    unsigned int acc   = flags & O_ACCMODE;

    __u64 src = current_exe_inode();

    // Read check (O_RDONLY or O_RDWR)
    if (acc == O_RDONLY || acc == O_RDWR) {
        int ret = bpfe_file_check(cgid, src, tgt, PERM_FILE_READ);
        if (ret)
            return ret;
    }
    // Write check (O_WRONLY, O_RDWR, O_CREAT, or O_TRUNC)
    if (acc == O_WRONLY || acc == O_RDWR || (flags & (O_CREAT | O_TRUNC))) {
        int ret = bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
        if (ret)
            return ret;
    }
    return 0;
}

// file_permission: belt-and-suspenders write check for MAY_WRITE on open fds.
SEC("lsm/file_permission")
int BPF_PROG(bpfe_file_permission, struct file *file, int mask)
{
    if (!(mask & MAY_WRITE))
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_file(file);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

// mmap_file: write permission when PROT_WRITE is requested.
SEC("lsm/mmap_file")
int BPF_PROG(bpfe_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    // Private (MAP_PRIVATE) COW mappings never write back to the file, so only
    // enforce write permission for shared (MAP_SHARED) writable mappings.
    if (!file || !(prot & PROT_WRITE) || !(flags & MAP_SHARED))
        return 0;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_file(file);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_chmod")
int BPF_PROG(bpfe_path_chmod, const struct path *path, umode_t mode)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_path(path);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

// path_chown: kuid_t/kgid_t are struct types — bypass BPF_PROG macro
// with void *ctx and extract path from first argument manually.
SEC("lsm/path_chown")
int bpfe_path_chown(void *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    unsigned long long *args = (unsigned long long *)ctx;
    const struct path *path = (const struct path *)(unsigned long)args[0];
    __u64 tgt = inode_from_path(path);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_unlink")
int BPF_PROG(bpfe_path_unlink, const struct path *dir, struct dentry *dentry)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_dentry(dentry);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_rename")
int BPF_PROG(bpfe_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_dentry(old_dentry);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_link")
int BPF_PROG(bpfe_path_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_dentry(old_dentry);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_mkdir")
int BPF_PROG(bpfe_path_mkdir, const struct path *dir, struct dentry *dentry,
             umode_t mode)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_path(dir);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_rmdir")
int BPF_PROG(bpfe_path_rmdir, const struct path *dir, struct dentry *dentry)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_dentry(dentry);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_truncate")
int BPF_PROG(bpfe_path_truncate, const struct path *path)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_path(path);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_symlink")
int BPF_PROG(bpfe_path_symlink, const struct path *dir, struct dentry *dentry,
             const char *old_name)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_path(dir);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}

SEC("lsm/path_mknod")
int BPF_PROG(bpfe_path_mknod, const struct path *dir, struct dentry *dentry,
             umode_t mode, unsigned int dev)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&bpfe_managed_cgroups, &cgid))
        return 0;

    __u64 tgt = inode_from_path(dir);
    if (!tgt)
        return 0;

    __u64 src = current_exe_inode();
    return bpfe_file_check(cgid, src, tgt, PERM_FILE_WRITE);
}
