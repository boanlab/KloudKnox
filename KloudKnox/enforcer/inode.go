// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// containerCgroupInodes returns the cgroup v2 inode for each live container
// in the pod by stat-ing container.CgroupPath from GlobalData.Containers.
//
// bpf_get_current_cgroup_id() returns the DEEPEST cgroup the task belongs
// to, which in Kubernetes with containerd is the per-container cgroup
// (e.g. cri-containerd-<id>.scope), NOT the parent pod cgroup. Rules and
// managed_cgroups entries must therefore be keyed by the container-level
// inode, not the pod-level inode.
func containerCgroupInodes(globalData *tp.GlobalData, pod tp.Pod) []uint64 {
	if globalData == nil {
		return nil
	}
	seen := make(map[uint64]struct{})
	var inodes []uint64
	for cid := range pod.Containers {
		globalData.ContainersLock.RLock()
		c, ok := globalData.Containers[cid]
		globalData.ContainersLock.RUnlock()
		if !ok || c.CgroupPath == "" {
			continue
		}
		info, err := os.Stat(c.CgroupPath)
		if err != nil {
			continue
		}
		st, ok2 := info.Sys().(*syscall.Stat_t)
		if !ok2 {
			continue
		}
		if _, dup := seen[st.Ino]; dup {
			continue
		}
		seen[st.Ino] = struct{}{}
		inodes = append(inodes, st.Ino)
	}
	return inodes
}

// cgroupInode returns the inode number of a cgroup v2 path.
// This value matches what bpf_get_current_cgroup_id() returns in BPF programs.
func cgroupInode(cgroupPath string) (uint64, error) {
	info, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup path %q: %w", cgroupPath, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected stat type for %q", cgroupPath)
	}
	return stat.Ino, nil
}

// resolveInodeInPod walks a pod's containers and resolves the first matching
// inode for `path` within any container's rootfs. BPF maps key on inode to
// express per-process policies without carrying path strings into the kernel.
//
// Returns (0, error) when no container has the path. Both the network and IPC
// (ptrace/signal target) enforcers share this resolver.
func resolveInodeInPod(globalData *tp.GlobalData, pod tp.Pod, path string) (uint64, error) {
	for containerID := range pod.Containers {
		globalData.ContainersLock.RLock()
		container, ok := globalData.Containers[containerID]
		globalData.ContainersLock.RUnlock()
		if !ok {
			continue
		}

		fullPath := filepath.Join(cfg.GlobalCfg.ProcDir, fmt.Sprintf("%d", container.RootPID), "root", path)
		if info, err := os.Stat(fullPath); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				return stat.Ino, nil
			}
		}
	}

	return 0, fmt.Errorf("could not find container that has the path '%s'", path)
}

// resolveInodesInPod is like resolveInodeInPod but also returns the overlayfs
// upper-layer backing inode when the file is in the container's upper layer.
// See overlayBackingInodes for the rationale.
func resolveInodesInPod(globalData *tp.GlobalData, pod tp.Pod, path string) ([]uint64, error) {
	for containerID := range pod.Containers {
		globalData.ContainersLock.RLock()
		container, ok := globalData.Containers[containerID]
		globalData.ContainersLock.RUnlock()
		if !ok || container.RootPID == 0 {
			continue
		}
		fullPath := filepath.Join(cfg.GlobalCfg.ProcDir, fmt.Sprintf("%d", container.RootPID), "root", path)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		upperDir := containerOverlayUpperDir(int(container.RootPID))
		return overlayBackingInodes(upperDir, path, st.Ino), nil
	}
	return nil, fmt.Errorf("could not find container that has the path '%s'", path)
}

// containerOverlayUpperDir reads /proc/<pid>/mountinfo and returns the overlayfs
// upperdir for the container's root filesystem ("/"). Returns "" if not overlay
// or on error. The upperdir is the writable upper layer of the container's
// overlayfs union mount.
func containerOverlayUpperDir(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		// mountinfo format:
		//   <mntid> <parent> <maj:min> <fsroot> <mntpnt> <opts> [opt-fields] - <fstype> <src> <superopts>
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		left := strings.Fields(line[:sep])
		right := strings.Fields(line[sep+3:])
		if len(left) < 5 || len(right) < 3 {
			continue
		}
		// left[4] = mount point in the container's namespace
		// right[0] = filesystem type
		if left[4] != "/" || right[0] != "overlay" {
			continue
		}
		for _, opt := range strings.Split(right[2], ",") {
			if strings.HasPrefix(opt, "upperdir=") {
				return strings.TrimPrefix(opt, "upperdir=")
			}
		}
	}
	return ""
}

// overlayBackingInodes returns the set of inodes that BPF file rules must cover
// for the given file. For lower-layer overlayfs files the overlay inode equals
// the backing inode so a single-element slice is returned. For upper-layer files
// (files created or modified inside the container), the kernel calls
// security_file_open twice: once with the overlay merged-view inode and once
// with the real backing inode on the host's underlying filesystem. Both must be
// covered by Allow rules to prevent the second call from falling through to the
// Block posture.
//
// upperDir is the result of containerOverlayUpperDir; pass "" to skip the check.
// containerRelPath is the file's path relative to the container root (e.g. "/credentials/password").
// overlayIno is the inode returned by stat-ing the file via /proc/<pid>/root.
func overlayBackingInodes(upperDir, containerRelPath string, overlayIno uint64) []uint64 {
	if upperDir == "" {
		return []uint64{overlayIno}
	}
	backingPath := filepath.Join(upperDir, containerRelPath)
	info, err := os.Lstat(backingPath)
	if err != nil {
		return []uint64{overlayIno}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == overlayIno {
		return []uint64{overlayIno}
	}
	return []uint64{overlayIno, st.Ino}
}
