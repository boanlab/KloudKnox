// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
)

// IsCgroupV2 reports whether the host uses cgroup v2 (unified hierarchy).
// Detection is done via the sentinel /sys/fs/cgroup/cgroup.controllers which
// exists only on v2 (or hybrid-unified) systems.
func IsCgroupV2() bool {
	sentinel := filepath.Join(cfg.GlobalCfg.CgroupDir, "cgroup.controllers")
	if _, err := os.Stat(sentinel); err == nil {
		return true
	}
	return false
}

// DockerCgroupPath resolves the absolute cgroup path for a Docker container.
// The derivation covers the common shapes observed in the wild:
//
//	systemd slice (cgroup v2):     <cgroupDir>/system.slice/docker-<id>.scope
//	cgroupfs (cgroup v2):          <cgroupDir>/docker/<id>
//	systemd slice (cgroup v1):     <cgroupDir>/<controller>/system.slice/docker-<id>.scope
//	cgroupfs (cgroup v1):          <cgroupDir>/<controller>/docker/<id>
//	rootless (cgroup v2):          <cgroupDir>/user.slice/.../docker-<id>.scope
//
// A non-empty cgroupParent hint (from HostConfig.CgroupParent) is honored when
// it points to an existing directory; otherwise the candidates below are tried
// in order and the first existing path wins. Falls back to the systemd-style
// path when nothing matches, so that enforcer attach still produces a useful
// error instead of silently aborting.
func DockerCgroupPath(containerID, cgroupParent string) string {
	if containerID == "" {
		return ""
	}
	base := cfg.GlobalCfg.CgroupDir
	if base == "" {
		base = "/sys/fs/cgroup"
	}

	candidates := make([]string, 0, 6)

	// Honor explicit parent hint.
	if cgroupParent != "" {
		parent := normalizeCgroupParent(base, cgroupParent)
		candidates = append(candidates,
			filepath.Join(parent, fmt.Sprintf("docker-%s.scope", containerID)),
			filepath.Join(parent, containerID),
		)
	}

	// Systemd-managed v2 layout (Docker >= 20.10 default).
	candidates = append(candidates,
		filepath.Join(base, "system.slice", fmt.Sprintf("docker-%s.scope", containerID)),
	)

	// Rootless docker (user.slice / systemd --user).
	if uid := os.Geteuid(); uid > 0 {
		userSlice := filepath.Join(base, "user.slice", fmt.Sprintf("user-%d.slice", uid))
		candidates = append(candidates,
			filepath.Join(userSlice, fmt.Sprintf("user@%d.service", uid), "app.slice",
				fmt.Sprintf("docker-%s.scope", containerID)),
		)
	}

	// cgroupfs driver (rare on modern distros).
	candidates = append(candidates,
		filepath.Join(base, "docker", containerID),
	)

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}

	// Return the most likely systemd path so downstream errors point to a
	// concrete location; callers can still fail loudly if the directory is
	// missing at attach time.
	return candidates[0]
}

// normalizeCgroupParent converts a parent hint into an absolute cgroup path.
// Docker returns parents like "/docker", "system.slice", or absolute paths.
func normalizeCgroupParent(base, parent string) string {
	if strings.HasPrefix(parent, base) {
		return parent
	}
	if strings.HasPrefix(parent, "/") {
		return filepath.Join(base, parent)
	}
	return filepath.Join(base, parent)
}
