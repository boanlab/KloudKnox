// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/core"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
)

// main is the entry point of the KloudKnox agent. eBPF attach and LSM
// profile loading both require CAP_SYS_ADMIN, so the binary refuses to
// start unless invoked as root.
func main() {
	if os.Geteuid() != 0 {
		log.Errf("Need root privileges to run %s", os.Args[0])
		return
	}

	// Change to the executable's directory so relative paths in config
	// (BPF objects, AppArmor profile dir, policy dir) resolve identically
	// regardless of the caller's working directory.
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Errf("Failed to get absolute path of executable: %v", err)
		return
	}
	if err := os.Chdir(dir); err != nil {
		log.Errf("Failed to change working directory: %v", err)
		return
	}

	exefile, err := os.Executable()
	if err != nil {
		log.Errf("Failed to get executable: %v", err)
		return
	}
	if finfo, err := os.Stat(exefile); err == nil {
		stat := finfo.Sys().(*syscall.Stat_t)
		log.Printf("Build time: %v", time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)))
	}

	if !cfg.LoadConfig() {
		log.Errf("Failed to load configuration")
		return
	}

	log.SetLogger(cfg.GlobalCfg.LogPath, cfg.GlobalCfg.LogLevel)

	core.KloudKnoxDaemon()
}
