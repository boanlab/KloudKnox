// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/enforcer"
	"github.com/boanlab/KloudKnox/KloudKnox/exporter"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	"github.com/boanlab/KloudKnox/KloudKnox/monitor"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// KloudKnox is the root object for the per-node agent. It owns references to
// every subsystem so that startup and shutdown can be coordinated centrally.
type KloudKnox struct {
	GlobalData      *tp.GlobalData
	Exporter        *exporter.Exporter
	RuntimeEnforcer *enforcer.RuntimeEnforcer
	SystemMonitor   *monitor.SystemMonitor

	// ContainerdHandler and K8sHandler are always active in kubernetes/hybrid mode.
	ContainerdHandler *ContainerdHandler
	K8sHandler        *K8sHandler

	// DockerHandler and PolicyFileLoader are active in docker/hybrid mode only.
	DockerHandler    *DockerHandler
	PolicyFileLoader *PolicyFileLoader

	WgDaemon sync.WaitGroup
}

// NewKloudKnox creates and initializes a new KloudKnox instance.
func NewKloudKnox() *KloudKnox {
	knox := new(KloudKnox)
	knox.GlobalData = tp.NewGlobalData()
	return knox
}

// DestroyKloudKnox performs a graceful shutdown of KloudKnox.
// Shutdown order is the reverse of start-up so that subsystems are
// stopped before their dependencies disappear.
func (knox *KloudKnox) DestroyKloudKnox() {
	knox.StopPolicyFileLoader()
	knox.StopDocker()
	knox.StopKubernetes()
	knox.StopContainerd()

	knox.StopSystemMonitor()
	knox.SystemMonitor = nil

	knox.StopRuntimeEnforcer()
	knox.RuntimeEnforcer = nil

	knox.StopExporter()

	knox.WgDaemon.Wait()

	log.Print("Terminated KloudKnox")
}

// StartExporter initializes and starts the exporter
func (knox *KloudKnox) StartExporter() bool {
	exporter, err := exporter.NewExporter()
	if err != nil {
		log.Errf("Failed to initialize Exporter: %v", err)
		return false
	}
	knox.Exporter = exporter
	log.LogHook = exporter.ExportLog
	return true
}

// StopExporter gracefully stops the exporter
func (knox *KloudKnox) StopExporter() {
	if knox.Exporter != nil {
		if err := knox.Exporter.Stop(); err != nil {
			log.Errf("Failed to stop Exporter: %v", err)
			return
		}
	}
}

// StartRuntimeEnforcer initializes and starts the runtime enforcer
func (knox *KloudKnox) StartRuntimeEnforcer() bool {
	enforcer, err := enforcer.NewRuntimeEnforcer(knox.GlobalData, knox.Exporter)
	if err != nil {
		log.Errf("Failed to initialize Runtime Enforcer: %v", err)
		return false
	}
	knox.RuntimeEnforcer = enforcer
	return true
}

// StopRuntimeEnforcer gracefully stops the runtime enforcer
func (knox *KloudKnox) StopRuntimeEnforcer() {
	if knox.RuntimeEnforcer != nil {
		if err := knox.RuntimeEnforcer.Stop(); err != nil {
			log.Errf("Failed to stop Runtime Enforcer: %v", err)
			return
		}
	}
}

// StartSystemMonitor initializes and starts the system monitor
func (knox *KloudKnox) StartSystemMonitor() bool {
	monitor, err := monitor.NewSystemMonitor(knox.GlobalData, knox.Exporter)
	if err != nil {
		log.Errf("Failed to initialize System Monitor: %v", err)
		return false
	}
	knox.SystemMonitor = monitor
	return true
}

// StopSystemMonitor gracefully stops the system monitor
func (knox *KloudKnox) StopSystemMonitor() {
	if knox.SystemMonitor != nil {
		if err := knox.SystemMonitor.Stop(); err != nil {
			log.Errf("Failed to stop System Monitor: %v", err)
			return
		}
	}
}

// StartContainerd initializes and starts the containerd handler
func (knox *KloudKnox) StartContainerd() bool {
	knox.ContainerdHandler = NewContainerdHandler(knox)
	if knox.ContainerdHandler == nil {
		log.Err("Containerd handler is not properly initialized")
		return false
	}
	return true
}

// StopContainerd gracefully stops the containerd handler
func (knox *KloudKnox) StopContainerd() {
	if knox.ContainerdHandler != nil {
		knox.ContainerdHandler.Close()
	}
}

// StartKubernetes initializes and starts the Kubernetes handler
func (knox *KloudKnox) StartKubernetes() bool {
	knox.K8sHandler = NewK8sHandler(knox)
	if knox.K8sHandler == nil {
		log.Err("Kubernetes handler is not properly initialized")
		return false
	}
	return true
}

// StopKubernetes gracefully stops the Kubernetes handler
func (knox *KloudKnox) StopKubernetes() {
	if knox.K8sHandler != nil {
		knox.K8sHandler.Close()
	}
}

// StartDocker initializes and starts the Docker Engine API handler
func (knox *KloudKnox) StartDocker() bool {
	knox.DockerHandler = NewDockerHandler(knox)
	if knox.DockerHandler == nil {
		log.Err("Docker handler is not properly initialized")
		return false
	}
	return true
}

// StopDocker gracefully stops the Docker handler
func (knox *KloudKnox) StopDocker() {
	if knox.DockerHandler != nil {
		knox.DockerHandler.Close()
	}
}

// StartPolicyFileLoader initializes and starts the local YAML policy watcher
func (knox *KloudKnox) StartPolicyFileLoader() bool {
	loader, err := NewPolicyFileLoader(knox)
	if err != nil {
		log.Errf("Failed to initialize Policy File Loader: %v", err)
		return false
	}
	knox.PolicyFileLoader = loader
	return true
}

// StopPolicyFileLoader gracefully stops the policy file loader
func (knox *KloudKnox) StopPolicyFileLoader() {
	if knox.PolicyFileLoader != nil {
		knox.PolicyFileLoader.Close()
	}
}

// GetOSSigChannel returns a buffered channel wired to the common
// termination signals so callers can block until a shutdown is requested.
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// KloudKnoxDaemon boots the KloudKnox agent, brings the operation-mode
// specific handlers up, and blocks until a termination signal arrives.
func KloudKnoxDaemon() {
	knox := NewKloudKnox()

	if !knox.StartExporter() {
		log.Err("Failed to start Exporter")
		knox.DestroyKloudKnox()
		return
	}

	if !knox.StartRuntimeEnforcer() {
		log.Err("Failed to start Runtime Enforcer")
		knox.DestroyKloudKnox()
		return
	}

	// Propagate enforcer type to GlobalData before starting the monitor so that
	// policyMatcher can skip attribution when BPF-LSM enforces directly.
	if knox.RuntimeEnforcer != nil {
		knox.GlobalData.EnforcerType = knox.RuntimeEnforcer.EnforcerType
	}

	if !knox.StartSystemMonitor() {
		log.Err("Failed to start System Monitor")
		knox.DestroyKloudKnox()
		return
	}

	switch cfg.GlobalCfg.Mode {
	case cfg.ModeKubernetes:
		if !knox.StartContainerd() {
			log.Err("Failed to start Containerd")
			knox.DestroyKloudKnox()
			return
		}
		if !knox.StartKubernetes() {
			log.Err("Failed to start Kubernetes")
			knox.DestroyKloudKnox()
			return
		}

	case cfg.ModeDocker:
		if !knox.StartDocker() {
			log.Err("Failed to start Docker handler")
			knox.DestroyKloudKnox()
			return
		}
		if !knox.StartPolicyFileLoader() {
			log.Err("Failed to start Policy File Loader")
			knox.DestroyKloudKnox()
			return
		}

	case cfg.ModeHybrid:
		if !knox.StartContainerd() {
			log.Err("Failed to start Containerd")
			knox.DestroyKloudKnox()
			return
		}
		if !knox.StartDocker() {
			log.Err("Failed to start Docker handler")
			knox.DestroyKloudKnox()
			return
		}
		if !knox.StartKubernetes() {
			log.Err("Failed to start Kubernetes")
			knox.DestroyKloudKnox()
			return
		}
		if !knox.StartPolicyFileLoader() {
			log.Err("Failed to start Policy File Loader")
			knox.DestroyKloudKnox()
			return
		}

	default:
		log.Errf("Unsupported mode %q", cfg.GlobalCfg.Mode)
		knox.DestroyKloudKnox()
		return
	}

	sigChan := GetOSSigChannel()
	<-sigChan

	knox.DestroyKloudKnox()
}
