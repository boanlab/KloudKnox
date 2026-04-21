// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	"github.com/boanlab/KloudKnox/KloudKnox/exporter"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

const (
	// EnforcerTypeBPF selects the eBPF-LSM backend.
	EnforcerTypeBPF = "bpf"
	// EnforcerTypeLegacy selects the AppArmor backend.
	EnforcerTypeLegacy = "apparmor"

	SecurityPath = "/sys/kernel/security"
	LSMPath      = "/sys/kernel/security/lsm"

	ErrNoSupportedLSM  = "no supported LSM found"
	ErrMountSecurityFS = "failed to mount securityfs"
	ErrReadLSMConfig   = "failed to read LSM configuration"
)

// RuntimeEnforcer owns either a BpfEnforcer (when the kernel reports "bpf" in
// /sys/kernel/security/lsm) or an AppArmorEnforcer, plus a NetworkEnforcer
// that is always active. The backend is selected once at NewRuntimeEnforcer
// time and cannot change at runtime.
type RuntimeEnforcer struct {
	// EnforcerType is "bpf" or "apparmor".
	EnforcerType string

	BpfEnforcer      *BpfEnforcer
	AppArmorEnforcer *AppArmorEnforcer
	NetworkEnforcer  *NetworkEnforcer
	GlobalData       *tp.GlobalData
}

// NewRuntimeEnforcer mounts securityfs if needed, reads /sys/kernel/security/lsm,
// and initialises the correct backend (BPF-LSM preferred, AppArmor fallback).
func NewRuntimeEnforcer(globalData *tp.GlobalData, exporter *exporter.Exporter) (*RuntimeEnforcer, error) {
	e := &RuntimeEnforcer{
		GlobalData: globalData,
	}

	if err := ensureSecurityFSMounted(); err != nil {
		return nil, fmt.Errorf("%s: %w", ErrMountSecurityFS, err)
	}

	lsm, err := readLSMConfiguration()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrReadLSMConfig, err)
	}

	// BPF is preferred if available, otherwise falls back to AppArmor
	if err := e.initializeEnforcer(lsm, exporter); err != nil {
		return nil, err
	}

	return e, nil
}

// ensureSecurityFSMounted ensures that securityfs is mounted
func ensureSecurityFSMounted() error {
	if _, err := os.Stat(filepath.Clean(SecurityPath)); err == nil {
		return nil
	}

	return lib.RunCommandAndWaitWithErr("mount", []string{"-t", "securityfs", "securityfs", SecurityPath})
}

// readLSMConfiguration reads the LSM configuration from the system
func readLSMConfiguration() (string, error) {
	lsm, err := os.ReadFile(LSMPath)
	if err != nil {
		return "", err
	}
	return string(lsm), nil
}

// initializeEnforcer initializes the appropriate enforcer based on LSM type
func (e *RuntimeEnforcer) initializeEnforcer(lsm string, ex *exporter.Exporter) error {
	useAppArmor := false

	switch {
	case strings.Contains(lsm, EnforcerTypeBPF):
		be, err := NewBpfEnforcer(e.GlobalData, ex)
		if err != nil {
			log.Printf("BPF LSM detected but enforcer unavailable (%v); using AppArmor", err)
			useAppArmor = true
			break
		}
		e.BpfEnforcer = be
		e.NetworkEnforcer = NewNetworkEnforcer(e.GlobalData, ex)
		e.EnforcerType = EnforcerTypeBPF

	case strings.Contains(lsm, EnforcerTypeLegacy):
		useAppArmor = true

	default:
		log.Errf("No supported LSM found. Available LSMs: %s", lsm)
		return errors.New(ErrNoSupportedLSM)
	}

	if useAppArmor {
		e.AppArmorEnforcer = NewAppArmorEnforcer()
		e.NetworkEnforcer = NewNetworkEnforcer(e.GlobalData, ex)
		e.EnforcerType = EnforcerTypeLegacy
	}

	return nil
}

// Stop stops the enforcer and cleans up resources
func (e *RuntimeEnforcer) Stop() error {
	if e == nil {
		return nil
	}

	var errs []error

	switch e.EnforcerType {
	case EnforcerTypeBPF:
		if e.BpfEnforcer != nil {
			if err := e.BpfEnforcer.StopBpfEnforcer(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop BPF enforcer: %w", err))
			}
		}
		if e.NetworkEnforcer != nil {
			if err := e.NetworkEnforcer.StopNetworkEnforcer(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop NetworkPolicy enforcer: %w", err))
			}
		}

	case EnforcerTypeLegacy:
		if e.AppArmorEnforcer != nil {
			if err := e.AppArmorEnforcer.StopAppArmorEnforcer(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop AppArmor enforcer: %w", err))
			}
		}
		if e.NetworkEnforcer != nil {
			if err := e.NetworkEnforcer.StopNetworkEnforcer(); err != nil {
				errs = append(errs, fmt.Errorf("failed to stop NetworkPolicy enforcer: %w", err))
			}
		}
	}

	e.BpfEnforcer = nil
	e.AppArmorEnforcer = nil
	e.NetworkEnforcer = nil

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// EnforceSecurityPolicies enforces security policies for a pod
func (e *RuntimeEnforcer) EnforceSecurityPolicies(pod tp.Pod) error {
	if e == nil {
		return nil
	}

	var errs []error

	switch e.EnforcerType {
	case EnforcerTypeBPF:
		if e.BpfEnforcer != nil {
			if err := e.UpdateBPFMaps(pod); err != nil {
				errs = append(errs, fmt.Errorf("failed to update BPF maps: %w", err))
			}
		}
		if e.NetworkEnforcer != nil {
			if err := e.UpdateNetworkPolicies(pod); err != nil {
				errs = append(errs, fmt.Errorf("failed to update NetworkPolicy: %w", err))
			}
		}

	case EnforcerTypeLegacy:
		if e.AppArmorEnforcer != nil {
			if err := e.UpdateAppArmorProfiles(pod); err != nil {
				errs = append(errs, fmt.Errorf("failed to update AppArmor profiles: %w", err))
			}
		}
		if e.NetworkEnforcer != nil {
			if err := e.UpdateNetworkPolicies(pod); err != nil {
				errs = append(errs, fmt.Errorf("failed to update NetworkPolicy: %w", err))
			}
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}
