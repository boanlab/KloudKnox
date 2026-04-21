// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

import "strings"

// capNameToID maps the canonical CAP_* symbol to its Linux bit number.
// Kept in sync with operator-controller/api/v1/kloudknoxpolicy_validation.go.
var capNameToID = map[string]uint32{
	"CAP_AUDIT_CONTROL":      30,
	"CAP_AUDIT_READ":         37,
	"CAP_AUDIT_WRITE":        29,
	"CAP_BLOCK_SUSPEND":      36,
	"CAP_BPF":                39,
	"CAP_CHECKPOINT_RESTORE": 40,
	"CAP_CHOWN":              0,
	"CAP_DAC_OVERRIDE":       1,
	"CAP_DAC_READ_SEARCH":    2,
	"CAP_FOWNER":             3,
	"CAP_FSETID":             4,
	"CAP_IPC_LOCK":           14,
	"CAP_IPC_OWNER":          15,
	"CAP_KILL":               5,
	"CAP_LEASE":              28,
	"CAP_LINUX_IMMUTABLE":    9,
	"CAP_MAC_ADMIN":          33,
	"CAP_MAC_OVERRIDE":       32,
	"CAP_MKNOD":              27,
	"CAP_NET_ADMIN":          12,
	"CAP_NET_BIND_SERVICE":   10,
	"CAP_NET_BROADCAST":      11,
	"CAP_NET_RAW":            13,
	"CAP_PERFMON":            38,
	"CAP_SETFCAP":            31,
	"CAP_SETGID":             6,
	"CAP_SETPCAP":            8,
	"CAP_SETUID":             7,
	"CAP_SYS_ADMIN":          21,
	"CAP_SYS_BOOT":           22,
	"CAP_SYS_CHROOT":         18,
	"CAP_SYS_MODULE":         16,
	"CAP_SYS_NICE":           23,
	"CAP_SYS_PACCT":          20,
	"CAP_SYS_PTRACE":         19,
	"CAP_SYS_RAWIO":          17,
	"CAP_SYS_RESOURCE":       24,
	"CAP_SYS_TIME":           25,
	"CAP_SYS_TTY_CONFIG":     26,
	"CAP_SYSLOG":             34,
	"CAP_WAKE_ALARM":         35,
}

var capIDToNameTable = func() map[uint32]string {
	out := make(map[uint32]string, len(capNameToID))
	for name, id := range capNameToID {
		out[id] = name
	}
	return out
}()

// NormalizeCapabilityName returns the canonical CAP_* symbol for user input
// accepting either "NET_RAW" or "CAP_NET_RAW" in any case. Returns false when
// the symbol is not a known Linux capability.
func NormalizeCapabilityName(name string) (string, bool) {
	upper := strings.ToUpper(strings.TrimSpace(name))
	if !strings.HasPrefix(upper, "CAP_") {
		upper = "CAP_" + upper
	}
	if _, ok := capNameToID[upper]; !ok {
		return "", false
	}
	return upper, true
}

// CapabilityID returns the Linux bit number for a capability name. The name
// is normalized with NormalizeCapabilityName first. Returns (0, false) when
// the symbol is unknown.
func CapabilityID(name string) (uint32, bool) {
	canonical, ok := NormalizeCapabilityName(name)
	if !ok {
		return 0, false
	}
	return capNameToID[canonical], true
}

// CapabilityName returns the canonical CAP_* symbol for a capability bit
// number. Returns an empty string for unknown IDs.
func CapabilityName(id uint32) string {
	return capIDToNameTable[id]
}
