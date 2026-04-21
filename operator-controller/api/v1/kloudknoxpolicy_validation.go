// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package v1

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var validFQDNRe = regexp.MustCompile(
	`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`,
)

// validDockerSelectorKeyRe validates the shape of docker.* selector keys,
// which are reserved for Docker / Hybrid mode. Keys outside this prefix are
// treated as ordinary label keys by both modes.
var validDockerSelectorKeyRe = regexp.MustCompile(`^docker\.[a-z][a-z0-9._-]*$`)

// ValidateSelector performs selector-key validation that applies to both K8s
// and Docker modes. Docker-only keys (prefix "docker.") must match the
// reserved shape even when the policy runs in Kubernetes so that the CRD
// remains portable across modes.
func ValidateSelector(sel map[string]string) error {
	if len(sel) == 0 {
		return fmt.Errorf("selector must be non-empty")
	}
	for k := range sel {
		if strings.HasPrefix(k, "docker.") && !validDockerSelectorKeyRe.MatchString(k) {
			return fmt.Errorf("invalid docker selector key: %s", k)
		}
	}
	return nil
}

// ValidateProcessRule checks that a ProcessRule is well-formed.
func ValidateProcessRule(rule ProcessRule) error {
	count := 0
	if rule.Path != "" {
		count++
	}
	if rule.Dir != "" {
		count++
	}
	if count == 0 {
		return fmt.Errorf("must specify one of path or dir")
	}
	if count > 1 {
		return fmt.Errorf("must specify exactly one of path or dir (got both)")
	}
	if rule.Recursive && rule.Dir == "" {
		return fmt.Errorf("recursive can only be set when dir is specified")
	}
	for _, source := range rule.FromSource {
		if source.Path == "" {
			return fmt.Errorf("fromSource entry must have a path set")
		}
	}
	return nil
}

// ValidateFileRule checks that a FileRule is well-formed.
func ValidateFileRule(rule FileRule) error {
	count := 0
	if rule.Path != "" {
		count++
	}
	if rule.Dir != "" {
		count++
	}
	if count == 0 {
		return fmt.Errorf("must specify one of path or dir")
	}
	if count > 1 {
		return fmt.Errorf("must specify exactly one of path or dir (got both)")
	}
	if rule.Recursive && rule.Dir == "" {
		return fmt.Errorf("recursive can only be set when dir is specified")
	}
	for _, source := range rule.FromSource {
		if source.Path == "" {
			return fmt.Errorf("fromSource entry must have a path set")
		}
	}
	return nil
}

// validCapabilities maps the canonical CAP_* symbol to its Linux bit number.
// Sourced from include/uapi/linux/capability.h; kept in sync with
// KloudKnox/common/capability.go.
var validCapabilities = map[string]int{
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

// ValidateCapabilityRule checks that a CapabilityRule is well-formed. The
// name is normalized to the canonical CAP_* form before lookup so users may
// write either "NET_RAW" or "CAP_NET_RAW".
func ValidateCapabilityRule(rule CapabilityRule) error {
	if rule.Name == "" {
		return fmt.Errorf("capability name must be set")
	}
	name := strings.ToUpper(rule.Name)
	if !strings.HasPrefix(name, "CAP_") {
		name = "CAP_" + name
	}
	if _, ok := validCapabilities[name]; !ok {
		return fmt.Errorf("unknown capability: %s", rule.Name)
	}
	for _, source := range rule.FromSource {
		if source.Path == "" {
			return fmt.Errorf("fromSource entry must have a path set")
		}
	}
	return nil
}

// validUnixPerms is the set of permission tokens accepted on UnixRule.
// AppArmor accepts bind/listen/connect/send/receive; we keep the same
// vocabulary so the converter can emit them verbatim.
var validUnixPerms = map[string]struct{}{
	"connect": {}, "send": {}, "receive": {}, "bind": {}, "listen": {},
}

// validPtracePerms — "trace"/"read" are tracer-side (source traces peer),
// "traceby"/"readby" are tracee-side (source is traced by peer).
var validPtracePerms = map[string]struct{}{
	"trace": {}, "read": {}, "traceby": {}, "readby": {},
}

// validSignals maps the symbolic signal name to its Linux signo. Matches
// asm-generic/signal.h on x86_64; RT signals (SIGRTMIN+N) are not tracked here
// because they are rarely used as policy targets. Kept in sync with
// KloudKnox/common/signal.go.
var validSignals = map[string]int{
	"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5,
	"SIGABRT": 6, "SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9, "SIGUSR1": 10,
	"SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13, "SIGALRM": 14, "SIGTERM": 15,
	"SIGCHLD": 17, "SIGCONT": 18, "SIGSTOP": 19, "SIGTSTP": 20,
	"SIGTTIN": 21, "SIGTTOU": 22, "SIGURG": 23, "SIGXCPU": 24, "SIGXFSZ": 25,
	"SIGVTALRM": 26, "SIGPROF": 27, "SIGWINCH": 28, "SIGIO": 29, "SIGPWR": 30,
	"SIGSYS": 31,
}

// ValidateUnixRule checks a UnixRule's type, path shape, and permission set.
// Abstract-namespace paths (starting with "@") skip the filesystem-path
// pattern enforced on other rule kinds because they have no / prefix.
func ValidateUnixRule(rule UnixRule) error {
	if rule.Type != "stream" && rule.Type != "dgram" {
		return fmt.Errorf("invalid unix type %q (want stream|dgram)", rule.Type)
	}
	if rule.Path != "" {
		if !strings.HasPrefix(rule.Path, "@") && !strings.HasPrefix(rule.Path, "/") {
			return fmt.Errorf("unix path must start with '/' or '@': %s", rule.Path)
		}
	}
	if len(rule.Permissions) == 0 {
		return fmt.Errorf("unix permission must be set")
	}
	for _, p := range rule.Permissions {
		if _, ok := validUnixPerms[p]; !ok {
			return fmt.Errorf("invalid unix permission: %s", p)
		}
	}
	for _, src := range rule.FromSource {
		if src.Path == "" {
			return fmt.Errorf("fromSource entry must have a path set")
		}
	}
	return nil
}

// ValidateSignalRule checks a SignalRule's permission and signal list.
func ValidateSignalRule(rule SignalRule) error {
	if rule.Permission != "send" {
		return fmt.Errorf("invalid signal permission %q (only 'send' is supported)", rule.Permission)
	}
	for _, sig := range rule.Signals {
		if _, ok := validSignals[sig]; !ok {
			return fmt.Errorf("unknown signal: %s", sig)
		}
	}
	for _, src := range rule.FromSource {
		if src.Path == "" {
			return fmt.Errorf("fromSource entry must have a path set")
		}
	}
	return nil
}

// ValidatePtraceRule checks a PtraceRule's permission token.
func ValidatePtraceRule(rule PtraceRule) error {
	if _, ok := validPtracePerms[rule.Permission]; !ok {
		return fmt.Errorf("invalid ptrace permission: %s", rule.Permission)
	}
	for _, src := range rule.FromSource {
		if src.Path == "" {
			return fmt.Errorf("fromSource entry must have a path set")
		}
	}
	return nil
}

// ValidateIPC dispatches per-subdomain validation for an IPCRules block.
func ValidateIPC(ipc *IPCRules) error {
	if ipc == nil {
		return nil
	}
	for i, r := range ipc.Unix {
		if err := ValidateUnixRule(r); err != nil {
			return fmt.Errorf("unix[%d]: %w", i, err)
		}
	}
	for i, r := range ipc.Signal {
		if err := ValidateSignalRule(r); err != nil {
			return fmt.Errorf("signal[%d]: %w", i, err)
		}
	}
	for i, r := range ipc.Ptrace {
		if err := ValidatePtraceRule(r); err != nil {
			return fmt.Errorf("ptrace[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateNetworkRule checks that a NetworkRule is well-formed.
func ValidateNetworkRule(rule NetworkRule) error {
	count := 0
	if rule.Selector != nil {
		count++
	}
	if rule.IPBlock.CIDR != "" {
		count++
	}
	if rule.FQDN != "" {
		count++
	}
	if count == 0 {
		return fmt.Errorf("must specify one of selector, ipBlock, or fqdn")
	}
	if count > 1 {
		return fmt.Errorf("must specify exactly one of selector, ipBlock, or fqdn (got %d)", count)
	}

	if rule.IPBlock.CIDR != "" {
		if err := validateCIDR(rule.IPBlock.CIDR); err != nil {
			return fmt.Errorf("invalid CIDR in ipBlock: %v", err)
		}
		for _, except := range rule.IPBlock.Except {
			if err := validateCIDR(except); err != nil {
				return fmt.Errorf("invalid CIDR in ipBlock.except: %v", err)
			}
		}
	}

	if rule.FQDN != "" {
		if err := validateFQDN(rule.FQDN); err != nil {
			return fmt.Errorf("invalid FQDN: %v", err)
		}
	}

	for _, p := range rule.Ports {
		if p.Protocol == "ICMP" && p.Port != 0 {
			return fmt.Errorf("ICMP does not use port numbers; remove port %d or use a different protocol", p.Port)
		}
	}

	for _, source := range rule.FromSource {
		if source.Path == "" {
			return fmt.Errorf("fromSource entry must have a path set")
		}
	}
	return nil
}

// ValidateSpec validates a KloudKnoxPolicySpec in full: selector, action
// presence, and each process/file/network rule in order. When ApplyToAll is
// set, the selector-must-be-non-empty check is skipped; any explicit selector
// keys still go through key-shape validation.
func ValidateSpec(spec *KloudKnoxPolicySpec) error {
	if spec.ApplyToAll {
		for k := range spec.Selector {
			if strings.HasPrefix(k, "docker.") && !validDockerSelectorKeyRe.MatchString(k) {
				return fmt.Errorf("invalid docker selector key: %s", k)
			}
		}
	} else if err := ValidateSelector(spec.Selector); err != nil {
		return err
	}
	if !hasAnyAction(spec) {
		return fmt.Errorf("no action defined: either spec.action or at least one rule action must be set")
	}
	for i, rule := range spec.Process {
		if err := ValidateProcessRule(rule); err != nil {
			return fmt.Errorf("process[%d]: %w", i, err)
		}
	}
	for i, rule := range spec.File {
		if err := ValidateFileRule(rule); err != nil {
			return fmt.Errorf("file[%d]: %w", i, err)
		}
	}
	for i, rule := range spec.Network {
		if err := ValidateNetworkRule(rule); err != nil {
			return fmt.Errorf("network[%d]: %w", i, err)
		}
	}
	for i, rule := range spec.Capability {
		if err := ValidateCapabilityRule(rule); err != nil {
			return fmt.Errorf("capability[%d]: %w", i, err)
		}
	}
	if err := ValidateIPC(spec.IPC); err != nil {
		return fmt.Errorf("ipc: %w", err)
	}
	return nil
}

func hasAnyAction(spec *KloudKnoxPolicySpec) bool {
	if spec.Action != "" {
		return true
	}
	for _, r := range spec.Process {
		if r.Action != "" {
			return true
		}
	}
	for _, r := range spec.File {
		if r.Action != "" {
			return true
		}
	}
	for _, r := range spec.Network {
		if r.Action != "" {
			return true
		}
	}
	for _, r := range spec.Capability {
		if r.Action != "" {
			return true
		}
	}
	if spec.IPC != nil {
		for _, r := range spec.IPC.Unix {
			if r.Action != "" {
				return true
			}
		}
		for _, r := range spec.IPC.Signal {
			if r.Action != "" {
				return true
			}
		}
		for _, r := range spec.IPC.Ptrace {
			if r.Action != "" {
				return true
			}
		}
	}
	return false
}

func validateCIDR(cidr string) error {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid CIDR format: %s", cidr)
	}
	ip := parts[0]
	ipParts := strings.Split(ip, ".")
	if len(ipParts) != 4 {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}
	for _, part := range ipParts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return fmt.Errorf("invalid IP address: %s", ip)
		}
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return fmt.Errorf("invalid mask: %s", parts[1])
	}
	return nil
}

func validateFQDN(fqdn string) error {
	if len(fqdn) > 253 {
		return fmt.Errorf("FQDN must not exceed 253 characters")
	}
	if !validFQDNRe.MatchString(fqdn) {
		return fmt.Errorf("invalid FQDN format: must contain only letters, numbers, hyphens, and dots; each label must be 1-63 characters and start/end with alphanumeric")
	}
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 || len(parts[len(parts)-1]) < 2 {
		return fmt.Errorf("FQDN must have at least one subdomain and a valid TLD (2+ characters)")
	}
	return nil
}
