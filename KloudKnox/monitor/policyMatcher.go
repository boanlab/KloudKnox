// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

import (
	"path"
	"sort"
	"strings"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// writeFlags contains flags that indicate write operations
var writeFlags = []string{"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}

// hasWriteFlag checks if the data contains any write operation flags
func hasWriteFlag(data string) bool {
	for _, flag := range writeFlags {
		if strings.Contains(data, flag) {
			return true
		}
	}
	return false
}

// matchProcessExecute handles process execution matching
func matchProcessExecute(rule tp.FileRule, evData *tp.EventData) bool {
	switch rule.Permission {
	case "x":
		return rule.Action == "Block" && evData.RetVal == -13 // Permission denied
	case "X":
		return rule.Action == "Audit" && evData.RetVal == 0 // Success
	}
	return false
}

// matchFileOpen handles file open operation matching
func matchFileOpen(rule tp.FileRule, evData *tp.EventData) bool {
	switch rule.Permission {
	case "r":
		return rule.Action == "Block" && !hasWriteFlag(evData.Data) && evData.RetVal == -13 // Permission denied on read
	case "R":
		return rule.Action == "Audit" && !hasWriteFlag(evData.Data) && evData.RetVal > 0 // Successful read open (FD)
	case "w":
		return rule.Action == "Block" && hasWriteFlag(evData.Data) && evData.RetVal == -13 // Permission denied on write
	case "W":
		return rule.Action == "Audit" && hasWriteFlag(evData.Data) && evData.RetVal > 0 // Successful write open (FD)
	case "rw":
		return rule.Action == "Block" && evData.RetVal == -13 // Permission denied
	case "RW":
		return rule.Action == "Audit" && evData.RetVal > 0 // Success (FD)
	}
	return false
}

// IsMatched checks if the rule matches the event data
func IsMatched(rule tp.FileRule, evData *tp.EventData) bool {
	switch evData.Operation {
	case "execute":
		return matchProcessExecute(rule, evData)
	case "open":
		return matchFileOpen(rule, evData)
	}
	return false
}

// matchCapability decides whether a capability rule fires for a cap_capable
// event. The kprobe fires at function entry (no retval is available there),
// so matching is purely attribution: if the capability name matches a
// Block/Audit rule we annotate the event with that policy's action. The actual
// deny is BPF LSM's job — this function only surfaces the "cap was used under
// rule X" observation for alerting.
func matchCapability(rule tp.CapabilityRule, evData *tp.EventData) bool {
	if rule.Name != evData.Resource {
		return false
	}
	return rule.Action == "Block" || rule.Action == "Audit"
}

// isRuleMatching checks if a rule path matches the resource
func (m *SystemMonitor) isRuleMatching(rule tp.FileRule, rulePath, resourcePath, resourceDir string) bool {
	switch {
	case rule.IsPath && rulePath == resourcePath:
		return true
	case rule.IsDir && !rule.Recursive:
		dir := strings.TrimSuffix(rulePath, "/")
		return dir == resourceDir
	case rule.IsDir && rule.Recursive:
		dir := strings.TrimSuffix(rulePath, "/")
		return resourceDir == dir || strings.HasPrefix(resourceDir, dir+"/")
	}
	return false
}

// findMatchedRules finds all matching rules for the event
func (m *SystemMonitor) findMatchedRules(fileRules tp.FileRules, evData *tp.EventData) []tp.FileRule {
	matched := []tp.FileRule{}

	sourcePath := evData.Source
	resourcePath := evData.Resource
	resourceDir := path.Dir(resourcePath)

	// Check source-specific rules first, then default rules
	sources := []string{sourcePath, "default"}

	for _, source := range sources {
		if srcMap, ok := fileRules.OuterRules[source]; ok {
			for rulePath, rule := range srcMap.InnerRules {
				if rule.Action == "Allow" {
					continue
				}

				if m.isRuleMatching(rule, rulePath, resourcePath, resourceDir) && IsMatched(rule, evData) {
					matched = append(matched, rule)
				}
			}
		}
	}

	return matched
}

// shellSources are the well-known shell binaries whose ambient startup opens
// (libc, /etc/nsswitch.conf, /etc/passwd, …) routinely trip EACCES under an
// allow-list posture. Attributing those shell-internal denials to the user
// policy produces false-positive Block alerts.
var shellSources = map[string]struct{}{
	"/bin/bash":     {},
	"/bin/sh":       {},
	"/bin/dash":     {},
	"/usr/bin/bash": {},
	"/usr/bin/sh":   {},
	"/usr/bin/dash": {},
}

// resourceCoveredByPolicy returns true when the event's resource is mentioned
// (as an exact path, a dir, or a dir-prefix) by any rule the policy defines —
// regardless of action. This is how we tell user-targeted accesses apart from
// shell scaffolding: a shell opening a path the policy never talks about is
// ambient noise, not a policy violation.
func resourceCoveredByPolicy(fileRules tp.FileRules, resourcePath, resourceDir string) bool {
	for _, srcMap := range fileRules.OuterRules {
		for rulePath, rule := range srcMap.InnerRules {
			switch {
			case rule.IsPath && rulePath == resourcePath:
				return true
			case rule.IsDir:
				dir := strings.TrimSuffix(rulePath, "/")
				if resourceDir == dir || strings.HasPrefix(resourceDir, dir+"/") {
					return true
				}
			}
		}
	}
	return false
}

// sortedJoinedNames returns the set's keys as a comma-joined string in sorted
// order. Used by Allow-posture attribution to build a stable composite policy
// name from the contributing allow policies.
func sortedJoinedNames(m map[string]struct{}) string {
	if len(m) == 0 {
		return ""
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// findAllowRule finds the originating allow policies for a blocked operation.
// A denied open/exec under an allow-listed source means the violation is
// attributable to the allow policies themselves — report them as a Block alert
// carrying the comma-joined names of every contributing allow policy.
//
// Shell-emitted *open* denials on paths the policy never names (e.g., bash
// probing /etc/nsswitch.conf at startup) are suppressed: those aren't user
// actions. Shell-emitted *execute* denials are never ambient — a shell only
// execve()s what the user told it to — so they must always be attributed.
func (m *SystemMonitor) findAllowRule(fileRules tp.FileRules, evData *tp.EventData) *tp.FileRule {
	sourcePath := evData.Source

	if evData.Operation != "execute" {
		if _, isShell := shellSources[sourcePath]; isShell {
			if !resourceCoveredByPolicy(fileRules, evData.Resource, path.Dir(evData.Resource)) {
				return nil
			}
		}
	}

	// For executes under an Allow (whitelist) posture, widen the search to
	// every source that contributes allow rules: a whitelist that lists
	// /bin/ls only under fromSource=/bin/dash still blocks `ls` invoked
	// directly from bash, and the resulting EACCES must be attributed to
	// that whitelist policy rather than dropped.
	sources := []string{sourcePath, "default"}
	if evData.Operation == "execute" && fileRules.GlobalAction == "Allow" {
		seen := map[string]bool{sourcePath: true, "default": true}
		for s := range fileRules.OuterRules {
			if !seen[s] {
				sources = append(sources, s)
				seen[s] = true
			}
		}
	}

	for _, source := range sources {
		srcMap, ok := fileRules.OuterRules[source]
		if !ok || len(srcMap.AllowRules) == 0 {
			continue
		}

		names := make(map[string]struct{}, len(srcMap.AllowRules))
		for _, rule := range srcMap.AllowRules {
			if rule.Policy.PolicyName != "" {
				names[rule.Policy.PolicyName] = struct{}{}
			}
		}
		joined := sortedJoinedNames(names)
		if joined == "" {
			continue
		}
		return &tp.FileRule{
			Action: "Block",
			Policy: tp.KloudKnoxPolicy{PolicyName: joined},
		}
	}
	return nil
}

// findMatchedCapRules finds all capability rules matching a cap_capable event.
// Mirrors findMatchedRules for file rules: source-specific first, default
// second. Allow rules are skipped (they attribute via findCapAllowRule).
func (m *SystemMonitor) findMatchedCapRules(capRules tp.CapabilityRules, evData *tp.EventData) []tp.CapabilityRule {
	matched := []tp.CapabilityRule{}

	sources := []string{evData.Source, "default"}
	for _, source := range sources {
		srcMap, ok := capRules.OuterRules[source]
		if !ok {
			continue
		}
		for _, rule := range srcMap.InnerRules {
			if rule.Action == "Allow" {
				continue
			}
			if matchCapability(rule, evData) {
				matched = append(matched, rule)
			}
		}
	}
	return matched
}

// findCapAllowRule attributes a non-whitelisted cap_capable event to the
// originating allow policies: any use from a source outside the Allow
// list is a violation, reported under the joined policy names.
func (m *SystemMonitor) findCapAllowRule(capRules tp.CapabilityRules, evData *tp.EventData) *tp.CapabilityRule {
	if inner, ok := capRules.OuterRules[evData.Source]; ok {
		for _, rule := range inner.AllowRules {
			if rule.Name == evData.Resource {
				return nil
			}
		}
	}

	names := make(map[string]struct{})
	for _, inner := range capRules.OuterRules {
		for _, rule := range inner.AllowRules {
			if rule.Name != evData.Resource {
				continue
			}
			if rule.Policy.PolicyName != "" {
				names[rule.Policy.PolicyName] = struct{}{}
			}
		}
	}
	joined := sortedJoinedNames(names)
	if joined == "" {
		return nil
	}
	return &tp.CapabilityRule{
		Action: "Block",
		Policy: tp.KloudKnoxPolicy{PolicyName: joined},
	}
}

// CapabilityPolicyMatch annotates a cap_capable event with matching
// capability-rule policy names and action, using the same Block > Audit > Allow
// priority as the file-rule PolicyMatch.
func (m *SystemMonitor) CapabilityPolicyMatch(capRules tp.CapabilityRules, evData *tp.EventData) {
	// BPF-LSM handles enforcement and alert attribution directly; skip here.
	if m.globalData != nil && m.globalData.EnforcerType == "bpf" {
		return
	}

	if evData.Operation != "capable" {
		return
	}

	matched := m.findMatchedCapRules(capRules, evData)

	if len(matched) == 0 {
		if allowRule := m.findCapAllowRule(capRules, evData); allowRule != nil {
			matched = append(matched, *allowRule)
		}
	}

	if len(matched) == 0 {
		return
	}

	policyNames := make([]string, 0, len(matched))
	policyAction := ""
	actionPriority := map[string]int{"Block": 2, "Audit": 1, "Allow": 0}
	currentPriority := -1
	for _, rule := range matched {
		if rule.Policy.PolicyName == "" {
			continue
		}
		policyNames = append(policyNames, rule.Policy.PolicyName)
		if p := actionPriority[rule.Action]; p > currentPriority {
			currentPriority = p
			policyAction = rule.Action
		}
	}
	evData.PolicyName = strings.Join(policyNames, ",")
	evData.PolicyAction = policyAction
}

// IPC policy matching

// matchUnixShape is the structure-only predicate used by both Block/Audit
// attribution and the Allow-posture scan in IPCPolicyMatch. Abstract-socket
// paths arrive as "@name" on both sides because lib.FNV1a64UnixPath preserves
// the user-space form, so a direct string compare is correct.
func matchUnixShape(rule tp.UnixRule, evData *tp.EventData) bool {
	switch rule.Permission {
	case "connect", "listen", "bind":
		if evData.Operation != "unix_connect" {
			return false
		}
	case "send", "receive":
		if evData.Operation != "unix_send" {
			return false
		}
	default:
		return false
	}
	if rule.Type != "" {
		// Only stream events flow through unix_connect; dgram through unix_send.
		if evData.Operation == "unix_connect" && rule.Type != "stream" {
			return false
		}
		if evData.Operation == "unix_send" && rule.Type != "dgram" {
			return false
		}
	}
	if rule.Path != "" && rule.Path != evData.Resource {
		return false
	}
	return true
}

// extractSignalNumber pulls the signal number out of the evData.Data string
// produced by the security_task_kill parser — "pid: %d, sig: SIGTERM" for
// kill(2) or "pid: %d, tid: %d, sig: SIGTERM" for tgkill(2).
// Returns 0 when the signal cannot be parsed; rule.Signals==nil still matches
// that (empty signal list means "any").
func extractSignalNumber(data string) int {
	idx := strings.Index(data, "sig:")
	if idx < 0 {
		return 0
	}
	tok := strings.TrimSpace(data[idx+len("sig:"):])
	tok = strings.TrimRight(tok, ",")
	tok = strings.TrimSpace(tok)
	if n, ok := lib.SignalNumber(tok); ok {
		return n
	}
	return 0
}

// matchSignalShape is the structure-only predicate used by both Block/Audit
// attribution and the Allow-posture scan in IPCPolicyMatch.
func matchSignalShape(rule tp.SignalRule, evData *tp.EventData) bool {
	if evData.Operation != "kill" {
		return false
	}
	if rule.Target != "" && rule.Target != evData.Resource {
		return false
	}
	if len(rule.Signals) > 0 {
		sig := extractSignalNumber(evData.Data)
		hit := false
		for _, s := range rule.Signals {
			if s == sig {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// matchPtraceShape is the structure-only predicate used by both Block/Audit
// attribution and the Allow-posture scan in IPCPolicyMatch.
func matchPtraceShape(rule tp.PtraceRule, evData *tp.EventData) bool {
	if evData.Operation != "ptrace" {
		return false
	}
	if rule.Target != "" && rule.Target != evData.Resource {
		return false
	}
	return true
}

// ipcDomainTag mirrors the enforcer-side ipcDomain but lives in the monitor
// package so we don't cross an import boundary for a one-line enum.
type ipcDomainTag int

const (
	ipcDomainUnixTag ipcDomainTag = iota
	ipcDomainSignalTag
	ipcDomainPtraceTag
)

// ipcSourceWhitelistsEvent reports whether an Allow rule matches this
// event's shape under either the caller's own source bucket or the
// "default" bucket (fromSource-less Allows live there). Matching under
// "default" means the policy permits every caller to perform the
// action, so the Allow-posture attribution must not fire.
func ipcSourceWhitelistsEvent(ipcRules tp.IPCRules, domain ipcDomainTag, evData *tp.EventData) bool {
	if ipcBucketWhitelistsEvent(ipcRules.OuterRules[evData.Source], domain, evData) {
		return true
	}
	if evData.Source == "default" {
		return false
	}
	return ipcBucketWhitelistsEvent(ipcRules.OuterRules["default"], domain, evData)
}

func ipcBucketWhitelistsEvent(inner tp.InnerIPCRules, domain ipcDomainTag, evData *tp.EventData) bool {
	switch domain {
	case ipcDomainUnixTag:
		for _, r := range inner.UnixAllow {
			if matchUnixShape(r, evData) {
				return true
			}
		}
	case ipcDomainSignalTag:
		for _, r := range inner.SignalAllow {
			if matchSignalShape(r, evData) {
				return true
			}
		}
	case ipcDomainPtraceTag:
		for _, r := range inner.PtraceAllow {
			if matchPtraceShape(r, evData) {
				return true
			}
		}
	}
	return false
}

// collectIPCAllowNames gathers the policy names of every Allow rule that
// would match this event, across all sources. Used only in the attribution
// path when the caller is not on the whitelist.
func collectIPCAllowNames(ipcRules tp.IPCRules, domain ipcDomainTag, evData *tp.EventData) map[string]struct{} {
	names := make(map[string]struct{})
	for _, inner := range ipcRules.OuterRules {
		switch domain {
		case ipcDomainUnixTag:
			for _, r := range inner.UnixAllow {
				if matchUnixShape(r, evData) && r.Policy.PolicyName != "" {
					names[r.Policy.PolicyName] = struct{}{}
				}
			}
		case ipcDomainSignalTag:
			for _, r := range inner.SignalAllow {
				if matchSignalShape(r, evData) && r.Policy.PolicyName != "" {
					names[r.Policy.PolicyName] = struct{}{}
				}
			}
		case ipcDomainPtraceTag:
			for _, r := range inner.PtraceAllow {
				if matchPtraceShape(r, evData) && r.Policy.PolicyName != "" {
					names[r.Policy.PolicyName] = struct{}{}
				}
			}
		}
	}
	return names
}

// IPCPolicyMatch annotates an IPC event with matching policy names and
// action using the same Block > Audit > Allow priority as the other matchers.
// Signal events arrive with Operation="kill" (via security_task_kill) while
// unix/ptrace events arrive with Category="ipc".
func (m *SystemMonitor) IPCPolicyMatch(ipcRules tp.IPCRules, evData *tp.EventData) {
	// BPF-LSM handles enforcement and alert attribution directly; skip here.
	if m.globalData != nil && m.globalData.EnforcerType == "bpf" {
		return
	}

	var domain ipcDomainTag
	switch evData.Operation {
	case "unix_connect", "unix_send":
		domain = ipcDomainUnixTag
	case "kill":
		domain = ipcDomainSignalTag
	case "ptrace":
		domain = ipcDomainPtraceTag
	default:
		return
	}

	type matchRes struct {
		action     string
		policyName string
	}
	var matched []matchRes

	sources := []string{evData.Source, "default"}
	for _, source := range sources {
		inner, ok := ipcRules.OuterRules[source]
		if !ok {
			continue
		}
		switch domain {
		case ipcDomainUnixTag:
			for _, r := range inner.Unix {
				if r.Action == "Allow" {
					continue
				}
				if matchUnixShape(r, evData) {
					matched = append(matched, matchRes{r.Action, r.Policy.PolicyName})
				}
			}
		case ipcDomainSignalTag:
			for _, r := range inner.Signal {
				if r.Action == "Allow" {
					continue
				}
				if matchSignalShape(r, evData) {
					matched = append(matched, matchRes{r.Action, r.Policy.PolicyName})
				}
			}
		case ipcDomainPtraceTag:
			for _, r := range inner.Ptrace {
				if r.Action == "Allow" {
					continue
				}
				if matchPtraceShape(r, evData) {
					matched = append(matched, matchRes{r.Action, r.Policy.PolicyName})
				}
			}
		}
	}

	// Allow-posture attribution: retVal==0 means the kernel allowed the
	// event, so there is no Block to attribute.
	if len(matched) == 0 && evData.RetVal != 0 {
		if ipcSourceWhitelistsEvent(ipcRules, domain, evData) {
			return
		}
		names := collectIPCAllowNames(ipcRules, domain, evData)
		if joined := sortedJoinedNames(names); joined != "" {
			matched = append(matched, matchRes{action: "Block", policyName: joined})
		}
	}

	if len(matched) == 0 {
		return
	}

	policyNames := make([]string, 0, len(matched))
	policyAction := ""
	priority := map[string]int{"Block": 2, "Audit": 1, "Allow": 0}
	current := -1
	for _, r := range matched {
		if r.policyName == "" {
			continue
		}
		policyNames = append(policyNames, r.policyName)
		if p := priority[r.action]; p > current {
			current = p
			policyAction = r.action
		}
	}
	evData.PolicyName = strings.Join(policyNames, ",")
	evData.PolicyAction = policyAction
}

// PolicyMatch checks if the pod matches the policy
func (m *SystemMonitor) PolicyMatch(fileRules tp.FileRules, evData *tp.EventData) {
	// BPF-LSM handles enforcement and alert attribution directly; skip here.
	if m.globalData != nil && m.globalData.EnforcerType == "bpf" {
		return
	}

	if evData.Operation != "execute" && evData.Operation != "open" {
		return
	}

	matched := m.findMatchedRules(fileRules, evData)

	// Check for allow rules if no matches found and operation was blocked
	if len(matched) == 0 && evData.RetVal == -13 {
		if allowRule := m.findAllowRule(fileRules, evData); allowRule != nil {
			matched = append(matched, *allowRule)
		}
	}

	if len(matched) > 0 {
		policyNames := make([]string, 0, len(matched))
		policyAction := ""

		// Block > Audit > Allow — highest-priority action wins.
		// currentPriority starts at -1 so that even "Allow" (priority 0) is accepted
		// on the first matched rule.
		actionPriority := map[string]int{"Block": 2, "Audit": 1, "Allow": 0}
		currentPriority := -1

		for _, rule := range matched {
			if rule.Policy.PolicyName == "" {
				continue
			}
			policyNames = append(policyNames, rule.Policy.PolicyName)
			if p := actionPriority[rule.Action]; p > currentPriority {
				currentPriority = p
				policyAction = rule.Action
			}
		}

		evData.PolicyName = strings.Join(policyNames, ",")
		evData.PolicyAction = policyAction
	}
}
