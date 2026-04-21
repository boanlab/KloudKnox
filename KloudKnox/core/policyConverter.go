// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"math"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// buildFileRules aggregates all process and file rules from a pod's runtime
// policies into a FileRules lookup structure keyed by source path.
// GlobalAction is set to "Allow" if any policy uses Allow semantics, otherwise
// it defaults to "Block".
func buildFileRules(pod tp.Pod) tp.FileRules {
	fileRules := tp.FileRules{
		OuterRules:   make(map[string]tp.InnerFileRules),
		GlobalAction: "Block",
	}

	for _, policy := range pod.RuntimePolicies {
		if len(policy.Process) == 0 && len(policy.File) == 0 {
			continue
		}

		if policy.Action == "Allow" {
			fileRules.GlobalAction = "Allow"
		}

		// Process execution rules
		processProcessRules(&fileRules, policy)

		// Process file access rules
		processFileRules(&fileRules, policy)
	}

	extractAllowRules(&fileRules)

	return fileRules
}

// processProcessRules processes process rules for a policy
func processProcessRules(fileRules *tp.FileRules, policy tp.KloudKnoxPolicy) {
	for _, procRule := range policy.Process {
		path, ruleType := determinePathAndType(procRule.Path, procRule.Dir)
		if path == "" {
			log.Warnf("Invalid process rule: %+v", procRule)
			continue
		}

		rule := tp.FileRule{
			Policy: policy,
		}

		switch ruleType {
		case "path":
			rule.IsPath = true
		case "dir":
			rule.IsDir = true
			rule.Recursive = procRule.Recursive
		}

		if procRule.Action != "" {
			rule.Action = procRule.Action
		} else if policy.Action != "" {
			rule.Action = policy.Action
		} else {
			log.Warnf("Invalid process rule: %+v", procRule)
			continue
		}

		rule.Permission = getProcessPermission(rule.Action)

		addRuleToFileRules(fileRules, rule, path, procRule.FromSource)
	}
}

// processFileRules processes file rules for a policy
func processFileRules(fileRules *tp.FileRules, policy tp.KloudKnoxPolicy) {
	for _, fileRule := range policy.File {
		path, ruleType := determinePathAndType(fileRule.Path, fileRule.Dir)
		if path == "" {
			log.Warnf("Invalid file rule: %+v", fileRule)
			continue
		}

		rule := tp.FileRule{
			Policy: policy,
		}

		switch ruleType {
		case "path":
			rule.IsPath = true
		case "dir":
			rule.IsDir = true
			rule.Recursive = fileRule.Recursive
		}

		if fileRule.Action != "" {
			rule.Action = fileRule.Action
		} else if policy.Action != "" {
			rule.Action = policy.Action
		} else {
			log.Warnf("Invalid file rule: %+v", fileRule)
			continue
		}

		rule.Permission = getFilePermission(rule.Action, fileRule.ReadOnly)

		addRuleToFileRules(fileRules, rule, path, fileRule.FromSource)
	}
}

// determinePathAndType determines the path and type from rule attributes
func determinePathAndType(path, dir string) (string, string) {
	if path != "" && dir == "" {
		return path, "path"
	} else if path == "" && dir != "" {
		return dir, "dir"
	}
	return "", ""
}

// getProcessPermission returns the permission string for process rules
func getProcessPermission(action string) string {
	switch action {
	case "Allow":
		return "X" // allow execution
	case "Audit":
		return "X" // audit execution
	case "Block":
		return "x" // block execution
	default:
		return "x"
	}
}

// getFilePermission returns the permission string for file rules
func getFilePermission(action string, readOnly bool) string {
	if readOnly {
		switch action {
		case "Allow":
			return "R" // allow read
		case "Audit":
			return "W" // ReadOnly + Audit: silently allow read, audit write attempts only
		case "Block":
			return "w" // block write
		default:
			return "w"
		}
	} else {
		switch action {
		case "Allow":
			return "RW" // allow read + write
		case "Audit":
			return "RW" // audit read + write
		case "Block":
			return "rw" // block read + write
		default:
			return "rw"
		}
	}
}

// addRuleToFileRules adds a rule to file rules with source handling
func addRuleToFileRules(fileRules *tp.FileRules, rule tp.FileRule, path string, fromSource []tp.SourceMatch) {
	if len(fromSource) > 0 {
		for _, sourcePath := range fromSource {
			addRuleToSource(fileRules, rule, path, sourcePath.Path)
		}
	} else {
		addRuleToSource(fileRules, rule, path, "default")
	}
}

// addRuleToSource adds a rule to a specific source in file rules
func addRuleToSource(fileRules *tp.FileRules, rule tp.FileRule, path, source string) {
	// Ensure OuterRules[source] is initialized
	if _, ok := fileRules.OuterRules[source]; !ok {
		innerRules := tp.InnerFileRules{
			InnerRules:  make(map[string]tp.FileRule),
			AllowRules:  make(map[string]tp.FileRule),
			InnerAction: "Block",
		}
		fileRules.OuterRules[source] = innerRules
	}

	// Set inner action based on rule action
	if rule.Action == "Allow" && fileRules.OuterRules[source].InnerAction == "Block" {
		tmpRules := fileRules.OuterRules[source]
		tmpRules.InnerAction = "Allow"
		fileRules.OuterRules[source] = tmpRules
	}

	if existingRule, ok := fileRules.OuterRules[source].InnerRules[path]; !ok {
		fileRules.OuterRules[source].InnerRules[path] = rule
	} else {
		// Check for rule conflicts (simple comparison instead of reflect.DeepEqual)
		if existingRule.Policy.PolicyName != rule.Policy.PolicyName ||
			existingRule.Permission != rule.Permission ||
			existingRule.Action != rule.Action {
			log.Debugf("Conflict in rules: %s(%s, %s) and %s(%s, %s)",
				existingRule.Policy.PolicyName, existingRule.Permission, existingRule.Action,
				rule.Policy.PolicyName, rule.Permission, rule.Action)
		}
	}
}

// extractAllowRules extracts allow rules from the main rules
func extractAllowRules(fileRules *tp.FileRules) {
	for source, srcRules := range fileRules.OuterRules {
		for path, rule := range srcRules.InnerRules {
			if rule.Action == "Allow" {
				// Add allow rule to allow rules
				fileRules.OuterRules[source].AllowRules[path] = rule
			}
			log.Debugf("[%s] %s: %s %s [%s, %s]", source, path, rule.Permission, rule.Action, srcRules.InnerAction, fileRules.GlobalAction)
		}
	}
}

// buildCapabilityRules builds capability rules for a pod, mirroring the
// OuterRules/InnerRules structure used by file rules.
func buildCapabilityRules(pod tp.Pod) tp.CapabilityRules {
	rules := tp.CapabilityRules{
		OuterRules:   make(map[string]tp.InnerCapabilityRules),
		GlobalAction: "Block",
	}

	for _, policy := range pod.RuntimePolicies {
		if len(policy.Capability) == 0 {
			continue
		}

		if policy.Action == "Allow" {
			rules.GlobalAction = "Allow"
		}

		for _, capRule := range policy.Capability {
			rule := tp.CapabilityRule{
				Policy: policy,
				CapID:  capRule.CapID,
				Name:   capRule.Name,
			}

			if capRule.Action != "" {
				rule.Action = capRule.Action
			} else if policy.Action != "" {
				rule.Action = policy.Action
			} else {
				log.Warnf("Invalid capability rule: %+v", capRule)
				continue
			}

			addCapabilityRule(&rules, rule, capRule.FromSource)
		}
	}

	extractAllowCapabilityRules(&rules)
	return rules
}

func addCapabilityRule(rules *tp.CapabilityRules, rule tp.CapabilityRule, fromSource []tp.SourceMatch) {
	if len(fromSource) > 0 {
		for _, src := range fromSource {
			addCapabilityRuleToSource(rules, rule, src.Path)
		}
	} else {
		addCapabilityRuleToSource(rules, rule, "default")
	}
}

func addCapabilityRuleToSource(rules *tp.CapabilityRules, rule tp.CapabilityRule, source string) {
	if _, ok := rules.OuterRules[source]; !ok {
		rules.OuterRules[source] = tp.InnerCapabilityRules{
			InnerRules:  make(map[uint32]tp.CapabilityRule),
			AllowRules:  make(map[uint32]tp.CapabilityRule),
			InnerAction: "Block",
		}
	}

	if rule.Action == "Allow" && rules.OuterRules[source].InnerAction == "Block" {
		tmp := rules.OuterRules[source]
		tmp.InnerAction = "Allow"
		rules.OuterRules[source] = tmp
	}

	if existing, ok := rules.OuterRules[source].InnerRules[rule.CapID]; !ok {
		rules.OuterRules[source].InnerRules[rule.CapID] = rule
	} else if existing.Policy.PolicyName != rule.Policy.PolicyName || existing.Action != rule.Action {
		log.Debugf("Conflict in capability rules: %s(%s) and %s(%s)",
			existing.Policy.PolicyName, existing.Action,
			rule.Policy.PolicyName, rule.Action)
	}
}

func extractAllowCapabilityRules(rules *tp.CapabilityRules) {
	for source, inner := range rules.OuterRules {
		for capID, rule := range inner.InnerRules {
			if rule.Action == "Allow" {
				rules.OuterRules[source].AllowRules[capID] = rule
			}
			log.Debugf("[%s] %s: %s [%s, %s]", source, rule.Name, rule.Action, inner.InnerAction, rules.GlobalAction)
		}
	}
}

// buildIPCRules builds IPC (unix/signal/ptrace) rules for a pod, mirroring
// the OuterRules/InnerRules structure used by file and capability rules.
// Multi-permission UnixRules are fanned out into one internal rule per
// permission so downstream lookups can key on a single token.
func buildIPCRules(pod tp.Pod) tp.IPCRules {
	rules := tp.IPCRules{
		OuterRules:   make(map[string]tp.InnerIPCRules),
		GlobalAction: "Block",
	}

	for _, policy := range pod.RuntimePolicies {
		ipc := policy.IPC
		if len(ipc.Unix) == 0 && len(ipc.Signal) == 0 && len(ipc.Ptrace) == 0 {
			continue
		}

		if policy.Action == "Allow" {
			rules.GlobalAction = "Allow"
		}

		for _, u := range ipc.Unix {
			addUnixRule(&rules, u, policy)
		}
		for _, s := range ipc.Signal {
			addSignalRule(&rules, s, policy)
		}
		for _, p := range ipc.Ptrace {
			addPtraceRule(&rules, p, policy)
		}
	}

	extractAllowIPCRules(&rules)
	return rules
}

// ensureIPCSource allocates the per-source container when the key appears for
// the first time and flips InnerAction to "Allow" as soon as any Allow rule
// lands — identical behavior to the capability converter.
func ensureIPCSource(rules *tp.IPCRules, source, ruleAction string) {
	if _, ok := rules.OuterRules[source]; !ok {
		rules.OuterRules[source] = tp.InnerIPCRules{
			Unix:        make(map[string]tp.UnixRule),
			Signal:      make(map[string]tp.SignalRule),
			Ptrace:      make(map[string]tp.PtraceRule),
			UnixAllow:   make(map[string]tp.UnixRule),
			SignalAllow: make(map[string]tp.SignalRule),
			PtraceAllow: make(map[string]tp.PtraceRule),
			InnerAction: "Block",
		}
	}
	if ruleAction == "Allow" && rules.OuterRules[source].InnerAction == "Block" {
		tmp := rules.OuterRules[source]
		tmp.InnerAction = "Allow"
		rules.OuterRules[source] = tmp
	}
}

// resolveAction picks per-rule action, falling back to policy-level action.
// Returns "" when neither is set, in which case the caller should skip the
// rule (a warn log is already emitted by ValidateSpec upstream).
func resolveAction(ruleAction, policyAction string) string {
	if ruleAction != "" {
		return ruleAction
	}
	return policyAction
}

func addUnixRule(rules *tp.IPCRules, u tp.KloudKnoxUnixRule, policy tp.KloudKnoxPolicy) {
	action := resolveAction(u.Action, policy.Action)
	if action == "" {
		log.Warnf("Invalid unix rule: %+v", u)
		return
	}

	sources := []string{"default"}
	if len(u.FromSource) > 0 {
		sources = sources[:0]
		for _, s := range u.FromSource {
			sources = append(sources, s.Path)
		}
	}

	for _, source := range sources {
		ensureIPCSource(rules, source, action)
		for _, perm := range u.Permissions {
			key := u.Type + "|" + u.Path + "|" + perm
			inner := rules.OuterRules[source]
			if _, exists := inner.Unix[key]; !exists {
				inner.Unix[key] = tp.UnixRule{
					Policy:     policy,
					Type:       u.Type,
					Path:       u.Path,
					Permission: perm,
					Action:     action,
				}
				rules.OuterRules[source] = inner
			}
		}
	}
}

// signalsCanonicalKey returns the bitmask-encoded key fragment so duplicate
// signal lists (order-independent) dedup correctly.
func signalsCanonicalKey(sigs []int) string {
	var mask uint64
	for _, s := range sigs {
		if s >= 1 && s <= 64 {
			mask |= 1 << (s - 1)
		}
	}
	if mask == 0 && len(sigs) == 0 {
		return "*"
	}
	return maskHex(mask)
}

func maskHex(mask uint64) string {
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 0, 16)
	for mask != 0 {
		buf = append(buf, hexdigits[mask&0xf])
		mask >>= 4
	}
	if len(buf) == 0 {
		return "0"
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func addSignalRule(rules *tp.IPCRules, s tp.KloudKnoxSignalRule, policy tp.KloudKnoxPolicy) {
	action := resolveAction(s.Action, policy.Action)
	if action == "" {
		log.Warnf("Invalid signal rule: %+v", s)
		return
	}

	sigs := make([]int, 0, len(s.Signals))
	for _, name := range s.Signals {
		if num, ok := lib.SignalNumber(name); ok {
			sigs = append(sigs, num)
		} else {
			log.Warnf("Dropping unknown signal: %s", name)
		}
	}

	sources := []string{"default"}
	if len(s.FromSource) > 0 {
		sources = sources[:0]
		for _, src := range s.FromSource {
			sources = append(sources, src.Path)
		}
	}

	for _, source := range sources {
		ensureIPCSource(rules, source, action)
		key := s.Target + "|" + signalsCanonicalKey(sigs)
		inner := rules.OuterRules[source]
		if _, exists := inner.Signal[key]; !exists {
			inner.Signal[key] = tp.SignalRule{
				Policy:  policy,
				Target:  s.Target,
				Signals: sigs,
				Action:  action,
			}
			rules.OuterRules[source] = inner
		}
	}
}

func addPtraceRule(rules *tp.IPCRules, p tp.KloudKnoxPtraceRule, policy tp.KloudKnoxPolicy) {
	action := resolveAction(p.Action, policy.Action)
	if action == "" {
		log.Warnf("Invalid ptrace rule: %+v", p)
		return
	}

	sources := []string{"default"}
	if len(p.FromSource) > 0 {
		sources = sources[:0]
		for _, src := range p.FromSource {
			sources = append(sources, src.Path)
		}
	}

	for _, source := range sources {
		ensureIPCSource(rules, source, action)
		key := p.Permission + "|" + p.Target
		inner := rules.OuterRules[source]
		if _, exists := inner.Ptrace[key]; !exists {
			inner.Ptrace[key] = tp.PtraceRule{
				Policy:     policy,
				Permission: p.Permission,
				Target:     p.Target,
				Action:     action,
			}
			rules.OuterRules[source] = inner
		}
	}
}

func extractAllowIPCRules(rules *tp.IPCRules) {
	for source, inner := range rules.OuterRules {
		for key, rule := range inner.Unix {
			if rule.Action == "Allow" {
				inner.UnixAllow[key] = rule
			}
		}
		for key, rule := range inner.Signal {
			if rule.Action == "Allow" {
				inner.SignalAllow[key] = rule
			}
		}
		for key, rule := range inner.Ptrace {
			if rule.Action == "Allow" {
				inner.PtraceAllow[key] = rule
			}
		}
		rules.OuterRules[source] = inner
	}
}

// SafeInt32ToUint16 converts n to uint16, returning 0 for out-of-range values.
// Port numbers in the policy spec are int32 (from proto) but the BPF map
// uses uint16; this converter makes the narrowing explicit and safe.
func SafeInt32ToUint16(n int32) uint16 {
	if n < 0 || n > math.MaxUint16 {
		return 0
	}
	return uint16(n)
}

// BuildNetworkRules builds network rules for a pod
func buildNetworkRules(pod tp.Pod) tp.NetworkRules {
	networkRules := tp.NetworkRules{
		IngressRules: make(map[string]tp.InnerNetworkRules),
		EgressRules:  make(map[string]tp.InnerNetworkRules),
	}

	for _, policy := range pod.RuntimePolicies {
		if len(policy.Network) == 0 {
			continue
		}

		for _, networkRule := range policy.Network {
			target := getNetworkTarget(networkRule)
			if target == "" {
				continue
			}

			rule := tp.NetworkRule{
				Policy:     policy,
				Ports:      make(map[string][]uint16),
				CIDRExcept: networkRule.IPBlock.Except,
			}

			if len(networkRule.Ports) > 0 {
				for _, port := range networkRule.Ports {
					if port.Port < 0 || port.Port > 65535 {
						log.Warnf("Invalid port number: %d", port.Port)
						continue
					}
					rule.Ports[port.Protocol] = append(rule.Ports[port.Protocol], SafeInt32ToUint16(port.Port))
				}
			}

			if networkRule.Action != "" {
				rule.Action = networkRule.Action
			} else if policy.Action != "" {
				rule.Action = policy.Action
			} else {
				log.Warnf("Invalid network rule: %+v", networkRule)
				continue
			}

			addNetworkRule(&networkRules, rule, networkRule.FromSource, target, networkRule.Direction)
		}
	}

	setDefaultPosture(&networkRules)

	return networkRules
}

// getNetworkTarget determines the target for a network rule
func getNetworkTarget(networkRule tp.KloudKnoxNetworkRule) string {
	if len(networkRule.Selector) > 0 {
		return "selector:" + lib.ConvertKVsToString(networkRule.Selector)
	}

	if networkRule.IPBlock.CIDR != "" {
		return "cidr:" + networkRule.IPBlock.CIDR
	}

	if networkRule.FQDN != "" {
		return "fqdn:" + networkRule.FQDN
	}

	return ""
}

// addNetworkRule adds a network rule to the appropriate direction
func addNetworkRule(networkRules *tp.NetworkRules, rule tp.NetworkRule, fromSource []tp.SourceMatch, target string, direction string) {
	if len(fromSource) > 0 {
		for _, sourcePath := range fromSource {
			addNetworkRuleToDirection(networkRules, rule, sourcePath.Path, target, direction)
		}
	} else {
		addNetworkRuleToDirection(networkRules, rule, "default", target, direction)
	}
}

// addNetworkRuleToDirection adds a network rule to the specified direction
func addNetworkRuleToDirection(networkRules *tp.NetworkRules, rule tp.NetworkRule, source, target, direction string) {
	var rulesMap map[string]tp.InnerNetworkRules

	switch direction {
	case "ingress":
		rulesMap = networkRules.IngressRules
	case "egress":
		rulesMap = networkRules.EgressRules
	default:
		return
	}

	// Ensure InnerRules is initialized
	if _, ok := rulesMap[source]; !ok {
		innerRules := tp.InnerNetworkRules{
			InnerRules:     make(map[string]tp.NetworkRule),
			DefaultPosture: "Allow",
		}
		rulesMap[source] = innerRules
	}

	if existingRule, ok := rulesMap[source].InnerRules[target]; !ok {
		rulesMap[source].InnerRules[target] = rule
	} else {
		log.Warnf("Conflict in network rules: %+v and %+v", existingRule, rule)
	}
}

// setDefaultPosture sets the default posture for network rules
// If there are Allow rules for a source, set "Block by default" for that source
// If there are no Allow rules at all, keep "Allow by default"
func setDefaultPosture(networkRules *tp.NetworkRules) {
	// Process Ingress rules
	for source, innerRules := range networkRules.IngressRules {
		hasAllowRule := false
		for _, rule := range innerRules.InnerRules {
			if rule.Action == "Allow" {
				hasAllowRule = true
				break
			}
		}

		if hasAllowRule {
			tmpRules := innerRules
			tmpRules.DefaultPosture = "Block"
			networkRules.IngressRules[source] = tmpRules
		}
	}

	// Process Egress rules
	for source, innerRules := range networkRules.EgressRules {
		hasAllowRule := false
		for _, rule := range innerRules.InnerRules {
			if rule.Action == "Allow" {
				hasAllowRule = true
				break
			}
		}

		if hasAllowRule {
			tmpRules := innerRules
			tmpRules.DefaultPosture = "Block"
			networkRules.EgressRules[source] = tmpRules
		}
	}
}
