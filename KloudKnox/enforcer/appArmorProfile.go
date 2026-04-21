// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"fmt"
	"sort"
	"strings"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

const autoInjectedEntrypointHeader = "  ## == AUTO-INJECTED ENTRYPOINT == ##\n"

// permissionMap maps KloudKnox permissions to AppArmor permissions
var permissionMap = map[string]string{
	"X":  "ix",   // Allow execution
	"x":  "x",    // Block execution
	"R":  "rml",  // Allow read (Allow with ReadOnly)
	"W":  "rwml", // Audit write (Audit with ReadOnly)
	"w":  "w",    // Block write (Block with ReadOnly)
	"RW": "rwml", // Allow read + write (Allow or Audit without ReadOnly)
	"rw": "rw",   // Block read + write (Block without ReadOnly)
}

// GenerateProfileBody generates the policy body section of an AppArmor profile.
// fileRules, capRules, and ipcRules share source-path buckets so the per-
// source sub-profile emits file/cap/ipc lines together; sources that appear
// only in one rule-kind still get a sub-profile.
func (ae *AppArmorEnforcer) GenerateProfileBody(fileRules tp.FileRules, capRules tp.CapabilityRules, ipcRules tp.IPCRules) (string, string) {
	var body strings.Builder
	body.Grow(1024)

	// Iterate over the union of source keys so rule-kind-only sources still
	// get a sub-profile. Sorted for deterministic output (matching on profile
	// change detection).
	for _, src := range collectAppArmorSources(fileRules, capRules, ipcRules) {
		srcFile := fileRules.OuterRules[src]
		srcCap := capRules.OuterRules[src]
		srcIPC := ipcRules.OuterRules[src]

		if src != "default" {
			fmt.Fprintf(&body, "  %s cx,\n", src)
			fmt.Fprintf(&body, "  profile %s {\n", src)
			body.WriteString("    ## == PRE START == ##\n")
			body.WriteString("    #include <abstractions/base>\n")

			// Baseline file access inside the nested fromSource profile.
			//   * If the inner rules are a file whitelist (any non-process
			//     Allow rule), comment out `file,` so only the whitelisted
			//     paths are readable.
			//   * Otherwise — process-only whitelist or any Block/Audit
			//     source — keep `file,`. Restricting file reads here would
			//     break binaries that we explicitly allow from running
			//     (they still need libc, /etc/nsswitch.conf, etc.).
			if srcFile.InnerAction == "Allow" && innerHasFileAllow(srcFile) {
				body.WriteString("    # file,\n")
			} else {
				body.WriteString("    file,\n")
			}

			body.WriteString("    network,\n")

			// Baseline capability inside the nested fromSource profile. Same
			// idea as file: when the source whitelists specific capabilities,
			// comment out the blanket `capability,` so only those listed
			// survive. Otherwise keep it so unrelated capabilities used by
			// libc/ld.so still work.
			if srcCap.InnerAction == "Allow" && innerHasCapAllow(srcCap) {
				body.WriteString("    # capability,\n")
			} else {
				body.WriteString("    capability,\n")
			}

			// IPC baselines — same allow-only narrowing. Each IPC sub-domain
			// is independent: a source can whitelist unix sockets while still
			// leaving signal/ptrace wide-open at baseline.
			if innerHasIPCAllow(srcIPC, ipcDomainUnix) {
				body.WriteString("    # unix,\n")
			} else {
				body.WriteString("    unix,\n")
			}
			if innerHasIPCAllow(srcIPC, ipcDomainSignal) {
				body.WriteString("    # signal,\n")
			} else {
				body.WriteString("    signal,\n")
			}
			if innerHasIPCAllow(srcIPC, ipcDomainPtrace) {
				body.WriteString("    # ptrace,\n")
			} else {
				body.WriteString("    ptrace,\n")
			}

			body.WriteString("    ## == PRE END == ##\n")
			body.WriteString("\n")
			body.WriteString("    ## == POLICY START == ##\n")

			fmt.Fprintf(&body, "    %s rmix,\n", src)
		}

		// Generate file rules for each path
		for path, rule := range srcFile.InnerRules {
			// Handle directory rules
			processedPath := ae.processPath(path, rule)

			// Add indentation for nested profiles
			pad := ""
			if src != "default" {
				pad = "  "
			}

			// Convert permission to AppArmor format using the permission map
			permission, exists := permissionMap[rule.Permission]
			if !exists {
				// Default to read-only if permission is not recognized
				permission = "rml"
			}

			// Generate rule based on action
			switch rule.Action {
			case "Block":
				fmt.Fprintf(&body, "  %sdeny %s %s,\n", pad, processedPath, permission)
			case "Audit":
				if rule.Permission == "W" {
					// ReadOnly+Audit: silently allow reads, audit only write attempts.
					fmt.Fprintf(&body, "  %s%s rml,\n", pad, processedPath)
					fmt.Fprintf(&body, "  %saudit %s w,\n", pad, processedPath)
				} else {
					fmt.Fprintf(&body, "  %saudit %s %s,\n", pad, processedPath, permission)
				}
			default:
				fmt.Fprintf(&body, "  %s%s %s,\n", pad, processedPath, permission)
			}
		}

		// Generate capability rules for this source.
		for _, capRule := range srcCap.InnerRules {
			pad := ""
			if src != "default" {
				pad = "  "
			}
			name := capKernelName(capRule.Name)
			switch capRule.Action {
			case "Block":
				fmt.Fprintf(&body, "  %sdeny capability %s,\n", pad, name)
			case "Audit":
				fmt.Fprintf(&body, "  %saudit capability %s,\n", pad, name)
			default: // Allow
				fmt.Fprintf(&body, "  %scapability %s,\n", pad, name)
			}
		}

		pad := ""
		if src != "default" {
			pad = "  "
		}
		emitUnixRules(&body, pad, srcIPC.Unix)
		emitSignalRules(&body, pad, srcIPC.Signal)
		emitPtraceRules(&body, pad, srcIPC.Ptrace)

		if src != "default" {
			// Use the footer template from constants
			appArmorFooter := strings.ReplaceAll(footerTemplate, "  ", "    ")
			appArmorFooter = strings.Replace(appArmorFooter, "}\n", "  }\n", 1)
			body.WriteString(appArmorFooter)
		}
	}

	return body.String(), fileRules.GlobalAction
}

// collectAppArmorSources returns the sorted union of source keys across
// file, capability, and IPC rules. Sorting gives deterministic profile output
// so that GenerateAppArmorProfile's change-detection does not churn on map
// iteration order.
func collectAppArmorSources(fileRules tp.FileRules, capRules tp.CapabilityRules, ipcRules tp.IPCRules) []string {
	seen := make(map[string]struct{}, len(fileRules.OuterRules)+len(capRules.OuterRules)+len(ipcRules.OuterRules))
	for src := range fileRules.OuterRules {
		seen[src] = struct{}{}
	}
	for src := range capRules.OuterRules {
		seen[src] = struct{}{}
	}
	for src := range ipcRules.OuterRules {
		seen[src] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for src := range seen {
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

// capKernelName returns the AppArmor-wire form of a capability symbol. The
// AppArmor parser expects the lower-case name without the CAP_ prefix, e.g.
// CAP_NET_RAW → net_raw.
func capKernelName(symbol string) string {
	return strings.ToLower(strings.TrimPrefix(symbol, "CAP_"))
}

// innerHasCapAllow reports whether the inner rules of a single source
// contain any Allow capability rule (i.e. a capability whitelist).
func innerHasCapAllow(srcRules tp.InnerCapabilityRules) bool {
	for _, rule := range srcRules.InnerRules {
		if rule.Action == "Allow" {
			return true
		}
	}
	return false
}

// hasCapAllowRules reports whether capRules contains any Allow rule. The
// outer header transformer uses this to decide whether to comment out the
// blanket `capability,` baseline.
func hasCapAllowRules(capRules tp.CapabilityRules) bool {
	for _, srcRules := range capRules.OuterRules {
		if innerHasCapAllow(srcRules) {
			return true
		}
	}
	return false
}

// processPath processes a path according to the rule specifications
func (ae *AppArmorEnforcer) processPath(path string, rule tp.FileRule) string {
	// Handle directory rules
	if rule.IsDir {
		// Add trailing slash if missing
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}

		// Add recursive rule if specified
		if rule.Recursive {
			path += "{*,**}"
		} else {
			path += "*"
		}
	}

	return path
}

// hasFileRules reports whether fileRules contains any non-process rule.
// Process rules use permission "X" (allow-exec) or "x" (block-exec); any
// other permission represents a file read/write rule.
func hasFileRules(fileRules tp.FileRules) bool {
	for _, srcRules := range fileRules.OuterRules {
		for _, rule := range srcRules.InnerRules {
			if rule.Permission != "X" && rule.Permission != "x" {
				return true
			}
		}
	}
	return false
}

// hasProcRules reports whether fileRules contains any process exec rule
// (permission "X" or "x"). A file-only allow policy must not set Block
// proc posture — only policies with explicit process rules need it.
func hasProcRules(fileRules tp.FileRules) bool {
	for _, srcRules := range fileRules.OuterRules {
		for _, rule := range srcRules.InnerRules {
			if rule.Permission == "X" || rule.Permission == "x" {
				return true
			}
		}
	}
	return false
}

// hasProcessOrFileRules reports whether fileRules contains any rule at
// all (process or file). Allow policies that list only process rules
// still need the baseline file access to be narrowed so that binaries
// outside the whitelist are blocked from executing.
func hasProcessOrFileRules(fileRules tp.FileRules) bool {
	for _, srcRules := range fileRules.OuterRules {
		if len(srcRules.InnerRules) > 0 {
			return true
		}
	}
	return false
}

// innerHasFileAllow reports whether the inner rules of a single source
// contain any Allow rule over a file path (i.e. a file whitelist), as
// opposed to only process whitelist rules (permission "X"/"x").
func innerHasFileAllow(srcRules tp.InnerFileRules) bool {
	for _, rule := range srcRules.InnerRules {
		if rule.Action == "Allow" && rule.Permission != "X" && rule.Permission != "x" {
			return true
		}
	}
	return false
}

// GenerateAppArmorProfile generates an AppArmor profile for a pod.
//
// entrypoints are auto-allowed with `ix` when the baseline is narrowed by an
// Allow-whitelist, so the container's init process can still exec. An
// explicit `deny <entrypoint> x,` rule still wins (AppArmor deny is absolute).
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(profileName string, fileRules tp.FileRules, capRules tp.CapabilityRules, ipcRules tp.IPCRules, entrypoints []string) (string, error) {
	// Get the existing profile from the profiles map
	ae.ProfileLock.RLock()
	existingProfile, exists := ae.Profiles[profileName]
	ae.ProfileLock.RUnlock()

	if !exists {
		return "", fmt.Errorf("apparmor profile not found: %s", profileName)
	}

	// Generate new policy body
	newBody, globalAction := ae.GenerateProfileBody(fileRules, capRules, ipcRules)

	// Create new header with profile name using the header template
	newAppArmorHeader := fmt.Sprintf(headerTemplate, profileName)

	// For Allow policies, narrow the outer profile's baseline file access
	// so that only explicitly listed rules take effect.
	//   * Policies with any file rule: comment out `file,` entirely — file
	//     access is governed by the explicit rules only.
	//   * Process-only whitelist policies: drop the generic `x` from the
	//     baseline while keeping r/w/m (needed for dynamic linking and
	//     common runtime reads). Specific process rules (e.g. `/bin/cat
	//     ix,`) then grant exec only for whitelisted binaries.
	//     Using a deny rule here does not work because AppArmor's deny is
	//     strictly subtractive and would also strip the `x` from specific
	//     `ix`/`cx` allows.
	narrowedBaseline := false
	if globalAction == "Allow" && hasFileRules(fileRules) {
		newAppArmorHeader = strings.Replace(newAppArmorHeader, "file,\n", "# file,\n", 1)
		narrowedBaseline = true
	} else if globalAction == "Allow" && hasProcessOrFileRules(fileRules) {
		newAppArmorHeader = strings.Replace(
			newAppArmorHeader, "file,\n",
			"/** rwlkm,\n", 1)
		narrowedBaseline = true
	}

	entrypointBody := ""
	if narrowedBaseline && len(entrypoints) > 0 {
		var b strings.Builder
		seen := make(map[string]struct{}, len(entrypoints))
		for _, p := range entrypoints {
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			fmt.Fprintf(&b, "  %s ix,\n", p)
		}
		if b.Len() > 0 {
			entrypointBody = autoInjectedEntrypointHeader + b.String()
		}
	}

	// Narrow the outer baseline capability line when the capability posture
	// is a whitelist. Capability policies are independent of file posture —
	// a pod can have Allow-file / Block-cap, or the reverse. Commenting is
	// tied to capRules.GlobalAction alone.
	if capRules.GlobalAction == "Allow" && hasCapAllowRules(capRules) {
		newAppArmorHeader = strings.Replace(newAppArmorHeader, "capability,\n", "# capability,\n", 1)
	}

	// IPC baselines follow the same whitelist narrowing rule, per sub-domain.
	// Each is independent of file/cap, so we only comment when the sub-domain
	// itself has an Allow rule — otherwise container management tooling
	// (runc/containerd-shim using unix sockets, etc.) would break.
	if hasIPCAllowRules(ipcRules, ipcDomainUnix) {
		newAppArmorHeader = strings.Replace(newAppArmorHeader, "  unix,\n", "  # unix,\n", 1)
	}
	if hasIPCAllowRules(ipcRules, ipcDomainSignal) {
		newAppArmorHeader = strings.Replace(newAppArmorHeader, "  signal,\n", "  # signal,\n", 1)
	}
	if hasIPCAllowRules(ipcRules, ipcDomainPtrace) {
		newAppArmorHeader = strings.Replace(newAppArmorHeader, "  ptrace,\n", "  # ptrace,\n", 1)
	}

	// Construct complete profile
	newProfile := newAppArmorHeader + entrypointBody + newBody + footerTemplate

	// Compare with existing profile to avoid unnecessary updates
	existingProfileStr := strings.Join(existingProfile, "\n")
	if newProfile == existingProfileStr {
		return "", nil
	}

	return newProfile, nil
}

// ipcDomain identifies which IPC sub-domain a helper acts on.
type ipcDomain int

const (
	ipcDomainUnix ipcDomain = iota
	ipcDomainSignal
	ipcDomainPtrace
)

// innerHasIPCAllow reports whether the inner rules of a single source contain
// an Allow rule for the given IPC sub-domain. Sub-domains are checked
// independently so the baseline `unix,` can be narrowed while `signal,` stays
// wide open.
func innerHasIPCAllow(srcRules tp.InnerIPCRules, domain ipcDomain) bool {
	switch domain {
	case ipcDomainUnix:
		for _, r := range srcRules.Unix {
			if r.Action == "Allow" {
				return true
			}
		}
	case ipcDomainSignal:
		for _, r := range srcRules.Signal {
			if r.Action == "Allow" {
				return true
			}
		}
	case ipcDomainPtrace:
		for _, r := range srcRules.Ptrace {
			if r.Action == "Allow" {
				return true
			}
		}
	}
	return false
}

// hasSignalRules reports whether ipcRules contains any signal rules.
func hasSignalRules(ipcRules tp.IPCRules) bool {
	for _, inner := range ipcRules.OuterRules {
		if len(inner.Signal) > 0 {
			return true
		}
	}
	return false
}

// hasPtraceIPCRules reports whether ipcRules contains any ptrace rules.
func hasPtraceIPCRules(ipcRules tp.IPCRules) bool {
	for _, inner := range ipcRules.OuterRules {
		if len(inner.Ptrace) > 0 {
			return true
		}
	}
	return false
}

// hasUnixRules reports whether ipcRules contains any unix socket rules.
func hasUnixRules(ipcRules tp.IPCRules) bool {
	for _, inner := range ipcRules.OuterRules {
		if len(inner.Unix) > 0 {
			return true
		}
	}
	return false
}

// hasIPCAllowRules reports whether any source in the pod has an Allow rule
// for the given IPC sub-domain.
func hasIPCAllowRules(ipcRules tp.IPCRules, domain ipcDomain) bool {
	for _, inner := range ipcRules.OuterRules {
		if innerHasIPCAllow(inner, domain) {
			return true
		}
	}
	return false
}

// unixPeerToken translates a KloudKnox unix path into an AppArmor `peer=(addr=...)`
// argument. Only abstract sockets (paths starting with `@`) are representable
// in unix `peer=(addr=...)` form; the parser rejects bare file-system paths
// there. Empty path and file-system paths both return "" — callers handle the
// file-system case with a separate file-path rule.
func unixPeerToken(path string) string {
	if path == "" || !strings.HasPrefix(path, "@") {
		return ""
	}
	return fmt.Sprintf("peer=(addr=%q)", path)
}

// sortedUnixKeys returns the source's unix rule keys in a stable order so the
// generated profile is deterministic.
func sortedUnixKeys(m map[string]tp.UnixRule) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSignalKeys(m map[string]tp.SignalRule) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPtraceKeys(m map[string]tp.PtraceRule) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// emitUnixRules writes AppArmor `unix (...)` lines for one source's unix
// rules. Each rule produces a single line because the internal converter has
// already split multi-permission CRD rules into per-permission entries.
//
// File-system unix sockets (paths not starting with `@`) cannot be expressed
// as `unix peer=(addr=...)` — the parser rejects non-abstract addresses.
// They get emitted as file-path rules instead, which AppArmor mediates at
// connect() time via the socket inode's LSM file hooks.
func emitUnixRules(body *strings.Builder, pad string, rules map[string]tp.UnixRule) {
	for _, key := range sortedUnixKeys(rules) {
		r := rules[key]
		if r.Path != "" && !strings.HasPrefix(r.Path, "@") {
			emitUnixPathFileRule(body, pad, r)
			continue
		}
		peer := unixPeerToken(r.Path)
		var line string
		if peer == "" {
			line = fmt.Sprintf("unix (%s) type=%s", r.Permission, r.Type)
		} else {
			line = fmt.Sprintf("unix (%s) type=%s %s", r.Permission, r.Type, peer)
		}
		switch r.Action {
		case "Block":
			fmt.Fprintf(body, "  %sdeny %s,\n", pad, line)
		case "Audit":
			fmt.Fprintf(body, "  %saudit %s,\n", pad, line)
		default: // Allow
			fmt.Fprintf(body, "  %s%s,\n", pad, line)
		}
	}
}

// emitUnixPathFileRule renders a pathname unix socket rule as an AppArmor
// file-path rule. `connect` maps to `r` (reading the socket inode is what
// triggers AppArmor's connect mediation); `send`/`receive` additionally need
// `w`. Unknown permissions fall back to `rw` to stay conservative.
func emitUnixPathFileRule(body *strings.Builder, pad string, r tp.UnixRule) {
	var fperm string
	switch r.Permission {
	case "connect":
		fperm = "r"
	case "send", "receive":
		fperm = "rw"
	default:
		fperm = "rw"
	}
	switch r.Action {
	case "Block":
		fmt.Fprintf(body, "  %sdeny %s %s,\n", pad, r.Path, fperm)
	case "Audit":
		fmt.Fprintf(body, "  %saudit %s %s,\n", pad, r.Path, fperm)
	default: // Allow
		fmt.Fprintf(body, "  %s%s %s,\n", pad, r.Path, fperm)
	}
}

// signalSetToken builds the AppArmor `set=(...)` token from a signal number
// list. An empty signal list yields an empty token, meaning AppArmor matches
// any signal for the rule.
func signalSetToken(sigs []int) string {
	if len(sigs) == 0 {
		return ""
	}
	tokens := make([]string, 0, len(sigs))
	sorted := append([]int(nil), sigs...)
	sort.Ints(sorted)
	for _, n := range sorted {
		name := lib.SignalName(n)
		if name == "" {
			continue
		}
		tokens = append(tokens, lib.AppArmorSignalToken(name))
	}
	if len(tokens) == 0 {
		return ""
	}
	return "set=(" + strings.Join(tokens, ", ") + ")"
}

// emitSignalRules writes AppArmor `signal (send) ...` lines for a source.
// Target narrowing is intentionally NOT emitted: AppArmor's `peer=<expr>`
// matches the peer's profile name, not its executable path, so mapping a
// KloudKnox `target: /bin/foo` onto `peer=/bin/foo` never matches the
// actual confined peer. We emit only `set=(<signals>)` and rely on the
// matcher in monitor/policyMatcher.go for per-target attribution.
func emitSignalRules(body *strings.Builder, pad string, rules map[string]tp.SignalRule) {
	for _, key := range sortedSignalKeys(rules) {
		r := rules[key]

		parts := []string{"signal", "(send)"}
		if tok := signalSetToken(r.Signals); tok != "" {
			parts = append(parts, tok)
		}
		line := strings.Join(parts, " ")

		switch r.Action {
		case "Block":
			fmt.Fprintf(body, "  %sdeny %s,\n", pad, line)
		case "Audit":
			fmt.Fprintf(body, "  %saudit %s,\n", pad, line)
		default: // Allow
			fmt.Fprintf(body, "  %s%s,\n", pad, line)
		}
	}
}

// ptracePermToken converts a KloudKnox ptrace permission into the AppArmor
// wire form. `traceby` / `readby` are tracee-side dialects — AppArmor uses
// `tracedby` / `readby`.
func ptracePermToken(perm string) string {
	switch perm {
	case "traceby":
		return "tracedby"
	case "readby":
		return "readby"
	default:
		return perm
	}
}

// emitPtraceRules writes AppArmor `ptrace (...) peer=<path>,` lines.
func emitPtraceRules(body *strings.Builder, pad string, rules map[string]tp.PtraceRule) {
	for _, key := range sortedPtraceKeys(rules) {
		r := rules[key]

		tok := ptracePermToken(r.Permission)
		parts := []string{fmt.Sprintf("ptrace (%s)", tok)}
		if r.Target != "" {
			parts = append(parts, "peer="+r.Target)
		}
		line := strings.Join(parts, " ")

		switch r.Action {
		case "Block":
			fmt.Fprintf(body, "  %sdeny %s,\n", pad, line)
		case "Audit":
			fmt.Fprintf(body, "  %saudit %s,\n", pad, line)
		default: // Allow
			fmt.Fprintf(body, "  %s%s,\n", pad, line)
		}
	}
}
