// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"strings"
	"testing"

	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// =========================== //
// ==  processPath Tests    == //
// =========================== //

func TestProcessPathFile(t *testing.T) {
	ae := &AppArmorEnforcer{}

	rule := tp.FileRule{IsPath: true}
	got := ae.processPath("/bin/ls", rule)
	if got != "/bin/ls" {
		t.Errorf("processPath file = %q, want %q", got, "/bin/ls")
	}
}

func TestProcessPathDirNonRecursive(t *testing.T) {
	ae := &AppArmorEnforcer{}

	rule := tp.FileRule{IsDir: true, Recursive: false}
	got := ae.processPath("/etc/", rule)
	if got != "/etc/*" {
		t.Errorf("processPath dir non-recursive = %q, want %q", got, "/etc/*")
	}
}

func TestProcessPathDirRecursive(t *testing.T) {
	ae := &AppArmorEnforcer{}

	rule := tp.FileRule{IsDir: true, Recursive: true}
	got := ae.processPath("/var/log/", rule)
	if got != "/var/log/{*,**}" {
		t.Errorf("processPath dir recursive = %q, want %q", got, "/var/log/{*,**}")
	}
}

func TestProcessPathDirNoTrailingSlash(t *testing.T) {
	ae := &AppArmorEnforcer{}

	rule := tp.FileRule{IsDir: true, Recursive: false}
	// Should append trailing slash before wildcard
	got := ae.processPath("/etc", rule)
	if got != "/etc/*" {
		t.Errorf("processPath dir without trailing slash = %q, want /etc/*", got)
	}
}

// ================================ //
// ==  GenerateProfileBody Tests == //
// ================================ //

func TestGenerateProfileBodyEmpty(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		OuterRules:   make(map[string]tp.InnerFileRules),
		GlobalAction: "Block",
	}

	body, globalAction := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())
	if body != "" {
		t.Errorf("expected empty body for empty rules, got %q", body)
	}
	if globalAction != "Block" {
		t.Errorf("globalAction = %q, want Block", globalAction)
	}
}

func TestGenerateProfileBodyBlockRule(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerFileRules{
			"default": {
				InnerRules: map[string]tp.FileRule{
					"/bin/cat": {
						IsPath:     true,
						Permission: "x",
						Action:     "Block",
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())

	if !strings.Contains(body, "deny") {
		t.Errorf("expected 'deny' in block rule body, got:\n%s", body)
	}
	if !strings.Contains(body, "/bin/cat") {
		t.Errorf("expected '/bin/cat' in body, got:\n%s", body)
	}
}

func TestGenerateProfileBodyAllowRule(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerFileRules{
			"default": {
				InnerRules: map[string]tp.FileRule{
					"/etc/passwd": {
						IsPath:     true,
						Permission: "R",
						Action:     "Audit",
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())

	if strings.Contains(body, "deny") {
		t.Errorf("expected no 'deny' for Audit rule, got:\n%s", body)
	}
	if !strings.Contains(body, "/etc/passwd") {
		t.Errorf("expected '/etc/passwd' in body, got:\n%s", body)
	}
	// "R" maps to "rml"
	if !strings.Contains(body, "rml") {
		t.Errorf("expected 'rml' permission in body, got:\n%s", body)
	}
}

func TestGenerateProfileBodyDirRule(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerFileRules{
			"default": {
				InnerRules: map[string]tp.FileRule{
					"/var/log": {
						IsDir:      true,
						Recursive:  true,
						Permission: "rw",
						Action:     "Block",
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())

	if !strings.Contains(body, "{*,**}") {
		t.Errorf("expected recursive wildcard in body, got:\n%s", body)
	}
	if !strings.Contains(body, "deny") {
		t.Errorf("expected 'deny' for Block action, got:\n%s", body)
	}
}

func TestGenerateProfileBodyGlobalActionAllow(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerFileRules{
			"default": {
				InnerRules: map[string]tp.FileRule{
					"/tmp/file": {
						IsPath:     true,
						Permission: "X",
						Action:     "Allow",
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	_, globalAction := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())
	if globalAction != "Allow" {
		t.Errorf("globalAction = %q, want Allow", globalAction)
	}
}

// ======================================= //
// ==  permissionMap correctness Tests  == //
// ======================================= //

// fromSource rule — verify a nested sub-profile is generated.
func TestGenerateProfileBodyFromSource(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerFileRules{
			"/bin/sh": {
				InnerAction: "Block",
				InnerRules: map[string]tp.FileRule{
					"/etc/shadow": {
						IsPath:     true,
						Permission: "rw",
						Action:     "Block",
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())

	// Nested fromSource profile must contain the "profile /bin/sh" block.
	if !strings.Contains(body, "profile /bin/sh") {
		t.Errorf("expected nested 'profile /bin/sh' in body, got:\n%s", body)
	}
	// Must contain the source-exec transition rule.
	if !strings.Contains(body, "/bin/sh cx,") {
		t.Errorf("expected '/bin/sh cx,' transition rule in body, got:\n%s", body)
	}
	// Must contain the target file.
	if !strings.Contains(body, "/etc/shadow") {
		t.Errorf("expected '/etc/shadow' in nested profile body, got:\n%s", body)
	}
}

// fromSource Allow mode (file whitelist) — the nested profile must comment out `file,`.
func TestGenerateProfileBodyFromSourceAllowMode(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerFileRules{
			"/usr/bin/python3": {
				InnerAction: "Allow",
				InnerRules: map[string]tp.FileRule{
					"/tmp/out": {
						IsPath:     true,
						Permission: "RW",
						Action:     "Allow",
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())

	// File-whitelist nested profiles must comment out `file,` so only the
	// explicitly listed paths are readable.
	if !strings.Contains(body, "# file,") {
		t.Errorf("expected '# file,' in allow-mode file-whitelist nested profile, got:\n%s", body)
	}
}

// fromSource Allow mode (process whitelist) — the nested profile must keep `file,`.
func TestGenerateProfileBodyFromSourceProcessAllowMode(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerFileRules{
			"/bin/dash": {
				InnerAction: "Allow",
				InnerRules: map[string]tp.FileRule{
					"/bin/ls": {
						IsPath:     true,
						Permission: "X",
						Action:     "Allow",
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), emptyIPCRules())

	// Process-only whitelist must keep baseline `file,` so that the
	// whitelisted binary (e.g. /bin/ls) can still open directories.
	if !strings.Contains(body, "    file,\n") {
		t.Errorf("expected '    file,' in process-whitelist nested profile, got:\n%s", body)
	}
	if strings.Contains(body, "# file,") {
		t.Errorf("unexpected '# file,' in process-whitelist nested profile, got:\n%s", body)
	}
}

// emptyCapRules returns a zero-value CapabilityRules for tests that only
// exercise the file-rule path but need to satisfy the new signature.
func emptyCapRules() tp.CapabilityRules {
	return tp.CapabilityRules{
		OuterRules:   make(map[string]tp.InnerCapabilityRules),
		GlobalAction: "Block",
	}
}

// emptyIPCRules returns a zero-value IPCRules for tests that do not exercise
// the IPC path but need to satisfy the new GenerateProfileBody signature.
func emptyIPCRules() tp.IPCRules {
	return tp.IPCRules{
		OuterRules:   make(map[string]tp.InnerIPCRules),
		GlobalAction: "Block",
	}
}

// ======================================== //
// ==  GenerateProfileBody — Capability  == //
// ======================================== //

func TestGenerateProfileBodyCapabilityAllowDefault(t *testing.T) {
	ae := &AppArmorEnforcer{}
	capRules := tp.CapabilityRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerCapabilityRules{
			"default": {
				InnerAction: "Allow",
				InnerRules: map[uint32]tp.CapabilityRule{
					13: {CapID: 13, Name: "CAP_NET_RAW", Action: "Allow"},
				},
				AllowRules: map[uint32]tp.CapabilityRule{
					13: {CapID: 13, Name: "CAP_NET_RAW", Action: "Allow"},
				},
			},
		},
	}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}

	body, _ := ae.GenerateProfileBody(fileRules, capRules, emptyIPCRules())

	if !strings.Contains(body, "capability net_raw,") {
		t.Errorf("expected 'capability net_raw,' in body, got:\n%s", body)
	}
}

func TestGenerateProfileBodyCapabilityBlockDefault(t *testing.T) {
	ae := &AppArmorEnforcer{}
	capRules := tp.CapabilityRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerCapabilityRules{
			"default": {
				InnerAction: "Block",
				InnerRules: map[uint32]tp.CapabilityRule{
					12: {CapID: 12, Name: "CAP_NET_ADMIN", Action: "Block"},
				},
				AllowRules: make(map[uint32]tp.CapabilityRule),
			},
		},
	}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}

	body, _ := ae.GenerateProfileBody(fileRules, capRules, emptyIPCRules())

	if !strings.Contains(body, "deny capability net_admin,") {
		t.Errorf("expected 'deny capability net_admin,' in body, got:\n%s", body)
	}
}

func TestGenerateProfileBodyCapabilityAuditDefault(t *testing.T) {
	ae := &AppArmorEnforcer{}
	capRules := tp.CapabilityRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerCapabilityRules{
			"default": {
				InnerAction: "Block",
				InnerRules: map[uint32]tp.CapabilityRule{
					21: {CapID: 21, Name: "CAP_SYS_ADMIN", Action: "Audit"},
				},
				AllowRules: make(map[uint32]tp.CapabilityRule),
			},
		},
	}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}

	body, _ := ae.GenerateProfileBody(fileRules, capRules, emptyIPCRules())

	if !strings.Contains(body, "audit capability sys_admin,") {
		t.Errorf("expected 'audit capability sys_admin,' in body, got:\n%s", body)
	}
}

// Capability rule with a fromSource path must land inside a nested sub-profile
// even if no file rule shares the same source.
func TestGenerateProfileBodyCapabilityFromSourceOnly(t *testing.T) {
	ae := &AppArmorEnforcer{}
	capRules := tp.CapabilityRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerCapabilityRules{
			"/usr/sbin/tcpdump": {
				InnerAction: "Allow",
				InnerRules: map[uint32]tp.CapabilityRule{
					13: {CapID: 13, Name: "CAP_NET_RAW", Action: "Allow"},
				},
				AllowRules: map[uint32]tp.CapabilityRule{
					13: {CapID: 13, Name: "CAP_NET_RAW", Action: "Allow"},
				},
			},
		},
	}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}

	body, _ := ae.GenerateProfileBody(fileRules, capRules, emptyIPCRules())

	if !strings.Contains(body, "profile /usr/sbin/tcpdump {") {
		t.Errorf("expected nested profile for capability-only source, got:\n%s", body)
	}
	if !strings.Contains(body, "/usr/sbin/tcpdump cx,") {
		t.Errorf("expected cx transition for capability-only source, got:\n%s", body)
	}
	if !strings.Contains(body, "    capability net_raw,") {
		t.Errorf("expected indented 'capability net_raw,' inside sub-profile, got:\n%s", body)
	}
	// Inside a capability whitelist sub-profile, the blanket `capability,`
	// baseline must be commented so only the whitelisted caps survive.
	if !strings.Contains(body, "    # capability,") {
		t.Errorf("expected commented baseline 'capability,' in whitelist sub-profile, got:\n%s", body)
	}
}

// innerHasCapAllow / hasCapAllowRules behavior.
func TestInnerHasCapAllow(t *testing.T) {
	inner := tp.InnerCapabilityRules{
		InnerRules: map[uint32]tp.CapabilityRule{
			14: {Action: "Block"},
		},
	}
	if innerHasCapAllow(inner) {
		t.Error("innerHasCapAllow should be false when only Block rules present")
	}
	inner.InnerRules[13] = tp.CapabilityRule{Action: "Allow"}
	if !innerHasCapAllow(inner) {
		t.Error("innerHasCapAllow should be true when any Allow rule present")
	}
}

func TestHasCapAllowRules(t *testing.T) {
	capRules := tp.CapabilityRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerCapabilityRules{
			"default": {
				InnerRules: map[uint32]tp.CapabilityRule{
					13: {Action: "Allow"},
				},
			},
		},
	}
	if !hasCapAllowRules(capRules) {
		t.Error("hasCapAllowRules should be true for Allow posture with whitelist")
	}
}

func TestCapKernelName(t *testing.T) {
	cases := map[string]string{
		"CAP_NET_RAW":   "net_raw",
		"CAP_SYS_ADMIN": "sys_admin",
		"CAP_BPF":       "bpf",
	}
	for in, want := range cases {
		if got := capKernelName(in); got != want {
			t.Errorf("capKernelName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectAppArmorSourcesUnion(t *testing.T) {
	file := tp.FileRules{
		OuterRules: map[string]tp.InnerFileRules{
			"default": {},
			"/a":      {},
		},
	}
	cap := tp.CapabilityRules{
		OuterRules: map[string]tp.InnerCapabilityRules{
			"/a": {},
			"/b": {},
		},
	}
	ipc := tp.IPCRules{
		OuterRules: map[string]tp.InnerIPCRules{
			"/b":      {},
			"default": {},
		},
	}
	got := collectAppArmorSources(file, cap, ipc)
	want := []string{"/a", "/b", "default"}
	if len(got) != len(want) {
		t.Fatalf("collectAppArmorSources len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("collectAppArmorSources[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPermissionMapContainsAllExpected(t *testing.T) {
	expected := map[string]string{
		"X":  "ix",
		"x":  "x",
		"R":  "rml",
		"W":  "rwml",
		"w":  "w",
		"RW": "rwml",
		"rw": "rw",
	}

	for perm, want := range expected {
		got, ok := permissionMap[perm]
		if !ok {
			t.Errorf("permissionMap missing key %q", perm)
			continue
		}
		if got != want {
			t.Errorf("permissionMap[%q] = %q, want %q", perm, got, want)
		}
	}
}

// =================================== //
// ==  GenerateProfileBody — IPC    == //
// =================================== //

// A Block unix rule on a pathname socket must emit a file-path deny (because
// AppArmor `unix peer=(addr=...)` only accepts abstract addresses) and must
// NOT narrow the default-source baseline (only Allow rules trigger narrowing).
func TestGenerateProfileBodyUnixBlock(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}
	ipcRules := tp.IPCRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerIPCRules{
			"default": {
				InnerAction: "Block",
				Unix: map[string]tp.UnixRule{
					"stream|/var/run/docker.sock|connect": {
						Type:       "stream",
						Path:       "/var/run/docker.sock",
						Permission: "connect",
						Action:     "Block",
					},
				},
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), ipcRules)

	if !strings.Contains(body, "deny /var/run/docker.sock r,") {
		t.Errorf("expected block file-path line for pathname unix socket, got:\n%s", body)
	}
}

// An Allow unix rule on a pathname socket inside a fromSource sub-profile must:
//   - emit a file-path allow (pathname sockets aren't representable as unix peer=addr)
//   - comment out the sub-profile's `unix,` baseline (whitelist narrowing)
//   - leave `signal,` / `ptrace,` baselines untouched (independent sub-domains)
func TestGenerateProfileBodyUnixAllowFromSource(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}
	ipcRules := tp.IPCRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerIPCRules{
			"/usr/bin/psql": {
				InnerAction: "Allow",
				Unix: map[string]tp.UnixRule{
					"stream|/var/run/postgresql/.s.PGSQL.5432|connect": {
						Type:       "stream",
						Path:       "/var/run/postgresql/.s.PGSQL.5432",
						Permission: "connect",
						Action:     "Allow",
					},
				},
				UnixAllow: map[string]tp.UnixRule{
					"stream|/var/run/postgresql/.s.PGSQL.5432|connect": {
						Type:       "stream",
						Path:       "/var/run/postgresql/.s.PGSQL.5432",
						Permission: "connect",
						Action:     "Allow",
					},
				},
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), ipcRules)

	if !strings.Contains(body, "profile /usr/bin/psql {") {
		t.Errorf("expected nested sub-profile, got:\n%s", body)
	}
	if !strings.Contains(body, "    /var/run/postgresql/.s.PGSQL.5432 r,") {
		t.Errorf("expected indented allow file-path line for pathname unix socket, got:\n%s", body)
	}
	if !strings.Contains(body, "    # unix,") {
		t.Errorf("expected commented baseline '# unix,' in unix-whitelist sub-profile, got:\n%s", body)
	}
	if !strings.Contains(body, "    signal,") || strings.Contains(body, "    # signal,") {
		t.Errorf("expected untouched 'signal,' baseline, got:\n%s", body)
	}
	if !strings.Contains(body, "    ptrace,") || strings.Contains(body, "    # ptrace,") {
		t.Errorf("expected untouched 'ptrace,' baseline, got:\n%s", body)
	}
}

// A signal rule with a concrete signal set must emit the AppArmor
// `set=(term, hup)` token with lib.AppArmorSignalToken lowercase form.
func TestGenerateProfileBodySignalSet(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}
	ipcRules := tp.IPCRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerIPCRules{
			"default": {
				InnerAction: "Allow",
				Signal: map[string]tp.SignalRule{
					"/usr/bin/postgres|hex": {
						Target:  "/usr/bin/postgres",
						Signals: []int{15, 1}, // SIGTERM, SIGHUP
						Action:  "Allow",
					},
				},
				SignalAllow: map[string]tp.SignalRule{
					"/usr/bin/postgres|hex": {
						Target:  "/usr/bin/postgres",
						Signals: []int{15, 1},
						Action:  "Allow",
					},
				},
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), ipcRules)

	// Signals sort ascending: 1 (hup) then 15 (term). Target-based peer=
	// narrowing is intentionally dropped by the renderer (AppArmor peer
	// expressions match profile names, not exe paths).
	if !strings.Contains(body, "signal (send) set=(hup, term),") {
		t.Errorf("expected signal line with sorted set token, got:\n%s", body)
	}
	if strings.Contains(body, "peer=/usr/bin/postgres") {
		t.Errorf("expected no peer= narrowing on signal rule, got:\n%s", body)
	}
}

// A ptrace `traceby` rule must translate to AppArmor's `tracedby` token.
func TestGenerateProfileBodyPtraceTracedby(t *testing.T) {
	ae := &AppArmorEnforcer{}
	fileRules := tp.FileRules{OuterRules: make(map[string]tp.InnerFileRules), GlobalAction: "Block"}
	ipcRules := tp.IPCRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerIPCRules{
			"default": {
				InnerAction: "Block",
				Ptrace: map[string]tp.PtraceRule{
					"traceby|/usr/bin/gdb": {
						Permission: "traceby",
						Target:     "/usr/bin/gdb",
						Action:     "Audit",
					},
				},
			},
		},
	}

	body, _ := ae.GenerateProfileBody(fileRules, emptyCapRules(), ipcRules)

	if !strings.Contains(body, "audit ptrace (tracedby) peer=/usr/bin/gdb,") {
		t.Errorf("expected ptrace tracedby audit line, got:\n%s", body)
	}
}

// hasIPCAllowRules must check each sub-domain independently.
func TestHasIPCAllowRulesPerDomain(t *testing.T) {
	ipcRules := tp.IPCRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerIPCRules{
			"default": {
				InnerAction: "Allow",
				Unix: map[string]tp.UnixRule{
					"stream|/a|connect": {Action: "Allow"},
				},
				Signal: map[string]tp.SignalRule{
					"/b|0": {Action: "Block"},
				},
			},
		},
	}
	if !hasIPCAllowRules(ipcRules, ipcDomainUnix) {
		t.Error("unix sub-domain should report Allow")
	}
	if hasIPCAllowRules(ipcRules, ipcDomainSignal) {
		t.Error("signal sub-domain should NOT report Allow (only Block rule present)")
	}
	if hasIPCAllowRules(ipcRules, ipcDomainPtrace) {
		t.Error("ptrace sub-domain should NOT report Allow (no rules present)")
	}
}

// ptracePermToken translates KloudKnox tracee-side dialects to AppArmor form.
func TestPtracePermToken(t *testing.T) {
	cases := map[string]string{
		"trace":   "trace",
		"read":    "read",
		"traceby": "tracedby",
		"readby":  "readby",
	}
	for in, want := range cases {
		if got := ptracePermToken(in); got != want {
			t.Errorf("ptracePermToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// unixPeerToken formats the AppArmor peer argument. Only abstract addresses
// (paths starting with `@`) are valid `peer=(addr=...)` arguments; empty and
// file-system paths both return "" — the caller renders those as file-path
// rules instead.
func TestUnixPeerToken(t *testing.T) {
	if got := unixPeerToken(""); got != "" {
		t.Errorf("unixPeerToken(\"\") = %q, want empty", got)
	}
	if got := unixPeerToken("/var/run/app.sock"); got != "" {
		t.Errorf("unixPeerToken(/var/run/app.sock) = %q, want empty (pathname socket is not representable as unix peer addr)", got)
	}
	if got := unixPeerToken("@/kloudknox/app"); got != `peer=(addr="@/kloudknox/app")` {
		t.Errorf("unixPeerToken(@/kloudknox/app) = %q, want quoted abstract form", got)
	}
}
