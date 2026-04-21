// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

import (
	"testing"

	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// ============================ //
// ==  hasWriteFlag Tests    == //
// ============================ //

func TestHasWriteFlag(t *testing.T) {
	tests := []struct {
		data string
		want bool
	}{
		{"O_RDONLY", false},
		{"O_WRONLY", true},
		{"O_RDWR", true},
		{"O_CREAT|O_WRONLY", true},
		{"O_TRUNC", true},
		{"O_APPEND", true},
		{"flags: O_CREAT", true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.data, func(t *testing.T) {
			got := hasWriteFlag(tt.data)
			if got != tt.want {
				t.Errorf("hasWriteFlag(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

// ================================= //
// ==  matchProcessExecute Tests  == //
// ================================= //

func TestMatchProcessExecuteBlockDenied(t *testing.T) {
	rule := tp.FileRule{Permission: "x", Action: "Block"}
	evData := &tp.EventData{Operation: "execute", RetVal: -13}
	if !matchProcessExecute(rule, evData) {
		t.Error("expected match for Block+denied execute")
	}
}

func TestMatchProcessExecuteBlockAllowed(t *testing.T) {
	rule := tp.FileRule{Permission: "x", Action: "Block"}
	evData := &tp.EventData{Operation: "execute", RetVal: 0}
	if matchProcessExecute(rule, evData) {
		t.Error("Block rule should not match when execute succeeded (RetVal=0)")
	}
}

func TestMatchProcessExecuteAuditSuccess(t *testing.T) {
	rule := tp.FileRule{Permission: "X", Action: "Audit"}
	evData := &tp.EventData{Operation: "execute", RetVal: 0}
	if !matchProcessExecute(rule, evData) {
		t.Error("expected match for Audit+success execute")
	}
}

func TestMatchProcessExecuteAuditFailed(t *testing.T) {
	rule := tp.FileRule{Permission: "X", Action: "Audit"}
	evData := &tp.EventData{Operation: "execute", RetVal: -13}
	if matchProcessExecute(rule, evData) {
		t.Error("Audit rule should not match when execute was denied")
	}
}

// ============================= //
// ==  matchFileOpen Tests    == //
// ============================= //

func TestMatchFileOpenReadBlock(t *testing.T) {
	rule := tp.FileRule{Permission: "r", Action: "Block"}
	evData := &tp.EventData{Data: "O_RDONLY", RetVal: -13}
	if !matchFileOpen(rule, evData) {
		t.Error("expected match for read-block on O_RDONLY with EACCES")
	}
}

func TestMatchFileOpenReadBlockWriteFlag(t *testing.T) {
	rule := tp.FileRule{Permission: "r", Action: "Block"}
	// write flag present — "r" rule should not match a write open
	evData := &tp.EventData{Data: "O_WRONLY", RetVal: -13}
	if matchFileOpen(rule, evData) {
		t.Error("read-block rule should not match when write flag is set")
	}
}

func TestMatchFileOpenWriteBlock(t *testing.T) {
	rule := tp.FileRule{Permission: "w", Action: "Block"}
	evData := &tp.EventData{Data: "O_WRONLY", RetVal: -13}
	if !matchFileOpen(rule, evData) {
		t.Error("expected match for write-block on O_WRONLY with EACCES")
	}
}

func TestMatchFileOpenWriteBlockReadFlag(t *testing.T) {
	rule := tp.FileRule{Permission: "w", Action: "Block"}
	evData := &tp.EventData{Data: "O_RDONLY", RetVal: -13}
	if matchFileOpen(rule, evData) {
		t.Error("write-block rule should not match when only read flag is set")
	}
}

func TestMatchFileOpenReadAudit(t *testing.T) {
	rule := tp.FileRule{Permission: "R", Action: "Audit"}
	evData := &tp.EventData{Data: "O_RDONLY", RetVal: 5}
	if !matchFileOpen(rule, evData) {
		t.Error("expected match for read-audit on successful read open")
	}
}

func TestMatchFileOpenRWBlock(t *testing.T) {
	rule := tp.FileRule{Permission: "rw", Action: "Block"}
	evData := &tp.EventData{RetVal: -13}
	if !matchFileOpen(rule, evData) {
		t.Error("expected match for rw-block with EACCES")
	}
}

func TestMatchFileOpenRWAudit(t *testing.T) {
	rule := tp.FileRule{Permission: "RW", Action: "Audit"}
	evData := &tp.EventData{RetVal: 5}
	if !matchFileOpen(rule, evData) {
		t.Error("expected match for RW-audit with success FD")
	}
}

// =========================== //
// ==  IsMatched Tests      == //
// =========================== //

func TestIsMatchedExecute(t *testing.T) {
	rule := tp.FileRule{Permission: "x", Action: "Block"}
	evData := &tp.EventData{Operation: "execute", RetVal: -13}
	if !IsMatched(rule, evData) {
		t.Error("expected IsMatched=true for blocked execute")
	}
}

func TestIsMatchedOpen(t *testing.T) {
	rule := tp.FileRule{Permission: "r", Action: "Block"}
	evData := &tp.EventData{Operation: "open", Data: "O_RDONLY", RetVal: -13}
	if !IsMatched(rule, evData) {
		t.Error("expected IsMatched=true for blocked read open")
	}
}

func TestIsMatchedUnknownOperation(t *testing.T) {
	rule := tp.FileRule{Permission: "x", Action: "Block"}
	evData := &tp.EventData{Operation: "network"}
	if IsMatched(rule, evData) {
		t.Error("IsMatched should return false for unknown operation")
	}
}

// ================================ //
// ==  isRuleMatching Tests      == //
// ================================ //

func TestIsRuleMatchingExactPath(t *testing.T) {
	m := &SystemMonitor{}
	rule := tp.FileRule{IsPath: true}
	got := m.isRuleMatching(rule, "/bin/ls", "/bin/ls", "/bin")
	if !got {
		t.Error("expected match for exact path")
	}
}

func TestIsRuleMatchingExactPathMismatch(t *testing.T) {
	m := &SystemMonitor{}
	rule := tp.FileRule{IsPath: true}
	got := m.isRuleMatching(rule, "/bin/ls", "/bin/cat", "/bin")
	if got {
		t.Error("expected no match for different path")
	}
}

func TestIsRuleMatchingDirNonRecursive(t *testing.T) {
	m := &SystemMonitor{}
	rule := tp.FileRule{IsDir: true, Recursive: false}
	// isRuleMatching uses path.Dir(rulePath): path.Dir("/etc/") = "/etc"
	// resource dir "/etc" matches → should return true
	got := m.isRuleMatching(rule, "/etc/", "/etc/hosts", "/etc")
	if !got {
		t.Error("expected match for dir non-recursive when resource is in same dir")
	}
}

func TestIsRuleMatchingDirNonRecursiveSubdir(t *testing.T) {
	m := &SystemMonitor{}
	rule := tp.FileRule{IsDir: true, Recursive: false}
	// resource is in a subdirectory — non-recursive should not match
	got := m.isRuleMatching(rule, "/etc/", "/etc/ssl/certs/ca.pem", "/etc/ssl/certs")
	if got {
		t.Error("non-recursive dir rule should not match resource in subdirectory")
	}
}

func TestIsRuleMatchingDirRecursive(t *testing.T) {
	m := &SystemMonitor{}
	rule := tp.FileRule{IsDir: true, Recursive: true}
	// path.Dir("/etc/") = "/etc"; strings.HasPrefix("/etc/ssl/certs", "/etc") = true
	got := m.isRuleMatching(rule, "/etc/", "/etc/ssl/certs/ca.pem", "/etc/ssl/certs")
	if !got {
		t.Error("recursive dir rule should match resource in subdirectory")
	}
}

// ============================== //
// ==  PolicyMatch Tests       == //
// ============================== //

func newTestSystemMonitor() *SystemMonitor {
	return &SystemMonitor{}
}

func TestPolicyMatchNoRules(t *testing.T) {
	m := newTestSystemMonitor()
	fileRules := tp.FileRules{
		OuterRules: make(map[string]tp.InnerFileRules),
	}
	evData := &tp.EventData{Operation: "execute", Resource: "/bin/ls", Source: "/bin/sh", RetVal: -13}

	m.PolicyMatch(fileRules, evData)

	if evData.PolicyName != "" || evData.PolicyAction != "" {
		t.Errorf("expected no policy match, got name=%q action=%q", evData.PolicyName, evData.PolicyAction)
	}
}

func TestPolicyMatchBlockRule(t *testing.T) {
	m := newTestSystemMonitor()
	fileRules := tp.FileRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerFileRules{
			"default": {
				InnerRules: map[string]tp.FileRule{
					"/bin/ls": {
						IsPath:     true,
						Permission: "x",
						Action:     "Block",
						Policy: tp.KloudKnoxPolicy{
							PolicyName: "block-ls",
						},
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	evData := &tp.EventData{
		Operation: "execute",
		Source:    "/bin/sh",
		Resource:  "/bin/ls",
		RetVal:    -13,
	}

	m.PolicyMatch(fileRules, evData)

	if evData.PolicyName != "block-ls" {
		t.Errorf("PolicyName = %q, want block-ls", evData.PolicyName)
	}
	if evData.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block", evData.PolicyAction)
	}
}

func TestPolicyMatchSourceSpecificRule(t *testing.T) {
	m := newTestSystemMonitor()
	fileRules := tp.FileRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerFileRules{
			"/bin/sh": {
				InnerRules: map[string]tp.FileRule{
					"/bin/cat": {
						IsPath:     true,
						Permission: "x",
						Action:     "Block",
						Policy:     tp.KloudKnoxPolicy{PolicyName: "block-cat-from-sh"},
					},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	evData := &tp.EventData{
		Operation: "execute",
		Source:    "/bin/sh",
		Resource:  "/bin/cat",
		RetVal:    -13,
	}

	m.PolicyMatch(fileRules, evData)

	if evData.PolicyName != "block-cat-from-sh" {
		t.Errorf("PolicyName = %q, want block-cat-from-sh", evData.PolicyName)
	}
}

func TestPolicyMatchAllowRuleOverrides(t *testing.T) {
	m := newTestSystemMonitor()
	// A blocked operation under an allow-list posture is attributed back to the
	// allow policies (they caused the implicit deny) and reported as a Block
	// alert carrying the originating policy name(s).
	fileRules := tp.FileRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerFileRules{
			"default": {
				InnerRules: make(map[string]tp.FileRule),
				AllowRules: map[string]tp.FileRule{
					"/bin/ls": {
						IsPath:     true,
						Permission: "X",
						Action:     "Allow",
						Policy:     tp.KloudKnoxPolicy{PolicyName: "allow-ls-only"},
					},
				},
			},
		},
	}

	evData := &tp.EventData{
		Operation: "execute",
		Source:    "/usr/bin/cat",
		Resource:  "/bin/cat",
		RetVal:    -13,
	}

	m.PolicyMatch(fileRules, evData)

	if evData.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block (allow-violation → Block)", evData.PolicyAction)
	}
	if evData.PolicyName != "allow-ls-only" {
		t.Errorf("PolicyName = %q, want allow-ls-only", evData.PolicyName)
	}
}

func TestPolicyMatchIgnoresNonFileOps(t *testing.T) {
	m := newTestSystemMonitor()
	fileRules := tp.FileRules{
		OuterRules: map[string]tp.InnerFileRules{
			"default": {
				InnerRules: map[string]tp.FileRule{
					"/bin/ls": {IsPath: true, Permission: "x", Action: "Block"},
				},
				AllowRules: make(map[string]tp.FileRule),
			},
		},
	}

	evData := &tp.EventData{
		Operation: "connect", // network event — PolicyMatch should skip
		Resource:  "/bin/ls",
		RetVal:    -13,
	}

	m.PolicyMatch(fileRules, evData)

	if evData.PolicyName != "" {
		t.Errorf("PolicyMatch should not set PolicyName for non-file/process operations")
	}
}

// ============================== //
// ==  Capability Tests        == //
// ============================== //

// matchCapability is a shape-only predicate: it asserts the rule applies
// to this cap name and has an actionable verdict. RetVal gating lives in
// CapabilityPolicyMatch, not here.
func TestMatchCapabilityShapeBlock(t *testing.T) {
	rule := tp.CapabilityRule{Name: "CAP_NET_RAW", Action: "Block"}
	evData := &tp.EventData{Operation: "capable", Resource: "CAP_NET_RAW", RetVal: -1}
	if !matchCapability(rule, evData) {
		t.Error("Block rule should match on cap name")
	}
}

func TestMatchCapabilityShapeAudit(t *testing.T) {
	rule := tp.CapabilityRule{Name: "CAP_SYS_ADMIN", Action: "Audit"}
	evData := &tp.EventData{Operation: "capable", Resource: "CAP_SYS_ADMIN", RetVal: 0}
	if !matchCapability(rule, evData) {
		t.Error("Audit rule should match on cap name")
	}
}

func TestMatchCapabilityAllowActionDoesNotMatch(t *testing.T) {
	rule := tp.CapabilityRule{Name: "CAP_NET_RAW", Action: "Allow"}
	evData := &tp.EventData{Operation: "capable", Resource: "CAP_NET_RAW", RetVal: -1}
	if matchCapability(rule, evData) {
		t.Error("Allow-action rule must not match in shape predicate")
	}
}

func TestMatchCapabilityWrongName(t *testing.T) {
	rule := tp.CapabilityRule{Name: "CAP_NET_ADMIN", Action: "Block"}
	evData := &tp.EventData{Operation: "capable", Resource: "CAP_NET_RAW", RetVal: -1}
	if matchCapability(rule, evData) {
		t.Error("rule with different cap name must not match")
	}
}

func TestCapabilityPolicyMatchBlock(t *testing.T) {
	m := newTestSystemMonitor()
	capRules := tp.CapabilityRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerCapabilityRules{
			"default": {
				InnerAction: "Block",
				InnerRules: map[uint32]tp.CapabilityRule{
					12: {CapID: 12, Name: "CAP_NET_ADMIN", Action: "Block",
						Policy: tp.KloudKnoxPolicy{PolicyName: "deny-netadmin"}},
				},
				AllowRules: make(map[uint32]tp.CapabilityRule),
			},
		},
	}
	evData := &tp.EventData{
		Operation: "capable",
		Source:    "/usr/bin/foo",
		Resource:  "CAP_NET_ADMIN",
		RetVal:    -1,
	}
	m.CapabilityPolicyMatch(capRules, evData)

	if evData.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block", evData.PolicyAction)
	}
	if evData.PolicyName != "deny-netadmin" {
		t.Errorf("PolicyName = %q, want deny-netadmin", evData.PolicyName)
	}
}

// Allow-posture capability whitelist: a capability check from a non-whitelisted
// source that gets denied must be attributed to the allow policy (findCapAllowRule).
func TestCapabilityPolicyMatchAllowViolation(t *testing.T) {
	m := newTestSystemMonitor()
	capRules := tp.CapabilityRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerCapabilityRules{
			"/usr/sbin/tcpdump": {
				InnerAction: "Allow",
				InnerRules: map[uint32]tp.CapabilityRule{
					13: {CapID: 13, Name: "CAP_NET_RAW", Action: "Allow",
						Policy: tp.KloudKnoxPolicy{PolicyName: "tcpdump-only"}},
				},
				AllowRules: map[uint32]tp.CapabilityRule{
					13: {CapID: 13, Name: "CAP_NET_RAW", Action: "Allow",
						Policy: tp.KloudKnoxPolicy{PolicyName: "tcpdump-only"}},
				},
			},
		},
	}
	// nmap attempting CAP_NET_RAW — denied → attributed to tcpdump-only policy
	evData := &tp.EventData{
		Operation: "capable",
		Source:    "/usr/bin/nmap",
		Resource:  "CAP_NET_RAW",
		RetVal:    -1,
	}
	m.CapabilityPolicyMatch(capRules, evData)

	if evData.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block (allow-whitelist violation)", evData.PolicyAction)
	}
	if evData.PolicyName != "tcpdump-only" {
		t.Errorf("PolicyName = %q, want tcpdump-only", evData.PolicyName)
	}
}

// Non-capability ops must be ignored by CapabilityPolicyMatch.
func TestCapabilityPolicyMatchIgnoresNonCapOps(t *testing.T) {
	m := newTestSystemMonitor()
	capRules := tp.CapabilityRules{
		OuterRules: map[string]tp.InnerCapabilityRules{
			"default": {
				InnerRules: map[uint32]tp.CapabilityRule{
					13: {Name: "CAP_NET_RAW", Action: "Block"},
				},
			},
		},
	}
	evData := &tp.EventData{Operation: "open", Resource: "CAP_NET_RAW", RetVal: -1}
	m.CapabilityPolicyMatch(capRules, evData)
	if evData.PolicyName != "" {
		t.Error("CapabilityPolicyMatch must not set PolicyName for non-capable ops")
	}
}

// ============================== //
// ==  matchUnix / matchSignal == //
// ==  matchPtrace Tests       == //
// ============================== //

// matchUnixShape is retVal-agnostic — it asserts rule/event shape only.
// The retVal gate for Allow-posture attribution lives in ipcPolicyMatch.
func TestMatchUnixConnectShape(t *testing.T) {
	rule := tp.UnixRule{
		Type: "stream", Path: "/var/run/docker.sock",
		Permission: "connect", Action: "Block",
	}
	evData := &tp.EventData{Operation: "unix_connect", Resource: "/var/run/docker.sock", RetVal: -13}
	if !matchUnixShape(rule, evData) {
		t.Error("expected shape match for unix_connect")
	}
}

func TestMatchUnixTypeMismatch(t *testing.T) {
	// A stream rule must NOT match a dgram unix_send event.
	rule := tp.UnixRule{
		Type: "stream", Path: "/tmp/s",
		Permission: "connect", Action: "Block",
	}
	evData := &tp.EventData{Operation: "unix_send", Resource: "/tmp/s", RetVal: -13}
	if matchUnixShape(rule, evData) {
		t.Error("stream rule must not match unix_send event")
	}
}

func TestMatchUnixEmptyPathMatchesAny(t *testing.T) {
	rule := tp.UnixRule{
		Type: "stream", Path: "",
		Permission: "connect", Action: "Audit",
	}
	evData := &tp.EventData{Operation: "unix_connect", Resource: "/var/run/x.sock", RetVal: 0}
	if !matchUnixShape(rule, evData) {
		t.Error("empty path should match any peer on Audit + success")
	}
}

func TestExtractSignalNumber(t *testing.T) {
	cases := map[string]int{
		"pid: 123, tid: 123, sig: SIGTERM": 15,
		"pid: 1, tid: 1, sig: SIGHUP":      1,
		"pid: 0, tid: 0, sig: SIGKILL":     9,
		"pid: 0, tid: 0, sig: UNKNOWN":     0,
		"no signal here":                   0,
	}
	for data, want := range cases {
		if got := extractSignalNumber(data); got != want {
			t.Errorf("extractSignalNumber(%q) = %d, want %d", data, got, want)
		}
	}
}

func TestMatchSignalTargetAndBitmask(t *testing.T) {
	rule := tp.SignalRule{
		Target:  "/usr/bin/postgres",
		Signals: []int{15, 1}, // SIGTERM, SIGHUP
		Action:  "Audit",
	}
	evData := &tp.EventData{
		Operation: "kill",
		Resource:  "/usr/bin/postgres",
		Data:      "pid: 123, tid: 123, sig: SIGTERM",
		RetVal:    0,
	}
	if !matchSignalShape(rule, evData) {
		t.Error("expected match for Audit kill of listed signal on matching target")
	}
	// Signal not in list → no match.
	evData.Data = "pid: 123, tid: 123, sig: SIGKILL"
	if matchSignalShape(rule, evData) {
		t.Error("SIGKILL is not in rule.Signals, must not match")
	}
	// Target mismatch → no match.
	evData.Data = "pid: 123, tid: 123, sig: SIGTERM"
	evData.Resource = "/usr/bin/redis"
	if matchSignalShape(rule, evData) {
		t.Error("non-matching target must not match")
	}
}

func TestMatchSignalEmptyListMatchesAny(t *testing.T) {
	rule := tp.SignalRule{Action: "Block"}
	evData := &tp.EventData{Operation: "kill", Data: "pid: 1, tid: 1, sig: SIGUSR1", RetVal: -1}
	if !matchSignalShape(rule, evData) {
		t.Error("empty Signals list must match any signal on Block+denied")
	}
}

func TestMatchPtraceTargetMatch(t *testing.T) {
	rule := tp.PtraceRule{Permission: "trace", Target: "/usr/bin/postgres", Action: "Block"}
	evData := &tp.EventData{Operation: "ptrace", Resource: "/usr/bin/postgres", RetVal: -13}
	if !matchPtraceShape(rule, evData) {
		t.Error("expected match for Block ptrace trace on matching target")
	}
	evData.Resource = "/usr/bin/other"
	if matchPtraceShape(rule, evData) {
		t.Error("non-matching target must not match")
	}
}

func TestIPCPolicyMatchAnnotatesBlock(t *testing.T) {
	m := newTestSystemMonitor()
	ipcRules := tp.IPCRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerIPCRules{
			"default": {
				InnerAction: "Block",
				Unix: map[string]tp.UnixRule{
					"stream|/var/run/docker.sock|connect": {
						Policy:     tp.KloudKnoxPolicy{PolicyName: "deny-docker-sock"},
						Type:       "stream",
						Path:       "/var/run/docker.sock",
						Permission: "connect",
						Action:     "Block",
					},
				},
			},
		},
	}
	evData := &tp.EventData{
		Operation: "unix_connect",
		Resource:  "/var/run/docker.sock",
		RetVal:    -13,
	}
	m.IPCPolicyMatch(ipcRules, evData)
	if evData.PolicyName != "deny-docker-sock" {
		t.Errorf("expected PolicyName=deny-docker-sock, got %q", evData.PolicyName)
	}
	if evData.PolicyAction != "Block" {
		t.Errorf("expected PolicyAction=Block, got %q", evData.PolicyAction)
	}
}

func TestIPCPolicyMatchAllowAttribution(t *testing.T) {
	// A fromSource-narrowed Allow rule whitelists only its configured
	// source. A caller outside that whitelist hitting the same (type,
	// path, permission) shape gets a denied event that must be attributed
	// back to the allow policy — the policy's fromSource narrowing is
	// what caused AppArmor to block it.
	m := newTestSystemMonitor()
	ipcRules := tp.IPCRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerIPCRules{
			"/allowed-sender": {
				InnerAction: "Allow",
				Unix: map[string]tp.UnixRule{
					"stream|/ok|connect": {
						Policy:     tp.KloudKnoxPolicy{PolicyName: "allow-only-ok"},
						Type:       "stream",
						Path:       "/ok",
						Permission: "connect",
						Action:     "Allow",
					},
				},
				UnixAllow: map[string]tp.UnixRule{
					"stream|/ok|connect": {
						Policy:     tp.KloudKnoxPolicy{PolicyName: "allow-only-ok"},
						Type:       "stream",
						Path:       "/ok",
						Permission: "connect",
						Action:     "Allow",
					},
				},
			},
		},
	}
	evData := &tp.EventData{
		Operation: "unix_connect",
		Source:    "/other-sender",
		Resource:  "/ok",
		RetVal:    -13,
	}
	m.IPCPolicyMatch(ipcRules, evData)
	if evData.PolicyName != "allow-only-ok" {
		t.Errorf("expected allow attribution, got PolicyName=%q", evData.PolicyName)
	}
	if evData.PolicyAction != "Block" {
		t.Errorf("expected PolicyAction=Block on allow attribution, got %q", evData.PolicyAction)
	}
}

func TestIPCPolicyMatchRetValZeroSuppressesAllowAttribution(t *testing.T) {
	// An Allow rule with fromSource narrowing would normally attribute a
	// Block to any non-whitelisted caller hitting the same shape. But if
	// the kernel reports retVal=0 (the event was actually allowed), we
	// must not fabricate a Block alert — the rule wasn't violated.
	m := newTestSystemMonitor()
	ipcRules := tp.IPCRules{
		GlobalAction: "Allow",
		OuterRules: map[string]tp.InnerIPCRules{
			"/allowed-sender": {
				InnerAction: "Allow",
				Unix: map[string]tp.UnixRule{
					"stream|/ok|connect": {
						Policy:     tp.KloudKnoxPolicy{PolicyName: "allow-only-ok"},
						Type:       "stream",
						Path:       "/ok",
						Permission: "connect",
						Action:     "Allow",
					},
				},
				UnixAllow: map[string]tp.UnixRule{
					"stream|/ok|connect": {
						Policy:     tp.KloudKnoxPolicy{PolicyName: "allow-only-ok"},
						Type:       "stream",
						Path:       "/ok",
						Permission: "connect",
						Action:     "Allow",
					},
				},
			},
		},
	}
	evData := &tp.EventData{
		Operation: "unix_connect",
		Source:    "/other-sender",
		Resource:  "/ok",
		RetVal:    0,
	}
	m.IPCPolicyMatch(ipcRules, evData)
	if evData.PolicyName != "" || evData.PolicyAction != "" {
		t.Errorf("expected no attribution on retVal=0, got PolicyName=%q PolicyAction=%q",
			evData.PolicyName, evData.PolicyAction)
	}
}

// A fromSource-less Allow (stored under the "default" source) must
// whitelist every caller, not just callers whose exec path happens to
// be keyed in OuterRules — otherwise allow-posture attribution fires a
// spurious Block on a genuinely permitted event.
func TestIPCPolicyMatchDefaultBucketWhitelistsEvent(t *testing.T) {
	m := newTestSystemMonitor()
	ipcRules := tp.IPCRules{
		GlobalAction: "Block",
		OuterRules: map[string]tp.InnerIPCRules{
			"default": {
				InnerAction: "Allow",
				Signal: map[string]tp.SignalRule{
					"send|/bin/busybox|sigterm": {
						Policy:  tp.KloudKnoxPolicy{PolicyName: "signal-allow"},
						Target:  "/bin/busybox",
						Signals: []int{15},
						Action:  "Allow",
					},
				},
				SignalAllow: map[string]tp.SignalRule{
					"send|/bin/busybox|sigterm": {
						Policy:  tp.KloudKnoxPolicy{PolicyName: "signal-allow"},
						Target:  "/bin/busybox",
						Signals: []int{15},
						Action:  "Allow",
					},
				},
			},
		},
	}
	evData := &tp.EventData{
		Operation: "kill",
		Source:    "/bin/busybox",
		Resource:  "/bin/busybox",
		Data:      "pid: 42, sig: SIGTERM",
		RetVal:    0,
	}
	m.IPCPolicyMatch(ipcRules, evData)
	if evData.PolicyName != "" || evData.PolicyAction != "" {
		t.Errorf("expected default-bucket Allow to whitelist caller, got PolicyName=%q PolicyAction=%q",
			evData.PolicyName, evData.PolicyAction)
	}
}

func TestIPCPolicyMatchIgnoresUnrelatedOps(t *testing.T) {
	m := newTestSystemMonitor()
	ipcRules := tp.IPCRules{OuterRules: map[string]tp.InnerIPCRules{}}
	evData := &tp.EventData{Operation: "open", Resource: "/etc/passwd"}
	m.IPCPolicyMatch(ipcRules, evData)
	if evData.PolicyName != "" || evData.PolicyAction != "" {
		t.Error("IPCPolicyMatch must not touch file-ops events")
	}
}
