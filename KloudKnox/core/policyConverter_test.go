// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"testing"

	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// ============================== //
// ==  SafeInt32ToUint16 Tests == //
// ============================== //

func TestSafeInt32ToUint16(t *testing.T) {
	tests := []struct {
		name  string
		input int32
		want  uint16
	}{
		{"zero", 0, 0},
		{"positive in range", 443, 443},
		{"max uint16", 65535, 65535},
		{"above max", 65536, 0},
		{"negative", -1, 0},
		{"large negative", -100, 0},
		{"http port", 80, 80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafeInt32ToUint16(tt.input)
			if got != tt.want {
				t.Errorf("SafeInt32ToUint16(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ================================= //
// ==  determinePathAndType Tests == //
// ================================= //

func TestDeterminePathAndType(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		dir      string
		wantPath string
		wantType string
	}{
		{"path only", "/bin/ls", "", "/bin/ls", "path"},
		{"dir only", "", "/etc/", "/etc/", "dir"},
		{"both empty", "", "", "", ""},
		{"both set", "/bin/ls", "/etc/", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotType := determinePathAndType(tt.path, tt.dir)
			if gotPath != tt.wantPath || gotType != tt.wantType {
				t.Errorf("determinePathAndType(%q, %q) = (%q, %q), want (%q, %q)",
					tt.path, tt.dir, gotPath, gotType, tt.wantPath, tt.wantType)
			}
		})
	}
}

// ================================== //
// ==  getProcessPermission Tests  == //
// ================================== //

func TestGetProcessPermission(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"Allow", "X"},
		{"Audit", "X"},
		{"Block", "x"},
		{"Unknown", "x"},
		{"", "x"},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := getProcessPermission(tt.action)
			if got != tt.want {
				t.Errorf("getProcessPermission(%q) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

// ================================ //
// ==  getFilePermission Tests   == //
// ================================ //

func TestGetFilePermission(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		readOnly bool
		want     string
	}{
		{"allow read-only", "Allow", true, "R"},
		{"audit read-only", "Audit", true, "W"},
		{"block read-only", "Block", true, "w"},
		{"allow read-write", "Allow", false, "RW"},
		{"audit read-write", "Audit", false, "RW"},
		{"block read-write", "Block", false, "rw"},
		{"unknown read-only", "Unknown", true, "w"},
		{"unknown read-write", "Unknown", false, "rw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFilePermission(tt.action, tt.readOnly)
			if got != tt.want {
				t.Errorf("getFilePermission(%q, %v) = %q, want %q", tt.action, tt.readOnly, got, tt.want)
			}
		})
	}
}

// ============================== //
// ==  getNetworkTarget Tests  == //
// ============================== //

func TestGetNetworkTarget(t *testing.T) {
	tests := []struct {
		name string
		rule tp.KloudKnoxNetworkRule
		want string
	}{
		{
			"cidr target",
			tp.KloudKnoxNetworkRule{IPBlock: tp.IPBlock{CIDR: "10.0.0.0/8"}},
			"cidr:10.0.0.0/8",
		},
		{
			"fqdn target",
			tp.KloudKnoxNetworkRule{FQDN: "api.example.com"},
			"fqdn:api.example.com",
		},
		{
			"empty rule",
			tp.KloudKnoxNetworkRule{},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNetworkTarget(tt.rule)
			if got != tt.want {
				t.Errorf("getNetworkTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ================================ //
// ==  buildFileRules Tests      == //
// ================================ //

func TestBuildFileRulesEmpty(t *testing.T) {
	pod := tp.Pod{}
	rules := buildFileRules(pod)

	if rules.GlobalAction != "Block" {
		t.Errorf("GlobalAction = %q, want %q", rules.GlobalAction, "Block")
	}
	if len(rules.OuterRules) != 0 {
		t.Errorf("OuterRules should be empty, got %d entries", len(rules.OuterRules))
	}
}

func TestBuildFileRulesBlockProcess(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "block-cat",
				Action:     "Block",
				Process: []tp.KloudKnoxProcessRule{
					{Path: "/bin/cat", Action: "Block"},
				},
			},
		},
	}

	rules := buildFileRules(pod)

	if rules.GlobalAction != "Block" {
		t.Errorf("GlobalAction = %q, want %q", rules.GlobalAction, "Block")
	}

	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[\"default\"]")
	}

	rule, ok := inner.InnerRules["/bin/cat"]
	if !ok {
		t.Fatal("expected InnerRules[\"/bin/cat\"]")
	}
	if rule.Permission != "x" {
		t.Errorf("Permission = %q, want %q", rule.Permission, "x")
	}
	if rule.Action != "Block" {
		t.Errorf("Action = %q, want %q", rule.Action, "Block")
	}
}

func TestBuildFileRulesAllowMode(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "allow-ls",
				Action:     "Allow",
				Process: []tp.KloudKnoxProcessRule{
					{Path: "/bin/ls", Action: "Allow"},
				},
			},
		},
	}

	rules := buildFileRules(pod)

	if rules.GlobalAction != "Allow" {
		t.Errorf("GlobalAction = %q, want Allow", rules.GlobalAction)
	}

	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[\"default\"]")
	}
	// Allow rules are moved to AllowRules by extractAllowRules
	if _, ok := inner.AllowRules["/bin/ls"]; !ok {
		t.Error("expected /bin/ls in AllowRules")
	}
}

func TestBuildFileRulesWithSource(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "source-rule",
				Process: []tp.KloudKnoxProcessRule{
					{
						Path:       "/bin/ls",
						Action:     "Block",
						FromSource: []tp.SourceMatch{{Path: "/bin/sh"}},
					},
				},
			},
		},
	}

	rules := buildFileRules(pod)

	if _, ok := rules.OuterRules["/bin/sh"]; !ok {
		t.Error("expected OuterRules[\"/bin/sh\"] for source-specific rule")
	}
	if _, ok := rules.OuterRules["default"]; ok {
		t.Error("default source should not exist when FromSource is specified")
	}
}

func TestBuildFileRulesReadOnlyFile(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "readonly-policy",
				File: []tp.KloudKnoxFileRule{
					{Path: "/etc/passwd", ReadOnly: true, Action: "Block"},
				},
			},
		},
	}

	rules := buildFileRules(pod)

	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[\"default\"]")
	}
	rule, ok := inner.InnerRules["/etc/passwd"]
	if !ok {
		t.Fatal("expected InnerRules[\"/etc/passwd\"]")
	}
	// Block + ReadOnly → "w"
	if rule.Permission != "w" {
		t.Errorf("Permission = %q, want %q", rule.Permission, "w")
	}
}

// ================================ //
// ==  buildNetworkRules Tests   == //
// ================================ //

func TestBuildNetworkRulesEmpty(t *testing.T) {
	pod := tp.Pod{}
	rules := buildNetworkRules(pod)

	if len(rules.IngressRules) != 0 || len(rules.EgressRules) != 0 {
		t.Error("expected empty network rules for empty pod")
	}
}

func TestBuildNetworkRulesEgressCIDR(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "allow-internal",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						IPBlock:   tp.IPBlock{CIDR: "10.0.0.0/8"},
						Action:    "Allow",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner, ok := rules.EgressRules["default"]
	if !ok {
		t.Fatal("expected EgressRules[\"default\"]")
	}

	rule, ok := inner.InnerRules["cidr:10.0.0.0/8"]
	if !ok {
		t.Fatal("expected InnerRules[\"cidr:10.0.0.0/8\"]")
	}
	if rule.Action != "Allow" {
		t.Errorf("Action = %q, want Allow", rule.Action)
	}
}

func TestBuildNetworkRulesDefaultPostureBlockWhenAllowRuleExists(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "policy",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						IPBlock:   tp.IPBlock{CIDR: "10.0.0.0/8"},
						Action:    "Allow",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner := rules.EgressRules["default"]
	// Allow rules → DefaultPosture should be "Block"
	if inner.DefaultPosture != "Block" {
		t.Errorf("DefaultPosture = %q, want Block", inner.DefaultPosture)
	}
}

func TestBuildNetworkRulesDefaultPostureAllowWhenBlockRuleOnly(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "policy",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						IPBlock:   tp.IPBlock{CIDR: "192.168.0.0/16"},
						Action:    "Block",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner := rules.EgressRules["default"]
	if inner.DefaultPosture != "Allow" {
		t.Errorf("DefaultPosture = %q, want Allow", inner.DefaultPosture)
	}
}

func TestBuildNetworkRulesFQDN(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "fqdn-policy",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						FQDN:      "api.example.com",
						Action:    "Allow",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner, ok := rules.EgressRules["default"]
	if !ok {
		t.Fatal("expected EgressRules[\"default\"]")
	}
	if _, ok := inner.InnerRules["fqdn:api.example.com"]; !ok {
		t.Error("expected InnerRules[\"fqdn:api.example.com\"]")
	}
}

func TestBuildNetworkRulesWithPorts(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "port-policy",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						IPBlock:   tp.IPBlock{CIDR: "0.0.0.0/0"},
						Ports: []tp.Port{
							{Protocol: "tcp", Port: 443},
							{Protocol: "tcp", Port: 80},
						},
						Action: "Allow",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner := rules.EgressRules["default"]
	rule, ok := inner.InnerRules["cidr:0.0.0.0/0"]
	if !ok {
		t.Fatal("expected rule for cidr:0.0.0.0/0")
	}

	tcpPorts := rule.Ports["tcp"]
	if len(tcpPorts) != 2 {
		t.Errorf("expected 2 TCP ports, got %d", len(tcpPorts))
	}
}

// ============================================= //
// ==  getNetworkTarget — selector handling   == //
// ============================================= //

func TestGetNetworkTargetSelector(t *testing.T) {
	rule := tp.KloudKnoxNetworkRule{
		Selector: map[string]string{"app": "nginx"},
	}
	got := getNetworkTarget(rule)
	// Selector rules must produce a "selector:app=nginx" style target.
	if got == "" {
		t.Error("expected non-empty target for selector rule")
	}
	if len(got) < 9 || got[:9] != "selector:" {
		t.Errorf("expected target to start with 'selector:', got %q", got)
	}
}

// Selector takes precedence over cidr / fqdn.
func TestGetNetworkTargetSelectorPriority(t *testing.T) {
	rule := tp.KloudKnoxNetworkRule{
		Selector: map[string]string{"app": "web"},
		IPBlock:  tp.IPBlock{CIDR: "10.0.0.0/8"},
	}
	got := getNetworkTarget(rule)
	if len(got) < 9 || got[:9] != "selector:" {
		t.Errorf("selector should take priority over cidr, got %q", got)
	}
}

// ============================================= //
// ==  buildNetworkRules — extra combinations == //
// ============================================= //

// Ingress direction.
func TestBuildNetworkRulesIngress(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "block-ingress",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "ingress",
						IPBlock:   tp.IPBlock{CIDR: "0.0.0.0/0"},
						Action:    "Block",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	if len(rules.EgressRules) != 0 {
		t.Errorf("expected no egress rules, got %d", len(rules.EgressRules))
	}
	inner, ok := rules.IngressRules["default"]
	if !ok {
		t.Fatal("expected IngressRules[\"default\"]")
	}
	if _, ok := inner.InnerRules["cidr:0.0.0.0/0"]; !ok {
		t.Error("expected ingress rule for cidr:0.0.0.0/0")
	}
}

// Audit action
func TestBuildNetworkRulesAuditAction(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "audit-egress",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						IPBlock:   tp.IPBlock{CIDR: "10.0.0.0/8"},
						Action:    "Audit",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner := rules.EgressRules["default"]
	rule, ok := inner.InnerRules["cidr:10.0.0.0/8"]
	if !ok {
		t.Fatal("expected rule for cidr:10.0.0.0/8")
	}
	if rule.Action != "Audit" {
		t.Errorf("Action = %q, want Audit", rule.Action)
	}
	// With Audit-only rules, DefaultPosture must remain Allow.
	if inner.DefaultPosture != "Allow" {
		t.Errorf("DefaultPosture = %q, want Allow for Audit-only rules", inner.DefaultPosture)
	}
}

// Selector-based target.
func TestBuildNetworkRulesSelector(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "selector-policy",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						Selector:  map[string]string{"app": "db"},
						Action:    "Allow",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner, ok := rules.EgressRules["default"]
	if !ok {
		t.Fatal("expected EgressRules[\"default\"]")
	}
	found := false
	for target := range inner.InnerRules {
		if len(target) >= 9 && target[:9] == "selector:" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a selector: target in EgressRules")
	}
}

// fromSource
func TestBuildNetworkRulesFromSource(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "source-net-policy",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction:  "egress",
						IPBlock:    tp.IPBlock{CIDR: "8.8.8.8/32"},
						Action:     "Allow",
						FromSource: []tp.SourceMatch{{Path: "/usr/bin/curl"}},
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	if _, ok := rules.EgressRules["default"]; ok {
		t.Error("default source should not exist when FromSource is specified")
	}
	if _, ok := rules.EgressRules["/usr/bin/curl"]; !ok {
		t.Error("expected EgressRules[\"/usr/bin/curl\"] for source-specific rule")
	}
}

// Verify ipBlock.except is propagated into the CIDRExcept field.
func TestBuildNetworkRulesCIDRExcept(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "allow-with-except",
				Network: []tp.KloudKnoxNetworkRule{
					{
						Direction: "egress",
						IPBlock: tp.IPBlock{
							CIDR:   "10.0.0.0/8",
							Except: []string{"10.1.0.0/16", "10.2.0.0/16"},
						},
						Action: "Allow",
					},
				},
			},
		},
	}

	rules := buildNetworkRules(pod)

	inner, ok := rules.EgressRules["default"]
	if !ok {
		t.Fatal("expected EgressRules[\"default\"]")
	}
	rule, ok := inner.InnerRules["cidr:10.0.0.0/8"]
	if !ok {
		t.Fatal("expected rule for cidr:10.0.0.0/8")
	}
	if len(rule.CIDRExcept) != 2 {
		t.Errorf("CIDRExcept len = %d, want 2", len(rule.CIDRExcept))
	}
	exceptSet := map[string]bool{}
	for _, e := range rule.CIDRExcept {
		exceptSet[e] = true
	}
	if !exceptSet["10.1.0.0/16"] {
		t.Error("expected 10.1.0.0/16 in CIDRExcept")
	}
	if !exceptSet["10.2.0.0/16"] {
		t.Error("expected 10.2.0.0/16 in CIDRExcept")
	}
}

// ============================================= //
// ==  buildFileRules — extra combinations    == //
// ============================================= //

// dir non-recursive
func TestBuildFileRulesDirNonRecursive(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "dir-policy",
				File: []tp.KloudKnoxFileRule{
					{Dir: "/tmp/", Recursive: false, Action: "Block"},
				},
			},
		},
	}

	rules := buildFileRules(pod)

	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[\"default\"]")
	}
	rule, ok := inner.InnerRules["/tmp/"]
	if !ok {
		t.Fatal("expected InnerRules[\"/tmp/\"]")
	}
	if !rule.IsDir {
		t.Error("expected IsDir=true")
	}
	if rule.Recursive {
		t.Error("expected Recursive=false")
	}
}

// dir recursive
func TestBuildFileRulesDirRecursive(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "recursive-dir-policy",
				File: []tp.KloudKnoxFileRule{
					{Dir: "/data/", Recursive: true, Action: "Block"},
				},
			},
		},
	}

	rules := buildFileRules(pod)

	inner := rules.OuterRules["default"]
	rule, ok := inner.InnerRules["/data/"]
	if !ok {
		t.Fatal("expected InnerRules[\"/data/\"]")
	}
	if !rule.Recursive {
		t.Error("expected Recursive=true")
	}
}

// Audit process
func TestBuildFileRulesAuditProcess(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "audit-proc",
				Process: []tp.KloudKnoxProcessRule{
					{Path: "/bin/bash", Action: "Audit"},
				},
			},
		},
	}

	rules := buildFileRules(pod)

	inner := rules.OuterRules["default"]
	rule, ok := inner.InnerRules["/bin/bash"]
	if !ok {
		t.Fatal("expected InnerRules[\"/bin/bash\"]")
	}
	if rule.Action != "Audit" {
		t.Errorf("Action = %q, want Audit", rule.Action)
	}
	// Audit on exec → Permission "X" (both Allow and Audit use "X").
	if rule.Permission != "X" {
		t.Errorf("Permission = %q, want X for Audit process", rule.Permission)
	}
}

// =================================== //
// ==  buildCapabilityRules Tests   == //
// =================================== //

func TestBuildCapabilityRulesEmpty(t *testing.T) {
	pod := tp.Pod{}
	rules := buildCapabilityRules(pod)

	if rules.GlobalAction != "Block" {
		t.Errorf("GlobalAction = %q, want %q", rules.GlobalAction, "Block")
	}
	if len(rules.OuterRules) != 0 {
		t.Errorf("OuterRules should be empty, got %d entries", len(rules.OuterRules))
	}
}

func TestBuildCapabilityRulesAllowWithFromSource(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "tcpdump-only",
				Action:     "Block",
				Capability: []tp.KloudKnoxCapabilityRule{
					{
						Name:       "CAP_NET_RAW",
						CapID:      13,
						FromSource: []tp.SourceMatch{{Path: "/usr/sbin/tcpdump"}},
						Action:     "Allow",
					},
				},
			},
		},
	}

	rules := buildCapabilityRules(pod)

	// Policy.Action is Block, so global default must stay Block.
	if rules.GlobalAction != "Block" {
		t.Errorf("GlobalAction = %q, want Block", rules.GlobalAction)
	}
	inner, ok := rules.OuterRules["/usr/sbin/tcpdump"]
	if !ok {
		t.Fatal("expected OuterRules[/usr/sbin/tcpdump]")
	}
	if inner.InnerAction != "Allow" {
		t.Errorf("InnerAction = %q, want Allow", inner.InnerAction)
	}
	rule, ok := inner.InnerRules[13]
	if !ok {
		t.Fatal("expected InnerRules[13]")
	}
	if rule.Action != "Allow" || rule.Name != "CAP_NET_RAW" {
		t.Errorf("rule = %+v, want Action=Allow Name=CAP_NET_RAW", rule)
	}
	if _, ok := inner.AllowRules[13]; !ok {
		t.Error("expected AllowRules[13] after extraction")
	}
}

func TestBuildCapabilityRulesBlockContainerWide(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "deny-net-admin",
				Action:     "Allow",
				Capability: []tp.KloudKnoxCapabilityRule{
					{Name: "CAP_NET_ADMIN", CapID: 12, Action: "Block"},
				},
			},
		},
	}

	rules := buildCapabilityRules(pod)

	// Policy.Action=Allow means the global posture is Allow (blacklist mode).
	if rules.GlobalAction != "Allow" {
		t.Errorf("GlobalAction = %q, want Allow", rules.GlobalAction)
	}
	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[default]")
	}
	rule := inner.InnerRules[12]
	if rule.Action != "Block" {
		t.Errorf("Action = %q, want Block", rule.Action)
	}
	if len(inner.AllowRules) != 0 {
		t.Errorf("AllowRules should be empty for Block rule, got %d", len(inner.AllowRules))
	}
}

func TestBuildCapabilityRulesInheritsPolicyAction(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "audit-ipc",
				Action:     "Audit",
				Capability: []tp.KloudKnoxCapabilityRule{
					// No per-rule Action — must inherit the policy Action.
					{Name: "CAP_IPC_LOCK", CapID: 14},
				},
			},
		},
	}

	rules := buildCapabilityRules(pod)

	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[default]")
	}
	rule := inner.InnerRules[14]
	if rule.Action != "Audit" {
		t.Errorf("Action = %q, want Audit (inherited)", rule.Action)
	}
}

func TestBuildCapabilityRulesSkipsEmpty(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{PolicyName: "no-caps", Action: "Block"},
		},
	}

	rules := buildCapabilityRules(pod)

	if len(rules.OuterRules) != 0 {
		t.Errorf("OuterRules should be empty for policy without capabilities, got %d", len(rules.OuterRules))
	}
}

// =============================== //
// ==  buildIPCRules Tests      == //
// =============================== //

func TestBuildIPCRulesEmpty(t *testing.T) {
	rules := buildIPCRules(tp.Pod{})
	if rules.GlobalAction != "Block" {
		t.Errorf("GlobalAction = %q, want Block", rules.GlobalAction)
	}
	if len(rules.OuterRules) != 0 {
		t.Errorf("OuterRules should be empty, got %d entries", len(rules.OuterRules))
	}
}

func TestBuildIPCRulesUnixBlockContainerWide(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "no-docker-sock",
				Action:     "Allow",
				IPC: tp.KloudKnoxIPCRules{
					Unix: []tp.KloudKnoxUnixRule{
						{
							Type:        "stream",
							Path:        "/var/run/docker.sock",
							Permissions: []string{"connect", "send"},
							Action:      "Block",
						},
					},
				},
			},
		},
	}

	rules := buildIPCRules(pod)

	if rules.GlobalAction != "Allow" {
		t.Errorf("GlobalAction = %q, want Allow", rules.GlobalAction)
	}
	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[default]")
	}
	// Two permissions should fan out into two internal rules.
	if len(inner.Unix) != 2 {
		t.Errorf("Unix rules count = %d, want 2 (fan-out)", len(inner.Unix))
	}
	for key, rule := range inner.Unix {
		if rule.Action != "Block" {
			t.Errorf("rule %q Action = %q, want Block", key, rule.Action)
		}
		if rule.Path != "/var/run/docker.sock" {
			t.Errorf("rule %q Path = %q, want /var/run/docker.sock", key, rule.Path)
		}
	}
	if len(inner.UnixAllow) != 0 {
		t.Errorf("UnixAllow should be empty for Block-only rule, got %d", len(inner.UnixAllow))
	}
}

func TestBuildIPCRulesUnixAllowWithFromSource(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "docker-cli-only",
				Action:     "Block",
				IPC: tp.KloudKnoxIPCRules{
					Unix: []tp.KloudKnoxUnixRule{
						{
							Type:        "stream",
							Path:        "/var/run/docker.sock",
							Permissions: []string{"connect"},
							FromSource:  []tp.SourceMatch{{Path: "/usr/bin/docker"}},
							Action:      "Allow",
						},
					},
				},
			},
		},
	}

	rules := buildIPCRules(pod)

	inner, ok := rules.OuterRules["/usr/bin/docker"]
	if !ok {
		t.Fatal("expected OuterRules[/usr/bin/docker]")
	}
	if inner.InnerAction != "Allow" {
		t.Errorf("InnerAction = %q, want Allow", inner.InnerAction)
	}
	if len(inner.UnixAllow) != 1 {
		t.Errorf("UnixAllow should have 1 entry, got %d", len(inner.UnixAllow))
	}
}

func TestBuildIPCRulesSignalInheritsPolicyAction(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "audit-signals",
				Action:     "Audit",
				IPC: tp.KloudKnoxIPCRules{
					Signal: []tp.KloudKnoxSignalRule{
						{
							Target:  "/usr/bin/init",
							Signals: []string{"SIGTERM", "SIGHUP"},
						},
					},
				},
			},
		},
	}

	rules := buildIPCRules(pod)
	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[default]")
	}
	if len(inner.Signal) != 1 {
		t.Errorf("Signal rules count = %d, want 1", len(inner.Signal))
	}
	for _, rule := range inner.Signal {
		if rule.Action != "Audit" {
			t.Errorf("Signal Action = %q, want Audit (inherited)", rule.Action)
		}
		if len(rule.Signals) != 2 {
			t.Errorf("resolved signals = %v, want 2 entries (15,1)", rule.Signals)
		}
	}
}

func TestBuildIPCRulesSignalDropsUnknown(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "bad-signals",
				Action:     "Block",
				IPC: tp.KloudKnoxIPCRules{
					Signal: []tp.KloudKnoxSignalRule{
						{
							Signals: []string{"SIGBOGUS", "SIGTERM"},
							Action:  "Block",
						},
					},
				},
			},
		},
	}

	rules := buildIPCRules(pod)
	inner := rules.OuterRules["default"]
	for _, rule := range inner.Signal {
		if len(rule.Signals) != 1 || rule.Signals[0] != 15 {
			t.Errorf("Signals = %v, want [15] (SIGBOGUS dropped)", rule.Signals)
		}
	}
}

func TestBuildIPCRulesPtraceBlock(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "block-ptrace",
				Action:     "Allow",
				IPC: tp.KloudKnoxIPCRules{
					Ptrace: []tp.KloudKnoxPtraceRule{
						{
							Permission: "trace",
							Target:     "/usr/bin/sshd",
							Action:     "Block",
						},
					},
				},
			},
		},
	}

	rules := buildIPCRules(pod)
	inner, ok := rules.OuterRules["default"]
	if !ok {
		t.Fatal("expected OuterRules[default]")
	}
	if len(inner.Ptrace) != 1 {
		t.Errorf("Ptrace rules count = %d, want 1", len(inner.Ptrace))
	}
	for _, rule := range inner.Ptrace {
		if rule.Action != "Block" || rule.Permission != "trace" {
			t.Errorf("rule = %+v, want Action=Block Permission=trace", rule)
		}
	}
	if len(inner.PtraceAllow) != 0 {
		t.Errorf("PtraceAllow should be empty for Block-only, got %d", len(inner.PtraceAllow))
	}
}

func TestBuildIPCRulesSkipsNoAction(t *testing.T) {
	pod := tp.Pod{
		RuntimePolicies: []tp.KloudKnoxPolicy{
			{
				PolicyName: "no-action-anywhere",
				// Policy.Action empty + per-rule Action empty → rule must be skipped
				IPC: tp.KloudKnoxIPCRules{
					Unix: []tp.KloudKnoxUnixRule{
						{Type: "stream", Path: "/var/run/x.sock", Permissions: []string{"connect"}},
					},
				},
			},
		},
	}
	rules := buildIPCRules(pod)
	if inner, ok := rules.OuterRules["default"]; ok && len(inner.Unix) != 0 {
		t.Errorf("rule with no resolvable action should be dropped, got %d rules", len(inner.Unix))
	}
}

func TestSignalsCanonicalKeyOrderIndependent(t *testing.T) {
	a := signalsCanonicalKey([]int{15, 1, 9})
	b := signalsCanonicalKey([]int{9, 15, 1})
	if a != b {
		t.Errorf("canonical keys differ: %q vs %q (must be order-independent)", a, b)
	}
	if empty := signalsCanonicalKey(nil); empty != "*" {
		t.Errorf("empty signals key = %q, want %q", empty, "*")
	}
}
