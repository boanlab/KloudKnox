// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"testing"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	securityv1 "github.com/boanlab/KloudKnox/operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================== //
// ==  convertIPBlock Tests    == //
// ============================== //

func TestConvertIPBlock(t *testing.T) {
	tests := []struct {
		name string
		in   securityv1.IPBlock
		want tp.IPBlock
	}{
		{
			"cidr only",
			securityv1.IPBlock{CIDR: "10.0.0.0/8"},
			tp.IPBlock{CIDR: "10.0.0.0/8"},
		},
		{
			"cidr with except",
			securityv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}},
			tp.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"}},
		},
		{
			"empty",
			securityv1.IPBlock{},
			tp.IPBlock{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertIPBlock(tt.in)
			if got.CIDR != tt.want.CIDR {
				t.Errorf("CIDR = %q, want %q", got.CIDR, tt.want.CIDR)
			}
			if len(got.Except) != len(tt.want.Except) {
				t.Errorf("Except len = %d, want %d", len(got.Except), len(tt.want.Except))
			}
		})
	}
}

// ============================== //
// ==  convertPorts Tests      == //
// ============================== //

func TestConvertPorts(t *testing.T) {
	in := []securityv1.Port{
		{Protocol: "tcp", Port: 80},
		{Protocol: "udp", Port: 53},
	}

	got := convertPorts(in)

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Protocol != "tcp" || got[0].Port != 80 {
		t.Errorf("got[0] = {%q %d}, want {tcp 80}", got[0].Protocol, got[0].Port)
	}
	if got[1].Protocol != "udp" || got[1].Port != 53 {
		t.Errorf("got[1] = {%q %d}, want {udp 53}", got[1].Protocol, got[1].Port)
	}
}

func TestConvertPortsEmpty(t *testing.T) {
	if got := convertPorts(nil); len(got) != 0 {
		t.Errorf("expected empty slice, got %d", len(got))
	}
}

// ================================== //
// ==  convertSourceMatches Tests  == //
// ================================== //

func TestConvertSourceMatches(t *testing.T) {
	in := []securityv1.SourceMatch{
		{Path: "/bin/sh"},
		{Path: "/usr/bin/curl"},
	}

	got := convertSourceMatches(in)

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Path != "/bin/sh" {
		t.Errorf("got[0].Path = %q, want /bin/sh", got[0].Path)
	}
	if got[1].Path != "/usr/bin/curl" {
		t.Errorf("got[1].Path = %q, want /usr/bin/curl", got[1].Path)
	}
}

// ================================== //
// ==  convertProcessRules Tests   == //
// ================================== //

func TestConvertProcessRules(t *testing.T) {
	in := []securityv1.ProcessRule{
		{
			Path:       "/bin/bash",
			Dir:        "",
			Recursive:  false,
			FromSource: []securityv1.SourceMatch{{Path: "/sbin/init"}},
			Action:     "Block",
		},
	}

	got := convertProcessRules(in)

	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	r := got[0]
	if r.Path != "/bin/bash" {
		t.Errorf("Path = %q, want /bin/bash", r.Path)
	}
	if r.Action != "Block" {
		t.Errorf("Action = %q, want Block", r.Action)
	}
	if len(r.FromSource) != 1 || r.FromSource[0].Path != "/sbin/init" {
		t.Errorf("FromSource = %v", r.FromSource)
	}
}

// ================================ //
// ==  convertFileRules Tests    == //
// ================================ //

func TestConvertFileRules(t *testing.T) {
	in := []securityv1.FileRule{
		{
			Path:     "/etc/passwd",
			ReadOnly: true,
			Action:   "Block",
		},
		{
			Dir:       "/tmp/",
			Recursive: true,
			Action:    "Allow",
		},
	}

	got := convertFileRules(in)

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Path != "/etc/passwd" || !got[0].ReadOnly || got[0].Action != "Block" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Dir != "/tmp/" || !got[1].Recursive || got[1].Action != "Allow" {
		t.Errorf("got[1] = %+v", got[1])
	}
}

// ================================== //
// ==  convertNetworkRules Tests   == //
// ================================== //

func TestConvertNetworkRules(t *testing.T) {
	in := []securityv1.NetworkRule{
		{
			Direction: "egress",
			IPBlock:   securityv1.IPBlock{CIDR: "0.0.0.0/0"},
			Ports:     []securityv1.Port{{Protocol: "tcp", Port: 443}},
			Action:    "Allow",
		},
		{
			Direction: "ingress",
			FQDN:      "api.example.com",
			Action:    "Block",
		},
	}

	got := convertNetworkRules(in)

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Direction != "egress" || got[0].IPBlock.CIDR != "0.0.0.0/0" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if len(got[0].Ports) != 1 || got[0].Ports[0].Port != 443 {
		t.Errorf("got[0].Ports = %+v", got[0].Ports)
	}
	if got[1].Direction != "ingress" || got[1].FQDN != "api.example.com" {
		t.Errorf("got[1] = %+v", got[1])
	}
}

// ==================================== //
// ==  convertKloudKnoxPolicy Tests  == //
// ==================================== //

func TestConvertKloudKnoxPolicy(t *testing.T) {
	policy := &securityv1.KloudKnoxPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
			UID:       "abc123",
		},
		Spec: securityv1.KloudKnoxPolicySpec{
			Selector: map[string]string{"app": "nginx"},
			Action:   "Block",
			Process: []securityv1.ProcessRule{
				{Path: "/bin/bash", Action: "Block"},
			},
			File: []securityv1.FileRule{
				{Path: "/etc/secret", ReadOnly: true, Action: "Block"},
			},
			Network: []securityv1.NetworkRule{
				{Direction: "egress", IPBlock: securityv1.IPBlock{CIDR: "10.0.0.0/8"}, Action: "Allow"},
			},
		},
	}

	got := convertKloudKnoxPolicy(policy)

	if got.PolicyName != "test-policy" {
		t.Errorf("PolicyName = %q, want test-policy", got.PolicyName)
	}
	if got.NamespaceName != "default" {
		t.Errorf("NamespaceName = %q, want default", got.NamespaceName)
	}
	if got.Action != "Block" {
		t.Errorf("Action = %q, want Block", got.Action)
	}
	if len(got.Process) != 1 {
		t.Errorf("Process len = %d, want 1", len(got.Process))
	}
	if len(got.File) != 1 {
		t.Errorf("File len = %d, want 1", len(got.File))
	}
	if len(got.Network) != 1 {
		t.Errorf("Network len = %d, want 1", len(got.Network))
	}
	// PolicyID is derived deterministically from the UID.
	if got.PolicyID == 0 {
		t.Error("PolicyID should be non-zero for non-empty UID")
	}
}

// ======================================= //
// ==  updateKloudKnoxPolicy Tests      == //
// ======================================= //

func newTestKnoxForPolicy() *KloudKnox {
	return &KloudKnox{GlobalData: tp.NewGlobalData()}
}

func TestUpdateKloudKnoxPolicy_AddNew(t *testing.T) {
	k8s := &K8sHandler{}
	knox := newTestKnoxForPolicy()

	policy := tp.KloudKnoxPolicy{
		NamespaceName: "default",
		PolicyName:    "policy-a",
	}

	k8s.updateKloudKnoxPolicy(knox, policy)

	policies := knox.GlobalData.RuntimePolicies["default"]
	if len(policies) != 1 {
		t.Fatalf("len = %d, want 1", len(policies))
	}
	if policies[0].PolicyName != "policy-a" {
		t.Errorf("PolicyName = %q, want policy-a", policies[0].PolicyName)
	}
}

func TestUpdateKloudKnoxPolicy_UpdateExisting(t *testing.T) {
	k8s := &K8sHandler{}
	knox := newTestKnoxForPolicy()

	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{
		NamespaceName: "default",
		PolicyName:    "policy-a",
		Action:        "Allow",
	})
	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{
		NamespaceName: "default",
		PolicyName:    "policy-a",
		Action:        "Block",
	})

	policies := knox.GlobalData.RuntimePolicies["default"]
	if len(policies) != 1 {
		t.Fatalf("len = %d, want 1 (no duplicate)", len(policies))
	}
	if policies[0].Action != "Block" {
		t.Errorf("Action = %q, want Block (updated)", policies[0].Action)
	}
}

func TestUpdateKloudKnoxPolicy_MultipleNamespaces(t *testing.T) {
	k8s := &K8sHandler{}
	knox := newTestKnoxForPolicy()

	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "ns-a", PolicyName: "p1"})
	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "ns-b", PolicyName: "p2"})

	if len(knox.GlobalData.RuntimePolicies["ns-a"]) != 1 {
		t.Error("expected 1 policy in ns-a")
	}
	if len(knox.GlobalData.RuntimePolicies["ns-b"]) != 1 {
		t.Error("expected 1 policy in ns-b")
	}
}

// ======================================= //
// ==  deleteKloudKnoxPolicy Tests      == //
// ======================================= //

func TestDeleteKloudKnoxPolicy_NotFound(t *testing.T) {
	k8s := &K8sHandler{}
	knox := newTestKnoxForPolicy()

	// Deleting from an unknown namespace must return without panicking.
	k8s.deleteKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{
		NamespaceName: "nonexistent",
		PolicyName:    "ghost",
	})
}

func TestDeleteKloudKnoxPolicy_Found(t *testing.T) {
	k8s := &K8sHandler{}
	knox := newTestKnoxForPolicy()

	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "default", PolicyName: "p1"})
	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "default", PolicyName: "p2"})

	k8s.deleteKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "default", PolicyName: "p1"})

	policies := knox.GlobalData.RuntimePolicies["default"]
	if len(policies) != 1 {
		t.Fatalf("len = %d, want 1", len(policies))
	}
	if policies[0].PolicyName != "p2" {
		t.Errorf("remaining policy = %q, want p2", policies[0].PolicyName)
	}
}

func TestDeleteKloudKnoxPolicy_NamespaceCleanup(t *testing.T) {
	k8s := &K8sHandler{}
	knox := newTestKnoxForPolicy()

	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "default", PolicyName: "only"})
	k8s.deleteKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "default", PolicyName: "only"})

	// Removing the last policy must also drop the namespace entry.
	if _, exists := knox.GlobalData.RuntimePolicies["default"]; exists {
		t.Error("namespace entry should be removed when the last policy is deleted")
	}
}

func TestDeleteKloudKnoxPolicy_NonExistentPolicy(t *testing.T) {
	k8s := &K8sHandler{}
	knox := newTestKnoxForPolicy()

	k8s.updateKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "default", PolicyName: "real"})

	// Deleting a non-existent policy must not affect the existing one.
	k8s.deleteKloudKnoxPolicy(knox, tp.KloudKnoxPolicy{NamespaceName: "default", PolicyName: "ghost"})

	if len(knox.GlobalData.RuntimePolicies["default"]) != 1 {
		t.Error("existing policy should not be affected by deleting a non-existent policy")
	}
}

// ============================== //
// ==  policyMatchesPod Tests  == //
// ============================== //

func TestPolicyMatchesPod_SelectorSubset(t *testing.T) {
	pod := tp.Pod{Identities: "app=web,image=nginx:1.25"}
	match := tp.KloudKnoxPolicy{Identities: "app=web"}
	noMatch := tp.KloudKnoxPolicy{Identities: "app=db"}

	if !policyMatchesPod(match, pod) {
		t.Error("policy whose identity is subset of pod identities must match")
	}
	if policyMatchesPod(noMatch, pod) {
		t.Error("policy whose identity is not subset must not match")
	}
}

func TestPolicyMatchesPod_ApplyToAllBypassesSelector(t *testing.T) {
	prev := cfg.GlobalCfg.Mode
	defer func() { cfg.GlobalCfg.Mode = prev }()
	cfg.GlobalCfg.Mode = cfg.ModeDocker

	pod := tp.Pod{Identities: ""}
	policy := tp.KloudKnoxPolicy{ApplyToAll: true, Identities: "docker.name=some-other-name"}

	if !policyMatchesPod(policy, pod) {
		t.Error("applyToAll must match every pod in docker mode, regardless of identities")
	}
}

func TestPolicyMatchesPod_ApplyToAllIgnoredInK8sMode(t *testing.T) {
	prev := cfg.GlobalCfg.Mode
	defer func() { cfg.GlobalCfg.Mode = prev }()
	cfg.GlobalCfg.Mode = cfg.ModeKubernetes

	pod := tp.Pod{Identities: ""}
	policy := tp.KloudKnoxPolicy{ApplyToAll: true, Identities: "app=web"}

	if policyMatchesPod(policy, pod) {
		t.Error("applyToAll must be ignored in kubernetes mode — selector match should still apply")
	}
}
