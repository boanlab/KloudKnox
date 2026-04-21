// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"testing"

	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// =================================================== //
// ==  UpdateMatchedNetworkPolicy Tests             == //
// =================================================== //

func newTestNetworkEnforcer() *NetworkEnforcer {
	// NetworkEnforcer with nil FqdnResolver — safe because
	// UpdateMatchedNetworkPolicy guards with ne.FqdnResolver != nil.
	return &NetworkEnforcer{}
}

func emptyNetworkRules() *tp.NetworkRules {
	return &tp.NetworkRules{
		IngressRules: make(map[string]tp.InnerNetworkRules),
		EgressRules:  make(map[string]tp.InnerNetworkRules),
	}
}

func TestUpdateMatchedNetworkPolicyDefaultAllow(t *testing.T) {
	ne := newTestNetworkEnforcer()
	evData := &tp.EventData{}

	ne.UpdateMatchedNetworkPolicy(emptyNetworkRules(), evData, 1)

	if evData.PolicyName != "DefaultPosture" {
		t.Errorf("PolicyName = %q, want DefaultPosture", evData.PolicyName)
	}
	if evData.PolicyAction != "Allow" {
		t.Errorf("PolicyAction = %q, want Allow", evData.PolicyAction)
	}
}

func TestUpdateMatchedNetworkPolicyDefaultBlock(t *testing.T) {
	ne := newTestNetworkEnforcer()
	evData := &tp.EventData{}

	ne.UpdateMatchedNetworkPolicy(emptyNetworkRules(), evData, 2)

	if evData.PolicyName != "DefaultPosture" {
		t.Errorf("PolicyName = %q, want DefaultPosture", evData.PolicyName)
	}
	if evData.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block", evData.PolicyAction)
	}
}

func TestUpdateMatchedNetworkPolicyNoMatch(t *testing.T) {
	ne := newTestNetworkEnforcer()
	evData := &tp.EventData{Operation: "connect"}

	ne.UpdateMatchedNetworkPolicy(emptyNetworkRules(), evData, 999)

	// No matching policy → fields should remain empty
	if evData.PolicyName != "" {
		t.Errorf("PolicyName = %q, want empty for no-match", evData.PolicyName)
	}
	if evData.PolicyAction != "" {
		t.Errorf("PolicyAction = %q, want empty for no-match", evData.PolicyAction)
	}
}

func TestUpdateMatchedNetworkPolicyEgressMatch(t *testing.T) {
	ne := newTestNetworkEnforcer()

	networkRules := &tp.NetworkRules{
		IngressRules: make(map[string]tp.InnerNetworkRules),
		EgressRules: map[string]tp.InnerNetworkRules{
			"default": {
				InnerRules: map[string]tp.NetworkRule{
					"cidr:10.0.0.0/8": {
						Policy: tp.KloudKnoxPolicy{
							PolicyID:   42,
							PolicyName: "allow-internal",
						},
						Action: "Allow",
					},
				},
			},
		},
	}

	evData := &tp.EventData{Operation: "connect"}

	ne.UpdateMatchedNetworkPolicy(networkRules, evData, 42)

	if evData.PolicyName != "allow-internal" {
		t.Errorf("PolicyName = %q, want allow-internal", evData.PolicyName)
	}
	if evData.PolicyAction != "Allow" {
		t.Errorf("PolicyAction = %q, want Allow", evData.PolicyAction)
	}
}

func TestUpdateMatchedNetworkPolicyIngressMatch(t *testing.T) {
	ne := newTestNetworkEnforcer()

	networkRules := &tp.NetworkRules{
		IngressRules: map[string]tp.InnerNetworkRules{
			"default": {
				InnerRules: map[string]tp.NetworkRule{
					"cidr:0.0.0.0/0": {
						Policy: tp.KloudKnoxPolicy{
							PolicyID:   77,
							PolicyName: "deny-all-ingress",
						},
						Action: "Block",
					},
				},
			},
		},
		EgressRules: make(map[string]tp.InnerNetworkRules),
	}

	evData := &tp.EventData{Operation: "accept"}

	ne.UpdateMatchedNetworkPolicy(networkRules, evData, 77)

	if evData.PolicyName != "deny-all-ingress" {
		t.Errorf("PolicyName = %q, want deny-all-ingress", evData.PolicyName)
	}
	if evData.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block", evData.PolicyAction)
	}
}

func TestUpdateMatchedNetworkPolicyUDPSendmsg(t *testing.T) {
	ne := newTestNetworkEnforcer()

	networkRules := &tp.NetworkRules{
		IngressRules: make(map[string]tp.InnerNetworkRules),
		EgressRules: map[string]tp.InnerNetworkRules{
			"default": {
				InnerRules: map[string]tp.NetworkRule{
					"cidr:8.8.8.8/32": {
						Policy: tp.KloudKnoxPolicy{
							PolicyID:   55,
							PolicyName: "allow-dns",
						},
						Action: "Allow",
					},
				},
			},
		},
	}

	evData := &tp.EventData{Operation: "udp_sendmsg"}

	ne.UpdateMatchedNetworkPolicy(networkRules, evData, 55)

	if evData.PolicyName != "allow-dns" {
		t.Errorf("PolicyName = %q, want allow-dns", evData.PolicyName)
	}
}

// udp_recvmsg — UDP ingress path.
func TestUpdateMatchedNetworkPolicyUDPRecvmsg(t *testing.T) {
	ne := newTestNetworkEnforcer()

	networkRules := &tp.NetworkRules{
		IngressRules: map[string]tp.InnerNetworkRules{
			"default": {
				InnerRules: map[string]tp.NetworkRule{
					"cidr:0.0.0.0/0": {
						Policy: tp.KloudKnoxPolicy{
							PolicyID:   88,
							PolicyName: "block-udp-ingress",
						},
						Action: "Block",
					},
				},
			},
		},
		EgressRules: make(map[string]tp.InnerNetworkRules),
	}

	evData := &tp.EventData{Operation: "udp_recvmsg"}

	ne.UpdateMatchedNetworkPolicy(networkRules, evData, 88)

	if evData.PolicyName != "block-udp-ingress" {
		t.Errorf("PolicyName = %q, want block-udp-ingress", evData.PolicyName)
	}
	if evData.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block", evData.PolicyAction)
	}
}

// "egress" operation — cgroup_skb egress path.
func TestUpdateMatchedNetworkPolicyCgroupEgress(t *testing.T) {
	ne := newTestNetworkEnforcer()

	networkRules := &tp.NetworkRules{
		IngressRules: make(map[string]tp.InnerNetworkRules),
		EgressRules: map[string]tp.InnerNetworkRules{
			"default": {
				InnerRules: map[string]tp.NetworkRule{
					"cidr:172.16.0.0/12": {
						Policy: tp.KloudKnoxPolicy{
							PolicyID:   33,
							PolicyName: "block-private",
						},
						Action: "Block",
					},
				},
			},
		},
	}

	evData := &tp.EventData{Operation: "egress"}

	ne.UpdateMatchedNetworkPolicy(networkRules, evData, 33)

	if evData.PolicyName != "block-private" {
		t.Errorf("PolicyName = %q, want block-private", evData.PolicyName)
	}
}

// "ingress" operation — cgroup_skb ingress path.
func TestUpdateMatchedNetworkPolicyCgroupIngress(t *testing.T) {
	ne := newTestNetworkEnforcer()

	networkRules := &tp.NetworkRules{
		IngressRules: map[string]tp.InnerNetworkRules{
			"default": {
				InnerRules: map[string]tp.NetworkRule{
					"cidr:192.168.0.0/16": {
						Policy: tp.KloudKnoxPolicy{
							PolicyID:   99,
							PolicyName: "allow-lan",
						},
						Action: "Allow",
					},
				},
			},
		},
		EgressRules: make(map[string]tp.InnerNetworkRules),
	}

	evData := &tp.EventData{Operation: "ingress"}

	ne.UpdateMatchedNetworkPolicy(networkRules, evData, 99)

	if evData.PolicyName != "allow-lan" {
		t.Errorf("PolicyName = %q, want allow-lan", evData.PolicyName)
	}
	if evData.PolicyAction != "Allow" {
		t.Errorf("PolicyAction = %q, want Allow", evData.PolicyAction)
	}
}

// Audit action matching.
func TestUpdateMatchedNetworkPolicyAuditAction(t *testing.T) {
	ne := newTestNetworkEnforcer()

	networkRules := &tp.NetworkRules{
		IngressRules: make(map[string]tp.InnerNetworkRules),
		EgressRules: map[string]tp.InnerNetworkRules{
			"default": {
				InnerRules: map[string]tp.NetworkRule{
					"cidr:0.0.0.0/0": {
						Policy: tp.KloudKnoxPolicy{
							PolicyID:   11,
							PolicyName: "audit-all-egress",
						},
						Action: "Audit",
					},
				},
			},
		},
	}

	evData := &tp.EventData{Operation: "connect"}

	ne.UpdateMatchedNetworkPolicy(networkRules, evData, 11)

	if evData.PolicyName != "audit-all-egress" {
		t.Errorf("PolicyName = %q, want audit-all-egress", evData.PolicyName)
	}
	if evData.PolicyAction != "Audit" {
		t.Errorf("PolicyAction = %q, want Audit", evData.PolicyAction)
	}
}
