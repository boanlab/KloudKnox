// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"encoding/base64"
	"testing"
)

// ============================== //
// ==  isLabelPolicyKey        == //
// ============================== //

func TestIsLabelPolicyKey(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"kloudknox.policy.b64", true},
		{"kloudknox.policy.0.b64", true},
		{"kloudknox.policy.web.b64", true},
		{"kloudknox.namespace", false},
		{"kloudknox.profile.name", false},
		{"kloudknox.policy.b64.extra", false},
		{"", false},
		{"kloudknox.policy.", false},
	}
	for _, tc := range tests {
		if got := isLabelPolicyKey(tc.in); got != tc.want {
			t.Errorf("isLabelPolicyKey(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// ============================== //
// ==  decodeLabelPolicy       == //
// ============================== //

const validPolicyYAML = `apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: block-tmp-write
spec:
  action: Block
  file:
  - path: /tmp/bad
    action: Block
`

func encode(y string) string { return base64.StdEncoding.EncodeToString([]byte(y)) }

func TestDecodeLabelPolicy_Valid(t *testing.T) {
	p, err := decodeLabelPolicy(encode(validPolicyYAML))
	if err != nil {
		t.Fatalf("decodeLabelPolicy: %v", err)
	}
	if p.Name != "block-tmp-write" {
		t.Errorf("Name = %q, want block-tmp-write", p.Name)
	}
}

func TestDecodeLabelPolicy_Errors(t *testing.T) {
	// Format-level failures only — semantic (Spec) validation is deferred to
	// collectLabelPolicies so auto-scoping can inject a selector first.
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"not base64", "!!!not-base64!!!"},
		{"missing name", encode("apiVersion: security.boanlab.com/v1\nkind: KloudKnoxPolicy\nspec:\n  action: Block\n")},
		{"wrong kind", encode("apiVersion: security.boanlab.com/v1\nkind: Pod\nmetadata:\n  name: x\nspec: {}\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeLabelPolicy(tc.in); err == nil {
				t.Errorf("decodeLabelPolicy(%q) = nil, want error", tc.name)
			}
		})
	}
}

// Spec validation failures surface as skipped policies during collect, not as
// decodeLabelPolicy errors.
func TestCollectLabelPolicies_RejectsInvalidSpec(t *testing.T) {
	noAction := encode("apiVersion: security.boanlab.com/v1\nkind: KloudKnoxPolicy\nmetadata:\n  name: x\nspec: {}\n")
	info := dockerInspect{ID: "abcdef123456000000000000", Name: "/noact"}
	info.Config.Labels = map[string]string{"kloudknox.policy.b64": noAction}
	if got := collectLabelPolicies(info); len(got) != 0 {
		t.Errorf("got %d policies, want 0 (no action → invalid spec)", len(got))
	}
}

// ============================== //
// ==  collectLabelPolicies    == //
// ============================== //

func TestCollectLabelPolicies_AutoScopeAndPrefix(t *testing.T) {
	info := dockerInspect{
		ID:   "abcdef1234567890deadbeef",
		Name: "/webapp",
	}
	info.Config.Labels = map[string]string{
		"kloudknox.policy.b64": encode(validPolicyYAML),
	}

	got := collectLabelPolicies(info)
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1", len(got))
	}
	p := got[0]

	// Name must be prefixed with the container short-ID to avoid collisions.
	const wantName = "abcdef123456-block-tmp-write"
	if p.PolicyName != wantName {
		t.Errorf("PolicyName = %q, want %q", p.PolicyName, wantName)
	}

	// Selector-less policy must be auto-scoped to docker.name=<container>.
	if got := p.Selector["docker.name"]; got != "webapp" {
		t.Errorf("Selector[docker.name] = %q, want %q", got, "webapp")
	}
}

func TestCollectLabelPolicies_PreservesExplicitSelector(t *testing.T) {
	y := `apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: shop-block
spec:
  action: Block
  selector:
    docker.compose.project: shop
`
	info := dockerInspect{ID: "abcdef123456000000000000", Name: "/shop-web"}
	info.Config.Labels = map[string]string{"kloudknox.policy.0.b64": encode(y)}

	got := collectLabelPolicies(info)
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1", len(got))
	}
	if got[0].Selector["docker.name"] != "" {
		t.Errorf("docker.name must not be injected when selector is explicit")
	}
	if got[0].Selector["docker.compose.project"] != "shop" {
		t.Errorf("explicit selector lost: %v", got[0].Selector)
	}
}

func TestCollectLabelPolicies_DeterministicOrder(t *testing.T) {
	info := dockerInspect{ID: "abcdef123456000000000000", Name: "/multi"}
	info.Config.Labels = map[string]string{
		"kloudknox.policy.1.b64": encode(validPolicyYAML),
		"kloudknox.policy.0.b64": encode(validPolicyYAML),
	}
	got := collectLabelPolicies(info)
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}
	// With sorted keys, the policy derived from .0.b64 should come first. Since
	// both wrap the same YAML, the distinguishing characteristic is the UID
	// suffix.
	if got[0].PolicyID == got[1].PolicyID {
		t.Errorf("expected distinct PolicyIDs for two label entries")
	}
}

func TestCollectLabelPolicies_NamespaceFallback(t *testing.T) {
	info := dockerInspect{ID: "abcdef123456000000000000", Name: "/app"}
	info.Config.Labels = map[string]string{
		"kloudknox.namespace":  "prod",
		"kloudknox.policy.b64": encode(validPolicyYAML),
	}
	got := collectLabelPolicies(info)
	if len(got) != 1 || got[0].NamespaceName != "prod" {
		t.Fatalf("NamespaceName = %q, want prod", got[0].NamespaceName)
	}
}

func TestCollectLabelPolicies_SkipsBadPolicyButKeepsGoodOnes(t *testing.T) {
	info := dockerInspect{ID: "abcdef123456000000000000", Name: "/mix"}
	info.Config.Labels = map[string]string{
		"kloudknox.policy.0.b64": "!!not-base64!!",
		"kloudknox.policy.1.b64": encode(validPolicyYAML),
	}
	got := collectLabelPolicies(info)
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1 (bad label must be skipped, good one kept)", len(got))
	}
}
