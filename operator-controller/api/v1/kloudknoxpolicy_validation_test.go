// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package v1

import (
	"strings"
	"testing"
)

func TestValidateProcessRulePathOnly(t *testing.T) {
	rule := ProcessRule{
		Path:       "/bin/ls",
		Action:     "Allow",
		FromSource: []SourceMatch{},
	}

	err := ValidateProcessRule(rule)
	if err != nil {
		t.Errorf("ValidateProcessRule with path only returned error: %v", err)
	}
}

func TestValidateProcessRuleDirOnly(t *testing.T) {
	rule := ProcessRule{
		Dir:        "/etc/",
		Recursive:  false,
		Action:     "Audit",
		FromSource: []SourceMatch{},
	}

	err := ValidateProcessRule(rule)
	if err != nil {
		t.Errorf("ValidateProcessRule with dir only returned error: %v", err)
	}
}

func TestValidateProcessRuleRecursiveWithoutDir(t *testing.T) {
	rule := ProcessRule{
		Path:      "/bin/ls",
		Recursive: true,
		Action:    "Block",
	}

	err := ValidateProcessRule(rule)
	if err == nil {
		t.Error("ValidateProcessRule should reject recursive without dir")
	}
}

func TestValidateProcessRulePathAndDir(t *testing.T) {
	rule := ProcessRule{
		Path:       "/bin/ls",
		Dir:        "/etc/",
		Action:     "Allow",
		FromSource: []SourceMatch{},
	}

	err := ValidateProcessRule(rule)
	if err == nil {
		t.Error("ValidateProcessRule should reject path and dir together")
	}
}

func TestValidateProcessRuleNoPathOrDir(t *testing.T) {
	rule := ProcessRule{
		Action: "Allow",
	}

	err := ValidateProcessRule(rule)
	if err == nil {
		t.Error("ValidateProcessRule should reject rule with no path or dir")
	}
}

func TestValidateProcessRuleEmptyFromSource(t *testing.T) {
	rule := ProcessRule{
		Path:       "/bin/ls",
		Action:     "Allow",
		FromSource: []SourceMatch{},
	}

	err := ValidateProcessRule(rule)
	if err != nil {
		t.Errorf("ValidateProcessRule with empty fromSource returned error: %v", err)
	}
}

func TestValidateProcessRuleFromSourceNoPath(t *testing.T) {
	rule := ProcessRule{
		Path:   "/bin/ls",
		Action: "Allow",
		FromSource: []SourceMatch{
			{},
		},
	}

	err := ValidateProcessRule(rule)
	if err == nil {
		t.Error("ValidateProcessRule should reject fromSource entry with no path")
	}
}

func TestValidateFileRulePathOnly(t *testing.T) {
	rule := FileRule{
		Path:       "/bin/cat",
		Action:     "Allow",
		FromSource: []SourceMatch{},
	}

	err := ValidateFileRule(rule)
	if err != nil {
		t.Errorf("ValidateFileRule with path only returned error: %v", err)
	}
}

func TestValidateFileRuleDirOnly(t *testing.T) {
	rule := FileRule{
		Dir:        "/var/log/",
		ReadOnly:   true,
		Action:     "Audit",
		FromSource: []SourceMatch{},
	}

	err := ValidateFileRule(rule)
	if err != nil {
		t.Errorf("ValidateFileRule with dir only returned error: %v", err)
	}
}

func TestValidateFileRuleRecursiveWithoutDir(t *testing.T) {
	rule := FileRule{
		Path:      "/bin/ls",
		Recursive: true,
		Action:    "Block",
	}

	err := ValidateFileRule(rule)
	if err == nil {
		t.Error("ValidateFileRule should reject recursive without dir")
	}
}

func TestValidateFileRulePathAndDir(t *testing.T) {
	rule := FileRule{
		Path:       "/bin/ls",
		Dir:        "/etc/",
		Action:     "Allow",
		FromSource: []SourceMatch{},
	}

	err := ValidateFileRule(rule)
	if err == nil {
		t.Error("ValidateFileRule should reject path and dir together")
	}
}

func TestValidateFileRuleNoPathOrDir(t *testing.T) {
	rule := FileRule{
		Action: "Allow",
	}

	err := ValidateFileRule(rule)
	if err == nil {
		t.Error("ValidateFileRule should reject rule with no path or dir")
	}
}

func TestValidateNetworkRuleWithSelector(t *testing.T) {
	rule := NetworkRule{
		Direction: "ingress",
		Selector:  map[string]string{"app": "web"},
		Action:    "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err != nil {
		t.Errorf("ValidateNetworkRule with selector returned error: %v", err)
	}
}

func TestValidateNetworkRuleWithIPBlock(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR: "10.0.0.0/8",
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err != nil {
		t.Errorf("ValidateNetworkRule with IPBlock returned error: %v", err)
	}
}

func TestValidateNetworkRuleWithFQDN(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		FQDN:      "example.com",
		Action:    "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err != nil {
		t.Errorf("ValidateNetworkRule with FQDN returned error: %v", err)
	}
}

func TestValidateNetworkRuleNoSelectorIPBlockOrFQDN(t *testing.T) {
	rule := NetworkRule{
		Direction: "ingress",
		Action:    "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject rule with no selector, ipBlock, or fqdn")
	}
}

func TestValidateNetworkRuleMultipleSelectors(t *testing.T) {
	rule := NetworkRule{
		Direction: "ingress",
		Selector:  map[string]string{"app": "web"},
		IPBlock: IPBlock{
			CIDR: "10.0.0.0/8",
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject rule with multiple selectors")
	}
}

func TestValidateNetworkRuleInvalidCIDR(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR: "invalid-cidr",
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject invalid CIDR")
	}
}

func TestValidateNetworkRuleInvalidCIDRExcept(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR:   "10.0.0.0/8",
			Except: []string{"invalid"},
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject invalid CIDR in except")
	}
}

func TestValidateNetworkRuleICMPWithPort(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR: "10.0.0.0/8",
		},
		Ports: []Port{
			{Protocol: "ICMP", Port: 80},
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject ICMP with non-zero port")
	}
}

func TestValidateNetworkRuleICMPWithoutPort(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR: "10.0.0.0/8",
		},
		Ports: []Port{
			{Protocol: "ICMP", Port: 0},
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err != nil {
		t.Errorf("ValidateNetworkRule with ICMP without port returned error: %v", err)
	}
}

func TestValidateNetworkRuleFromSourceNoPath(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR: "10.0.0.0/8",
		},
		FromSource: []SourceMatch{
			{},
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject fromSource entry with no path")
	}
}

func TestValidateNetworkRuleValidCIDR(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR: "192.168.1.0/24",
		},
		Action: "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err != nil {
		t.Errorf("ValidateNetworkRule with valid CIDR returned error: %v", err)
	}
}

func TestValidateNetworkRuleValidFQDN(t *testing.T) {
	tests := []struct {
		name string
		fqdn string
	}{
		{"simple domain", "example.com"},
		{"subdomain", "www.example.com"},
		{"multiple subdomains", "a.b.c.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NetworkRule{
				Direction: "egress",
				FQDN:      tt.fqdn,
				Action:    "Allow",
			}

			err := ValidateNetworkRule(rule)
			if err != nil {
				t.Errorf("ValidateNetworkRule with valid FQDN %q returned error: %v", tt.fqdn, err)
			}
		})
	}
}

func TestValidateNetworkRuleInvalidFQDN(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		FQDN:      "invalid..domain",
		Action:    "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject invalid FQDN")
	}
}

func TestValidateNetworkRuleFQDNTooLong(t *testing.T) {
	// FQDN > 253 characters
	fqdn := "a." + string(make([]byte, 250)) + ".com"

	rule := NetworkRule{
		Direction: "egress",
		FQDN:      fqdn,
		Action:    "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject FQDN > 253 characters")
	}
}

func TestValidateNetworkRuleFQDNNoSubdomain(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		FQDN:      "com",
		Action:    "Allow",
	}

	err := ValidateNetworkRule(rule)
	if err == nil {
		t.Error("ValidateNetworkRule should reject FQDN without subdomain")
	}
}

func TestValidateSpecNoAction(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
	}

	err := ValidateSpec(&spec)
	if err == nil {
		t.Error("ValidateSpec should reject spec with no action")
	}
}

func TestValidateSpecApplyToAllAllowsEmptySelector(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		ApplyToAll: true,
		Action:     "Block",
	}

	if err := ValidateSpec(&spec); err != nil {
		t.Errorf("ValidateSpec with applyToAll and empty selector returned error: %v", err)
	}
}

func TestValidateSpecApplyToAllStillRejectsInvalidDockerSelectorKey(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		ApplyToAll: true,
		Selector:   map[string]string{"docker.BAD KEY": "x"},
		Action:     "Block",
	}

	if err := ValidateSpec(&spec); err == nil {
		t.Error("ValidateSpec must still reject malformed docker.* keys even when applyToAll is true")
	}
}

func TestValidateSpecNoApplyToAllStillRequiresSelector(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Action: "Block",
	}

	if err := ValidateSpec(&spec); err == nil {
		t.Error("ValidateSpec must reject empty selector when applyToAll is false")
	}
}

func TestValidateSpecWithGlobalAction(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Action:   "Allow",
	}

	err := ValidateSpec(&spec)
	if err != nil {
		t.Errorf("ValidateSpec with global action returned error: %v", err)
	}
}

func TestValidateSpecWithProcessAction(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Process: []ProcessRule{
			{
				Path:   "/bin/ls",
				Action: "Audit",
			},
		},
	}

	err := ValidateSpec(&spec)
	if err != nil {
		t.Errorf("ValidateSpec with process action returned error: %v", err)
	}
}

func TestValidateSpecWithFileAction(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		File: []FileRule{
			{
				Path:   "/etc/passwd",
				Action: "Block",
			},
		},
	}

	err := ValidateSpec(&spec)
	if err != nil {
		t.Errorf("ValidateSpec with file action returned error: %v", err)
	}
}

func TestValidateSpecWithNetworkAction(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Network: []NetworkRule{
			{
				Direction: "egress",
				IPBlock: IPBlock{
					CIDR: "10.0.0.0/8",
				},
				Action: "Allow",
			},
		},
	}

	err := ValidateSpec(&spec)
	if err != nil {
		t.Errorf("ValidateSpec with network action returned error: %v", err)
	}
}

func TestValidateSpecAllRulesValid(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Action:   "Block", // global action
		Process: []ProcessRule{
			{
				Path:   "/bin/ls",
				Action: "Audit",
			},
		},
		File: []FileRule{
			{
				Path:   "/etc/passwd",
				Action: "Block",
			},
		},
		Network: []NetworkRule{
			{
				Direction: "egress",
				IPBlock: IPBlock{
					CIDR: "10.0.0.0/8",
				},
				Action: "Allow",
			},
		},
	}

	err := ValidateSpec(&spec)
	if err != nil {
		t.Errorf("ValidateSpec with all valid rules returned error: %v", err)
	}
}

func TestValidateSpecInvalidProcessRule(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Process: []ProcessRule{
			{
				Recursive: true, // Invalid: no dir
				Action:    "Allow",
			},
		},
	}

	err := ValidateSpec(&spec)
	if err == nil {
		t.Error("ValidateSpec should reject invalid process rule")
	}
}

func TestValidateSpecInvalidFileRule(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		File: []FileRule{
			{
				Path:      "/bin/ls",
				Recursive: true, // Invalid: no dir
				Action:    "Allow",
			},
		},
	}

	err := ValidateSpec(&spec)
	if err == nil {
		t.Error("ValidateSpec should reject invalid file rule")
	}
}

func TestValidateSpecInvalidNetworkRule(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Network: []NetworkRule{
			{
				Direction: "egress",
				// No selector, ipBlock, or fqdn
				Action: "Allow",
			},
		},
	}

	err := ValidateSpec(&spec)
	if err == nil {
		t.Error("ValidateSpec should reject invalid network rule")
	}
}

func TestValidateCIDRValid(t *testing.T) {
	tests := []struct {
		cidr string
	}{
		{"0.0.0.0/0"},
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.1.0/24"},
		{"255.255.255.255/32"},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			err := validateCIDR(tt.cidr)
			if err != nil {
				t.Errorf("validateCIDR(%q) returned error: %v", tt.cidr, err)
			}
		})
	}
}

func TestValidateCIDRInvalidFormat(t *testing.T) {
	tests := []struct {
		cidr string
	}{
		{"10.0.0.0"},    // missing mask
		{"10.0.0.0/99"}, // invalid mask
		{"256.0.0.0/8"}, // invalid IP octet
		{"10.0/8"},      // missing octets
		{"invalid"},     // not IP
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			err := validateCIDR(tt.cidr)
			if err == nil {
				t.Errorf("validateCIDR(%q) should return error for invalid format", tt.cidr)
			}
		})
	}
}

func TestValidateFQDNValid(t *testing.T) {
	tests := []struct {
		fqdn string
	}{
		{"example.com"},
		{"www.example.com"},
		{"sub.example.com"},
		{"a.b.c.example.com"},
		{"test-domain.com"},
		{"example.io"},
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			err := validateFQDN(tt.fqdn)
			if err != nil {
				t.Errorf("validateFQDN(%q) returned error: %v", tt.fqdn, err)
			}
		})
	}
}

func TestValidateFQDNInvalid(t *testing.T) {
	tests := []struct {
		fqdn string
	}{
		{"example"},                 // no TLD
		{".example.com"},            // starts with dot
		{"example..com"},            // double dot
		{"-example.com"},            // starts with hyphen
		{"example-.com"},            // label ends with hyphen
		{"ex ample.com"},            // space
		{"example.com."},            // trailing dot
		{string(make([]byte, 255))}, // too long
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			err := validateFQDN(tt.fqdn)
			if err == nil {
				t.Errorf("validateFQDN(%q) should return error for invalid FQDN", tt.fqdn)
			}
		})
	}
}

func TestHasAnyAction(t *testing.T) {
	tests := []struct {
		name     string
		spec     KloudKnoxPolicySpec
		expected bool
	}{
		{
			name: "global action set",
			spec: KloudKnoxPolicySpec{
				Action: "Allow",
			},
			expected: true,
		},
		{
			name: "process action set",
			spec: KloudKnoxPolicySpec{
				Process: []ProcessRule{{Action: "Audit"}},
			},
			expected: true,
		},
		{
			name: "file action set",
			spec: KloudKnoxPolicySpec{
				File: []FileRule{{Action: "Block"}},
			},
			expected: true,
		},
		{
			name: "network action set",
			spec: KloudKnoxPolicySpec{
				Network: []NetworkRule{{Action: "Allow"}},
			},
			expected: true,
		},
		{
			name:     "no action set",
			spec:     KloudKnoxPolicySpec{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAnyAction(&tt.spec)
			if result != tt.expected {
				t.Errorf("hasAnyAction() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHasAnyActionAllEmpty(t *testing.T) {
	spec := KloudKnoxPolicySpec{}
	result := hasAnyAction(&spec)
	if result {
		t.Error("hasAnyAction() should return false for empty spec")
	}
}

// ---------------------------------------------------------------------------
// ProcessRule — additional edge cases
// ---------------------------------------------------------------------------

func TestValidateProcessRuleMultipleFromSourceAllValid(t *testing.T) {
	rule := ProcessRule{
		Path:   "/bin/ls",
		Action: "Allow",
		FromSource: []SourceMatch{
			{Path: "/usr/bin/bash"},
			{Path: "/bin/sh"},
		},
	}
	if err := ValidateProcessRule(rule); err != nil {
		t.Errorf("ValidateProcessRule with multiple valid FromSource returned error: %v", err)
	}
}

func TestValidateProcessRuleFromSourceSecondEntryInvalid(t *testing.T) {
	rule := ProcessRule{
		Path:   "/bin/ls",
		Action: "Allow",
		FromSource: []SourceMatch{
			{Path: "/usr/bin/bash"},
			{},
		},
	}
	if err := ValidateProcessRule(rule); err == nil {
		t.Error("ValidateProcessRule should reject FromSource entry with empty path")
	}
}

func TestValidateProcessRuleRecursiveWithDir(t *testing.T) {
	rule := ProcessRule{
		Dir:       "/etc/",
		Recursive: true,
		Action:    "Allow",
	}
	if err := ValidateProcessRule(rule); err != nil {
		t.Errorf("ValidateProcessRule with dir+recursive should be valid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// FileRule — additional edge cases
// ---------------------------------------------------------------------------

func TestValidateFileRuleReadOnlyWithPath(t *testing.T) {
	rule := FileRule{
		Path:     "/etc/passwd",
		ReadOnly: true,
		Action:   "Allow",
	}
	if err := ValidateFileRule(rule); err != nil {
		t.Errorf("ValidateFileRule ReadOnly with path should be valid: %v", err)
	}
}

func TestValidateFileRuleReadOnlyWithDirAndRecursive(t *testing.T) {
	rule := FileRule{
		Dir:       "/etc/",
		ReadOnly:  true,
		Recursive: true,
		Action:    "Allow",
	}
	if err := ValidateFileRule(rule); err != nil {
		t.Errorf("ValidateFileRule ReadOnly+dir+recursive should be valid: %v", err)
	}
}

func TestValidateFileRuleMultipleFromSourceAllValid(t *testing.T) {
	rule := FileRule{
		Path:   "/etc/passwd",
		Action: "Block",
		FromSource: []SourceMatch{
			{Path: "/usr/bin/cat"},
			{Path: "/usr/bin/less"},
		},
	}
	if err := ValidateFileRule(rule); err != nil {
		t.Errorf("ValidateFileRule with multiple valid FromSource returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NetworkRule — additional edge cases
// ---------------------------------------------------------------------------

func TestValidateNetworkRuleEmptySelectorMap(t *testing.T) {
	// An empty (but non-nil) map is treated as a selector by the validator.
	rule := NetworkRule{
		Direction: "ingress",
		Selector:  map[string]string{},
		Action:    "Allow",
	}
	if err := ValidateNetworkRule(rule); err != nil {
		t.Errorf("ValidateNetworkRule with empty selector map returned error: %v", err)
	}
}

func TestValidateNetworkRuleMultipleValidExcepts(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		IPBlock: IPBlock{
			CIDR:   "10.0.0.0/8",
			Except: []string{"10.1.0.0/16", "10.2.0.0/16"},
		},
		Action: "Allow",
	}
	if err := ValidateNetworkRule(rule); err != nil {
		t.Errorf("ValidateNetworkRule with multiple valid Excepts returned error: %v", err)
	}
}

func TestValidateNetworkRuleFromSourceMultipleValid(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		FQDN:      "example.com",
		Action:    "Allow",
		FromSource: []SourceMatch{
			{Path: "/usr/bin/curl"},
			{Path: "/usr/bin/wget"},
		},
	}
	if err := ValidateNetworkRule(rule); err != nil {
		t.Errorf("ValidateNetworkRule with multiple valid FromSource returned error: %v", err)
	}
}

func TestValidateNetworkRuleAllThreeTargets(t *testing.T) {
	rule := NetworkRule{
		Direction: "egress",
		Selector:  map[string]string{"app": "db"},
		IPBlock:   IPBlock{CIDR: "10.0.0.0/8"},
		FQDN:      "example.com",
		Action:    "Allow",
	}
	if err := ValidateNetworkRule(rule); err == nil {
		t.Error("ValidateNetworkRule should reject rule with all three targets set")
	}
}

// ---------------------------------------------------------------------------
// ValidateSpec — error message format and rule index
// ---------------------------------------------------------------------------

func TestValidateSpecErrorContainsRuleIndex(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Process: []ProcessRule{
			{Recursive: true, Action: "Allow"}, // index 0, invalid
		},
	}
	err := ValidateSpec(&spec)
	if err == nil {
		t.Fatal("ValidateSpec should return error for invalid process rule")
	}
	if !strings.Contains(err.Error(), "process[0]") {
		t.Errorf("Error message should contain rule index 'process[0]', got: %v", err)
	}
}

func TestValidateSpecSecondRuleInvalidHasCorrectIndex(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "web"},
		Process: []ProcessRule{
			{Path: "/bin/ls", Action: "Allow"}, // index 0, valid
			{Recursive: true, Action: "Allow"}, // index 1, invalid
		},
	}
	err := ValidateSpec(&spec)
	if err == nil {
		t.Fatal("ValidateSpec should return error for second invalid process rule")
	}
	if !strings.Contains(err.Error(), "process[1]") {
		t.Errorf("Error message should reference 'process[1]', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// hasAnyAction — additional edge cases
// ---------------------------------------------------------------------------

func TestHasAnyActionOnlySecondRuleHasAction(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Process: []ProcessRule{
			{Action: ""},
			{Action: "Block"},
		},
	}
	if !hasAnyAction(&spec) {
		t.Error("hasAnyAction() should return true when second rule has action")
	}
}

func TestHasAnyActionMultipleRulesAllEmpty(t *testing.T) {
	spec := KloudKnoxPolicySpec{
		Process: []ProcessRule{{Action: ""}, {Action: ""}},
		File:    []FileRule{{Action: ""}},
		Network: []NetworkRule{{Action: ""}},
	}
	if hasAnyAction(&spec) {
		t.Error("hasAnyAction() should return false when all rule actions are empty")
	}
}

// ---------------------------------------------------------------------------
// validateCIDR — boundary and format edge cases
// ---------------------------------------------------------------------------

func TestValidateCIDRMaskBoundaries(t *testing.T) {
	tests := []struct {
		cidr string
	}{
		{"10.0.0.0/1"},
		{"10.0.0.0/31"},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			if err := validateCIDR(tt.cidr); err != nil {
				t.Errorf("validateCIDR(%q) should be valid: %v", tt.cidr, err)
			}
		})
	}
}

func TestValidateCIDRNonNumericOctet(t *testing.T) {
	tests := []struct {
		cidr string
	}{
		{"10.0.0.a/24"},
		{"a.b.c.d/8"},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			if err := validateCIDR(tt.cidr); err == nil {
				t.Errorf("validateCIDR(%q) should return error for non-numeric octet", tt.cidr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateFQDN — boundary and format edge cases
// ---------------------------------------------------------------------------

func TestValidateFQDNExactly253Chars(t *testing.T) {
	// 63 + "." + 63 + "." + 63 + "." + 61 = 253 chars exactly
	fqdn253 := strings.Repeat("a", 63) + "." +
		strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." +
		strings.Repeat("d", 61)
	if len(fqdn253) != 253 {
		t.Fatalf("test setup error: expected 253 chars, got %d", len(fqdn253))
	}
	if err := validateFQDN(fqdn253); err != nil {
		t.Errorf("validateFQDN with exactly 253 chars should be valid: %v", err)
	}
}

func TestValidateFQDNSingleCharTLD(t *testing.T) {
	if err := validateFQDN("example.c"); err == nil {
		t.Error("validateFQDN should reject FQDN with single-character TLD")
	}
}

func TestValidateFQDNNumericLabels(t *testing.T) {
	// Numeric-only labels are allowed by DNS and the validator regex
	if err := validateFQDN("123.example.com"); err != nil {
		t.Errorf("validateFQDN with numeric subdomain should be valid: %v", err)
	}
}

func TestValidateFQDN63CharLabel(t *testing.T) {
	label := strings.Repeat("a", 63)
	fqdn := label + ".com"
	if err := validateFQDN(fqdn); err != nil {
		t.Errorf("validateFQDN with 63-char label should be valid: %v", err)
	}
}

func TestValidateFQDN64CharLabelInvalid(t *testing.T) {
	label := strings.Repeat("a", 64)
	fqdn := label + ".com"
	if err := validateFQDN(fqdn); err == nil {
		t.Error("validateFQDN should reject label exceeding 63 characters")
	}
}

// ==================== //
// == Capability rule == //
// ==================== //

func TestValidateCapabilityRuleCanonical(t *testing.T) {
	rule := CapabilityRule{Name: "CAP_NET_RAW", Action: "Allow"}
	if err := ValidateCapabilityRule(rule); err != nil {
		t.Errorf("ValidateCapabilityRule rejected canonical name: %v", err)
	}
}

func TestValidateCapabilityRuleShortForm(t *testing.T) {
	rule := CapabilityRule{Name: "NET_RAW", Action: "Block"}
	if err := ValidateCapabilityRule(rule); err != nil {
		t.Errorf("ValidateCapabilityRule rejected short form: %v", err)
	}
}

func TestValidateCapabilityRuleLowercase(t *testing.T) {
	rule := CapabilityRule{Name: "cap_net_admin", Action: "Audit"}
	if err := ValidateCapabilityRule(rule); err != nil {
		t.Errorf("ValidateCapabilityRule rejected lowercase form: %v", err)
	}
}

func TestValidateCapabilityRuleEmpty(t *testing.T) {
	rule := CapabilityRule{Action: "Allow"}
	if err := ValidateCapabilityRule(rule); err == nil {
		t.Error("ValidateCapabilityRule should reject empty name")
	}
}

func TestValidateCapabilityRuleUnknown(t *testing.T) {
	rule := CapabilityRule{Name: "CAP_DOES_NOT_EXIST", Action: "Allow"}
	if err := ValidateCapabilityRule(rule); err == nil {
		t.Error("ValidateCapabilityRule should reject unknown capability")
	}
}

func TestValidateCapabilityRuleFromSourceEmptyPath(t *testing.T) {
	rule := CapabilityRule{
		Name:       "CAP_NET_RAW",
		Action:     "Allow",
		FromSource: []SourceMatch{{Path: ""}},
	}
	if err := ValidateCapabilityRule(rule); err == nil {
		t.Error("ValidateCapabilityRule should reject fromSource entry with empty path")
	}
}

func TestValidateSpecCapability(t *testing.T) {
	spec := &KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "sniffer"},
		Capability: []CapabilityRule{
			{Name: "CAP_NET_RAW", Action: "Allow"},
		},
	}
	if err := ValidateSpec(spec); err != nil {
		t.Errorf("ValidateSpec rejected valid capability spec: %v", err)
	}
}

func TestValidateSpecCapabilityActionSatisfiesHasAnyAction(t *testing.T) {
	spec := &KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "sniffer"},
		Capability: []CapabilityRule{
			{Name: "CAP_NET_RAW", Action: "Allow"},
		},
	}
	if !hasAnyAction(spec) {
		t.Error("hasAnyAction should return true when a capability rule supplies an action")
	}
}

func TestValidateSpecCapabilityInvalidBubbles(t *testing.T) {
	spec := &KloudKnoxPolicySpec{
		Selector: map[string]string{"app": "sniffer"},
		Action:   "Block",
		Capability: []CapabilityRule{
			{Name: "CAP_NOPE"},
		},
	}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("ValidateSpec should reject spec with unknown capability")
	}
	if !strings.Contains(err.Error(), "capability[0]") {
		t.Errorf("error should identify the offending rule index: %v", err)
	}
}
