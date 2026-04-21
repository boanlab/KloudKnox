// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package controller

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1 "github.com/boanlab/KloudKnox/operator/api/v1"
)

func TestNormalizeDir(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "dir with trailing slash",
			input:    "/etc/",
			expected: "/etc/",
		},
		{
			name:     "dir without trailing slash",
			input:    "/etc",
			expected: "/etc/",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "root directory",
			input:    "/",
			expected: "/",
		},
		{
			name:     "nested directory",
			input:    "/var/log/audit",
			expected: "/var/log/audit/",
		},
		{
			name:     "single character directory",
			input:    "/a",
			expected: "/a/",
		},
		{
			name:     "multiple trailing slashes",
			input:    "/etc///",
			expected: "/etc///",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeDir(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeDir(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestReconcileLogic(t *testing.T) {
	tests := []struct {
		name              string
		spec              *securityv1.KloudKnoxPolicySpec
		expectedStatus    string
		expectedNormalize bool
	}{
		{
			name: "valid spec with process rule",
			spec: &securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Path:   "/bin/ls",
						Action: "Allow",
					},
				},
			},
			expectedStatus:    securityv1.PolicyStatusActive,
			expectedNormalize: false,
		},
		{
			name: "valid spec with file rule",
			spec: &securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				File: []securityv1.FileRule{
					{
						Path:   "/etc/passwd",
						Action: "Block",
					},
				},
			},
			expectedStatus:    securityv1.PolicyStatusActive,
			expectedNormalize: false,
		},
		{
			name: "valid spec with network rule",
			spec: &securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Network: []securityv1.NetworkRule{
					{
						Direction: "egress",
						IPBlock: securityv1.IPBlock{
							CIDR: "10.0.0.0/8",
						},
						Action: "Allow",
					},
				},
			},
			expectedStatus:    securityv1.PolicyStatusActive,
			expectedNormalize: false,
		},
		{
			name: "spec with invalid process rule",
			spec: &securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Recursive: true, // Invalid: no dir
						Action:    "Allow",
					},
				},
			},
			expectedStatus:    securityv1.PolicyStatusInvalid,
			expectedNormalize: false,
		},
		{
			name: "spec with invalid network rule",
			spec: &securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Network: []securityv1.NetworkRule{
					{
						Direction: "egress",
						// No selector, ipBlock, or fqdn
						Action: "Allow",
					},
				},
			},
			expectedStatus:    securityv1.PolicyStatusInvalid,
			expectedNormalize: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := securityv1.ValidateSpec(tt.spec)
			if tt.expectedStatus == securityv1.PolicyStatusInvalid {
				if err == nil {
					t.Error("Expected validation to fail for invalid spec")
				}
			} else {
				if err != nil {
					t.Errorf("Expected validation to succeed for valid spec, got: %v", err)
				}
			}
		})
	}
}

func TestReconcileNormalizationLogic(t *testing.T) {
	tests := []struct {
		name            string
		spec            securityv1.KloudKnoxPolicySpec
		expectedSpec    securityv1.KloudKnoxPolicySpec
		shouldNormalize bool
	}{
		{
			name: "normalize process dir without trailing slash",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Dir:    "/etc",
						Action: "Audit",
					},
				},
			},
			expectedSpec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Dir:    "/etc/",
						Action: "Audit",
					},
				},
			},
			shouldNormalize: true,
		},
		{
			name: "normalize file dir without trailing slash",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				File: []securityv1.FileRule{
					{
						Dir:    "/var/log",
						Action: "Block",
					},
				},
			},
			expectedSpec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				File: []securityv1.FileRule{
					{
						Dir:    "/var/log/",
						Action: "Block",
					},
				},
			},
			shouldNormalize: true,
		},
		{
			name: "no normalization needed",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Dir:    "/etc/",
						Action: "Audit",
					},
				},
			},
			expectedSpec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Dir:    "/etc/",
						Action: "Audit",
					},
				},
			},
		},
		{
			name: "mixed process with and without trailing slash",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Dir:    "/etc",
						Action: "Audit",
					},
					{
						Dir:    "/var/log/",
						Action: "Block",
					},
				},
			},
			expectedSpec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Dir:    "/etc/",
						Action: "Audit",
					},
					{
						Dir:    "/var/log/",
						Action: "Block",
					},
				},
			},
			shouldNormalize: true,
		},
		{
			name: "process without dir should not change",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Path:   "/bin/ls",
						Action: "Audit",
					},
				},
			},
			expectedSpec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Path:   "/bin/ls",
						Action: "Audit",
					},
				},
			},
			shouldNormalize: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.spec.DeepCopy()
			normalized := false
			for i := range spec.Process {
				if spec.Process[i].Dir != "" {
					before := spec.Process[i].Dir
					spec.Process[i].Dir = normalizeDir(before)
					if spec.Process[i].Dir != before {
						normalized = true
					}
				}
			}
			for i := range spec.File {
				if spec.File[i].Dir != "" {
					before := spec.File[i].Dir
					spec.File[i].Dir = normalizeDir(before)
					if spec.File[i].Dir != before {
						normalized = true
					}
				}
			}

			if !normalized && tt.shouldNormalize {
				t.Error("Expected normalization to happen but it didn't")
			}
			if normalized && !tt.shouldNormalize {
				t.Error("Expected no normalization but it happened")
			}

			for i, rule := range spec.Process {
				expectedRule := tt.expectedSpec.Process[i]
				if rule.Dir != expectedRule.Dir {
					t.Errorf("Process[%d].Dir = %q, want %q", i, rule.Dir, expectedRule.Dir)
				}
				if rule.Path != expectedRule.Path {
					t.Errorf("Process[%d].Path = %q, want %q", i, rule.Path, expectedRule.Path)
				}
			}

			for i, rule := range spec.File {
				expectedRule := tt.expectedSpec.File[i]
				if rule.Dir != expectedRule.Dir {
					t.Errorf("File[%d].Dir = %q, want %q", i, rule.Dir, expectedRule.Dir)
				}
				if rule.Path != expectedRule.Path {
					t.Errorf("File[%d].Path = %q, want %q", i, rule.Path, expectedRule.Path)
				}
			}
		})
	}
}

func TestReconcileEmptySpec(t *testing.T) {
	tests := []struct {
		name        string
		spec        securityv1.KloudKnoxPolicySpec
		shouldError bool
	}{
		{
			name: "empty spec with no action",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
			},
			shouldError: true,
		},
		{
			name: "spec with global action only",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Action:   "Allow",
			},
			shouldError: false,
		},
		{
			name: "spec with only process rules",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Process: []securityv1.ProcessRule{
					{
						Path:   "/bin/ls",
						Action: "Audit",
					},
				},
			},
			shouldError: false,
		},
		{
			name: "spec with only file rules",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				File: []securityv1.FileRule{
					{
						Path:   "/etc/passwd",
						Action: "Block",
					},
				},
			},
			shouldError: false,
		},
		{
			name: "spec with only network rules",
			spec: securityv1.KloudKnoxPolicySpec{
				Selector: map[string]string{"app": "web"},
				Network: []securityv1.NetworkRule{
					{
						Direction: "egress",
						IPBlock: securityv1.IPBlock{
							CIDR: "10.0.0.0/8",
						},
						Action: "Allow",
					},
				},
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := securityv1.ValidateSpec(&tt.spec)
			if tt.shouldError && err == nil {
				t.Error("Expected validation to fail but it passed")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Expected validation to pass but it failed: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reconcile — fake-client integration tests
// ---------------------------------------------------------------------------

func newFakeReconciler(objs ...client.Object) *KloudKnoxPolicyReconciler {
	s := runtime.NewScheme()
	_ = securityv1.AddToScheme(s)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&securityv1.KloudKnoxPolicy{}).
		Build()
	return &KloudKnoxPolicyReconciler{Client: c, Scheme: s}
}

func reconcileReq(name, namespace string) ctrl.Request { //nolint:unparam
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: namespace}}
}

func TestReconcileNotFound(t *testing.T) {
	r := newFakeReconciler() // no objects in the store
	result, err := r.Reconcile(context.Background(), reconcileReq("ghost", "default"))
	if err != nil {
		t.Errorf("Reconcile should not error for a deleted resource: %v", err)
	}
	if result != (ctrl.Result{}) {
		t.Errorf("Reconcile should return empty result for not-found resource: %v", result)
	}
}

func TestReconcileInvalidSpecSetsInvalidStatus(t *testing.T) {
	policy := &securityv1.KloudKnoxPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-policy", Namespace: "default"},
		Spec: securityv1.KloudKnoxPolicySpec{
			Selector: map[string]string{"app": "web"},
			Process:  []securityv1.ProcessRule{{Recursive: true, Action: "Allow"}}, // invalid: no dir
		},
	}
	r := newFakeReconciler(policy)

	_, err := r.Reconcile(context.Background(), reconcileReq("bad-policy", "default"))
	if err != nil {
		t.Errorf("Reconcile should not return error for invalid spec: %v", err)
	}

	var updated securityv1.KloudKnoxPolicy
	if getErr := r.Get(context.Background(), types.NamespacedName{Name: "bad-policy", Namespace: "default"}, &updated); getErr != nil {
		t.Fatalf("Failed to fetch updated policy: %v", getErr)
	}
	if !strings.HasPrefix(updated.Status.PolicyStatus, securityv1.PolicyStatusInvalid) {
		t.Errorf("Status should start with %q, got %q", securityv1.PolicyStatusInvalid, updated.Status.PolicyStatus)
	}
}

func TestReconcileApplyToAllRejectedInK8sMode(t *testing.T) {
	policy := &securityv1.KloudKnoxPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "host-wide", Namespace: "default"},
		Spec: securityv1.KloudKnoxPolicySpec{
			ApplyToAll: true,
			Process:    []securityv1.ProcessRule{{Path: "/bin/ls", Action: "Block"}},
		},
	}
	r := newFakeReconciler(policy)

	if _, err := r.Reconcile(context.Background(), reconcileReq("host-wide", "default")); err != nil {
		t.Errorf("Reconcile should not return error: %v", err)
	}

	var updated securityv1.KloudKnoxPolicy
	if err := r.Get(context.Background(), types.NamespacedName{Name: "host-wide", Namespace: "default"}, &updated); err != nil {
		t.Fatalf("Failed to fetch updated policy: %v", err)
	}
	if !strings.HasPrefix(updated.Status.PolicyStatus, securityv1.PolicyStatusInvalid) {
		t.Errorf("K8s reconciler must mark applyToAll policy Invalid, got %q", updated.Status.PolicyStatus)
	}
	if !strings.Contains(updated.Status.PolicyStatus, "applyToAll") {
		t.Errorf("Status message should explain the applyToAll rejection, got %q", updated.Status.PolicyStatus)
	}
}

func TestReconcileValidSpecSetsActiveStatus(t *testing.T) {
	policy := &securityv1.KloudKnoxPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "good-policy", Namespace: "default"},
		Spec: securityv1.KloudKnoxPolicySpec{
			Selector: map[string]string{"app": "web"},
			Process:  []securityv1.ProcessRule{{Path: "/bin/ls", Action: "Allow"}},
		},
	}
	r := newFakeReconciler(policy)

	_, err := r.Reconcile(context.Background(), reconcileReq("good-policy", "default"))
	if err != nil {
		t.Errorf("Reconcile should not error for valid spec: %v", err)
	}

	var updated securityv1.KloudKnoxPolicy
	if getErr := r.Get(context.Background(), types.NamespacedName{Name: "good-policy", Namespace: "default"}, &updated); getErr != nil {
		t.Fatalf("Failed to fetch updated policy: %v", getErr)
	}
	if updated.Status.PolicyStatus != securityv1.PolicyStatusActive {
		t.Errorf("Status should be %q, got %q", securityv1.PolicyStatusActive, updated.Status.PolicyStatus)
	}
}

func TestReconcileNormalizesAndSetsActive(t *testing.T) {
	policy := &securityv1.KloudKnoxPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "norm-policy", Namespace: "default"},
		Spec: securityv1.KloudKnoxPolicySpec{
			Selector: map[string]string{"app": "web"},
			Process:  []securityv1.ProcessRule{{Dir: "/etc", Action: "Allow"}},  // missing trailing slash
			File:     []securityv1.FileRule{{Dir: "/var/log", Action: "Block"}}, // missing trailing slash
		},
	}
	r := newFakeReconciler(policy)

	_, err := r.Reconcile(context.Background(), reconcileReq("norm-policy", "default"))
	if err != nil {
		t.Errorf("Reconcile should not error: %v", err)
	}

	var updated securityv1.KloudKnoxPolicy
	if getErr := r.Get(context.Background(), types.NamespacedName{Name: "norm-policy", Namespace: "default"}, &updated); getErr != nil {
		t.Fatalf("Failed to fetch updated policy: %v", getErr)
	}
	if updated.Spec.Process[0].Dir != "/etc/" {
		t.Errorf("Process[0].Dir should be normalized to %q, got %q", "/etc/", updated.Spec.Process[0].Dir)
	}
	if updated.Spec.File[0].Dir != "/var/log/" {
		t.Errorf("File[0].Dir should be normalized to %q, got %q", "/var/log/", updated.Spec.File[0].Dir)
	}
	if updated.Status.PolicyStatus != securityv1.PolicyStatusActive {
		t.Errorf("Status should be %q, got %q", securityv1.PolicyStatusActive, updated.Status.PolicyStatus)
	}
}

func TestReconcileAlreadyNormalizedIsIdempotent(t *testing.T) {
	policy := &securityv1.KloudKnoxPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "idem-policy", Namespace: "default"},
		Spec: securityv1.KloudKnoxPolicySpec{
			Selector: map[string]string{"app": "web"},
			Process:  []securityv1.ProcessRule{{Dir: "/etc/", Action: "Allow"}}, // already has trailing slash
		},
	}
	r := newFakeReconciler(policy)

	_, err := r.Reconcile(context.Background(), reconcileReq("idem-policy", "default"))
	if err != nil {
		t.Errorf("Reconcile should not error: %v", err)
	}

	var updated securityv1.KloudKnoxPolicy
	if getErr := r.Get(context.Background(), types.NamespacedName{Name: "idem-policy", Namespace: "default"}, &updated); getErr != nil {
		t.Fatalf("Failed to fetch updated policy: %v", getErr)
	}
	if updated.Spec.Process[0].Dir != "/etc/" {
		t.Errorf("Already-normalized dir should be unchanged, got %q", updated.Spec.Process[0].Dir)
	}
	if updated.Status.PolicyStatus != securityv1.PolicyStatusActive {
		t.Errorf("Status should be %q, got %q", securityv1.PolicyStatusActive, updated.Status.PolicyStatus)
	}
}
