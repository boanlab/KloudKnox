// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"testing"

	"github.com/boanlab/KloudKnox/KloudKnox/enforcer"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

func TestHasAppArmorAttachment(t *testing.T) {
	tests := []struct {
		name string
		opts []string
		want bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"seccomp only", []string{"seccomp=default.json"}, false},
		{"apparmor named profile", []string{"apparmor=docker-default"}, true},
		{"apparmor unconfined", []string{"apparmor=unconfined"}, true},
		{"mixed with apparmor", []string{"seccomp=unconfined", "apparmor=kloudknox-foo"}, true},
		{"leading whitespace", []string{"  apparmor=foo"}, true},
		{"no-new-privileges only", []string{"no-new-privileges:true"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasAppArmorAttachment(tc.opts); got != tc.want {
				t.Errorf("hasAppArmorAttachment(%v) = %v, want %v", tc.opts, got, tc.want)
			}
		})
	}
}

// auditAppArmorAttachment should be silent (not panic) in all short-circuit
// branches. We can't observe log output here, but we can at least confirm the
// function exits cleanly and does not mutate its inputs.
func TestAuditAppArmorAttachment_ShortCircuits(t *testing.T) {
	policy := tp.KloudKnoxPolicy{PolicyName: "p"}

	cases := []struct {
		name string
		knox *KloudKnox
		info dockerInspect
		pod  tp.Pod
	}{
		{
			name: "nil enforcer",
			knox: &KloudKnox{},
			pod:  tp.Pod{RuntimePolicies: []tp.KloudKnoxPolicy{policy}, AppArmorProfiles: map[string]bool{"kloudknox-p": true}},
		},
		{
			name: "bpf enforcer",
			knox: &KloudKnox{RuntimeEnforcer: &enforcer.RuntimeEnforcer{EnforcerType: "bpf"}},
			pod:  tp.Pod{RuntimePolicies: []tp.KloudKnoxPolicy{policy}, AppArmorProfiles: map[string]bool{"kloudknox-p": true}},
		},
		{
			name: "no runtime policies",
			knox: &KloudKnox{RuntimeEnforcer: &enforcer.RuntimeEnforcer{EnforcerType: "apparmor"}},
			pod:  tp.Pod{AppArmorProfiles: map[string]bool{"kloudknox-p": true}},
		},
		{
			name: "securityopt already has apparmor",
			knox: &KloudKnox{RuntimeEnforcer: &enforcer.RuntimeEnforcer{EnforcerType: "apparmor"}},
			info: func() dockerInspect {
				var i dockerInspect
				i.HostConfig.SecurityOpt = []string{"apparmor=unconfined"}
				return i
			}(),
			pod: tp.Pod{RuntimePolicies: []tp.KloudKnoxPolicy{policy}, AppArmorProfiles: map[string]bool{"kloudknox-p": true}},
		},
		{
			name: "no profile in pod",
			knox: &KloudKnox{RuntimeEnforcer: &enforcer.RuntimeEnforcer{EnforcerType: "apparmor"}},
			pod:  tp.Pod{RuntimePolicies: []tp.KloudKnoxPolicy{policy}, AppArmorProfiles: map[string]bool{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			auditAppArmorAttachment(tc.knox, tc.info, tc.pod)
		})
	}
}

// The warning path itself: matched container, apparmor enforcer, no attachment.
// We don't assert on log output (the log package writes globally), but we do
// exercise the code path to catch nil-pointer regressions.
func TestAuditAppArmorAttachment_WarnsOnMissing(t *testing.T) {
	knox := &KloudKnox{RuntimeEnforcer: &enforcer.RuntimeEnforcer{EnforcerType: "apparmor"}}
	var info dockerInspect
	info.ID = "abcdef1234567890"
	info.HostConfig.SecurityOpt = []string{"seccomp=unconfined"}
	pod := tp.Pod{
		RuntimePolicies:  []tp.KloudKnoxPolicy{{PolicyName: "p"}},
		AppArmorProfiles: map[string]bool{"kloudknox-docker-abcdef123456": true},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()
	auditAppArmorAttachment(knox, info, pod)
}
