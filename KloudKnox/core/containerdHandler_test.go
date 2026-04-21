// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"testing"
)

// =============================== //
// ==  parseImageInfo Tests     == //
// =============================== //

func TestParseImageInfoWithTag(t *testing.T) {
	tests := []struct {
		image    string
		wantName string
		wantTag  string
	}{
		{"nginx:1.21", "nginx", "1.21"},
		{"ubuntu:latest", "ubuntu", "latest"},
		{"registry.io/repo/image:v2.0", "registry.io/repo/image", "v2.0"},
		{"busybox", "busybox", "latest"},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			gotName, gotTag := parseImageInfo(tt.image)
			if gotName != tt.wantName || gotTag != tt.wantTag {
				t.Errorf("parseImageInfo(%q) = (%q, %q), want (%q, %q)",
					tt.image, gotName, gotTag, tt.wantName, tt.wantTag)
			}
		})
	}
}

// ================================= //
// ==  parseCgroupPath Tests      == //
// ================================= //

func TestParseCgroupPathBestEffort(t *testing.T) {
	input := "kubepods-besteffort:pod-uid-123:container-abc"
	got := parseCgroupPath(input)
	if got == "" {
		t.Error("expected non-empty cgroup path for besteffort")
	}
}

func TestParseCgroupPathBurstable(t *testing.T) {
	input := "kubepods-burstable:pod-uid-456:container-def"
	got := parseCgroupPath(input)
	if got == "" {
		t.Error("expected non-empty cgroup path for burstable")
	}
}

func TestParseCgroupPathEmpty(t *testing.T) {
	got := parseCgroupPath("")
	if got != "" {
		t.Errorf("parseCgroupPath(\"\") = %q, want empty", got)
	}
}

func TestParseCgroupPathTooFewParts(t *testing.T) {
	got := parseCgroupPath("only-two-parts:here")
	if got != "" {
		t.Errorf("parseCgroupPath with <3 parts = %q, want empty", got)
	}
}
