// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

import "testing"

func TestSignalNumber(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"SIGTERM", 15, true},
		{"sigterm", 15, true},
		{"TERM", 15, true},
		{"term", 15, true},
		{"SIGKILL", 9, true},
		{"KILL", 9, true},
		{"SIGHUP", 1, true},
		{"SIGSYS", 31, true},
		{"SIGDOESNOTEXIST", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		got, ok := SignalNumber(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("SignalNumber(%q) = (%d, %v), want (%d, %v)",
				tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSignalNameRoundTrip(t *testing.T) {
	n, ok := SignalNumber("TERM")
	if !ok || n != 15 {
		t.Fatalf("SignalNumber(TERM) = (%d, %v), want (15, true)", n, ok)
	}
	if name := SignalName(n); name != "SIGTERM" {
		t.Errorf("SignalName(15) = %q, want SIGTERM", name)
	}
}

func TestSignalNameUnknown(t *testing.T) {
	if got := SignalName(9999); got != "" {
		t.Errorf("SignalName(9999) = %q, want empty", got)
	}
}

func TestAppArmorSignalToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"SIGTERM", "term"},
		{"sigterm", "term"},
		{"TERM", "term"},
		{"SIGKILL", "kill"},
		{"SIGUSR1", "usr1"},
	}
	for _, tc := range cases {
		if got := AppArmorSignalToken(tc.in); got != tc.want {
			t.Errorf("AppArmorSignalToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
