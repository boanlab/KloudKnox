// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

import "testing"

func TestNormalizeCapabilityName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"CAP_NET_RAW", "CAP_NET_RAW", true},
		{"cap_net_raw", "CAP_NET_RAW", true},
		{"NET_RAW", "CAP_NET_RAW", true},
		{"net_raw", "CAP_NET_RAW", true},
		{"  cap_sys_admin  ", "CAP_SYS_ADMIN", true},
		{"CAP_DOES_NOT_EXIST", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeCapabilityName(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("NormalizeCapabilityName(%q) = (%q, %v), want (%q, %v)",
				tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestCapabilityIDRoundTrip(t *testing.T) {
	id, ok := CapabilityID("NET_RAW")
	if !ok || id != 13 {
		t.Fatalf("CapabilityID(NET_RAW) = (%d, %v), want (13, true)", id, ok)
	}
	if name := CapabilityName(id); name != "CAP_NET_RAW" {
		t.Errorf("CapabilityName(13) = %q, want CAP_NET_RAW", name)
	}
}

func TestCapabilityNameUnknown(t *testing.T) {
	if name := CapabilityName(9999); name != "" {
		t.Errorf("CapabilityName(9999) = %q, want empty string", name)
	}
}
