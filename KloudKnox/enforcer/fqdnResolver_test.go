// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"testing"
)

// =============================== //
// ==  reverseDNSLabels Tests   == //
// =============================== //

func TestReverseDNSLabels(t *testing.T) {
	tests := []struct {
		fqdn string
		want string
	}{
		{"api.test.com", "com.test.api"},
		{"sub.api.test.com", "com.test.api.sub"},
		{"example.com", "com.example"},
		{"*.api.test.com", "com.test.api"}, // wildcard prefix stripped
		{"*.example.com", "com.example"},   // wildcard prefix stripped
		{"com", "com"},                     // single label
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			got := reverseDNSLabels(tt.fqdn)
			if got != tt.want {
				t.Errorf("reverseDNSLabels(%q) = %q, want %q", tt.fqdn, got, tt.want)
			}
		})
	}
}

// ================================== //
// ==  reverseReversedLabels Tests == //
// ================================== //

func TestReverseReversedLabels(t *testing.T) {
	tests := []struct {
		reversed string
		want     string
	}{
		{"com.test.api", "api.test.com"},
		{"com.test.api.sub", "sub.api.test.com"},
		{"com.example", "example.com"},
		{"com", "com"},
	}

	for _, tt := range tests {
		t.Run(tt.reversed, func(t *testing.T) {
			got := reverseReversedLabels(tt.reversed)
			if got != tt.want {
				t.Errorf("reverseReversedLabels(%q) = %q, want %q", tt.reversed, got, tt.want)
			}
		})
	}
}

// ========================= //
// ==  nullTermStr Tests  == //
// ========================= //

func TestNullTermStr(t *testing.T) {
	tests := []struct {
		b    []byte
		want string
	}{
		{[]byte{'h', 'i', 0, 'x', 'y'}, "hi"},
		{[]byte{'h', 'i'}, "hi"},  // no null terminator
		{[]byte{0, 'h', 'i'}, ""}, // null at start
		{[]byte{}, ""},
	}

	for _, tt := range tests {
		got := nullTermStr(tt.b)
		if got != tt.want {
			t.Errorf("nullTermStr(%v) = %q, want %q", tt.b, got, tt.want)
		}
	}
}

// ========================= //
// ==  netIPToStr Tests   == //
// ========================= //

func TestNetIPToStr(t *testing.T) {
	tests := []struct {
		ip   uint32
		want string
	}{
		{0x01020304, "1.2.3.4"},
		{0x7f000001, "127.0.0.1"},
		{0x00000000, "0.0.0.0"},
		{0xffffffff, "255.255.255.255"},
	}

	for _, tt := range tests {
		got := netIPToStr(tt.ip)
		if got != tt.want {
			t.Errorf("netIPToStr(0x%08x) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

// =========================== //
// ==  actionToString Tests == //
// =========================== //

func TestActionToString(t *testing.T) {
	tests := []struct {
		action int8
		want   string
	}{
		{0, "Allow"},
		{1, "Audit"},
		{-1, "Block"},
		{2, "Allow"}, // unknown defaults to Allow
	}

	for _, tt := range tests {
		got := actionToString(tt.action)
		if got != tt.want {
			t.Errorf("actionToString(%d) = %q, want %q", tt.action, got, tt.want)
		}
	}
}
