// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"testing"
)

// ========================== //
// ==  FNV-1a hash tests    == //
// ========================== //

// Reference: BPF-side bpfe_unix_hash() uses the same FNV-1a parameters.
// If this drifts from the BPF implementation, socket-path matching breaks
// silently (no compile error) — so this test is load-bearing.

func TestFnv1aUnixPath_KnownValues(t *testing.T) {
	cases := []struct {
		path string
		want uint32
	}{
		// Empty string — hash of no bytes = FNV offset basis
		{"", 2166136261},
		// "/tmp/test.sock" — manually computed FNV-1a (first 64 bytes, null-stop)
		{"/tmp/test.sock", fnv1aRef("/tmp/test.sock")},
		// 64-byte-exactly path: full prefix hashed
		{string(make([]byte, 64)), fnv1aRef(string(make([]byte, 64)))},
		// path longer than 64 bytes: must hash only first 64 bytes
		{"/a" + string(make([]byte, 100)), fnv1aRef("/a" + string(make([]byte, 64)))},
	}

	for _, c := range cases {
		got := fnv1aUnixPath(c.path)
		if got != c.want {
			t.Errorf("fnv1aUnixPath(%q) = 0x%x, want 0x%x", c.path, got, c.want)
		}
	}
}

// fnv1aRef is the reference implementation used only in tests to cross-check
// the production fnv1aUnixPath. It mirrors the BPF C code exactly.
func fnv1aRef(path string) uint32 {
	const (
		offset = uint32(2166136261)
		prime  = uint32(16777619)
		limit  = 64
	)
	h := offset
	for i := 0; i < limit && i < len(path); i++ {
		c := path[i]
		if c == 0 {
			break
		}
		h = (h ^ uint32(c)) * prime
	}
	return h
}

// Verify long-path truncation: two paths that share the first 64 bytes but
// differ after must produce identical hashes (since BPF only reads 64 bytes).
func TestFnv1aUnixPath_Truncation(t *testing.T) {
	prefix := string(make([]byte, 63)) + "x"
	pathA := prefix + "AAA"
	pathB := prefix + "BBB"
	if fnv1aUnixPath(pathA) != fnv1aUnixPath(pathB) {
		t.Errorf("paths sharing first 64 bytes must hash identically")
	}
}

// ========================= //
// ==  encodeAction tests  == //
// ========================= //

func TestEncodeAction(t *testing.T) {
	if encodeAction("Allow") != actionAllow {
		t.Error("Allow must encode to actionAllow")
	}
	if encodeAction("Audit") != actionAudit {
		t.Error("Audit must encode to actionAudit")
	}
	if encodeAction("Block") != actionBlock {
		t.Error("Block must encode to actionBlock")
	}
	// Unknown string falls back to Allow
	if encodeAction("") != actionAllow {
		t.Error("empty string must encode to actionAllow")
	}
	if encodeAction("deny") != actionAllow {
		t.Error("unknown string must encode to actionAllow")
	}
}

// ========================= //
// ==  encodeSockType      == //
// ========================= //

func TestEncodeSockType(t *testing.T) {
	if encodeSockType("stream") != 1 {
		t.Error("stream must be 1 (SOCK_STREAM)")
	}
	if encodeSockType("dgram") != 2 {
		t.Error("dgram must be 2 (SOCK_DGRAM)")
	}
	if encodeSockType("") != 0 {
		t.Error("empty must be 0 (any)")
	}
	if encodeSockType("unknown") != 0 {
		t.Error("unknown type must be 0 (any)")
	}
}

// ========================= //
// ==  encodeUnixPerm      == //
// ========================= //

func TestEncodeUnixPerm(t *testing.T) {
	cases := []struct {
		perm string
		want uint8
	}{
		{"connect", 0},
		{"send", 1},
		{"receive", 2},
		{"bind", 3},
		{"listen", 4},
		{"", 0}, // default
		{"unknown", 0},
	}
	for _, c := range cases {
		if got := encodeUnixPerm(c.perm); got != c.want {
			t.Errorf("encodeUnixPerm(%q) = %d, want %d", c.perm, got, c.want)
		}
	}
}

// ========================= //
// ==  containsXxx tests   == //
// ========================= //

func TestContainsBpfeProcKey(t *testing.T) {
	k := bpf_enforcerBpfeProcKey{PodInode: 1, SrcInode: 2, TgtInode: 3}
	keys := []bpf_enforcerBpfeProcKey{k}
	if !containsBpfeProcKey(keys, k) {
		t.Error("should contain key")
	}
	other := bpf_enforcerBpfeProcKey{PodInode: 9}
	if containsBpfeProcKey(keys, other) {
		t.Error("should not contain unrelated key")
	}
	if containsBpfeProcKey(nil, k) {
		t.Error("nil slice should return false")
	}
}

func TestContainsBpfeFileKey(t *testing.T) {
	k := bpf_enforcerBpfeFileKey{PodInode: 1, SrcInode: 2, TgtInode: 3, Permission: permFileRead}
	keys := []bpf_enforcerBpfeFileKey{k}
	if !containsBpfeFileKey(keys, k) {
		t.Error("should contain key")
	}
	kw := bpf_enforcerBpfeFileKey{PodInode: 1, SrcInode: 2, TgtInode: 3, Permission: permFileWrite}
	if containsBpfeFileKey(keys, kw) {
		t.Error("read and write keys must be distinct")
	}
}

func TestContainsBpfeCapKey(t *testing.T) {
	k := bpf_enforcerBpfeCapKey{PodInode: 10, SrcInode: 20, CapId: 5}
	keys := []bpf_enforcerBpfeCapKey{k}
	if !containsBpfeCapKey(keys, k) {
		t.Error("should contain key")
	}
	if containsBpfeCapKey(nil, k) {
		t.Error("nil slice should return false")
	}
}

func TestContainsBpfeSignalKey(t *testing.T) {
	k := bpf_enforcerBpfeSignalKey{PodInode: 1, SrcInode: 2, TargetInode: 3}
	keys := []bpf_enforcerBpfeSignalKey{k}
	if !containsBpfeSignalKey(keys, k) {
		t.Error("should contain key")
	}
	k2 := bpf_enforcerBpfeSignalKey{PodInode: 1, SrcInode: 2, TargetInode: 0}
	if containsBpfeSignalKey(keys, k2) {
		t.Error("different TargetInode must not match")
	}
}

func TestContainsBpfePtraceKey(t *testing.T) {
	k := bpf_enforcerBpfePtraceKey{PodInode: 1, SrcInode: 2, TargetInode: 3}
	if !containsBpfePtraceKey([]bpf_enforcerBpfePtraceKey{k}, k) {
		t.Error("should contain key")
	}
}

func TestContainsBpfeUnixKey(t *testing.T) {
	k := bpf_enforcerBpfeUnixKey{PodInode: 1, SrcInode: 2, PathHash: 0xdeadbeef, SockType: 1, Permission: 0}
	if !containsBpfeUnixKey([]bpf_enforcerBpfeUnixKey{k}, k) {
		t.Error("should contain key")
	}
	k2 := k
	k2.Permission = 1
	if containsBpfeUnixKey([]bpf_enforcerBpfeUnixKey{k}, k2) {
		t.Error("different Permission must not match")
	}
}

// ========================= //
// ==  postureForGlobal    == //
// ========================= //

func TestPostureForGlobal(t *testing.T) {
	// Allow policy → posture must block unlisted entries
	if postureForGlobal("Allow") != "Block" {
		t.Error("Allow policy must yield Block posture")
	}
	// Block policy → posture must allow unlisted entries (BPF default)
	if postureForGlobal("Block") != "Allow" {
		t.Error("Block policy must yield Allow posture")
	}
	// Unknown/empty → safe default
	if postureForGlobal("") != "Allow" {
		t.Error("empty GlobalAction must yield Allow posture")
	}
}

func TestContainsBpfePostureKey(t *testing.T) {
	k := bpf_enforcerBpfePostureKey{PodInode: 1, SrcInode: 0, Domain: domainFile}
	if !containsBpfePostureKey([]bpf_enforcerBpfePostureKey{k}, k) {
		t.Error("should contain key")
	}
	k2 := k
	k2.Domain = domainProc
	if containsBpfePostureKey([]bpf_enforcerBpfePostureKey{k}, k2) {
		t.Error("different Domain must not match")
	}
}
