// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

// FNV-1a 64-bit constants from the FNV specification.
const (
	fnvOffsetBasis64 = 14695981039346656037
	fnvPrime64       = 1099511628211
)

// FNV1a64 returns the FNV-1a 64-bit hash of data. The implementation is
// intentionally byte-identical to the BPF-side hash in
// KloudKnox/BPF/enforcer/bpf_enforcer.bpf.h so that user-space keys match what
// the kernel program computes when looking up policy map entries.
func FNV1a64(data []byte) uint64 {
	h := uint64(fnvOffsetBasis64)
	for _, b := range data {
		h ^= uint64(b)
		h *= fnvPrime64
	}
	return h
}

// FNV1a64String is the string convenience variant of FNV1a64.
func FNV1a64String(s string) uint64 {
	return FNV1a64([]byte(s))
}

// FNV1a64UnixPath hashes a Unix-socket path exactly the way the BPF hook does:
// abstract-namespace sockets (user-space form "@name") are hashed with the
// leading '@' replaced by a NUL byte, mirroring the kernel's sun_path[0]==0
// convention.
func FNV1a64UnixPath(path string) uint64 {
	if len(path) == 0 {
		return 0
	}
	if path[0] == '@' {
		b := make([]byte, len(path))
		b[0] = 0
		copy(b[1:], path[1:])
		return FNV1a64(b)
	}
	return FNV1a64([]byte(path))
}
