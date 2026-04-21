// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-19 -cflags "-O3 -g" -target amd64 net_enforcer ../BPF/enforcer/net_enforcer.bpf.c
