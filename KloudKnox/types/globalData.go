// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package types

import (
	"sync"
	"sync/atomic"
)

// IPEntry stores IP information for a node, pod, or service
type IPEntry struct {
	Type    string // "node" or "pod" or "service"
	Node    Node
	Pod     Pod
	Service Service
}

// GlobalData stores global data for KloudKnox
type GlobalData struct {
	// Nodes
	Node     map[string]Node
	NodeLock sync.RWMutex

	// Pods
	Pods     map[string]Pod
	PodsLock sync.RWMutex

	// Containers
	Containers     map[string]Container
	ContainersLock sync.RWMutex

	// Services
	Services     map[string]Service
	ServicesLock sync.RWMutex

	RuntimePolicies     map[string][]KloudKnoxPolicy
	RuntimePoliciesLock sync.RWMutex

	// IP Map for Pod and Service lookup
	IPMap     map[string]IPEntry
	IPMapLock sync.RWMutex

	// PidNS-MntNS Namespaces for container lookup
	NsMap     map[uint64]Container
	NsMapLock sync.RWMutex

	// SkipNsHook is called when a namespace is added to st_skip_ns_map so that
	// the network enforcer can mirror the update to ne_skip_ns_map.
	SkipNsHook func(nsKey uint64)

	// Pid Map for process lookup
	PidMap sync.Map

	// ExitHook is called on process exit so that the network enforcer can clean up
	// orphan entries in its kprobe intermediate maps keyed by pid_tgid.
	ExitHook func(hostPID, hostTID int32)

	// Mono base time for timestamp conversion
	MonoBaseNS atomic.Int64

	// EnforcerType is set to "bpf" when BpfEnforcer is active, "apparmor" otherwise.
	// Used by the monitor to skip policy attribution when BPF does it directly.
	EnforcerType string
}

// NewGlobalData creates a new GlobalData instance
func NewGlobalData() *GlobalData {
	return &GlobalData{
		Node:                map[string]Node{},
		NodeLock:            sync.RWMutex{},
		Pods:                map[string]Pod{},
		PodsLock:            sync.RWMutex{},
		Containers:          map[string]Container{},
		ContainersLock:      sync.RWMutex{},
		Services:            map[string]Service{},
		ServicesLock:        sync.RWMutex{},
		RuntimePolicies:     map[string][]KloudKnoxPolicy{},
		RuntimePoliciesLock: sync.RWMutex{},
		IPMap:               map[string]IPEntry{},
		IPMapLock:           sync.RWMutex{},
		NsMap:               map[uint64]Container{},
		NsMapLock:           sync.RWMutex{},
		PidMap:              sync.Map{},
		MonoBaseNS:          atomic.Int64{},
	}
}
