// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package types

// KloudKnoxProcessRule defines execution control rules for processes within containers
type KloudKnoxProcessRule struct {
	Path       string        // Absolute path to the process executable
	Dir        string        // Directory path for process execution
	Recursive  bool          // Apply rules to subdirectories
	FromSource []SourceMatch // Parent process restrictions
	Action     string        // Enforcement action (allow/audit/block)
}

// KloudKnoxFileRule defines access control rules for files and directories
type KloudKnoxFileRule struct {
	Path       string        // Absolute path to the file
	Dir        string        // Directory path for file access
	Recursive  bool          // Apply rules to subdirectories
	ReadOnly   bool          // Restrict to read-only access
	FromSource []SourceMatch // Process restrictions for access
	Action     string        // Enforcement action (allow/audit/block)
}

// KloudKnoxCapabilityRule defines Linux capability usage rules for containers.
// Name is the canonical CAP_* symbol; CapID caches the resolved bit number so
// enforcers and monitors do not have to re-normalize on every rule lookup.
type KloudKnoxCapabilityRule struct {
	Name       string        // Canonical CAP_* symbol (e.g. "CAP_NET_RAW")
	CapID      uint32        // Linux capability bit number
	FromSource []SourceMatch // Process restrictions for capability use
	Action     string        // Enforcement action (Allow/Audit/Block)
}

// KloudKnoxIPCRules is the internal mirror of the CRD `spec.ipc` block.
type KloudKnoxIPCRules struct {
	Unix   []KloudKnoxUnixRule   // Unix domain socket restrictions
	Signal []KloudKnoxSignalRule // Signal delivery restrictions
	Ptrace []KloudKnoxPtraceRule // Ptrace-class restrictions
}

// KloudKnoxUnixRule mirrors UnixRule with all permissions normalized to a
// slice so policy converter code can treat single- and multi-permission rules
// uniformly.
type KloudKnoxUnixRule struct {
	Type        string        // stream | dgram
	Path        string        // filesystem ("/...") or abstract ("@...") socket
	Permissions []string      // connect / send / receive / bind / listen
	FromSource  []SourceMatch // process restrictions
	Action      string        // Allow / Audit / Block
}

// KloudKnoxSignalRule mirrors SignalRule. Signals is an ordered list of
// SIG* symbols; the converter resolves them to numeric values. Permission is
// implicitly "send" — the LSM hook is send-side only.
type KloudKnoxSignalRule struct {
	Target     string        // recipient binary path (empty = any)
	Signals    []string      // e.g. ["SIGTERM", "SIGHUP"]; empty = any
	FromSource []SourceMatch // process restrictions
	Action     string        // Allow / Audit / Block
}

// KloudKnoxPtraceRule mirrors PtraceRule. traceby/readby flip the source/target
// interpretation — see AppArmor `ptrace (tracedby, readby) peer=...`.
type KloudKnoxPtraceRule struct {
	Permission string        // trace | read | traceby | readby
	Target     string        // peer binary path
	FromSource []SourceMatch // process restrictions
	Action     string        // Allow / Audit / Block
}

// KloudKnoxNetworkRule defines network access control rules for containers
type KloudKnoxNetworkRule struct {
	Direction  string            // Traffic direction (ingress/egress)
	Selector   map[string]string // Pod selector for target matching
	IPBlock    IPBlock           // IP address range restrictions
	FQDN       string            // Fully qualified domain name
	Ports      []Port            // Allowed port configurations
	FromSource []SourceMatch     // Process restrictions for connections
	Action     string            // Enforcement action (allow/audit/block)
}

// IPBlock defines IP address range restrictions for network rules
type IPBlock struct {
	CIDR   string   // CIDR notation for IP range
	Except []string // Excluded IP ranges from the CIDR block
}

// Port defines port and protocol configurations for network rules
type Port struct {
	Protocol string // Transport protocol (TCP, UDP)
	Port     int32  // Port number (1-65535)
}

// SourceMatch defines process matching rules for policy enforcement
type SourceMatch struct {
	Path string // Absolute path to the process executable
}

// KloudKnoxPolicy defines the complete security policy configuration for Kubernetes resources
type KloudKnoxPolicy struct {
	NamespaceName string                    // Kubernetes namespace identifier
	PolicyID      uint32                    // Policy ID
	PolicyName    string                    // Policy name
	Selector      map[string]string         // Pod selector for policy application
	Identities    string                    // Security identity string
	ApplyToAll    bool                      // Bypass selector match; applies to every container (docker/hybrid only)
	Process       []KloudKnoxProcessRule    // Process execution rules
	File          []KloudKnoxFileRule       // File access rules
	Network       []KloudKnoxNetworkRule    // Network access rules
	Capability    []KloudKnoxCapabilityRule // Linux capability rules
	IPC           KloudKnoxIPCRules         // Inter-process communication rules
	Action        string                    // Default enforcement action
}

// InnerFileRules groups file/process rules for a single source path bucket.
// Block and Audit rules live in InnerRules; Allow rules are also mirrored into
// AllowRules so enforcers can test whitelist membership in O(1).
type InnerFileRules struct {
	InnerRules  map[string]FileRule
	AllowRules  map[string]FileRule
	InnerAction string // per-source default: "Allow" or "Block"
}

// FileRules is the pod-level file and process rule set.
// OuterRules is keyed by source-binary path or "default" (container-wide).
type FileRules struct {
	OuterRules   map[string]InnerFileRules
	GlobalAction string // global default: "Allow" or "Block"
}

// FileRule is the normalized in-core form of a single process-exec or file
// access rule. Permission encodes both the domain and the action:
// uppercase = Allow or Audit, lowercase = Block.
type FileRule struct {
	Policy     KloudKnoxPolicy
	IsPath     bool   // rule targets a single path (vs. a directory)
	IsDir      bool   // rule targets a directory
	Recursive  bool   // directory match descends into subdirectories
	Permission string // "r"/"R"/"w"/"W"/"x"/"X"/"rw"/"RW" — see policyConverter
	Action     string // "Allow", "Audit", or "Block"
}

// CapabilityRule is the normalized in-core form of a capability rule produced
// by policyConverter and consumed by both the AppArmor enforcer and monitor.
type CapabilityRule struct {
	Policy KloudKnoxPolicy // Policy that this rule belongs to
	CapID  uint32          // Linux capability bit number
	Name   string          // Canonical CAP_* symbol (alert payload)
	Action string          // Enforcement action (Allow/Audit/Block)
}

// InnerCapabilityRules groups capability rules by source path, mirroring
// InnerFileRules. Block and Audit rules live in InnerRules, Allow rules in
// AllowRules (populated after extraction).
type InnerCapabilityRules struct {
	InnerRules  map[uint32]CapabilityRule // Block and Audit rules keyed by CapID
	AllowRules  map[uint32]CapabilityRule // Allow rules keyed by CapID
	InnerAction string                    // Per-source default (Allow/Block)
}

// CapabilityRules is the pod-level capability rule set, keyed by source path
// or "default" for the container-wide bucket.
type CapabilityRules struct {
	OuterRules   map[string]InnerCapabilityRules
	GlobalAction string // Global default (Allow/Block)
}

// InnerNetworkRules groups network rules for one source-path bucket.
type InnerNetworkRules struct {
	InnerRules     map[string]NetworkRule // key: "selector:…", "cidr:…", or "fqdn:…"
	DefaultPosture string                 // "Allow" or "Block"
}

// NetworkRules is the pod-level network rule set split by direction.
// Each map is keyed by source-binary path or "default".
type NetworkRules struct {
	IngressRules map[string]InnerNetworkRules
	EgressRules  map[string]InnerNetworkRules
}

// NetworkRule is the normalized in-core form of a network access rule.
type NetworkRule struct {
	Policy     KloudKnoxPolicy
	CIDRExcept []string            // excluded subnets from an IPBlock CIDR
	Ports      map[string][]uint16 // protocol → port list
	Action     string              // "Allow", "Audit", or "Block"
}

// UnixRule is the normalized in-core form of a Unix-socket rule produced by
// policyConverter and consumed by both enforcers (AppArmor, BPF LSM) and the
// monitor. Permission is the single token this rule installs — multi-permission
// CRD rules fan out into one UnixRule per token at conversion time.
type UnixRule struct {
	Policy     KloudKnoxPolicy
	Type       string // stream | dgram
	Path       string // socket address
	Permission string // connect | send | receive | bind | listen
	Action     string // Allow / Audit / Block
}

// SignalRule is the normalized in-core form of a signal rule. Signals lists
// the raw signal numbers (1..31) matched by this rule; empty means match-any.
type SignalRule struct {
	Policy  KloudKnoxPolicy
	Target  string // recipient binary path (empty = any)
	Signals []int  // signal numbers; empty = any
	Action  string // Allow / Audit / Block
}

// PtraceRule is the normalized in-core form of a ptrace rule.
type PtraceRule struct {
	Policy     KloudKnoxPolicy
	Permission string // trace | read | traceby | readby
	Target     string // peer binary path
	Action     string // Allow / Audit / Block
}

// InnerIPCRules groups IPC rules by source path, mirroring InnerFileRules and
// InnerCapabilityRules. AllowRules is populated during the extract pass and
// used by the monitor to attribute "not-Allowed" events back to a policy.
type InnerIPCRules struct {
	Unix   map[string]UnixRule   // key: type|path|permission
	Signal map[string]SignalRule // key: target|signalsCanonical
	Ptrace map[string]PtraceRule // key: permission|target

	UnixAllow   map[string]UnixRule
	SignalAllow map[string]SignalRule
	PtraceAllow map[string]PtraceRule

	InnerAction string // Per-source default (Allow/Block)
}

// IPCRules is the pod-level IPC rule set, keyed by source path or "default"
// for the container-wide bucket.
type IPCRules struct {
	OuterRules   map[string]InnerIPCRules
	GlobalAction string // Global default (Allow/Block)
}
