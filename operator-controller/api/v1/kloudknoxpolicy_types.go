// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Policy status values reported in KloudKnoxPolicyStatus.PolicyStatus.
const (
	PolicyStatusActive  = "Active"
	PolicyStatusInvalid = "Invalid"
	PolicyStatusPending = "Pending"
)

// ProcessRule restricts process execution within matched pods.
// Exactly one of Path or Dir must be set; Recursive is only valid with Dir.
type ProcessRule struct {
	// Path is the absolute path of the executable to match (e.g. /bin/bash).
	// +kubebuilder:validation:Pattern="^/(?:[^/\\s]+/)*[^/\\s]+$"
	Path string `json:"path,omitempty"`
	// Dir is the absolute directory prefix to match (must end with /).
	// +kubebuilder:validation:Pattern="^/(?:[^/\\s]+/)+$"
	Dir string `json:"dir,omitempty"`
	// Recursive enables matching in all subdirectories when Dir is set.
	Recursive bool `json:"recursive,omitempty"`
	// FromSource restricts the rule to processes spawned by one of the listed executables.
	FromSource []SourceMatch `json:"fromSource,omitempty"`
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// FileRule restricts file-system access within matched pods.
// Exactly one of Path or Dir must be set; Recursive is only valid with Dir.
type FileRule struct {
	// Path is the absolute path of the file to match.
	// +kubebuilder:validation:Pattern="^/(?:[^/\\s]+/)*[^/\\s]+$"
	Path string `json:"path,omitempty"`
	// Dir is the absolute directory prefix to match (must end with /).
	// +kubebuilder:validation:Pattern="^/(?:[^/\\s]+/)+$"
	Dir string `json:"dir,omitempty"`
	// Recursive enables matching in all subdirectories when Dir is set.
	Recursive bool `json:"recursive,omitempty"`
	// ReadOnly enforces read-only access when set together with an Allow action.
	ReadOnly   bool          `json:"readOnly,omitempty"`
	FromSource []SourceMatch `json:"fromSource,omitempty"`
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// CapabilityRule restricts Linux capability usage within matched pods.
// Name accepts either the "CAP_" prefix or the short form (case insensitive);
// the validator normalizes both to the canonical CAP_* symbol.
type CapabilityRule struct {
	// Name is the Linux capability symbol (e.g. NET_RAW or CAP_NET_RAW).
	// +kubebuilder:validation:Pattern="^(CAP_)?[A-Z0-9_]+$"
	Name string `json:"name"`
	// FromSource restricts the rule to processes whose executable matches Path.
	FromSource []SourceMatch `json:"fromSource,omitempty"`
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// NetworkRule restricts ingress or egress traffic within matched pods.
// Exactly one of Selector, IPBlock, or FQDN must be set.
type NetworkRule struct {
	// Direction specifies whether the rule applies to incoming or outgoing traffic.
	// +kubebuilder:validation:Enum=ingress;egress
	Direction string `json:"direction"`
	// Selector matches remote pods by label (Kubernetes mode only).
	Selector map[string]string `json:"selector,omitempty"`
	// IPBlock matches a remote CIDR range with optional exceptions.
	IPBlock IPBlock `json:"ipBlock,omitempty"`
	// FQDN matches a fully-qualified domain name (e.g. api.example.com).
	// +kubebuilder:validation:Pattern="^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
	FQDN       string        `json:"fqdn,omitempty"`
	Ports      []Port        `json:"ports,omitempty"`
	FromSource []SourceMatch `json:"fromSource,omitempty"`
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// IPBlock specifies an IPv4 CIDR range with optional exception sub-ranges.
type IPBlock struct {
	// +kubebuilder:validation:Pattern="^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}/([0-9]|[1-2][0-9]|3[0-2])$"
	CIDR string `json:"cidr,omitempty"`
	// Except lists sub-CIDRs that are excluded from the match.
	Except []string `json:"except,omitempty"`
}

// Port identifies a transport-layer protocol and port number.
// ICMP entries must leave Port as zero (ICMP has no port concept).
type Port struct {
	// +kubebuilder:validation:Enum=TCP;UDP;ICMP;SCTP
	Protocol string `json:"protocol"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// SourceMatch constrains a rule to processes whose executable matches Path.
type SourceMatch struct {
	// +kubebuilder:validation:Pattern="^/(?:[^/\\s]+/)*[^/\\s]+$"
	Path string `json:"path,omitempty"`
}

// IPCRules groups the three inter-process-communication sub-domains under a
// single spec.ipc block.
type IPCRules struct {
	Unix   []UnixRule   `json:"unix,omitempty"`
	Signal []SignalRule `json:"signal,omitempty"`
	Ptrace []PtraceRule `json:"ptrace,omitempty"`
}

// UnixRule restricts Unix domain socket operations within matched pods. Path
// accepts either a filesystem path ("/var/run/...") or an abstract namespace
// socket prefixed with "@".
type UnixRule struct {
	// +kubebuilder:validation:Enum=stream;dgram
	Type string `json:"type"`
	// Path is the socket address. Empty matches any path.
	// +kubebuilder:validation:Pattern="^(@|/)[^\\s]+$"
	Path string `json:"path,omitempty"`
	// Permissions accepts one or more of connect, send, receive, bind, listen.
	// The webhook coerces single strings to a singleton array.
	Permissions []string      `json:"permission"`
	FromSource  []SourceMatch `json:"fromSource,omitempty"`
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// SignalRule restricts signal delivery from matched pods. LSM hooks intercept
// only the send side, so Permission is fixed to "send".
type SignalRule struct {
	// +kubebuilder:validation:Enum=send
	Permission string `json:"permission"`
	// Target is the absolute path of the recipient binary. Empty matches any.
	// +kubebuilder:validation:Pattern="^/(?:[^/\\s]+/)*[^/\\s]+$"
	Target string `json:"target,omitempty"`
	// Signals lists SIGHUP..SIGSYS by symbolic name; empty matches any signal.
	Signals    []string      `json:"signals,omitempty"`
	FromSource []SourceMatch `json:"fromSource,omitempty"`
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// PtraceRule restricts ptrace-class operations. "trace"/"read" apply when the
// source is the tracer; "traceby"/"readby" apply when the source is the tracee.
type PtraceRule struct {
	// +kubebuilder:validation:Enum=trace;read;traceby;readby
	Permission string `json:"permission"`
	// Target is the peer binary path (tracer for *by, tracee otherwise).
	// +kubebuilder:validation:Pattern="^/(?:[^/\\s]+/)*[^/\\s]+$"
	Target     string        `json:"target,omitempty"`
	FromSource []SourceMatch `json:"fromSource,omitempty"`
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// KloudKnoxPolicySpec defines the desired security policy for a set of pods.
type KloudKnoxPolicySpec struct {
	// Selector maps pod label keys to values. Required unless ApplyToAll is true.
	Selector map[string]string `json:"selector,omitempty"`

	// ApplyToAll, when true, applies the policy to every container on the
	// host without requiring a selector. Only honored in docker/hybrid modes;
	// Kubernetes mode treats it as a validation error because cluster-wide
	// enforcement should go through namespace selectors instead.
	ApplyToAll bool `json:"applyToAll,omitempty"`

	Process    []ProcessRule    `json:"process,omitempty"`
	File       []FileRule       `json:"file,omitempty"`
	Network    []NetworkRule    `json:"network,omitempty"`
	Capability []CapabilityRule `json:"capability,omitempty"`
	IPC        *IPCRules        `json:"ipc,omitempty"`

	// Action is the default enforcement action for rules that do not specify one.
	// +kubebuilder:validation:Enum=Allow;Audit;Block
	Action string `json:"action,omitempty"`
}

// KloudKnoxPolicyStatus is the observed state of a KloudKnoxPolicy.
type KloudKnoxPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

// KloudKnoxPolicy is the Schema for the kloudknoxpolicies API.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type KloudKnoxPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KloudKnoxPolicySpec   `json:"spec"`
	Status            KloudKnoxPolicyStatus `json:"status,omitempty"`
}

// KloudKnoxPolicyList contains a list of KloudKnoxPolicy.
//
// +kubebuilder:object:root=true
type KloudKnoxPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KloudKnoxPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KloudKnoxPolicy{}, &KloudKnoxPolicyList{})
}
