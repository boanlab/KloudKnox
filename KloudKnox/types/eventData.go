// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package types

import "time"

// Event Data Structure

// EventExporter is an interface for exporting events
type EventExporter interface {
	ExportEvent(EventData) error
}

// EventData represents an event captured from the system
type EventData struct {
	// Basic event information
	Timestamp uint64 `json:"timestamp"`
	CPUID     uint32 `json:"cpuID"`
	SeqNum    uint32 `json:"seqNum"`

	// Namespace information
	PidNsID uint32 `json:"pidNsID,omitempty"`
	MntNsID uint32 `json:"mntNsID,omitempty"`

	// Host process information
	HostPPID int32 `json:"hostPPID"`
	HostPID  int32 `json:"hostPID"`
	HostTID  int32 `json:"hostTID"`

	// Process information
	PPID int32 `json:"PPID"`
	PID  int32 `json:"PID"`
	TID  int32 `json:"TID"`

	// User information
	UID uint32 `json:"UID"`
	GID uint32 `json:"GID"`

	// System call information
	EventID   int32  `json:"eventID"`
	EventName string `json:"eventName"`
	EventType int32  `json:"eventType,omitempty"`
	ArgNum    int32  `json:"argNum,omitempty"`
	RetVal    int32  `json:"retVal"`
	RetCode   string `json:"retCode"`

	// Event categorization
	Source    string `json:"source"`
	Category  string `json:"category"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Data      string `json:"data"`

	// Container information
	NodeName      string `json:"nodeName"`
	NamespaceName string `json:"namespaceName,omitempty"`
	PodName       string `json:"podName,omitempty"`
	ContainerName string `json:"containerName,omitempty"`
	Labels        string `json:"labels,omitempty"`

	// Policy information
	PolicyName   string `json:"policyName,omitempty"`
	PolicyAction string `json:"policyAction,omitempty"`

	// Network routing metadata — not exported over gRPC; set by network
	// event handlers for internal packet attribution only.
	Saddr uint32 // source IPv4 address (network byte order)
	Daddr uint32 // destination IPv4 address (network byte order)

	// TempInt32 and TempUint32 carry ephemeral values between the syscall-
	// enter and syscall-exit handlers for the same thread (e.g. the fd opened
	// by accept, or the rename flags). Never exported; zero outside the
	// enter/exit pairing window.
	TempInt32  int32
	TempUint32 uint32
}

// PendingEvents represents a collection of events that are buffered for retry
type PendingEvents struct {
	PendingEvents []EventData
	CreatedAt     time.Time
}
