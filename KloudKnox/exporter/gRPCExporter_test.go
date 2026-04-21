// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package exporter

import (
	"testing"

	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/boanlab/KloudKnox/protobuf"
)

// ===================================== //
// ==  convertEventDataToEvent Tests  == //
// ===================================== //

func TestConvertEventDataToEvent(t *testing.T) {
	evData := &tp.EventData{
		Timestamp:     1000,
		CPUID:         1,
		SeqNum:        2,
		HostPPID:      10,
		HostPID:       100,
		HostTID:       101,
		PPID:          5,
		PID:           50,
		TID:           51,
		UID:           1000,
		GID:           1000,
		EventID:       59,
		EventName:     "execve",
		RetVal:        0,
		RetCode:       "success",
		Source:        "/bin/sh",
		Category:      "process",
		Operation:     "execute",
		Resource:      "/bin/ls",
		Data:          "test-data",
		NodeName:      "node-1",
		NamespaceName: "default",
		PodName:       "nginx-abc",
		ContainerName: "nginx",
		Labels:        "app=nginx",
	}

	ev := convertEventDataToEvent(evData)

	if ev.Timestamp != 1000 {
		t.Errorf("Timestamp = %d, want 1000", ev.Timestamp)
	}
	if ev.EventName != "execve" {
		t.Errorf("EventName = %q, want execve", ev.EventName)
	}
	if ev.Source != "/bin/sh" {
		t.Errorf("Source = %q, want /bin/sh", ev.Source)
	}
	if ev.PodName != "nginx-abc" {
		t.Errorf("PodName = %q, want nginx-abc", ev.PodName)
	}
	if ev.NamespaceName != "default" {
		t.Errorf("NamespaceName = %q, want default", ev.NamespaceName)
	}
	// PolicyName/PolicyAction should NOT be in Event (only in Alert)
	_ = ev
}

func TestConvertEventDataToEventZeroValues(t *testing.T) {
	ev := convertEventDataToEvent(&tp.EventData{})
	if ev == nil {
		t.Fatal("expected non-nil event for zero EventData")
	}
	if ev.EventName != "" {
		t.Errorf("expected empty EventName, got %q", ev.EventName)
	}
}

// ===================================== //
// ==  convertEventDataToAlert Tests  == //
// ===================================== //

func TestConvertEventDataToAlert(t *testing.T) {
	evData := &tp.EventData{
		EventID:      59,
		EventName:    "execve",
		PolicyName:   "block-cat",
		PolicyAction: "Block",
		PodName:      "pod-xyz",
	}

	alert := convertEventDataToAlert(evData)

	if alert.PolicyName != "block-cat" {
		t.Errorf("PolicyName = %q, want block-cat", alert.PolicyName)
	}
	if alert.PolicyAction != "Block" {
		t.Errorf("PolicyAction = %q, want Block", alert.PolicyAction)
	}
	if alert.EventName != "execve" {
		t.Errorf("EventName = %q, want execve", alert.EventName)
	}
	if alert.PodName != "pod-xyz" {
		t.Errorf("PodName = %q, want pod-xyz", alert.PodName)
	}
}

// ==================================== //
// ==  matchEventFilter Tests        == //
// ==================================== //

func buildTestEvent(name, source, category, operation, resource, data, node, ns, pod, container, labels string) *protobuf.Event {
	return &protobuf.Event{
		EventName:     name,
		Source:        source,
		Category:      category,
		Operation:     operation,
		Resource:      resource,
		Data:          data,
		NodeName:      node,
		NamespaceName: ns,
		PodName:       pod,
		ContainerName: container,
		Labels:        labels,
	}
}

func TestMatchEventFilterNilFilter(t *testing.T) {
	ev := buildTestEvent("execve", "/bin/sh", "", "", "", "", "", "", "", "", "")
	if !matchEventFilter(ev, nil) {
		t.Error("nil filter should match everything")
	}
}

func TestMatchEventFilterEmptyFilter(t *testing.T) {
	ev := buildTestEvent("execve", "/bin/sh", "", "", "", "", "", "", "", "", "")
	if !matchEventFilter(ev, &protobuf.EventFilter{}) {
		t.Error("empty filter should match everything")
	}
}

func TestMatchEventFilterExactEventName(t *testing.T) {
	ev := buildTestEvent("execve", "", "", "", "", "", "", "", "", "", "")
	filter := &protobuf.EventFilter{EventName: "execve"}
	if !matchEventFilter(ev, filter) {
		t.Error("exact EventName should match")
	}
}

func TestMatchEventFilterEventNameMismatch(t *testing.T) {
	ev := buildTestEvent("openat", "", "", "", "", "", "", "", "", "", "")
	filter := &protobuf.EventFilter{EventName: "execve"}
	if matchEventFilter(ev, filter) {
		t.Error("different EventName should not match")
	}
}

func TestMatchEventFilterPodNamePrefix(t *testing.T) {
	ev := buildTestEvent("", "", "", "", "", "", "", "", "nginx-abc123", "", "")
	filter := &protobuf.EventFilter{PodName: "nginx-"}
	if !matchEventFilter(ev, filter) {
		t.Error("pod name prefix should match")
	}
}

func TestMatchEventFilterPodNamePrefixNoMatch(t *testing.T) {
	ev := buildTestEvent("", "", "", "", "", "", "", "", "apache-abc", "", "")
	filter := &protobuf.EventFilter{PodName: "nginx-"}
	if matchEventFilter(ev, filter) {
		t.Error("pod name with wrong prefix should not match")
	}
}

func TestMatchEventFilterDataSubset(t *testing.T) {
	ev := buildTestEvent("", "", "", "", "", "flags: O_WRONLY|O_CREAT", "", "", "", "", "")
	filter := &protobuf.EventFilter{Data: "O_WRONLY"}
	if !matchEventFilter(ev, filter) {
		t.Error("data subset match should succeed")
	}
}

func TestMatchEventFilterDataSubsetNoMatch(t *testing.T) {
	ev := buildTestEvent("", "", "", "", "", "O_RDONLY", "", "", "", "", "")
	filter := &protobuf.EventFilter{Data: "O_WRONLY"}
	if matchEventFilter(ev, filter) {
		t.Error("data subset mismatch should fail")
	}
}

func TestMatchEventFilterMultipleFields(t *testing.T) {
	ev := buildTestEvent("execve", "/bin/sh", "process", "execute", "/bin/ls", "", "node-1", "default", "nginx-abc", "nginx", "app=nginx")
	filter := &protobuf.EventFilter{
		EventName:     "execve",
		NamespaceName: "default",
		PodName:       "nginx-",
	}
	if !matchEventFilter(ev, filter) {
		t.Error("all fields matching should succeed")
	}
}

func TestMatchEventFilterMultipleFieldsOneFails(t *testing.T) {
	ev := buildTestEvent("execve", "/bin/sh", "process", "execute", "/bin/ls", "", "node-1", "default", "nginx-abc", "nginx", "app=nginx")
	filter := &protobuf.EventFilter{
		EventName:     "execve",
		NamespaceName: "kube-system", // mismatch
	}
	if matchEventFilter(ev, filter) {
		t.Error("one mismatched field should cause overall filter failure")
	}
}

// ==================================== //
// ==  matchAlertFilter Tests        == //
// ==================================== //

func buildTestAlert(name, source, ns, pod, policyName, policyAction string) *protobuf.Alert {
	return &protobuf.Alert{
		EventName:     name,
		Source:        source,
		NamespaceName: ns,
		PodName:       pod,
		PolicyName:    policyName,
		PolicyAction:  policyAction,
	}
}

func TestMatchAlertFilterNilFilter(t *testing.T) {
	at := buildTestAlert("execve", "/bin/sh", "default", "pod-1", "block-policy", "Block")
	if !matchAlertFilter(at, nil) {
		t.Error("nil filter should match everything")
	}
}

func TestMatchAlertFilterExactMatch(t *testing.T) {
	at := buildTestAlert("execve", "", "default", "nginx-abc", "", "")
	filter := &protobuf.AlertFilter{
		EventName:     "execve",
		NamespaceName: "default",
	}
	if !matchAlertFilter(at, filter) {
		t.Error("matching alert filter should succeed")
	}
}

func TestMatchAlertFilterPodPrefix(t *testing.T) {
	at := buildTestAlert("", "", "", "nginx-abc123", "", "")
	filter := &protobuf.AlertFilter{PodName: "nginx-"}
	if !matchAlertFilter(at, filter) {
		t.Error("pod name prefix filter should match")
	}
}

func TestMatchAlertFilterNoMatch(t *testing.T) {
	at := buildTestAlert("execve", "", "default", "pod-1", "", "")
	filter := &protobuf.AlertFilter{NamespaceName: "production"}
	if matchAlertFilter(at, filter) {
		t.Error("different namespace should not match")
	}
}
