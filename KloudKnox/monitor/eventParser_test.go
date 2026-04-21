// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ================================= //
// ==  readEventFromBuff Tests    == //
// ================================= //

func TestReadEventFromBuff(t *testing.T) {
	// Build the Event struct in little-endian binary form
	ev := Event{
		Timestamp: 1234567890,
		CPUID:     2,
		SeqNum:    42,
		PidNsID:   100,
		MntNsID:   200,
		HostPPID:  1,
		HostPID:   1000,
		HostTID:   1001,
		PPID:      10,
		PID:       100,
		TID:       101,
		UID:       0,
		GID:       0,
		EventID:   59,
		EventType: EventTypeUnary,
		ArgNum:    0,
		RetVal:    0,
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, ev); err != nil {
		t.Fatalf("failed to write test event: %v", err)
	}

	got, err := readEventFromBuff(buf)
	if err != nil {
		t.Fatalf("readEventFromBuff error: %v", err)
	}

	if got.Timestamp != ev.Timestamp {
		t.Errorf("Timestamp = %d, want %d", got.Timestamp, ev.Timestamp)
	}
	if got.EventID != ev.EventID {
		t.Errorf("EventID = %d, want %d", got.EventID, ev.EventID)
	}
	if got.HostPID != ev.HostPID {
		t.Errorf("HostPID = %d, want %d", got.HostPID, ev.HostPID)
	}
}

func TestReadEventFromBuffEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	_, err := readEventFromBuff(buf)
	if err == nil {
		t.Error("expected error when reading from empty buffer")
	}
}

// ================================== //
// ==  readStringFromBuff Tests    == //
// ================================== //

func writeString(buf *bytes.Buffer, s string) {
	data := append([]byte(s), 0x00) // null-terminated
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)
}

func TestReadStringFromBuff(t *testing.T) {
	buf := new(bytes.Buffer)
	writeString(buf, "hello")

	got, err := readStringFromBuff(buf)
	if err != nil {
		t.Fatalf("readStringFromBuff error: %v", err)
	}
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestReadStringFromBuffEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // size=0

	got, err := readStringFromBuff(buf)
	if err != nil {
		t.Fatalf("readStringFromBuff(empty) error: %v", err)
	}
	// Size 0 → "unknown" per implementation
	if got != "unknown" {
		t.Errorf("got %q, want unknown for zero-length string", got)
	}
}

func TestReadStringFromBuffTooLarge(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(4096)) // exceeds 2048 limit

	_, err := readStringFromBuff(buf)
	if err == nil {
		t.Error("expected error when string size exceeds limit")
	}
}

func TestReadStringFromBuffNullTrimming(t *testing.T) {
	buf := new(bytes.Buffer)
	data := []byte{'a', 'b', 'c', 0, 0, 0} // trailing nulls
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	buf.Write(data)

	got, err := readStringFromBuff(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if got != "abc" {
		t.Errorf("got %q, want %q (trailing nulls should be trimmed)", got, "abc")
	}
}

// ===================================== //
// ==  readStringArrayFromBuff Tests  == //
// ===================================== //

func writeStringArrayEntry(buf *bytes.Buffer, s string) {
	_ = binary.Write(buf, binary.LittleEndian, uint32(TypeStr))
	writeString(buf, s)
}

func TestReadStringArrayFromBuff(t *testing.T) {
	buf := new(bytes.Buffer)
	writeStringArrayEntry(buf, "arg1")
	writeStringArrayEntry(buf, "arg2")
	// Terminate with type=0
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))

	got, err := readStringArrayFromBuff(buf)
	if err != nil {
		t.Fatalf("readStringArrayFromBuff error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d strings, want 2", len(got))
	}
	if got[0] != "arg1" || got[1] != "arg2" {
		t.Errorf("got %v, want [arg1 arg2]", got)
	}
}

func TestReadStringArrayFromBuffEmpty(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // immediate terminator

	got, err := readStringArrayFromBuff(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty array, got %v", got)
	}
}

// ================================= //
// ==  readArgFromBuff Tests      == //
// ================================= //

func TestReadArgFromBuffInt(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(TypeInt))
	_ = binary.Write(buf, binary.LittleEndian, int32(-42))

	v, err := readArgFromBuff(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if v.(int32) != -42 {
		t.Errorf("got %v, want -42", v)
	}
}

func TestReadArgFromBuffUInt(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(TypeUInt))
	_ = binary.Write(buf, binary.LittleEndian, uint32(1000))

	v, err := readArgFromBuff(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if v.(uint32) != 1000 {
		t.Errorf("got %v, want 1000", v)
	}
}

func TestReadArgFromBuffULong(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(TypeULong))
	_ = binary.Write(buf, binary.LittleEndian, uint64(0xDEADBEEF))

	v, err := readArgFromBuff(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if v.(uint64) != 0xDEADBEEF {
		t.Errorf("got %v, want 0xDEADBEEF", v)
	}
}

func TestReadArgFromBuffStr(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(TypeStr))
	writeString(buf, "/bin/ls")

	v, err := readArgFromBuff(buf)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if v.(string) != "/bin/ls" {
		t.Errorf("got %v, want /bin/ls", v)
	}
}

func TestReadArgFromBuffUnknownType(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint32(9999))

	_, err := readArgFromBuff(buf)
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

// ============================ //
// ==  safe* helpers Tests   == //
// ============================ //

func TestSafeString(t *testing.T) {
	if safeString("hello") != "hello" {
		t.Error("safeString string passthrough failed")
	}
	if safeString(nil) != "unknown" {
		t.Error("safeString(nil) should return unknown")
	}
	if safeString(42) != "42" {
		t.Error("safeString(int) should fallback to Sprintf")
	}
}

func TestSafeStringSlice(t *testing.T) {
	in := []string{"a", "b"}
	got := safeStringSlice(in)
	if len(got) != 2 || got[0] != "a" {
		t.Errorf("safeStringSlice passthrough failed: %v", got)
	}

	got2 := safeStringSlice(nil)
	if len(got2) != 1 || got2[0] != "unknown" {
		t.Errorf("safeStringSlice(nil) = %v, want [unknown]", got2)
	}
}

func TestSafeInt32(t *testing.T) {
	if safeInt32(int32(-5)) != -5 {
		t.Error("safeInt32 passthrough failed")
	}
	if safeInt32(nil) != 0 {
		t.Error("safeInt32(nil) should return 0")
	}
	if safeInt32("not-int") != 0 {
		t.Error("safeInt32 wrong type should return 0")
	}
}

func TestSafeUint32(t *testing.T) {
	if safeUint32(uint32(99)) != 99 {
		t.Error("safeUint32 passthrough failed")
	}
	if safeUint32(nil) != 0 {
		t.Error("safeUint32(nil) should return 0")
	}
}

func TestSafeUint64(t *testing.T) {
	if safeUint64(uint64(12345678)) != 12345678 {
		t.Error("safeUint64 passthrough failed")
	}
	if safeUint64(nil) != 0 {
		t.Error("safeUint64(nil) should return 0")
	}
}
