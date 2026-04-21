// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package exporter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

func TestMain(m *testing.M) {
	log.SetLogger("stdout", "error")
	os.Exit(m.Run())
}

// =============================== //
// ==  ExportEvent Queue Tests  == //
// =============================== //

// newTestExporter creates an Exporter with a fake GRPCExporter that does
// nothing, so tests do not need a real TCP listener.
func newTestExporter(queueSize int) *Exporter {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{
		eventQueue:    make(chan tp.EventData, queueSize),
		queueSize:     queueSize,
		workerContext: ctx,
		workerCancel:  cancel,
		workerDone:    make(chan struct{}),
		grpcExporter:  nil, // no real gRPC server
	}
	// Start a no-op worker that just drains the queue so it doesn't block.
	go func() {
		defer close(e.workerDone)
		for {
			select {
			case <-e.workerContext.Done():
				return
			case <-e.eventQueue:
				// discard
			}
		}
	}()
	return e
}

func TestExportEventQueues(t *testing.T) {
	e := newTestExporter(100)
	defer e.Stop() // nolint

	ev := tp.EventData{EventID: 59, EventName: "execve"}
	if err := e.ExportEvent(ev); err != nil {
		t.Fatalf("ExportEvent returned error: %v", err)
	}
}

func TestExportEventQueueFull(t *testing.T) {
	e := newTestExporter(2)
	defer e.Stop() // nolint

	// Stop the draining worker so the queue fills up.
	e.workerCancel()
	<-e.workerDone

	// Reset worker done so Stop() doesn't deadlock on a closed channel.
	e.workerDone = make(chan struct{})
	close(e.workerDone)

	// Fill the queue exactly.
	_ = e.ExportEvent(tp.EventData{EventID: 1})
	_ = e.ExportEvent(tp.EventData{EventID: 2})

	// Third call should drop silently (queue full) and still return nil.
	if err := e.ExportEvent(tp.EventData{EventID: 3}); err != nil {
		t.Errorf("ExportEvent on full queue should return nil, got %v", err)
	}

	// Queue should still hold exactly 2 events.
	if len(e.eventQueue) != 2 {
		t.Errorf("queue length = %d, want 2 after overflow drop", len(e.eventQueue))
	}
}

func TestExportEventReturnNil(t *testing.T) {
	e := newTestExporter(100)
	defer e.Stop() // nolint

	for i := 0; i < 10; i++ {
		if err := e.ExportEvent(tp.EventData{EventID: int32(i)}); err != nil {
			t.Fatalf("ExportEvent[%d] = %v, want nil", i, err)
		}
	}
}

// ========================== //
// ==  Stop Tests          == //
// ========================== //

func TestStopNilExporter(t *testing.T) {
	var e *Exporter
	if err := e.Stop(); err != nil {
		t.Errorf("Stop(nil) = %v, want nil", err)
	}
}

func TestStopGraceful(t *testing.T) {
	e := newTestExporter(100)

	done := make(chan struct{})
	go func() {
		_ = e.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() timed out — worker did not exit")
	}
}

func TestStopIdempotent(t *testing.T) {
	e := newTestExporter(10)
	_ = e.Stop()

	// Calling Stop again should not panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("second Stop() panicked: %v", r)
			}
		}()
		// workerCancel() after first Stop has already cancelled the context;
		// calling it again is a no-op for context.CancelFunc.
		_ = e.Stop()
	}()
}
