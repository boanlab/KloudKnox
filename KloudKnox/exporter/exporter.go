// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package exporter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// Exporter represents the exporters that export events to multiple backends
type Exporter struct {
	// Event queue system
	eventQueue chan tp.EventData
	queueSize  int

	// Worker context and cancel function
	workerContext context.Context
	workerCancel  context.CancelFunc
	workerDone    chan struct{}

	// Worker pool
	workerCount int
	workerWg    sync.WaitGroup

	// gRPC exporter
	grpcExporter *GRPCExporter
}

// Configuration constants
const (
	eventQueueSize = 100000
	workerCount    = 4 // Number of concurrent workers
	batchSize      = 128
	batchTimeout   = 100 * time.Millisecond
)

// batchItem holds an event data with its alert flag
type batchItem struct {
	evData  *tp.EventData
	isAlert bool // true if this should trigger ExportAlert
}

// NewExporter creates and initializes a new exporter instance
func NewExporter() (*Exporter, error) {
	// Create context for worker goroutine
	ctx, cancel := context.WithCancel(context.Background())

	newExporter := &Exporter{
		eventQueue:  make(chan tp.EventData, eventQueueSize),
		queueSize:   eventQueueSize,
		workerCount: workerCount,

		workerContext: ctx,
		workerCancel:  cancel,
		workerDone:    make(chan struct{}),
	}

	// Initialize gRPC exporter
	grpcExporter := NewGRPCExporter()
	if grpcExporter == nil {
		cancel() // Clean up context
		return nil, fmt.Errorf("failed to create gRPC exporter")
	}
	newExporter.grpcExporter = grpcExporter

	// Start event processing workers
	newExporter.startEventWorkers()

	return newExporter, nil
}

// startEventWorkers starts multiple background workers that process events from the queue
func (e *Exporter) startEventWorkers() {
	for i := 0; i < e.workerCount; i++ {
		e.workerWg.Add(1)
		go func() {
			defer e.workerWg.Done()
			e.processEventQueue()
		}()
	}
}

// processEventQueue processes events from the queue in a separate goroutine
func (e *Exporter) processEventQueue() {
	batch := make([]*batchItem, 0, batchSize)
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-e.workerContext.Done():
			// Drain remaining in-flight batch
			if len(batch) > 0 {
				e.flushBatch(batch)
				batch = batch[:0]
			}
			// Drain buffered events still in the channel
			for {
				select {
				case evData := <-e.eventQueue:
					item := &batchItem{evData: &evData, isAlert: evData.PolicyName != ""}
					batch = append(batch, item)
					if len(batch) >= batchSize {
						e.flushBatch(batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						e.flushBatch(batch)
					}
					log.Debug("Event queue worker shutting down")
					return
				}
			}
		case evData := <-e.eventQueue:
			item := &batchItem{
				evData:  &evData,
				isAlert: evData.PolicyName != "",
			}
			batch = append(batch, item)

			if len(batch) >= batchSize {
				e.flushBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				e.flushBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// flushBatch processes a batch of events
func (e *Exporter) flushBatch(batch []*batchItem) {
	// Export all events to EventStream
	for _, item := range batch {
		if err := e.grpcExporter.ExportEvent(e.workerContext, item.evData); err != nil {
			log.Errf("Failed to export event: %v", err)
		}
	}

	// Export alerts to AlertStream (separate from EventStream)
	for _, item := range batch {
		if item.isAlert {
			if err := e.grpcExporter.ExportAlert(e.workerContext, item.evData); err != nil {
				log.Errf("Failed to export alert: %v", err)
			}
		}
	}
}

// Stop stops the exporter and cleans up resources
func (e *Exporter) Stop() error {
	if e == nil {
		return nil
	}

	// Stop the event workers
	if e.workerCancel != nil {
		e.workerCancel()
	}
	e.workerWg.Wait()

	return nil
}

// ExportLog forwards a log entry to the gRPC log stream
func (e *Exporter) ExportLog(level, message string) {
	if e.grpcExporter != nil {
		e.grpcExporter.ExportLog(level, message)
	}
}

// ExportEvent exports an event to Exporters
func (e *Exporter) ExportEvent(evData tp.EventData) error {
	select {
	case e.eventQueue <- evData:
	default:
		log.Warnf("Export queue full: event dropped (backpressure from gRPC exporter)")
	}
	return nil
}
