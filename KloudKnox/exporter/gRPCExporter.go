// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package exporter

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/boanlab/KloudKnox/protobuf"
	"google.golang.org/grpc"
)

// StreamWorker represents a worker for a single gRPC event stream
type StreamWorker struct {
	stream     grpc.ServerStreamingServer[protobuf.Event]
	filter     *protobuf.EventFilter
	queue      chan *protobuf.Event
	workerDone chan struct{}
}

// AlertStreamWorker represents a worker for a single alert stream
type AlertStreamWorker struct {
	stream     grpc.ServerStreamingServer[protobuf.Alert]
	filter     *protobuf.AlertFilter
	queue      chan *protobuf.Alert
	workerDone chan struct{}
}

// LogStreamWorker represents a worker for a single log stream
type LogStreamWorker struct {
	stream     grpc.ServerStreamingServer[protobuf.Log]
	filter     *protobuf.LogFilter
	queue      chan *protobuf.Log
	workerDone chan struct{}
}

// GRPCExporter implements a gRPC server for exporting security events
type GRPCExporter struct {
	// gRPC server
	protobuf.UnimplementedKloudKnoxServer

	// context and cancel function
	ctx    context.Context
	cancel context.CancelFunc

	// server and listener
	server   *grpc.Server
	listener net.Listener
	port     int

	// event streams with per-stream workers
	eventStreams map[grpc.ServerStreamingServer[protobuf.Event]]*StreamWorker
	eventLock    sync.RWMutex

	// alert streams with per-stream workers
	alertStreams map[grpc.ServerStreamingServer[protobuf.Alert]]*AlertStreamWorker
	alertLock    sync.RWMutex

	// log streams with per-stream workers
	logStreams map[grpc.ServerStreamingServer[protobuf.Log]]*LogStreamWorker
	logLock    sync.RWMutex

	// shutdown signal
	shutdownSignal chan struct{}

	// worker wait group for graceful shutdown
	workerWg sync.WaitGroup
}

// NewGRPCExporter creates and initializes a new gRPC exporter
func NewGRPCExporter() *GRPCExporter {
	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create TCP listener on configured port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GlobalCfg.GRPCPort))
	if err != nil {
		cancel()
		log.Errf("failed to listen: %v", err)
		return nil
	}

	// Initialize gRPC server
	server := grpc.NewServer()
	exporter := &GRPCExporter{
		ctx:      ctx,
		cancel:   cancel,
		server:   server,
		listener: listener,
		port:     cfg.GlobalCfg.GRPCPort,

		eventStreams: make(map[grpc.ServerStreamingServer[protobuf.Event]]*StreamWorker),
		alertStreams: make(map[grpc.ServerStreamingServer[protobuf.Alert]]*AlertStreamWorker),
		logStreams:   make(map[grpc.ServerStreamingServer[protobuf.Log]]*LogStreamWorker),

		shutdownSignal: make(chan struct{}),
	}

	// Register the exporter as a KloudKnox server
	protobuf.RegisterKloudKnoxServer(server, exporter)

	// Start serving in a goroutine
	go func() {
		if err := server.Serve(listener); err != nil {
			if err != grpc.ErrServerStopped {
				log.Errf("failed to serve: %v", err)
			}
		}
	}()

	log.Printf("Started gRPC Exporter on port %d", cfg.GlobalCfg.GRPCPort)

	return exporter
}

// Stop gracefully shuts down the gRPC server
func (ge *GRPCExporter) Stop() error {
	// Cancel context to stop all goroutines
	ge.cancel()

	// Close all active event streams and wait for workers to finish
	ge.eventLock.Lock()
	for stream, worker := range ge.eventStreams {
		close(worker.queue)
		delete(ge.eventStreams, stream)
	}
	ge.eventLock.Unlock()
	ge.workerWg.Wait()

	// Close all active alert streams and wait for workers to finish
	ge.alertLock.Lock()
	for stream, worker := range ge.alertStreams {
		close(worker.queue)
		delete(ge.alertStreams, stream)
	}
	ge.alertLock.Unlock()
	ge.workerWg.Wait()

	// Close all active log streams and wait for workers to finish
	ge.logLock.Lock()
	for stream, worker := range ge.logStreams {
		close(worker.queue)
		delete(ge.logStreams, stream)
	}
	ge.logLock.Unlock()
	ge.workerWg.Wait()

	// Stop gRPC server with timeout
	stopChan := make(chan struct{})
	go func() {
		if ge.server != nil {
			ge.server.GracefulStop()
		}
		close(stopChan)
	}()

	// Wait for graceful stop with timeout
	select {
	case <-stopChan:
		// Server stopped gracefully
	case <-time.After(1 * time.Second):
		// Force stop after timeout
		if ge.server != nil {
			ge.server.Stop()
		}
	}

	// Close listener
	if ge.listener != nil {
		if err := ge.listener.Close(); err != nil {
			log.Debugf("Error closing listener: %v", err)
		}
	}

	// Signal shutdown complete
	close(ge.shutdownSignal)

	log.Print("Stopped gRPC Exporter")

	return nil
}

// convertEventDataToEvent converts EventData to protobuf Event
func convertEventDataToEvent(evData *tp.EventData) *protobuf.Event {
	return &protobuf.Event{
		Timestamp: evData.Timestamp,
		CPUID:     evData.CPUID,
		SeqNum:    evData.SeqNum,

		HostPPID: evData.HostPPID,
		HostPID:  evData.HostPID,
		HostTID:  evData.HostTID,

		PPID: evData.PPID,
		PID:  evData.PID,
		TID:  evData.TID,

		UID: evData.UID,
		GID: evData.GID,

		EventID:   evData.EventID,
		EventName: evData.EventName,
		RetVal:    evData.RetVal,
		RetCode:   evData.RetCode,

		Source:    evData.Source,
		Category:  evData.Category,
		Operation: evData.Operation,
		Resource:  evData.Resource,
		Data:      evData.Data,

		NodeName:      evData.NodeName,
		NamespaceName: evData.NamespaceName,
		PodName:       evData.PodName,
		ContainerName: evData.ContainerName,
		Labels:        evData.Labels,
	}
}

// ExportEvent creates a trace span to represent a security event
func (ge *GRPCExporter) ExportEvent(ctx context.Context, evData *tp.EventData) error {
	// Convert event data to protobuf format
	event := convertEventDataToEvent(evData)

	// Snapshot the streams map under the lock
	ge.eventLock.RLock()
	streams := make([]*StreamWorker, 0, len(ge.eventStreams))
	for _, worker := range ge.eventStreams {
		streams = append(streams, worker)
	}
	ge.eventLock.RUnlock()

	// Send to each stream outside the lock using per-stream workers.
	// Non-blocking send with timeout to prevent slow clients from blocking others.
	for _, worker := range streams {
		if !matchEventFilter(event, worker.filter) {
			continue
		}
		// Non-blocking send with context cancellation check
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-worker.stream.Context().Done():
			// Stream closed, skip
		case worker.queue <- event:
			// Event queued for async send
		default:
			// Queue full, skip this worker (log occasionally)
			log.Debugf("gRPC stream queue full: event dropped")
		}
	}

	return nil
}

// matchEventFilter checks if an event matches the given filter criteria
func matchEventFilter(ev *protobuf.Event, filter *protobuf.EventFilter) bool {
	if filter == nil {
		return true
	}

	// Check fields that are most likely to filter out events first
	// (PodName/ContainerName typically have more unique values)
	if filter.PodName != "" && !lib.MatchPrefix(ev.PodName, filter.PodName) {
		return false
	}
	if filter.ContainerName != "" && !lib.MatchPrefix(ev.ContainerName, filter.ContainerName) {
		return false
	}
	if filter.NamespaceName != "" && !lib.MatchExact(ev.NamespaceName, filter.NamespaceName) {
		return false
	}
	if filter.NodeName != "" && !lib.MatchExact(ev.NodeName, filter.NodeName) {
		return false
	}
	if filter.EventName != "" && !lib.MatchExact(ev.EventName, filter.EventName) {
		return false
	}
	if filter.Source != "" && !lib.MatchExact(ev.Source, filter.Source) {
		return false
	}
	if filter.Category != "" && !lib.MatchExact(ev.Category, filter.Category) {
		return false
	}
	if filter.Operation != "" && !lib.MatchExact(ev.Operation, filter.Operation) {
		return false
	}
	if filter.Resource != "" && !lib.MatchExact(ev.Resource, filter.Resource) {
		return false
	}
	if filter.Data != "" && !lib.MatchSubset(ev.Data, filter.Data) {
		return false
	}
	if filter.Labels != "" && !lib.MatchSubset(ev.Labels, filter.Labels) {
		return false
	}

	return true
}

// EventStream implements the gRPC EventStream service
func (ge *GRPCExporter) EventStream(filter *protobuf.EventFilter, stream grpc.ServerStreamingServer[protobuf.Event]) error {
	// Create a new worker for this stream
	worker := &StreamWorker{
		stream:     stream,
		filter:     filter,
		queue:      make(chan *protobuf.Event, 1000),
		workerDone: make(chan struct{}),
	}

	// Add to active streams map
	ge.eventLock.Lock()
	ge.eventStreams[stream] = worker
	ge.eventLock.Unlock()

	log.Printf("New client connected to event stream with filter: [%v]", filter)

	// Start the worker goroutine
	ge.workerWg.Add(1)
	go func() {
		defer ge.workerWg.Done()
		defer close(worker.workerDone)
		ge.processEventStream(worker)
	}()

	// Monitor stream context for client disconnection
	go func() {
		<-stream.Context().Done()
		ge.eventLock.Lock()
		if _, exists := ge.eventStreams[stream]; exists {
			close(worker.queue) // Close queue to stop worker
			delete(ge.eventStreams, stream)
		}
		ge.eventLock.Unlock()
		log.Print("gRPC Client disconnected")
	}()

	// Wait for either context cancellation or client disconnection
	select {
	case <-ge.ctx.Done():
		return ge.ctx.Err()
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

// processEventStream processes events for a single stream
func (ge *GRPCExporter) processEventStream(worker *StreamWorker) {
	for ev := range worker.queue {
		if err := worker.stream.Send(ev); err != nil {
			log.Debugf("Failed to send event: %v", err)
			return
		}
	}
}

// convertEventDataToAlert converts EventData to protobuf Alert
func convertEventDataToAlert(atData *tp.EventData) *protobuf.Alert {
	return &protobuf.Alert{
		Timestamp: atData.Timestamp,
		CPUID:     atData.CPUID,
		SeqNum:    atData.SeqNum,

		HostPPID: atData.HostPPID,
		HostPID:  atData.HostPID,
		HostTID:  atData.HostTID,
		PPID:     atData.PPID,
		PID:      atData.PID,
		TID:      atData.TID,

		UID: atData.UID,
		GID: atData.GID,

		EventID:   atData.EventID,
		EventName: atData.EventName,
		RetVal:    atData.RetVal,
		RetCode:   atData.RetCode,

		Source:    atData.Source,
		Category:  atData.Category,
		Operation: atData.Operation,
		Resource:  atData.Resource,
		Data:      atData.Data,

		NodeName:      atData.NodeName,
		NamespaceName: atData.NamespaceName,
		PodName:       atData.PodName,
		ContainerName: atData.ContainerName,
		Labels:        atData.Labels,

		PolicyName:   atData.PolicyName,
		PolicyAction: atData.PolicyAction,
	}
}

// ExportAlert creates a trace span to represent a security alert
func (ge *GRPCExporter) ExportAlert(ctx context.Context, atData *tp.EventData) error {
	// Convert event data to protobuf format
	alert := convertEventDataToAlert(atData)

	// Snapshot the streams map under the lock
	ge.alertLock.RLock()
	streams := make([]*AlertStreamWorker, 0, len(ge.alertStreams))
	for _, worker := range ge.alertStreams {
		streams = append(streams, worker)
	}
	ge.alertLock.RUnlock()

	// Send to each stream outside the lock using per-stream workers.
	for _, worker := range streams {
		if !matchAlertFilter(alert, worker.filter) {
			continue
		}
		// Non-blocking send with context cancellation check
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-worker.stream.Context().Done():
			// Stream closed, skip
		case worker.queue <- alert:
			// Alert queued for async send
		default:
			// Queue full, skip this worker
		}
	}

	return nil
}

// matchAlertFilter checks if an alert matches the given filter criteria
func matchAlertFilter(at *protobuf.Alert, filter *protobuf.AlertFilter) bool {
	if filter == nil {
		return true
	}

	// Check fields that are most likely to filter out events first
	if filter.PodName != "" && !lib.MatchPrefix(at.PodName, filter.PodName) {
		return false
	}
	if filter.ContainerName != "" && !lib.MatchPrefix(at.ContainerName, filter.ContainerName) {
		return false
	}
	if filter.NamespaceName != "" && !lib.MatchExact(at.NamespaceName, filter.NamespaceName) {
		return false
	}
	if filter.NodeName != "" && !lib.MatchExact(at.NodeName, filter.NodeName) {
		return false
	}
	if filter.EventName != "" && !lib.MatchExact(at.EventName, filter.EventName) {
		return false
	}
	if filter.Source != "" && !lib.MatchExact(at.Source, filter.Source) {
		return false
	}
	if filter.Category != "" && !lib.MatchExact(at.Category, filter.Category) {
		return false
	}
	if filter.Operation != "" && !lib.MatchExact(at.Operation, filter.Operation) {
		return false
	}
	if filter.Resource != "" && !lib.MatchExact(at.Resource, filter.Resource) {
		return false
	}
	if filter.Data != "" && !lib.MatchSubset(at.Data, filter.Data) {
		return false
	}
	if filter.Labels != "" && !lib.MatchSubset(at.Labels, filter.Labels) {
		return false
	}

	return true
}

// AlertStream implements the gRPC AlertStream service
func (ge *GRPCExporter) AlertStream(filter *protobuf.AlertFilter, stream grpc.ServerStreamingServer[protobuf.Alert]) error {
	// Create a new worker for this stream
	worker := &AlertStreamWorker{
		stream:     stream,
		filter:     filter,
		queue:      make(chan *protobuf.Alert, 1000),
		workerDone: make(chan struct{}),
	}

	// Add to active streams map
	ge.alertLock.Lock()
	ge.alertStreams[stream] = worker
	ge.alertLock.Unlock()

	log.Printf("New client connected to alert stream with filter: [%v]", filter)

	// Start the worker goroutine
	ge.workerWg.Add(1)
	go func() {
		defer ge.workerWg.Done()
		defer close(worker.workerDone)
		ge.processAlertStream(worker)
	}()

	// Monitor stream context for client disconnection
	go func() {
		<-stream.Context().Done()
		ge.alertLock.Lock()
		if _, exists := ge.alertStreams[stream]; exists {
			close(worker.queue) // Close queue to stop worker
			delete(ge.alertStreams, stream)
		}
		ge.alertLock.Unlock()
		log.Print("gRPC Client disconnected")
	}()

	// Wait for either context cancellation or client disconnection
	select {
	case <-ge.ctx.Done():
		return ge.ctx.Err()
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

// processAlertStream processes alerts for a single stream
func (ge *GRPCExporter) processAlertStream(worker *AlertStreamWorker) {
	for alert := range worker.queue {
		if err := worker.stream.Send(alert); err != nil {
			log.Debugf("Failed to send alert: %v", err)
			return
		}
	}
}

// ExportLog sends a log entry to all connected log stream clients
func (ge *GRPCExporter) ExportLog(level, message string) {
	entry := &protobuf.Log{
		Timestamp: uint64(time.Now().UnixNano()),
		Level:     level,
		Message:   message,
	}

	ge.logLock.RLock()
	workers := make([]*LogStreamWorker, 0, len(ge.logStreams))
	for _, w := range ge.logStreams {
		workers = append(workers, w)
	}
	ge.logLock.RUnlock()

	for _, w := range workers {
		if w.filter != nil && w.filter.Level != "" && w.filter.Level != level {
			continue
		}
		select {
		case w.queue <- entry:
		default:
			// queue full: drop silently to avoid recursive log calls
		}
	}
}

// LogStream implements the gRPC LogStream service
func (ge *GRPCExporter) LogStream(filter *protobuf.LogFilter, stream grpc.ServerStreamingServer[protobuf.Log]) error {
	worker := &LogStreamWorker{
		stream:     stream,
		filter:     filter,
		queue:      make(chan *protobuf.Log, 1000),
		workerDone: make(chan struct{}),
	}

	ge.logLock.Lock()
	ge.logStreams[stream] = worker
	ge.logLock.Unlock()

	log.Printf("New client connected to log stream with filter: [%v]", filter)

	ge.workerWg.Add(1)
	go func() {
		defer ge.workerWg.Done()
		defer close(worker.workerDone)
		for entry := range worker.queue {
			if err := worker.stream.Send(entry); err != nil {
				return
			}
		}
	}()

	go func() {
		<-stream.Context().Done()
		ge.logLock.Lock()
		if _, exists := ge.logStreams[stream]; exists {
			close(worker.queue)
			delete(ge.logStreams, stream)
		}
		ge.logLock.Unlock()
	}()

	select {
	case <-ge.ctx.Done():
		return ge.ctx.Err()
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}
