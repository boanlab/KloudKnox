// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/exporter"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// StopChan signals graceful shutdown to all monitor goroutines.
var StopChan chan struct{}

func init() {
	StopChan = make(chan struct{})
}

// SystemMonitor represents the core system monitor that tracks
// process, file system, and network events using eBPF programs
type SystemMonitor struct {
	// eBPF objects and links
	sysEventsObjs  *system_eventsObjects
	sysEventsLinks []link.Link

	// Ring buffer and per-worker channels for critical events.
	// Events are sharded by HostTID so Enter/Exit pairs for the same
	// thread land on the same worker and are processed in order —
	// without this, a parallel worker could pull an Exit before
	// another worker had stored the paired Enter, orphaning the event.
	sysCriticalEventsRb *ringbuf.Reader
	CriticalEventsChans []chan *bytes.Buffer

	// Ring buffer and per-worker channels for non-critical events.
	sysNonCriticalEventsRb *ringbuf.Reader
	NonCriticalEventsChans []chan *bytes.Buffer

	// Global Data (Pod, NsMap, PidMap, MonoBaseNS)
	globalData *tp.GlobalData

	// Sharded event map
	evMapShards []struct {
		data       map[int64]tp.EventData
		timestamps map[int64]time.Time
		lock       sync.RWMutex
	}
	evMapShardCount int

	// Drop counters for ring buffer channel saturation
	criticalDrops    atomic.Uint64
	nonCriticalDrops atomic.Uint64

	// Pending events for handling race conditions
	pendingEvents     map[uint64]tp.PendingEvents
	pendingEventsLock sync.Mutex

	// Path map for pid, fd, and sock
	fdMap   sync.Map
	sockMap sync.Map

	// Delete map for pid
	deletePidMap []struct {
		key  int32
		time time.Time
	}
	deletePidMapLock sync.RWMutex

	// Delete map for fd
	deleteFdMap []struct {
		key  int64
		time time.Time
	}
	deleteFdMapLock sync.RWMutex

	// Delete map for sock
	deleteSockMap []struct {
		key  int64
		time time.Time
	}
	deleteSockMapLock sync.RWMutex

	// Exporter
	exporter *exporter.Exporter

	// WaitGroup for workers and readers
	stopOnce  sync.Once
	wg        sync.WaitGroup
	readersWg sync.WaitGroup
}

// Configuration constants
const (
	maxCriticalWorkerPools = 4
	// Per-worker queue depth. Total buffering = pools * depth.
	criticalEventsChanSize = 25000

	maxNonCriticalWorkerPools = 4
	nonCriticalEventsChanSize = 25000

	evMapShardCount = 256
	evMapShardSize  = 1024
)

// NewSystemMonitor creates and initializes a new system monitor instance
func NewSystemMonitor(globalData *tp.GlobalData, exporter *exporter.Exporter) (*SystemMonitor, error) {
	newMonitor := &SystemMonitor{
		sysEventsLinks: make([]link.Link, 0, 128),

		CriticalEventsChans:    makeWorkerChans(maxCriticalWorkerPools, criticalEventsChanSize),
		NonCriticalEventsChans: makeWorkerChans(maxNonCriticalWorkerPools, nonCriticalEventsChanSize),

		globalData: globalData,

		evMapShards: make([]struct {
			data       map[int64]tp.EventData
			timestamps map[int64]time.Time
			lock       sync.RWMutex
		}, evMapShardCount),
		evMapShardCount: evMapShardCount,

		pendingEvents:     make(map[uint64]tp.PendingEvents),
		pendingEventsLock: sync.Mutex{},

		fdMap:   sync.Map{},
		sockMap: sync.Map{},

		deletePidMap: make([]struct {
			key  int32
			time time.Time
		}, 0),
		deletePidMapLock: sync.RWMutex{},

		deleteFdMap: make([]struct {
			key  int64
			time time.Time
		}, 0),
		deleteFdMapLock: sync.RWMutex{},

		deleteSockMap: make([]struct {
			key  int64
			time time.Time
		}, 0),
		deleteSockMapLock: sync.RWMutex{},

		exporter: exporter,

		stopOnce:  sync.Once{},
		wg:        sync.WaitGroup{},
		readersWg: sync.WaitGroup{},
	}

	// Initialize each shard's map and lock
	for i := 0; i < newMonitor.evMapShardCount; i++ {
		newMonitor.evMapShards[i].data = make(map[int64]tp.EventData, evMapShardSize)
		newMonitor.evMapShards[i].timestamps = make(map[int64]time.Time, evMapShardSize)
		newMonitor.evMapShards[i].lock = sync.RWMutex{}
	}

	// Load eBPF program
	sysEventsObjs := &system_eventsObjects{}
	if err := loadSystem_eventsObjects(sysEventsObjs, nil); err != nil {
		return nil, fmt.Errorf("loading system events objects: %w", err)
	}
	newMonitor.sysEventsObjs = sysEventsObjs

	// syscalls tracepoints
	tracepoints := []struct {
		name string
		prog *ebpf.Program
	}{
		// Process Events

		{"sys_enter_execve", sysEventsObjs.TracepointSyscallsSysEnterExecve},
		{"sys_exit_execve", sysEventsObjs.TracepointSyscallsSysExitExecve},
		{"sys_enter_execveat", sysEventsObjs.TracepointSyscallsSysEnterExecveat},
		{"sys_exit_execveat", sysEventsObjs.TracepointSyscallsSysExitExecveat},
		{"sys_enter_exit", sysEventsObjs.TracepointSyscallsSysEnterExit},
		{"sys_exit_exit", sysEventsObjs.TracepointSyscallsSysExitExit},
		{"sys_enter_exit_group", sysEventsObjs.TracepointSyscallsSysEnterExitGroup},
		{"sys_exit_exit_group", sysEventsObjs.TracepointSyscallsSysExitExitGroup},

		// IPC Events — signal/ptrace syscalls feed IPCPolicyMatch.
		{"sys_enter_kill", sysEventsObjs.TracepointSyscallsSysEnterKill},
		{"sys_exit_kill", sysEventsObjs.TracepointSyscallsSysExitKill},
		{"sys_enter_tgkill", sysEventsObjs.TracepointSyscallsSysEnterTgkill},
		{"sys_exit_tgkill", sysEventsObjs.TracepointSyscallsSysExitTgkill},
		{"sys_enter_ptrace", sysEventsObjs.TracepointSyscallsSysEnterPtrace},
		{"sys_exit_ptrace", sysEventsObjs.TracepointSyscallsSysExitPtrace},

		// File Events

		{"sys_enter_open", sysEventsObjs.TracepointSyscallsSysEnterOpen},
		{"sys_exit_open", sysEventsObjs.TracepointSyscallsSysExitOpen},
		{"sys_enter_openat", sysEventsObjs.TracepointSyscallsSysEnterOpenat},
		{"sys_exit_openat", sysEventsObjs.TracepointSyscallsSysExitOpenat},
		{"sys_enter_openat2", sysEventsObjs.TracepointSyscallsSysEnterOpenat2},
		{"sys_exit_openat2", sysEventsObjs.TracepointSyscallsSysExitOpenat2},
		{"sys_enter_close", sysEventsObjs.TracepointSyscallsSysEnterClose},
		{"sys_exit_close", sysEventsObjs.TracepointSyscallsSysExitClose},
	}

	if cfg.GlobalCfg.Coverage == "extended" {
		tracepoints = append(tracepoints, []struct {
			name string
			prog *ebpf.Program
		}{
			// Process Events
			{"sys_enter_clone", sysEventsObjs.TracepointSyscallsSysEnterClone},
			{"sys_exit_clone", sysEventsObjs.TracepointSyscallsSysExitClone},
			{"sys_enter_clone3", sysEventsObjs.TracepointSyscallsSysEnterClone3},
			{"sys_exit_clone3", sysEventsObjs.TracepointSyscallsSysExitClone3},

			{"sys_enter_setuid", sysEventsObjs.TracepointSyscallsSysEnterSetuid},
			{"sys_exit_setuid", sysEventsObjs.TracepointSyscallsSysExitSetuid},
			{"sys_enter_setreuid", sysEventsObjs.TracepointSyscallsSysEnterSetreuid},
			{"sys_exit_setreuid", sysEventsObjs.TracepointSyscallsSysExitSetreuid},
			{"sys_enter_setresuid", sysEventsObjs.TracepointSyscallsSysEnterSetresuid},
			{"sys_exit_setresuid", sysEventsObjs.TracepointSyscallsSysExitSetresuid},
			{"sys_enter_setfsuid", sysEventsObjs.TracepointSyscallsSysEnterSetfsuid},
			{"sys_exit_setfsuid", sysEventsObjs.TracepointSyscallsSysExitSetfsuid},
			{"sys_enter_setgid", sysEventsObjs.TracepointSyscallsSysEnterSetgid},
			{"sys_exit_setgid", sysEventsObjs.TracepointSyscallsSysExitSetgid},
			{"sys_enter_setregid", sysEventsObjs.TracepointSyscallsSysEnterSetregid},
			{"sys_exit_setregid", sysEventsObjs.TracepointSyscallsSysExitSetregid},
			{"sys_enter_setresgid", sysEventsObjs.TracepointSyscallsSysEnterSetresgid},
			{"sys_exit_setresgid", sysEventsObjs.TracepointSyscallsSysExitSetresgid},
			{"sys_enter_setfsgid", sysEventsObjs.TracepointSyscallsSysEnterSetfsgid},
			{"sys_exit_setfsgid", sysEventsObjs.TracepointSyscallsSysExitSetfsgid},
			{"sys_enter_unshare", sysEventsObjs.TracepointSyscallsSysEnterUnshare},
			{"sys_exit_unshare", sysEventsObjs.TracepointSyscallsSysExitUnshare},
			{"sys_enter_setns", sysEventsObjs.TracepointSyscallsSysEnterSetns},
			{"sys_exit_setns", sysEventsObjs.TracepointSyscallsSysExitSetns},
			{"sys_enter_setrlimit", sysEventsObjs.TracepointSyscallsSysEnterSetrlimit},
			{"sys_exit_setrlimit", sysEventsObjs.TracepointSyscallsSysExitSetrlimit},
			{"sys_enter_chroot", sysEventsObjs.TracepointSyscallsSysEnterChroot},
			{"sys_exit_chroot", sysEventsObjs.TracepointSyscallsSysExitChroot},
			{"sys_enter_capset", sysEventsObjs.TracepointSyscallsSysEnterCapset},
			{"sys_exit_capset", sysEventsObjs.TracepointSyscallsSysExitCapset},

			// File Events
			{"sys_enter_chown", sysEventsObjs.TracepointSyscallsSysEnterChown},
			{"sys_exit_chown", sysEventsObjs.TracepointSyscallsSysExitChown},
			{"sys_enter_fchown", sysEventsObjs.TracepointSyscallsSysEnterFchown},
			{"sys_exit_fchown", sysEventsObjs.TracepointSyscallsSysExitFchown},
			{"sys_enter_fchownat", sysEventsObjs.TracepointSyscallsSysEnterFchownat},
			{"sys_exit_fchownat", sysEventsObjs.TracepointSyscallsSysExitFchownat},
			{"sys_enter_chmod", sysEventsObjs.TracepointSyscallsSysEnterChmod},
			{"sys_exit_chmod", sysEventsObjs.TracepointSyscallsSysExitChmod},
			{"sys_enter_fchmod", sysEventsObjs.TracepointSyscallsSysEnterFchmod},
			{"sys_exit_fchmod", sysEventsObjs.TracepointSyscallsSysExitFchmod},
			{"sys_enter_fchmodat", sysEventsObjs.TracepointSyscallsSysEnterFchmodat},
			{"sys_exit_fchmodat", sysEventsObjs.TracepointSyscallsSysExitFchmodat},
			{"sys_enter_unlink", sysEventsObjs.TracepointSyscallsSysEnterUnlink},
			{"sys_exit_unlink", sysEventsObjs.TracepointSyscallsSysExitUnlink},
			{"sys_enter_unlinkat", sysEventsObjs.TracepointSyscallsSysEnterUnlinkat},
			{"sys_exit_unlinkat", sysEventsObjs.TracepointSyscallsSysExitUnlinkat},
			{"sys_enter_rename", sysEventsObjs.TracepointSyscallsSysEnterRename},
			{"sys_exit_rename", sysEventsObjs.TracepointSyscallsSysExitRename},
			{"sys_enter_renameat", sysEventsObjs.TracepointSyscallsSysEnterRenameat},
			{"sys_exit_renameat", sysEventsObjs.TracepointSyscallsSysExitRenameat},
			{"sys_enter_renameat2", sysEventsObjs.TracepointSyscallsSysEnterRenameat2},
			{"sys_exit_renameat2", sysEventsObjs.TracepointSyscallsSysExitRenameat2},
			{"sys_enter_link", sysEventsObjs.TracepointSyscallsSysEnterLink},
			{"sys_exit_link", sysEventsObjs.TracepointSyscallsSysExitLink},
			{"sys_enter_linkat", sysEventsObjs.TracepointSyscallsSysEnterLinkat},
			{"sys_exit_linkat", sysEventsObjs.TracepointSyscallsSysExitLinkat},
			{"sys_enter_symlink", sysEventsObjs.TracepointSyscallsSysEnterSymlink},
			{"sys_exit_symlink", sysEventsObjs.TracepointSyscallsSysExitSymlink},
			{"sys_enter_symlinkat", sysEventsObjs.TracepointSyscallsSysEnterSymlinkat},
			{"sys_exit_symlinkat", sysEventsObjs.TracepointSyscallsSysExitSymlinkat},
			{"sys_enter_mkdir", sysEventsObjs.TracepointSyscallsSysEnterMkdir},
			{"sys_exit_mkdir", sysEventsObjs.TracepointSyscallsSysExitMkdir},
			{"sys_enter_mkdirat", sysEventsObjs.TracepointSyscallsSysEnterMkdirat},
			{"sys_exit_mkdirat", sysEventsObjs.TracepointSyscallsSysExitMkdirat},
			{"sys_enter_rmdir", sysEventsObjs.TracepointSyscallsSysEnterRmdir},
			{"sys_exit_rmdir", sysEventsObjs.TracepointSyscallsSysExitRmdir},
			{"sys_enter_mount", sysEventsObjs.TracepointSyscallsSysEnterMount},
			{"sys_exit_mount", sysEventsObjs.TracepointSyscallsSysExitMount},
			{"sys_enter_umount", sysEventsObjs.TracepointSyscallsSysEnterUmount}, // not umount2, use umount (internally use umount2)
			{"sys_exit_umount", sysEventsObjs.TracepointSyscallsSysExitUmount},   // not umount2, use umount (internally use umount2)

			// Network Events

			{"sys_enter_socket", sysEventsObjs.TracepointSyscallsSysEnterSocket},
			{"sys_exit_socket", sysEventsObjs.TracepointSyscallsSysExitSocket},
			{"sys_enter_bind", sysEventsObjs.TracepointSyscallsSysEnterBind},
			{"sys_exit_bind", sysEventsObjs.TracepointSyscallsSysExitBind},
			{"sys_enter_connect", sysEventsObjs.TracepointSyscallsSysEnterConnect},
			{"sys_exit_connect", sysEventsObjs.TracepointSyscallsSysExitConnect},

			{"sys_enter_listen", sysEventsObjs.TracepointSyscallsSysEnterListen},
			{"sys_exit_listen", sysEventsObjs.TracepointSyscallsSysExitListen},
			{"sys_enter_accept", sysEventsObjs.TracepointSyscallsSysEnterAccept},
			{"sys_exit_accept", sysEventsObjs.TracepointSyscallsSysExitAccept},
			{"sys_enter_accept4", sysEventsObjs.TracepointSyscallsSysEnterAccept4},
			{"sys_exit_accept4", sysEventsObjs.TracepointSyscallsSysExitAccept4},
		}...)
	}

	// Attach syscalls tracepoints
	for _, tp := range tracepoints {
		link, err := link.Tracepoint("syscalls", tp.name, tp.prog, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching syscalls tracepoint %s: %w", tp.name, err)
		}
		newMonitor.sysEventsLinks = append(newMonitor.sysEventsLinks, link)
	}

	// sched tracepoints
	schedTracepoints := []struct {
		name string
		prog *ebpf.Program
	}{
		{"sched_process_exit", sysEventsObjs.TracepointSchedSchedProcessExit},
	}

	// Attach sched tracepoints
	for _, tp := range schedTracepoints {
		link, err := link.Tracepoint("sched", tp.name, tp.prog, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching sched tracepoint %s: %w", tp.name, err)
		}
		newMonitor.sysEventsLinks = append(newMonitor.sysEventsLinks, link)
	}

	// kprobes
	kprobes := []struct {
		name string
		prog *ebpf.Program
	}{
		// Process Events

		{"security_bprm_check", sysEventsObjs.KprobeSecurityBprmCheck}, // execve(at)
		{"cap_capable", sysEventsObjs.KprobeCapCapable},                // capability()
		{"security_task_kill", sysEventsObjs.KprobeSecurityTaskKill},   // (tg)kill

		// IPC Events

		{"security_unix_stream_connect", sysEventsObjs.KprobeSecurityUnixStreamConnect}, // AF_UNIX connect (stream/seqpacket)
		{"security_unix_may_send", sysEventsObjs.KprobeSecurityUnixMaySend},             // AF_UNIX sendmsg (dgram)
		{"security_ptrace_access_check", sysEventsObjs.KprobeSecurityPtraceAccessCheck}, // ptrace tracer/tracee check

		// File Events

		{"security_file_open", sysEventsObjs.KprobeSecurityFileOpen}, // open(at(2))
	}

	if cfg.GlobalCfg.Coverage == "extended" {
		kprobes = append(kprobes, []struct {
			name string
			prog *ebpf.Program
		}{
			// Process Events
			{"security_path_chroot", sysEventsObjs.KprobeSecurityPathChroot}, // chroot

			// File Events

			{"filp_close", sysEventsObjs.KprobeFilpClose},                    // close
			{"security_path_chown", sysEventsObjs.KprobeSecurityPathChown},   // chown
			{"security_path_chmod", sysEventsObjs.KprobeSecurityPathChmod},   // chmod
			{"security_path_unlink", sysEventsObjs.KprobeSecurityPathUnlink}, // unlink(at)
			{"security_path_rename", sysEventsObjs.KprobeSecurityPathRename}, // rename(at)
			{"security_path_link", sysEventsObjs.KprobeSecurityPathLink},     // link(at)
			{"security_path_mkdir", sysEventsObjs.KprobeSecurityPathMkdir},   // mkdir(at)
			{"security_path_rmdir", sysEventsObjs.KprobeSecurityPathRmdir},   // rmdir
		}...)
	}

	// Attach kprobes
	for _, tp := range kprobes {
		link, err := link.Kprobe(tp.name, tp.prog, nil)
		if err != nil {
			return nil, fmt.Errorf("attaching kprobe %s: %w", tp.name, err)
		}
		newMonitor.sysEventsLinks = append(newMonitor.sysEventsLinks, link)
	}

	// do not monitor kloudknox if running in k8s cluster
	if lib.IsInK8sCluster() {
		aPidNS, aMntNS, _ := lib.GetNamespaceIDs("self")
		knoxNS := (uint64(aPidNS) << 32) | uint64(aMntNS)
		if err := sysEventsObjs.StSkipNsMap.Update(knoxNS, uint32(0), ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("updating skip_ns_map: %w", err)
		}
	}

	// Create ring buffer reader for critical events
	prb, err := ringbuf.NewReader(sysEventsObjs.StCriticalEventRb)
	if err != nil {
		if err := sysEventsObjs.Close(); err != nil {
			log.Errf("Error closing process objects: %v", err)
		}
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}
	newMonitor.sysCriticalEventsRb = prb

	// Create ring buffer reader for non-critical events
	prb, err = ringbuf.NewReader(sysEventsObjs.StNonCriticalEventRb)
	if err != nil {
		if closeErr := newMonitor.sysCriticalEventsRb.Close(); closeErr != nil {
			log.Errf("Error closing critical event ring buffer: %v", closeErr)
		}
		if closeErr := sysEventsObjs.Close(); closeErr != nil {
			log.Errf("Error closing process objects: %v", closeErr)
		}
		return nil, fmt.Errorf("opening non-critical ringbuf reader: %w", err)
	}
	newMonitor.sysNonCriticalEventsRb = prb

	// Start ring buffer workers
	newMonitor.startWorkers()

	log.Print("Started System Monitor")
	return newMonitor, nil
}

// Stop gracefully terminates the system monitor and cleans up resources
func (m *SystemMonitor) Stop() error {
	// Signal all workers and readers to stop
	m.stopOnce.Do(func() {
		close(StopChan)
	})

	// Close active ring buffers
	if err := m.sysCriticalEventsRb.Close(); err != nil {
		log.Errf("Error closing ring buffer: %v", err)
	}
	if err := m.sysNonCriticalEventsRb.Close(); err != nil {
		log.Errf("Error closing ring buffer: %v", err)
	}

	// Wait for readers to finish before closing channels
	m.readersWg.Wait()

	// Close event channels
	for _, ch := range m.CriticalEventsChans {
		close(ch)
	}
	for _, ch := range m.NonCriticalEventsChans {
		close(ch)
	}

	// Close all active eBPF program objects
	if err := m.sysEventsObjs.Close(); err != nil {
		log.Errf("Error closing eBPF program objects: %v", err)
	}

	// Wait for all workers to finish
	m.wg.Wait()

	log.Print("Stopped System Monitor")
	return nil
}

// Worker Management

// startWorkers starts workers that read directly from ring buffers
func (m *SystemMonitor) startWorkers() {
	// Start single reader goroutine for critical events
	m.readersWg.Add(1)
	go m.readRingBuffer(m.sysCriticalEventsRb, m.CriticalEventsChans, "critical-reader", &m.criticalDrops)

	// Start workers for critical events (one per shard channel)
	for i, ch := range m.CriticalEventsChans {
		m.wg.Add(1)
		go m.ringBufferWorker(i, ch, "critical-worker")
	}

	// Start single reader goroutine for non-critical events
	m.readersWg.Add(1)
	go m.readRingBuffer(m.sysNonCriticalEventsRb, m.NonCriticalEventsChans, "non-critical-reader", &m.nonCriticalDrops)

	// Start workers for non-critical events
	for i, ch := range m.NonCriticalEventsChans {
		m.wg.Add(1)
		go m.ringBufferWorker(i, ch, "non-critical-worker")
	}

	// Start cleanUpMapsAndPendingEvents worker
	m.wg.Add(1)
	go m.cleanUpMapsAndPendingEvents()
}

// makeWorkerChans allocates n channels of the given depth.
func makeWorkerChans(n, depth int) []chan *bytes.Buffer {
	chans := make([]chan *bytes.Buffer, n)
	for i := range chans {
		chans[i] = make(chan *bytes.Buffer, depth)
	}
	return chans
}

// eventHostTIDShard extracts HostTID from the event header to pick a shard.
// Layout (LE): Timestamp u64 | CPUID u32 | SeqNum u32 | PidNsID u32 |
// MntNsID u32 | HostPPID i32 | HostPID i32 | HostTID i32 (offset 32).
// Keep in sync with monitor.Event struct.
const eventHostTIDOffset = 32

func eventHostTIDShard(raw []byte, nShards uint32) uint32 {
	if len(raw) < eventHostTIDOffset+4 || nShards <= 1 {
		return 0
	}
	// Treat the 32-bit TID as unsigned for hashing — we only care about
	// consistent routing, not the signed value.
	tid := binary.LittleEndian.Uint32(raw[eventHostTIDOffset:])
	return tid % nShards
}

// readRingBuffer reads events from the ring buffer and shards each event to
// a per-worker channel keyed on HostTID. Sharding by HostTID ensures the
// Enter and Exit halves of a syscall land on the same worker and are
// processed in submission order — a shared channel with multiple workers
// races and orphans the Exit when it gets pulled before the paired Enter
// has been stored.
func (m *SystemMonitor) readRingBuffer(rb *ringbuf.Reader, chans []chan *bytes.Buffer, workerType string, dropCounter *atomic.Uint64) {
	defer m.readersWg.Done()

	var record ringbuf.Record
	n := uint32(len(chans)) // #nosec G115 -- bounded by maxCriticalWorkerPools

	for {
		select {
		case <-StopChan:
			return
		default:
			err := rb.ReadInto(&record)
			if err != nil {
				if err == ringbuf.ErrClosed {
					log.Debugf("%s ring buffer closed", workerType)
					return
				}
				continue
			}

			// Copy data to new buffer to avoid race condition when reusing record.RawSample
			// The record memory is reused by ringbuf.Reader
			data := bytes.NewBuffer(make([]byte, len(record.RawSample)))
			copy(data.Bytes(), record.RawSample)

			ch := chans[eventHostTIDShard(record.RawSample, n)]
			select {
			case ch <- data:
			case <-StopChan:
				return
			default:
				// Channel full — drop event and record for observability
				dropCounter.Add(1)
			}
		}
	}
}

// ringBufferWorker reads events from a channel with panic recovery and backoff
func (m *SystemMonitor) ringBufferWorker(workerID int, ch <-chan *bytes.Buffer, workerType string) {
	defer m.wg.Done()

	// Loop handles panic recovery to avoid recursive stack exhaustion and properly maintain state
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errf("Panic in %s worker %d: %v", workerType, workerID, r)
					time.Sleep(100 * time.Millisecond) // Simple backoff
				}
			}()

			// Process events
			for data := range ch {
				// Process the event
				ev, err := readEventFromBuff(data)
				if err != nil {
					continue
				}

				// Handle the event
				m.handleEvent(&ev, data)
			}
		}()

		// Check if we should exit
		select {
		case <-StopChan:
			return
		default:
			// Ensure we don't busy loop if channel is closed but panic occurred
			if len(ch) == 0 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}
