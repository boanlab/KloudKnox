// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// EventData Management

// getShardIndex returns the shard index for a given key
func (m *SystemMonitor) getShardIndex(key int64) int {
	// Handle negative keys by taking absolute value
	if key < 0 {
		key = -key
	}
	return int(key % int64(m.evMapShardCount))
}

// getEventData gets event data from the appropriate shard
func (m *SystemMonitor) getEventData(key int64) (tp.EventData, bool) {
	shardIndex := m.getShardIndex(key)
	shard := &m.evMapShards[shardIndex]

	shard.lock.RLock()
	defer shard.lock.RUnlock()

	data, ok := shard.data[key]
	return data, ok
}

// setEventData sets event data in the appropriate shard and records the store time
// for TTL-based GC of orphan enter events.
func (m *SystemMonitor) setEventData(key int64, data tp.EventData) {
	shardIndex := m.getShardIndex(key)
	shard := &m.evMapShards[shardIndex]

	shard.lock.Lock()
	defer shard.lock.Unlock()

	shard.data[key] = data
	shard.timestamps[key] = time.Now()
}

// deleteEventData deletes event data from the appropriate shard
func (m *SystemMonitor) deleteEventData(key int64) {
	shardIndex := m.getShardIndex(key)
	shard := &m.evMapShards[shardIndex]

	shard.lock.Lock()
	defer shard.lock.Unlock()

	delete(shard.data, key)
	delete(shard.timestamps, key)
}

// Pending Events Management

// maxPendingEventsPerNs is the upper bound on buffered events per namespace key.
// Prevents memory exhaustion under event storms (e.g. fork bombs) while a
// container's NsMap entry has not yet been registered.
const maxPendingEventsPerNs = 1000

// bufferPendingEvent adds an event to the pending buffer for retry
// when container metadata is not yet available in nsMap.
// Events beyond maxPendingEventsPerNs per namespace are silently dropped.
func (m *SystemMonitor) bufferPendingEvent(evData tp.EventData) {
	nsKey := uint64(evData.PidNsID)<<32 | uint64(evData.MntNsID)

	m.pendingEventsLock.Lock()
	defer m.pendingEventsLock.Unlock()

	if _, exists := m.pendingEvents[nsKey]; !exists {
		m.pendingEvents[nsKey] = tp.PendingEvents{
			PendingEvents: make([]tp.EventData, 0),
			CreatedAt:     time.Now(),
		}
	}

	pendingEventsForNs := m.pendingEvents[nsKey]

	if len(pendingEventsForNs.PendingEvents) >= maxPendingEventsPerNs {
		log.Debugf("pendingEvents full for nsKey=%d, dropping event", nsKey)
		return
	}

	pendingEventsForNs.PendingEvents = append(pendingEventsForNs.PendingEvents, evData)
	m.pendingEvents[nsKey] = pendingEventsForNs
}

// drainPendingEvents atomically removes and returns all buffered events for nsKey.
// The lock is held only for the map operation; callers must process the returned
// slice outside the lock.
func (m *SystemMonitor) drainPendingEvents(nsKey uint64) []tp.EventData {
	m.pendingEventsLock.Lock()
	defer m.pendingEventsLock.Unlock()

	if entry, ok := m.pendingEvents[nsKey]; ok {
		events := entry.PendingEvents
		delete(m.pendingEvents, nsKey)
		return events
	}
	return nil
}

// PidMap Management

// getPathFromPidMap gets the path from the pidMap
func (m *SystemMonitor) getPathFromPidMap(hostPID int32) string {
	if pathInfo, ok := m.globalData.PidMap.Load(hostPID); ok {
		return pathInfo.(string)
	}

	if cfg.GlobalCfg.Coverage == "extended" {
		if pidPath, err := os.Readlink(fmt.Sprintf("%s/%d/exe", cfg.GlobalCfg.ProcDir, hostPID)); err == nil && pidPath != "" {
			m.globalData.PidMap.Store(hostPID, pidPath)
			return pidPath
		}
	}

	return ""
}

// updatePathToPidMap updates the path to the pidMap
func (m *SystemMonitor) updatePathToPidMap(hostPID int32, path string) {
	if strings.HasPrefix(path, "/") {
		m.globalData.PidMap.Store(hostPID, path)
	}
}

// deletePathFromPidMap deletes the path from the pidMap
func (m *SystemMonitor) deletePathFromPidMap(hostPID int32) {
	m.deletePidMapLock.Lock()
	defer m.deletePidMapLock.Unlock()

	m.deletePidMap = append(m.deletePidMap, struct {
		key  int32
		time time.Time
	}{key: hostPID, time: time.Now()})
}

// FdMap Management

// getPathFromFdMap gets the path from the fdMap
func (m *SystemMonitor) getPathFromFdMap(hostPID int32, fd int32) string {
	key := int64(hostPID)<<32 | int64(fd)
	if fdPath, ok := m.fdMap.Load(key); ok {
		return fdPath.(string)
	}

	if cfg.GlobalCfg.Coverage == "extended" {
		if fdPath, err := os.Readlink(fmt.Sprintf("%s/%d/fd/%d", cfg.GlobalCfg.ProcDir, hostPID, fd)); err == nil && fdPath != "" {
			m.updatePathToFdMap(hostPID, fd, fdPath)
			return fdPath
		}
	}

	return ""
}

// updatePathToFdMap updates the path to the fdMap
func (m *SystemMonitor) updatePathToFdMap(hostPID int32, fd int32, path string) {
	key := int64(hostPID)<<32 | int64(fd)
	m.fdMap.Store(key, path)
}

// deletePathFromFdMap deletes the path from the fdMap
func (m *SystemMonitor) deletePathFromFdMap(hostPID int32, fd int32) {
	m.deleteFdMapLock.Lock()
	defer m.deleteFdMapLock.Unlock()

	m.deleteFdMap = append(m.deleteFdMap, struct {
		key  int64
		time time.Time
	}{key: int64(hostPID)<<32 | int64(fd), time: time.Now()})
}

// SockMap Management

// getDataFromSockMap gets the data from the sockMap
func (m *SystemMonitor) getDataFromSockMap(hostPID int32, fd int32) string {
	key := int64(hostPID)<<32 | int64(fd)
	if fdData, ok := m.sockMap.Load(key); ok {
		return fdData.(string)
	}

	return ""
}

// updateDataToSockMap updates the data to the sockMap
func (m *SystemMonitor) updateDataToSockMap(hostPID int32, fd int32, data string) {
	key := int64(hostPID)<<32 | int64(fd)
	m.sockMap.Store(key, data)
}

// deleteDataFromSockMap deletes the data from the sockMap
func (m *SystemMonitor) deleteDataFromSockMap(hostPID int32, fd int32) {
	m.deleteSockMapLock.Lock()
	defer m.deleteSockMapLock.Unlock()

	m.deleteSockMap = append(m.deleteSockMap, struct {
		key  int64
		time time.Time
	}{key: int64(hostPID)<<32 | int64(fd), time: time.Now()})
}

// Timestamp Conversion

// refreshMonoBase refreshes the mono base
func (m *SystemMonitor) refreshMonoBase() error {
	var rt, mt unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &rt); err != nil {
		return err
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mt); err != nil {
		return err
	}
	base := (rt.Nano() - mt.Nano())
	m.globalData.MonoBaseNS.Store(base)
	return nil
}

// bpf_ktime_get_ns() -> time.Time
func (m *SystemMonitor) monoNSToTime(ktimeNS uint64) uint64 {
	base := m.globalData.MonoBaseNS.Load()
	ts := int64(ktimeNS) + base // #nosec G115
	if ts < 0 {
		return 0
	}
	return uint64(ts)
}

// CleanUp Function

// cleanUpMapsAndPendingEvents cleans up the pidMap, fdMap, and pendingEvents
func (m *SystemMonitor) cleanUpMapsAndPendingEvents() {
	defer m.wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-StopChan:
			return
		case <-ticker.C:
			if err := m.refreshMonoBase(); err != nil {
				log.Errf("Error refreshing mono base: %v", err)
			}

			now := time.Now()

			// Delete expired PIDs from pidMap
			m.deletePidMapLock.Lock()
			keepCount := 0
			for _, deletePid := range m.deletePidMap {
				if now.Sub(deletePid.time) > 1*time.Second {
					m.globalData.PidMap.Delete(deletePid.key)
				} else {
					m.deletePidMap[keepCount] = deletePid
					keepCount++
				}
			}
			m.deletePidMap = m.deletePidMap[:keepCount]
			m.deletePidMapLock.Unlock()

			// Delete expired FDs from fdMap
			m.deleteFdMapLock.Lock()
			keepCount = 0
			for _, deleteFd := range m.deleteFdMap {
				if now.Sub(deleteFd.time) > 1*time.Second {
					m.fdMap.Delete(deleteFd.key)
				} else {
					m.deleteFdMap[keepCount] = deleteFd
					keepCount++
				}
			}
			m.deleteFdMap = m.deleteFdMap[:keepCount]
			m.deleteFdMapLock.Unlock()

			// Delete expired sockets from sockMap
			m.deleteSockMapLock.Lock()
			keepCount = 0
			for _, deleteSock := range m.deleteSockMap {
				if now.Sub(deleteSock.time) > 1*time.Second {
					m.sockMap.Delete(deleteSock.key)
				} else {
					m.deleteSockMap[keepCount] = deleteSock
					keepCount++
				}
			}
			m.deleteSockMap = m.deleteSockMap[:keepCount]
			m.deleteSockMapLock.Unlock()

			// Delete pending events.
			//
			// The TTL-based skip is for HOST processes — namespaces where we keep
			// seeing events that never resolve to a registered container. A known
			// container's nsKey must NEVER be added to skip_ns_map here: if it is,
			// the BPF filter drops all future events from that container (and
			// from any future container that reuses the same ns ids). We have
			// hit this in docker mode when a container was mostly idle between
			// registration and the first matched event — the pendingEvents
			// accumulated before registration aged past 1m, and the ns got
			// silenced for the rest of the daemon's lifetime.
			m.pendingEventsLock.Lock()
			for nsKey, pendingEvents := range m.pendingEvents {
				if time.Since(pendingEvents.CreatedAt) > 1*time.Minute {
					m.globalData.NsMapLock.RLock()
					_, isKnownContainer := m.globalData.NsMap[nsKey]
					m.globalData.NsMapLock.RUnlock()

					if !isKnownContainer {
						pidNsID := uint64(nsKey >> 32)
						mntNsID := uint64(nsKey & 0xFFFFFFFF)

						if err := m.sysEventsObjs.StSkipNsMap.Update(nsKey, uint32(0), ebpf.UpdateAny); err != nil {
							log.Errf("Failed to update skip_ns_map for PIDNS %d and MNTNS %d: %v", pidNsID, mntNsID, err)
						}
						// 4-3: mirror update to ne_skip_ns_map via hook
						if hook := m.globalData.SkipNsHook; hook != nil {
							hook(nsKey)
						}
					}

					delete(m.pendingEvents, nsKey)
				}
			}
			m.pendingEventsLock.Unlock()

			// Evict orphan enter events from evMapShards (no matching exit received)
			const evMapEntryTTL = 5 * time.Second
			for i := 0; i < m.evMapShardCount; i++ {
				shard := &m.evMapShards[i]
				shard.lock.Lock()
				for k, t := range shard.timestamps {
					if now.Sub(t) > evMapEntryTTL {
						delete(shard.timestamps, k)
						delete(shard.data, k)
					}
				}
				shard.lock.Unlock()
			}

			// Log ring buffer channel drop counts (reset atomically)
			if d := m.criticalDrops.Swap(0); d > 0 {
				log.Warnf("Ring buffer full: dropped %d critical events (consider increasing buffer size)", d)
			}
			if d := m.nonCriticalDrops.Swap(0); d > 0 {
				log.Warnf("Ring buffer full: dropped %d non-critical events", d)
			}
		}
	}
}

// Event Handling

// handleEvent handles the event
func (m *SystemMonitor) handleEvent(ev *Event, data *bytes.Buffer) {
	evData := &tp.EventData{
		Timestamp: m.monoNSToTime(ev.Timestamp),
		CPUID:     ev.CPUID,
		SeqNum:    ev.SeqNum,

		PidNsID: ev.PidNsID,
		MntNsID: ev.MntNsID,

		HostPPID: ev.HostPPID,
		HostPID:  ev.HostPID,
		HostTID:  ev.HostTID,

		PPID: ev.PPID,
		PID:  ev.PID,
		TID:  ev.TID,

		UID: ev.UID,
		GID: ev.GID,

		EventID:   int32(ev.EventID),
		EventName: syscall2name[int32(ev.EventID)],
		EventType: int32(ev.EventType),
		ArgNum:    int32(ev.ArgNum),
		RetVal:    ev.RetVal,
		RetCode:   getSyscallRetMessage(ev.RetVal),

		NodeName: cfg.GlobalCfg.Node,
	}

	evKey := int64(ev.HostTID)<<16 | int64(ev.EventID)

	switch ev.EventType {
	case EventTypeUnary:
		if ev.ArgNum > 0 {
			if err := m.getArgs(data, evData); err != nil {
				log.Debugf("Error getting args: %v", err)
				return
			}
		}

		if evData.Category != "" {
			nsKey := uint64(evData.PidNsID)<<32 | uint64(evData.MntNsID)

			m.globalData.NsMapLock.RLock()
			if foundContainer, ok := m.globalData.NsMap[nsKey]; ok {
				m.globalData.NsMapLock.RUnlock()

				// Drain pending events under lock, then process outside lock
				for _, pendingEvent := range m.drainPendingEvents(nsKey) {
					pendingEvent.NamespaceName = foundContainer.NamespaceName
					pendingEvent.PodName = foundContainer.PodName
					pendingEvent.ContainerName = foundContainer.ContainerName
					if err := m.processEvent(pendingEvent); err != nil {
						log.Errf("Error processing event: %v", err)
					}
				}

				// Enrich event with container metadata
				evData.NamespaceName = foundContainer.NamespaceName
				evData.PodName = foundContainer.PodName
				evData.ContainerName = foundContainer.ContainerName

				// Process event
				if err := m.processEvent(*evData); err != nil {
					log.Errf("Error processing event: %v", err)
				}
			} else {
				m.globalData.NsMapLock.RUnlock()

				// Container not found in nsMap yet, buffer for retry
				m.bufferPendingEvent(*evData)
			}
		}

	case EventTypeEnter:
		if ev.ArgNum > 0 {
			if err := m.getArgs(data, evData); err != nil {
				log.Debugf("Error getting args: %v", err)
				return
			}
		}

		// Store system call events (enter)
		m.setEventData(evKey, *evData)

	case EventTypeExit:
		// Pop system call events (exit)
		origEvData, ok := m.getEventData(evKey)
		if ok {
			m.deleteEventData(evKey)

			origEvData.RetVal = ev.RetVal
			origEvData.RetCode = getSyscallRetMessage(ev.RetVal)

			switch origEvData.Operation {
			case "clone":
				// Record child PID when clone/clone3 succeeds (RetVal > 0 = child PID in parent).
				if origEvData.RetVal > 0 {
					origEvData.Data += fmt.Sprintf(", child_pid: %d", origEvData.RetVal)
				}
			case "execute":
				// update the path to the pidMap
				m.updatePathToPidMap(origEvData.HostPID, origEvData.Resource)
			case "exit":
				// delete the path from the pidMap
				m.deletePathFromPidMap(origEvData.HostPID)
				// Clean up kprobe intermediate map entries in network enforcer.
				if hook := m.globalData.ExitHook; hook != nil {
					hook(origEvData.HostPID, origEvData.HostTID)
				}
			case "open":
				// update the path to the fdMap
				m.updatePathToFdMap(origEvData.HostPID, origEvData.RetVal, origEvData.Resource)
			case "socket":
				// Record the newly allocated fd as Resource.
				if origEvData.RetVal >= 0 {
					origEvData.Resource = fmt.Sprintf("fd:%d", origEvData.RetVal)
				}
				// update the data to the sockMap
				m.updateDataToSockMap(origEvData.HostPID, origEvData.RetVal, origEvData.Data)
			case "bind", "connect":
				// update the data to the fdMap again
				m.updateDataToSockMap(origEvData.HostPID, origEvData.TempInt32, origEvData.Data)
			case "close":
				// delete the path from the fdMap
				m.deletePathFromFdMap(origEvData.HostPID, origEvData.TempInt32)

				// delete the data from the sockMap
				m.deleteDataFromSockMap(origEvData.HostPID, origEvData.TempInt32)
			}

			nsKey := uint64(origEvData.PidNsID)<<32 | uint64(origEvData.MntNsID)

			m.globalData.NsMapLock.RLock()
			if foundContainer, ok := m.globalData.NsMap[nsKey]; ok {
				m.globalData.NsMapLock.RUnlock()

				// Drain pending events under lock, then process outside lock
				for _, pendingEvent := range m.drainPendingEvents(nsKey) {
					pendingEvent.NamespaceName = foundContainer.NamespaceName
					pendingEvent.PodName = foundContainer.PodName
					pendingEvent.ContainerName = foundContainer.ContainerName
					if err := m.processEvent(pendingEvent); err != nil {
						log.Errf("Error processing event: %v", err)
					}
				}

				// Enrich event with container metadata
				origEvData.NamespaceName = foundContainer.NamespaceName
				origEvData.PodName = foundContainer.PodName
				origEvData.ContainerName = foundContainer.ContainerName

				// Process event
				if err := m.processEvent(origEvData); err != nil {
					log.Errf("Error processing event: %v", err)
				}
			} else {
				m.globalData.NsMapLock.RUnlock()

				// Container not found in nsMap yet, buffer for retry
				m.bufferPendingEvent(origEvData)
			}
		}
	}
}

// processEvent processes and exports system event data captured by eBPF programs
func (m *SystemMonitor) processEvent(evData tp.EventData) error {
	// Perform policy matching for file and process events
	switch evData.Operation {
	case "execute", "open":
		// Get pod information for policy matching
		podKey := evData.NamespaceName + "/" + evData.PodName
		m.globalData.PodsLock.RLock()
		pod, exists := m.globalData.Pods[podKey]
		if exists {
			// PolicyMatch held under RLock: FileRules.OuterRules is a map (reference
			// type), so releasing the lock before use would allow a concurrent
			// buildFileRules replacement to race on the inner maps.
			m.PolicyMatch(pod.FileRules, &evData)
		}
		m.globalData.PodsLock.RUnlock()
	case "capable":
		podKey := evData.NamespaceName + "/" + evData.PodName
		m.globalData.PodsLock.RLock()
		pod, exists := m.globalData.Pods[podKey]
		if exists {
			m.CapabilityPolicyMatch(pod.CapabilityRules, &evData)
		}
		m.globalData.PodsLock.RUnlock()

		// Drop unmatched capable events: cap_capable fires at very high rate
		// (every syscall path that checks a cap). Only events annotated by a
		// user policy are worth exporting.
		if evData.PolicyName == "" {
			return nil
		}
	case "unix_connect", "unix_send", "kill", "ptrace":
		// IPC events share a matcher across three kernel hooks:
		//   unix_connect / unix_send → security_unix_{stream_connect,may_send}
		//   kill                     → security_task_kill
		//   ptrace                   → security_ptrace_access_check
		podKey := evData.NamespaceName + "/" + evData.PodName
		m.globalData.PodsLock.RLock()
		pod, exists := m.globalData.Pods[podKey]
		if exists {
			m.IPCPolicyMatch(pod.IPCRules, &evData)
		}
		m.globalData.PodsLock.RUnlock()

		// Unix/ptrace hooks fire on every IPC attempt in the container, so
		// drop them unless a user policy annotated the event. Signal events
		// (Operation="kill") are exported unconditionally for visibility
		// even when no signal rule is defined.
		if evData.PolicyName == "" &&
			(evData.Operation == "unix_connect" || evData.Operation == "unix_send" || evData.Operation == "ptrace") {
			return nil
		}
	}

	// Export the event data to the configured backend
	if err := m.exporter.ExportEvent(evData); err != nil {
		log.Errf("Failed to export event: %v", err)
		return err
	}

	return nil
}
