// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/cilium/ebpf/ringbuf"
)

// BpfeAlert mirrors the C struct bpfe_alert_t written to bpfe_alerts_rb.
// The layout must be kept in sync with BPF/enforcer/bpfe_alert.h.
type BpfeAlert struct {
	Ts          uint64
	Cgid        uint64
	PidNsId     uint32
	MntNsId     uint32
	HostPPID    int32
	HostPID     int32
	HostTID     int32
	PPID        int32
	PID         int32
	TID         int32
	SrcInode    uint64
	TargetInode uint64
	Domain      uint8
	Action      uint8
	EventID     uint16
	PolicyID    uint32
	RetVal      int32
	Extra       uint32
}

// startAlertWorkers starts the ring-buffer reader and worker pool.
// Mirrors NetworkEnforcer.startNetworkEventWorkers.
func (be *BpfEnforcer) startAlertWorkers() {
	be.ReadersWg.Add(1)
	go be.readAlertsRingBuffer()

	for i := 0; i < BpfAlertWorkerPools; i++ {
		be.Wg.Add(1)
		go be.alertWorker(i)
	}

	be.Wg.Add(1)
	go be.alertDropLogger()
}

// readAlertsRingBuffer reads raw bytes from bpfe_alerts_rb and forwards them
// to AlertsChan. It exits when the ring buffer is closed.
func (be *BpfEnforcer) readAlertsRingBuffer() {
	defer be.ReadersWg.Done()

	var record ringbuf.Record
	for {
		err := be.AlertsRb.ReadInto(&record)
		if err != nil {
			if err == ringbuf.ErrClosed {
				log.Debug("BPF-LSM alert ring buffer closed")
				return
			}
			continue
		}

		raw := make([]byte, len(record.RawSample))
		copy(raw, record.RawSample)

		select {
		case be.AlertsChan <- raw:
		default:
			be.alertDrops.Add(1)
		}
	}
}

// alertDropLogger periodically logs the number of dropped alert events.
func (be *BpfEnforcer) alertDropLogger() {
	defer be.Wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-be.stopChan:
			return
		case <-ticker.C:
			if d := be.alertDrops.Swap(0); d > 0 {
				log.Warnf("BPF-LSM alert channel full: dropped %d alerts", d)
			}
		}
	}
}

// alertWorker drains AlertsChan, parses each bpfe_alert_t record, and
// forwards a tp.EventData to the exporter.
func (be *BpfEnforcer) alertWorker(workerID int) {
	defer be.Wg.Done()

	for raw := range be.AlertsChan {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errf("Panic in BPF-LSM alert worker %d: %v", workerID, r)
				}
			}()

			alert := BpfeAlert{}
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &alert); err != nil {
				return
			}
			be.handleAlert(&alert)
		}()
	}
}

// domainName maps domain constants to human-readable strings.
var domainName = map[uint8]string{
	0: "process",
	1: "file",
	2: "capability",
	3: "unix",
	4: "signal",
	5: "ptrace",
}

// resolveInodePath returns the cached container-relative path for the given
// inode, or "" if not cached. Callers fall back to "inode:X" formatting.
func (be *BpfEnforcer) resolveInodePath(ino uint64) string {
	if ino == 0 {
		return ""
	}
	if v, ok := be.inodePaths.Load(ino); ok {
		return v.(string)
	}
	return ""
}

// cacheInodePath stores a container-relative path for an inode so that alert
// messages can show a human-readable path instead of a bare inode number.
func (be *BpfEnforcer) cacheInodePath(ino uint64, path string) {
	if ino == 0 || path == "" {
		return
	}
	be.inodePaths.Store(ino, path)
}

// formatAlertResource returns a human-readable resource string for an alert.
// - CAP domain: capability name (e.g. "NET_ADMIN")
// - FILE/PROC domain: resolved path from cache, or "inode:X" fallback
// - Other domains: resolved path from cache, or "inode:X" fallback
func (be *BpfEnforcer) formatAlertResource(alert *BpfeAlert) string {
	if alert.Domain == uint8(domainCap) {
		name := lib.CapabilityName(uint32(alert.TargetInode)) // #nosec G115 -- TargetInode holds a cap_id in [0,63] for CAP domain
		if name != "" {
			return name
		}
		return fmt.Sprintf("cap:%d", alert.TargetInode)
	}
	if path := be.resolveInodePath(alert.TargetInode); path != "" {
		return path
	}
	return fmt.Sprintf("inode:%d", alert.TargetInode)
}

// resolveSourcePath returns the executable path for the alerting process.
// Tries the inode cache first, then falls back to reading /proc/<pid>/exe.
func (be *BpfEnforcer) resolveSourcePath(srcInode uint64, hostPID int32) string {
	if p := be.resolveInodePath(srcInode); p != "" {
		return p
	}
	if hostPID <= 0 {
		return ""
	}
	// Read /proc/<pid>/exe symlink — works even if the process has exited
	// (the kernel keeps the link open while the process runs).
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", hostPID))
	if err != nil {
		return ""
	}
	if srcInode != 0 {
		be.cacheInodePath(srcInode, target)
	}
	return target
}

// resolveTargetPath returns the container-relative path for the target inode.
// Uses the inode cache; unknown inodes retain the "inode:X" fallback.
func (be *BpfEnforcer) resolveTargetPath(tgtInode uint64, hostPID int32) string {
	if p := be.resolveInodePath(tgtInode); p != "" {
		return p
	}
	// Attempt to find the path via /proc/<pid>/fd symlinks (works for audited
	// opens where the fd is still open; not useful for blocked opens).
	if hostPID > 0 {
		fdDir := fmt.Sprintf("/proc/%d/fd", hostPID)
		entries, err := os.ReadDir(fdDir)
		if err == nil {
			for _, e := range entries {
				link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, e.Name()))
				if err != nil {
					continue
				}
				info, err := os.Stat(link)
				if err != nil {
					continue
				}
				if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Ino == tgtInode {
					be.cacheInodePath(tgtInode, link)
					return link
				}
			}
		}
	}
	return ""
}

// handleAlert converts a BpfeAlert into a tp.EventData and exports it.
func (be *BpfEnforcer) handleAlert(alert *BpfeAlert) {
	evData := tp.EventData{
		Timestamp: be.monoNSToTime(alert.Ts),
		PidNsID:   alert.PidNsId,
		MntNsID:   alert.MntNsId,
		HostPPID:  alert.HostPPID,
		HostPID:   alert.HostPID,
		HostTID:   alert.HostTID,
		PPID:      alert.PPID,
		PID:       alert.PID,
		TID:       alert.TID,
		RetVal:    alert.RetVal,
		NodeName:  cfg.GlobalCfg.Node,
	}

	dom := domainName[alert.Domain]
	evData.Category = dom
	evData.Operation = be.alertOperation(alert)
	evData.Resource = be.formatAlertResource(alert)
	evData.Source = be.resolveSourcePath(alert.SrcInode, alert.HostPID)
	// For file/proc domain, also try to resolve target via fd if not cached
	if evData.Resource == fmt.Sprintf("inode:%d", alert.TargetInode) {
		if p := be.resolveTargetPath(alert.TargetInode, alert.HostPID); p != "" {
			evData.Resource = p
		}
	}
	evData.Data = fmt.Sprintf("src_inode:%d event_id:%d", alert.SrcInode, alert.EventID)

	if alert.RetVal < 0 {
		evData.PolicyAction = "Block"
	} else {
		evData.PolicyAction = "Audit"
	}

	// Resolve policy name from policy_id (matches NetworkEnforcer pattern).
	evData.PolicyName = be.resolvePolicyName(alert)

	// Fill namespace/pod/container names from NsMap.
	be.fillContainerMeta(&evData, alert.PolicyID)

	if err := be.Exporter.ExportEvent(evData); err != nil {
		log.Errf("BPF-LSM: failed to export alert: %v", err)
	}
}

// alertOperation returns the EventData.Operation string for an alert.
func (be *BpfEnforcer) alertOperation(alert *BpfeAlert) string {
	switch alert.Domain {
	case 0: // PROC
		return "execute"
	case 1: // FILE
		return "open"
	case 2: // CAP
		return "capable"
	case 3: // UNIX
		return "unix_connect"
	case 4: // SIGNAL
		return "kill"
	case 5: // PTRACE
		return "ptrace"
	default:
		return "unknown"
	}
}

// resolvePolicyName looks up policy_id in RuntimePolicies to get a policy name.
// policy_id == 0 means posture-driven deny.
func (be *BpfEnforcer) resolvePolicyName(alert *BpfeAlert) string {
	if alert.PolicyID == 0 {
		return "<posture:block>"
	}

	be.GlobalData.RuntimePoliciesLock.RLock()
	defer be.GlobalData.RuntimePoliciesLock.RUnlock()

	for _, policies := range be.GlobalData.RuntimePolicies {
		for _, p := range policies {
			if p.PolicyID == alert.PolicyID {
				return p.PolicyName
			}
		}
	}
	return fmt.Sprintf("policy:%d", alert.PolicyID)
}

// fillContainerMeta resolves namespace/pod/container from the NsMap.
func (be *BpfEnforcer) fillContainerMeta(evData *tp.EventData, policyID uint32) {
	nsKey := uint64(evData.PidNsID)<<32 | uint64(evData.MntNsID)

	be.GlobalData.NsMapLock.RLock()
	container, ok := be.GlobalData.NsMap[nsKey]
	be.GlobalData.NsMapLock.RUnlock()

	if !ok {
		return
	}

	evData.NamespaceName = container.NamespaceName
	evData.PodName = container.PodName
	evData.ContainerName = container.ContainerName
}

// monoNSToTime converts a bpf_ktime_get_ns() timestamp to a wall-clock
// Unix nanosecond value using the monotonic base captured at daemon start.
func (be *BpfEnforcer) monoNSToTime(ktimeNS uint64) uint64 {
	base := be.GlobalData.MonoBaseNS.Load()
	ts := int64(ktimeNS) + base // #nosec G115
	if ts < 0 {
		return 0
	}
	return uint64(ts)
}
