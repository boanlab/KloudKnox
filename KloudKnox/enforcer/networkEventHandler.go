// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/cilium/ebpf/ringbuf"
)

// Network Event Structure

// NetworkEvent mirrors the C struct written by the net_enforcer eBPF program
// into the ne_event_rb ring buffer. Fields are in host byte order unless noted.
type NetworkEvent struct {
	Timestamp uint64

	PidNsID uint32
	MntNsID uint32

	HostPPID int32
	HostPID  int32
	HostTID  int32

	PPID int32
	PID  int32
	TID  int32

	SrcIP uint32
	DstIP uint32
	Sport uint16
	Dport uint16

	Proto   uint16
	EventID uint16

	PolicyID uint32
	RetVal   int32
}

// PidMap Management

// getPathFromPidMap gets the path from the pidMap
func (ne *NetworkEnforcer) getPathFromPidMap(hostPID int32) string {
	exePath := fmt.Sprintf("%s/%d/exe", cfg.GlobalCfg.ProcDir, hostPID)

	if pathInfo, ok := ne.GlobalData.PidMap.Load(hostPID); ok {
		cachedPath := pathInfo.(string)
		// Verify if the cached path is still valid (detect PID reuse)
		if currentPath, err := os.Readlink(exePath); err == nil && currentPath == cachedPath {
			return cachedPath
		}
		// PID has been recycled or process is gone, remove from cache
		ne.GlobalData.PidMap.Delete(hostPID)
	}

	if pidPath, err := os.Readlink(exePath); err == nil && pidPath != "" {
		ne.GlobalData.PidMap.Store(hostPID, pidPath)
		return pidPath
	}

	return ""
}

// Worker Management

// startNetworkEventWorkers starts workers that read directly from ring buffers
func (ne *NetworkEnforcer) startNetworkEventWorkers() {
	// Start single reader goroutine, tracked in ReadersWg so StopNetworkEnforcer
	// can wait for it before closing the channel the reader writes to.
	ne.ReadersWg.Add(1)
	go ne.readRingBuffer(ne.NetworkEventsRb, ne.NetworkEventsChan)

	// Start workers
	for i := 0; i < NetworkEventWorkerPools; i++ {
		ne.Wg.Add(1)
		go ne.networkEventWorker(i)
	}

	// Start drop counter logger (4-4)
	ne.Wg.Add(1)
	go ne.dropLogger()
}

// readRingBuffer reads events from the ring buffer and sends them to the channel
func (ne *NetworkEnforcer) readRingBuffer(rb *ringbuf.Reader, ch chan<- []byte) {
	defer ne.ReadersWg.Done()

	var record ringbuf.Record

	for {
		select {
		case <-StopChan:
			return
		default:
			err := rb.ReadInto(&record)
			if err != nil {
				if err == ringbuf.ErrClosed {
					log.Debug("network-event ring buffer closed")
					return
				}
				continue
			}

			raw := make([]byte, len(record.RawSample))
			copy(raw, record.RawSample)

			select {
			case ch <- raw:
			case <-StopChan:
				return
			default:
				ne.networkDrops.Add(1)
			}
		}
	}
}

// dropLogger periodically logs the number of dropped network events (4-4)
func (ne *NetworkEnforcer) dropLogger() {
	defer ne.Wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-StopChan:
			return
		case <-ticker.C:
			if d := ne.networkDrops.Swap(0); d > 0 {
				log.Warnf("Network event channel full: dropped %d events", d)
			}
		}
	}
}

// networkEventWorker reads events from channel with panic recovery
func (ne *NetworkEnforcer) networkEventWorker(workerID int) {
	defer ne.Wg.Done()

	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errf("Panic in network event worker %d: %v", workerID, r)
					time.Sleep(100 * time.Millisecond) // Simple backoff
				}
			}()

			for raw := range ne.NetworkEventsChan {
				// Read event data
				networkEvent := NetworkEvent{}
				err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &networkEvent)
				if err != nil {
					continue
				}

				// Handle the event directly
				ne.handleNetworkEvent(&networkEvent)
			}
		}()

		// Check exit condition
		select {
		case <-StopChan:
			return
		default:
			if len(ne.NetworkEventsChan) == 0 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}

// Event Handling

// monoNSToTime converts a bpf_ktime_get_ns() monotonic nanosecond timestamp
// to a wall-clock Unix nanosecond timestamp using the monotonic base captured
// at daemon start (GlobalData.MonoBaseNS).
func (ne *NetworkEnforcer) monoNSToTime(ktimeNS uint64) uint64 {
	base := ne.GlobalData.MonoBaseNS.Load()
	ts := int64(ktimeNS) + base // #nosec G115
	if ts < 0 {
		return 0
	}
	return uint64(ts)
}

// event2name is a map of event numbers to their names
var event2name = map[int32]string{
	0: "inet_stream_connect",
	1: "inet_csk_accept",
	2: "udp_sendmsg",
	3: "udp_recvmsg",
	4: "cgroup_skb_egress",
	5: "cgroup_skb_ingress",
}

// IP Protocol numbers
const (
	IPProtoTCP = 6
	IPProtoUDP = 17
)

func getIPProtocol(proto uint16) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("unknown(%d)", proto)
	}
}

func getRetCode(retVal int32) string {
	switch retVal {
	case 0:
		return "Allowed"
	case 1:
		return "Audited"
	case -1:
		return "Blocked"
	default:
		return "Unknown"
	}
}

// handleNetworkEvent handles the event
func (ne *NetworkEnforcer) handleNetworkEvent(ev *NetworkEvent) {
	evData := tp.EventData{
		Timestamp: ne.monoNSToTime(ev.Timestamp),

		PidNsID: ev.PidNsID,
		MntNsID: ev.MntNsID,

		HostPPID: ev.HostPPID,
		HostPID:  ev.HostPID,
		HostTID:  ev.HostTID,

		PPID: ev.PPID,
		PID:  ev.PID,
		TID:  ev.TID,

		EventID:   int32(ev.EventID),
		EventName: event2name[int32(ev.EventID)],

		RetVal:  ev.RetVal,
		RetCode: getRetCode(ev.RetVal),

		NodeName: cfg.GlobalCfg.Node,

		// Network routing metadata for FQDN enrichment (network byte order)
		Saddr: ev.SrcIP,
		Daddr: ev.DstIP,
	}

	switch evData.EventName {

	case "inet_stream_connect": // audit or block
		evData.Category = "networkEnforcer"
		evData.Operation = "egress"

		saddr := lib.Uint32ToIPv4(ev.SrcIP)
		daddr := lib.Uint32ToIPv4(ev.DstIP)
		sport := ev.Sport
		dport := ev.Dport

		proto := getIPProtocol(ev.Proto)

		// Update namespace, pod, and container name based on namespace IDs
		ne.updateFieldsWithNS(&evData, ev.PolicyID)

		// Get target info from IP map
		targetInfo := ne.getNameFromIP(daddr)

		evData.Source = ne.getPathFromPidMap(ev.HostPID)
		evData.Resource = fmt.Sprintf("%s/%s:%d-%s:%d", proto, saddr, sport, daddr, dport)
		evData.Data = fmt.Sprintf("direction: egress, protocol: %s, src: %s/%s, srcip: %s, sport: %d, dst: %s, dstip: %s, dport: %d",
			proto, evData.NamespaceName, evData.PodName, saddr, sport, targetInfo, daddr, dport)

	case "inet_csk_accept": // audit only
		evData.Category = "networkEnforcer"
		evData.Operation = "ingress"

		saddr := lib.Uint32ToIPv4(ev.SrcIP)
		daddr := lib.Uint32ToIPv4(ev.DstIP)
		sport := ev.Sport
		dport := ev.Dport

		proto := getIPProtocol(ev.Proto)

		// Update namespace, pod, and container name based on namespace IDs
		ne.updateFieldsWithNS(&evData, ev.PolicyID)

		// Get target info from IP map
		targetInfo := ne.getNameFromIP(saddr)

		evData.Source = ne.getPathFromPidMap(ev.HostPID)
		evData.Resource = fmt.Sprintf("%s/%s:%d-%s:%d", proto, saddr, sport, daddr, dport)
		evData.Data = fmt.Sprintf("direction: ingress, protocol: %s, src: %s, srcip: %s, sport: %d, dst: %s/%s, dstip: %s, dport: %d",
			proto, targetInfo, saddr, sport, evData.NamespaceName, evData.PodName, daddr, dport)

	case "udp_sendmsg": // audit or block
		evData.Category = "networkEnforcer"
		evData.Operation = "egress"

		saddr := lib.Uint32ToIPv4(ev.SrcIP)
		daddr := lib.Uint32ToIPv4(ev.DstIP)
		sport := ev.Sport
		dport := ev.Dport

		// Update namespace, pod, and container name based on namespace IDs
		ne.updateFieldsWithNS(&evData, ev.PolicyID)

		// Get target info from IP map
		targetInfo := ne.getNameFromIP(daddr)

		evData.Source = ne.getPathFromPidMap(ev.HostPID)
		evData.Resource = fmt.Sprintf("udp/%s:%d-%s:%d", saddr, sport, daddr, dport)
		evData.Data = fmt.Sprintf("direction: egress, protocol: udp, src: %s/%s, srcip: %s, sport: %d, dst: %s, dstip: %s, dport: %d",
			evData.NamespaceName, evData.PodName, saddr, sport, targetInfo, daddr, dport)

	case "udp_recvmsg": // audit only
		evData.Category = "networkEnforcer"
		evData.Operation = "ingress"

		saddr := lib.Uint32ToIPv4(ev.SrcIP)
		daddr := lib.Uint32ToIPv4(ev.DstIP)
		sport := ev.Sport
		dport := ev.Dport

		// Update namespace, pod, and container name based on namespace IDs
		ne.updateFieldsWithNS(&evData, ev.PolicyID)

		// Get target info from IP map
		targetInfo := ne.getNameFromIP(saddr)

		evData.Source = ne.getPathFromPidMap(ev.HostPID)
		evData.Resource = fmt.Sprintf("udp/%s:%d-%s:%d", saddr, sport, daddr, dport)
		evData.Data = fmt.Sprintf("direction: ingress, protocol: udp, src: %s, srcip: %s, sport: %d, dst: %s/%s, dstip: %s, dport: %d",
			targetInfo, saddr, sport, evData.NamespaceName, evData.PodName, daddr, dport)

	case "cgroup_skb_egress": // audit and block
		evData.Category = "networkEnforcer"
		evData.Operation = "egress"

		saddr := lib.Uint32ToIPv4(ev.SrcIP)
		daddr := lib.Uint32ToIPv4(ev.DstIP)
		sport := ev.Sport
		dport := ev.Dport
		proto := getIPProtocol(ev.Proto)

		// saddr is the Pod IP (egress: local container is the source)
		ne.updateFieldsWithIP(&evData, saddr, ev.PolicyID)

		targetInfo := ne.getNameFromIP(daddr)

		evData.Resource = fmt.Sprintf("%s/%s:%d-%s:%d", proto, saddr, sport, daddr, dport)
		evData.Data = fmt.Sprintf(
			"direction: egress, protocol: %s, src: %s/%s, srcip: %s, sport: %d, dst: %s, dstip: %s, dport: %d",
			proto, evData.NamespaceName, evData.PodName, saddr, sport, targetInfo, daddr, dport)

	case "cgroup_skb_ingress": // block only
		evData.Category = "networkEnforcer"
		evData.Operation = "ingress"

		saddr := lib.Uint32ToIPv4(ev.SrcIP)
		daddr := lib.Uint32ToIPv4(ev.DstIP)
		sport := ev.Sport
		dport := ev.Dport

		proto := getIPProtocol(ev.Proto)

		// Update namespace and pod name based on destination IP (which is the source IP for ingress)
		ne.updateFieldsWithIP(&evData, daddr, ev.PolicyID)

		// Get target info from IP map
		targetInfo := ne.getNameFromIP(saddr)

		evData.Resource = fmt.Sprintf("%s/%s:%d-%s:%d", proto, saddr, sport, daddr, dport)
		evData.Data = fmt.Sprintf("direction: ingress, protocol: %s, src: %s, srcip: %s, sport: %d, dst: %s/%s, dstip: %s, dport: %d",
			proto, targetInfo, saddr, sport, evData.NamespaceName, evData.PodName, daddr, dport)

	default:
		return

	}

	// Export the event data to the configured backend
	if err := ne.Exporter.ExportEvent(evData); err != nil {
		log.Errf("Failed to export event: %v", err)
	}
}

// updateFieldsWithNS updates namespace, pod, and container name based on namespace IDs
func (ne *NetworkEnforcer) updateFieldsWithNS(evData *tp.EventData, policyID uint32) {
	nsKey := uint64(evData.PidNsID)<<32 | uint64(evData.MntNsID)

	ne.GlobalData.NsMapLock.RLock()
	if foundContainer, ok := ne.GlobalData.NsMap[nsKey]; ok {
		ne.GlobalData.NsMapLock.RUnlock()

		evData.NamespaceName = foundContainer.NamespaceName
		evData.PodName = foundContainer.PodName
		evData.ContainerName = foundContainer.ContainerName

		if evData.RetVal != 0 {
			ne.GlobalData.PodsLock.RLock()
			pod, podExists := ne.GlobalData.Pods[evData.NamespaceName+"/"+evData.PodName]
			ne.GlobalData.PodsLock.RUnlock()
			if podExists {
				// Update matched network policy
				ne.UpdateMatchedNetworkPolicy(&pod.NetworkRules, evData, policyID)
			}
		}
	} else {
		ne.GlobalData.NsMapLock.RUnlock()
	}
}

// updateFieldsWithIP updates namespace and pod name based on the IP address
func (ne *NetworkEnforcer) updateFieldsWithIP(evData *tp.EventData, ipAddr string, policyID uint32) {
	ne.GlobalData.IPMapLock.RLock()
	if ipEntry, ok := ne.GlobalData.IPMap[ipAddr]; ok {
		ne.GlobalData.IPMapLock.RUnlock()
		if ipEntry.Type != "pod" {
			return
		}

		evData.NamespaceName = ipEntry.Pod.NamespaceName
		evData.PodName = ipEntry.Pod.PodName

		if evData.RetVal != 0 {
			ne.GlobalData.PodsLock.RLock()
			pod, podExists := ne.GlobalData.Pods[evData.NamespaceName+"/"+evData.PodName]
			ne.GlobalData.PodsLock.RUnlock()
			if podExists {
				// Update matched network policy
				ne.UpdateMatchedNetworkPolicy(&pod.NetworkRules, evData, policyID)
			}
		}

	} else {
		ne.GlobalData.IPMapLock.RUnlock()
	}
}

// getNameFromIP gets the name (node/pod/service) from the IP address
func (ne *NetworkEnforcer) getNameFromIP(ipAddr string) string {
	ne.GlobalData.IPMapLock.RLock()
	if ipEntry, ok := ne.GlobalData.IPMap[ipAddr]; ok {
		ne.GlobalData.IPMapLock.RUnlock()
		switch ipEntry.Type {
		case "node":
			return fmt.Sprintf("node/%s", ipEntry.Node.NodeName)
		case "pod":
			return fmt.Sprintf("pod/%s/%s", ipEntry.Pod.NamespaceName, ipEntry.Pod.PodName)
		case "service":
			return fmt.Sprintf("svc/%s/%s", ipEntry.Service.NamespaceName, ipEntry.Service.ServiceName)
		default:
			return "unknown"
		}
	}
	ne.GlobalData.IPMapLock.RUnlock()
	return "externalNode"
}
