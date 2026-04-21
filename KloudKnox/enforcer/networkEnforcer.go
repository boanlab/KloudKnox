// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/exporter"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Network Enforcer

// StopChan is a channel used to signal the termination of the network enforcer
var StopChan chan struct{}

// stopOnce ensures StopChan is closed exactly once even if Stop is called multiple times
var stopOnce sync.Once

// init initializes the stop channel for graceful shutdown
func init() {
	StopChan = make(chan struct{})
}

// podLinks represents the links for ingress and egress of a pod
type podLinks struct {
	Ingress    link.Link
	Egress     link.Link
	IngressDns link.Link
	EgressDns  link.Link
}

// netPodRules stores the BPF map keys installed for a single pod
type netPodRules struct {
	EgressLpmKeys       []net_enforcerLpmKey
	EgressHashKeys      []net_enforcerPolicyKey
	EgressPostureKeys   []net_enforcerDefaultPostureKey
	IngressLpmKeys      []net_enforcerLpmKey
	IngressHashKeys     []net_enforcerPolicyKey
	IngressPostureKeys  []net_enforcerDefaultPostureKey
	EgressFqdnKeys      []net_enforcerFqdnIpKey // IP map keys for cleanup
	IngressFqdnKeys     []net_enforcerFqdnIpKey // IP map keys for cleanup
	EgressFqdnRuleKeys  []string                // reversed FQDN strings for ne_fqdn_rules_map cleanup
	IngressFqdnRuleKeys []string                // reversed FQDN strings for ne_fqdn_rules_map cleanup
}

// NetworkEnforcer represents the core network enforcer that tracks
// network events using eBPF programs
type NetworkEnforcer struct {
	// eBPF objects and links
	NetworkEventsObjs  *net_enforcerObjects
	NetworkEventsLinks []link.Link

	// Ring buffer and channel for network events
	NetworkEventsRb   *ringbuf.Reader
	NetworkEventsChan chan []byte

	// Pod links for ingress and egress
	PodLinks     map[string]*podLinks
	PodLinksLock sync.RWMutex

	// Network policies for each pod
	NetRules     map[string]*netPodRules
	NetRulesLock sync.Mutex

	// FQDN resolver for domain-name-based policy enforcement
	FqdnResolver *FqdnResolver

	// Global data
	GlobalData *tp.GlobalData

	// Exporter
	Exporter tp.EventExporter

	// WaitGroup for reader goroutine (separate from worker WaitGroup)
	ReadersWg sync.WaitGroup

	// WaitGroup for workers
	Wg sync.WaitGroup

	// Drop counter for network event channel saturation (4-4)
	networkDrops atomic.Uint64
}

// Configuration constants
const (
	NetworkEventWorkerPools = 2
	NetworkEventChanSize    = 100000
)

// NewNetworkEnforcer creates a new NetworkEnforcer
func NewNetworkEnforcer(globalData *tp.GlobalData, exporter *exporter.Exporter) *NetworkEnforcer {
	ne := &NetworkEnforcer{
		NetworkEventsLinks: make([]link.Link, 0, 128),
		NetworkEventsChan:  make(chan []byte, NetworkEventChanSize),

		PodLinks:     make(map[string]*podLinks),
		PodLinksLock: sync.RWMutex{},

		NetRules:     make(map[string]*netPodRules),
		NetRulesLock: sync.Mutex{},

		GlobalData: globalData,

		Exporter: exporter,

		Wg: sync.WaitGroup{},
	}

	// cleanup releases all eBPF resources accumulated so far; used on error paths.
	cleanup := func(objs *net_enforcerObjects) {
		if ne.FqdnResolver != nil {
			ne.FqdnResolver.Stop()
			ne.FqdnResolver = nil
		}
		for _, l := range ne.NetworkEventsLinks {
			if err := l.Close(); err != nil {
				log.Errf("Error closing link during cleanup: %v", err)
			}
		}
		if objs != nil {
			if err := objs.Close(); err != nil {
				log.Errf("Error closing eBPF objects during cleanup: %v", err)
			}
		}
	}

	// Load eBPF program
	netEventsObjs := &net_enforcerObjects{}
	if err := loadNet_enforcerObjects(netEventsObjs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch,
			LogSizeStart: 1 << 24,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Errf("Verifier error loading network enforcer: %v\n%s", err, strings.Join(ve.Log, "\n"))
		} else {
			log.Errf("Error loading network enforcer objects: %+v", err)
		}
		return nil
	}
	ne.NetworkEventsObjs = netEventsObjs

	// Initialise FQDN resolver (requires the new DNS ring buffer map)
	fqdnResolver, err := NewFqdnResolver(netEventsObjs, globalData, exporter)
	if err != nil {
		log.Warnf("FQDN resolver unavailable (BPF rebuild required): %v", err)
	} else {
		ne.FqdnResolver = fqdnResolver
	}

	// kprobes
	kprobes := []struct {
		name string
		prog *ebpf.Program
	}{
		{"inet_bind", netEventsObjs.KprobeInetBind},
		{"inet_hash_connect", netEventsObjs.KprobeInetHashConnect},
		{"inet_autobind", netEventsObjs.KprobeInetAutobind},
		{"udp_destroy_sock", netEventsObjs.KprobeUdpDestroySock},
		{"inet_stream_connect", netEventsObjs.KprobeInetStreamConnect},
		{"udp_sendmsg", netEventsObjs.KprobeUdpSendmsg},
		{"udp_recvmsg", netEventsObjs.KprobeUdpRecvmsg},
	}

	// Attach kprobes
	for _, kp := range kprobes {
		l, err := link.Kprobe(kp.name, kp.prog, nil)
		if err != nil {
			log.Errf("Error attaching kprobe %s: %v", kp.name, err)
			cleanup(netEventsObjs)
			return nil
		}
		ne.NetworkEventsLinks = append(ne.NetworkEventsLinks, l)
	}

	// kretprobes
	kretprobes := []struct {
		name string
		prog *ebpf.Program
	}{
		{"inet_bind", netEventsObjs.KretprobeInetBind},
		{"inet_hash_connect", netEventsObjs.KretprobeInetHashConnect},
		{"inet_autobind", netEventsObjs.KretprobeInetAutobind},
		{"inet_stream_connect", netEventsObjs.KretprobeInetStreamConnect},
		{"inet_csk_accept", netEventsObjs.KretprobeInetCskAccept},
		{"udp_sendmsg", netEventsObjs.KretprobeUdpSendmsg},
		{"udp_recvmsg", netEventsObjs.KretprobeUdpRecvmsg},
	}

	// Attach kretprobes
	for _, kp := range kretprobes {
		l, err := link.Kretprobe(kp.name, kp.prog, nil)
		if err != nil {
			log.Errf("Error attaching kretprobe %s: %v", kp.name, err)
			cleanup(netEventsObjs)
			return nil
		}
		ne.NetworkEventsLinks = append(ne.NetworkEventsLinks, l)
	}

	// tracepoints
	tracepoints := []struct {
		name string
		prog *ebpf.Program
	}{
		{"inet_sock_set_state", netEventsObjs.TpInetSockSetState},
	}

	// Attach tracepoints
	for _, tp := range tracepoints {
		l, err := link.Tracepoint("sock", tp.name, tp.prog, nil)
		if err != nil {
			log.Errf("Error attaching tracepoint %s: %v", tp.name, err)
			cleanup(netEventsObjs)
			return nil
		}
		ne.NetworkEventsLinks = append(ne.NetworkEventsLinks, l)
	}

	// do not monitor kloudknox if running in k8s cluster
	if lib.IsInK8sCluster() {
		aPidNS, aMntNS, _ := lib.GetNamespaceIDs("self")
		selfNS := (uint64(aPidNS) << 32) | uint64(aMntNS)
		if err := netEventsObjs.NeSkipNsMap.Update(selfNS, uint32(0), ebpf.UpdateAny); err != nil {
			log.Errf("Error updating skip_ns_map: %v", err)
			cleanup(netEventsObjs)
			return nil
		}
	}

	// Create ring buffer reader for network events
	prb, err := ringbuf.NewReader(netEventsObjs.NeEventRb)
	if err != nil {
		cleanup(netEventsObjs)
		return nil
	}
	ne.NetworkEventsRb = prb

	// Start workers that read from ring buffers
	ne.startNetworkEventWorkers()

	// 4-3: mirror st_skip_ns_map updates to ne_skip_ns_map
	globalData.SkipNsHook = func(nsKey uint64) {
		if err := ne.NetworkEventsObjs.NeSkipNsMap.Update(nsKey, uint32(0), ebpf.UpdateAny); err != nil {
			log.Debugf("ne_skip_ns_map update failed for nsKey=%d: %v", nsKey, err)
		}
	}

	// 4-5: clean up kprobe intermediate map entries on process exit
	globalData.ExitHook = func(hostPID, hostTID int32) {
		key := uint64(uint32(hostPID))<<32 | uint64(uint32(hostTID)) // #nosec G115
		_ = ne.NetworkEventsObjs.NeBindSocketMap.Delete(&key)
		_ = ne.NetworkEventsObjs.NeConnectSockMap.Delete(&key)
		_ = ne.NetworkEventsObjs.NeAutobindMap.Delete(&key)
		_ = ne.NetworkEventsObjs.NeMsgMap.Delete(&key)
	}

	log.Printf("Started NetworkEnforcer")
	return ne
}

// StopNetworkEnforcer stops the network enforcer
func (ne *NetworkEnforcer) StopNetworkEnforcer() error {
	if ne == nil {
		return nil
	}

	// Detach all network enforcers from pods
	ne.detachAllNetworkEnforcers()

	// 1. Signal all goroutines to stop
	stopOnce.Do(func() { close(StopChan) })

	// 1a. Stop the FQDN resolver (closes the DNS ring buffer reader)
	if ne.FqdnResolver != nil {
		ne.FqdnResolver.Stop()
	}

	// 2. Close the ring buffer to unblock the reader goroutine
	if ne.NetworkEventsRb != nil {
		if err := ne.NetworkEventsRb.Close(); err != nil {
			log.Errf("Error closing ring buffer reader: %v", err)
		}
	}

	// 3. Wait for the reader goroutine to exit before closing the channel it writes to
	ne.ReadersWg.Wait()
	close(ne.NetworkEventsChan)

	// 4. Detach all kprobes/tracepoints
	for _, l := range ne.NetworkEventsLinks {
		if err := l.Close(); err != nil {
			log.Errf("Error closing link: %v", err)
		}
	}

	// 5. Close all active eBPF program objects
	if err := ne.NetworkEventsObjs.Close(); err != nil {
		log.Errf("Error closing eBPF program objects: %v", err)
	}

	// 6. Wait for worker goroutines
	ne.Wg.Wait()

	log.Print("Stopped NetworkEnforcer")
	return nil
}

// Network Enforcer Management

// AttachNetworkEnforcer attaches the network enforcer to the pod
func (e *RuntimeEnforcer) AttachNetworkEnforcer(pod tp.Pod) error {
	if e == nil || e.NetworkEnforcer == nil {
		return nil
	}

	// If cgroup path is empty, log and skip
	if pod.CgroupPath == "" {
		log.Debugf("Skipping network enforcer attach for pod %s/%s: cgroup path is empty", pod.NamespaceName, pod.PodName)
		return nil
	}

	// If cgroup path doesn't exist, log and skip
	if _, err := os.Stat(pod.CgroupPath); os.IsNotExist(err) {
		log.Debugf("Skipping network enforcer attach for pod %s/%s: cgroup path %s does not exist", pod.NamespaceName, pod.PodName, pod.CgroupPath)
		return nil
	}

	// Check if already attached
	e.NetworkEnforcer.PodLinksLock.RLock()
	_, ok := e.NetworkEnforcer.PodLinks[pod.CgroupPath]
	e.NetworkEnforcer.PodLinksLock.RUnlock()

	if ok {
		log.Debugf("Skipping network enforcer attach for pod %s/%s: already attached", pod.NamespaceName, pod.PodName)
		return nil
	}

	// If entry doesn't exist, create it
	e.NetworkEnforcer.PodLinksLock.Lock()
	entry, ok := e.NetworkEnforcer.PodLinks[pod.CgroupPath]
	if !ok {
		entry = &podLinks{}
		e.NetworkEnforcer.PodLinks[pod.CgroupPath] = entry
	}
	e.NetworkEnforcer.PodLinksLock.Unlock()

	// Attach DNS programs first so that on multi-attach ordering they run
	// before the enforcer and populate FQDN maps even if the enforcer would
	// later drop the packet.
	if entry.IngressDns == nil {
		linkIngressDns, err := link.AttachCgroup(link.CgroupOptions{
			Path:    pod.CgroupPath,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: e.NetworkEnforcer.NetworkEventsObjs.CgroupSkbIngressDns,
		})
		if err != nil {
			return fmt.Errorf("failed to attach ingress DNS: %w", err)
		}
		entry.IngressDns = linkIngressDns
	}

	if entry.EgressDns == nil {
		linkEgressDns, err := link.AttachCgroup(link.CgroupOptions{
			Path:    pod.CgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: e.NetworkEnforcer.NetworkEventsObjs.CgroupSkbEgressDns,
		})
		if err != nil {
			return fmt.Errorf("failed to attach egress DNS: %w", err)
		}
		entry.EgressDns = linkEgressDns
	}

	// Attach ingress
	if entry.Ingress == nil {
		linkIngress, err := link.AttachCgroup(link.CgroupOptions{
			Path:    pod.CgroupPath,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: e.NetworkEnforcer.NetworkEventsObjs.CgroupSkbIngress,
		})
		if err != nil {
			return fmt.Errorf("failed to attach ingress: %w", err)
		}
		entry.Ingress = linkIngress
	}

	// Attach egress
	if entry.Egress == nil {
		linkEgress, err := link.AttachCgroup(link.CgroupOptions{
			Path:    pod.CgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: e.NetworkEnforcer.NetworkEventsObjs.CgroupSkbEgress,
		})
		if err != nil {
			return fmt.Errorf("failed to attach egress: %w", err)
		}
		entry.Egress = linkEgress
	}

	// Scan for existing sockets to populate BPF maps
	if err := e.NetworkEnforcer.scanExistingSockets(pod); err != nil {
		log.Warnf("Failed to scan existing sockets for pod %s/%s: %v", pod.NamespaceName, pod.PodName, err)
	}

	log.Printf("Attached NetworkEnforcer to pod %s/%s", pod.NamespaceName, pod.PodName)

	return nil
}

// scanExistingSockets scans /proc for existing bound sockets and updates NeInodeMap
func (ne *NetworkEnforcer) scanExistingSockets(pod tp.Pod) error {
	// Get cgroup ID for the pod
	cgid, err := ne.getInodeFromPath(pod.CgroupPath)
	if err != nil {
		return fmt.Errorf("failed to get cgroup ID for pod %s: %w", pod.PodName, err)
	}

	// Iterate through containers in the pod to find PIDs
	for containerID := range pod.Containers {
		ne.GlobalData.ContainersLock.RLock()
		container, ok := ne.GlobalData.Containers[containerID]
		ne.GlobalData.ContainersLock.RUnlock()
		if !ok {
			continue
		}

		pid := container.RootPID
		if pid == 0 {
			continue
		}

		// Get executable inode
		exePath := filepath.Join(cfg.GlobalCfg.ProcDir, fmt.Sprintf("%d", pid), "exe")
		exeInode, err := ne.getInodeFromPath(exePath)
		if err != nil {
			log.Debugf("Failed to get exe inode for PID %d: %v", pid, err)
			continue
		}

		// Scan TCP and UDP sockets
		protocols := []struct {
			name  string
			proto uint8
		}{
			{"tcp", 6},  // IPPROTO_TCP
			{"udp", 17}, // IPPROTO_UDP
		}

		// Use io/fs to scope file access and satisfy gosec
		procFS := os.DirFS(cfg.GlobalCfg.ProcDir)

		for _, p := range protocols {
			relPath := fmt.Sprintf("%d/net/%s", pid, p.name)
			data, err := fs.ReadFile(procFS, relPath)
			if err != nil {
				continue
			}

			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if i == 0 || strings.TrimSpace(line) == "" {
					continue
				}

				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}

				// Local address is in field 1: hexIP:hexPort
				localAddr := fields[1]
				parts := strings.Split(localAddr, ":")
				if len(parts) != 2 {
					continue
				}

				port64, err := strconv.ParseUint(parts[1], 16, 16)
				if err != nil {
					continue
				}
				port := uint16(port64)

				if port == 0 {
					continue
				}

				// For TCP, state should be 0A (LISTEN)
				if p.name == "tcp" && fields[3] != "0A" {
					continue
				}

				key := net_enforcerInodeKey{
					CgroupId: cgid,
					Protocol: uint32(p.proto),
					Port:     uint32(port),
				}

				// Update inode map
				if err := ne.NetworkEventsObjs.NeInodeMap.Update(&key, &exeInode, ebpf.UpdateAny); err != nil {
					log.Debugf("Failed to update NeInodeMap for existing %s socket %d: %v", p.name, port, err)
				} else {
					log.Debugf("Populated existing %s socket %d (inode %d) for cgroup %d", p.name, port, exeInode, cgid)
				}
			}
		}
	}

	return nil
}

// getInodeFromPath returns the inode number for a given path
func (ne *NetworkEnforcer) getInodeFromPath(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("failed to get syscall.Stat_t for %s", path)
	}
	return stat.Ino, nil
}

// DetachNetworkEnforcer detaches the network enforcer from the pod
func (e *RuntimeEnforcer) DetachNetworkEnforcer(pod tp.Pod) error {
	if e == nil || e.NetworkEnforcer == nil {
		return nil
	}

	// If cgroup path doesn't exist, skip
	if _, err := os.Stat(pod.CgroupPath); os.IsNotExist(err) {
		return nil
	}

	e.NetworkEnforcer.PodLinksLock.Lock()

	// Get entry from podLinks
	entry, ok := e.NetworkEnforcer.PodLinks[pod.CgroupPath]
	if !ok {
		e.NetworkEnforcer.PodLinksLock.Unlock()
		return nil
	}

	// Detach ingress
	if entry.Ingress != nil {
		if err := entry.Ingress.Close(); err != nil {
			e.NetworkEnforcer.PodLinksLock.Unlock()
			return fmt.Errorf("failed to close ingress link: %w", err)
		}
		entry.Ingress = nil
	}

	// Detach egress
	if entry.Egress != nil {
		if err := entry.Egress.Close(); err != nil {
			e.NetworkEnforcer.PodLinksLock.Unlock()
			return fmt.Errorf("failed to close egress link: %w", err)
		}
		entry.Egress = nil
	}

	// Detach ingress DNS
	if entry.IngressDns != nil {
		if err := entry.IngressDns.Close(); err != nil {
			e.NetworkEnforcer.PodLinksLock.Unlock()
			return fmt.Errorf("failed to close ingress DNS link: %w", err)
		}
		entry.IngressDns = nil
	}

	// Detach egress DNS
	if entry.EgressDns != nil {
		if err := entry.EgressDns.Close(); err != nil {
			e.NetworkEnforcer.PodLinksLock.Unlock()
			return fmt.Errorf("failed to close egress DNS link: %w", err)
		}
		entry.EgressDns = nil
	}

	// Remove entry from podLinks now that links are closed
	delete(e.NetworkEnforcer.PodLinks, pod.CgroupPath)
	e.NetworkEnforcer.PodLinksLock.Unlock()

	// Clean up BPF map entries (these have their own internal synchronisation)
	cgid, err := e.NetworkEnforcer.getInodeFromPath(pod.CgroupPath)
	if err == nil {
		e.NetworkEnforcer.cleanupInodeMapForCgroup(cgid)
	}
	e.NetworkEnforcer.cleanupNetworkPoliciesByCgroup(pod.CgroupPath)

	log.Printf("Detached NetworkEnforcer from pod %s/%s", pod.NamespaceName, pod.PodName)
	return nil
}

// cleanupInodeMapForCgroup removes all entries in inode map that match the given cgroup ID
func (ne *NetworkEnforcer) cleanupInodeMapForCgroup(cgid uint64) {
	iterator := ne.NetworkEventsObjs.NeInodeMap.Iterate()

	var key net_enforcerInodeKey
	var inode uint64

	keysToDelete := []net_enforcerInodeKey{}

	for iterator.Next(&key, &inode) {
		if key.CgroupId == cgid {
			keysToDelete = append(keysToDelete, key)
		}
	}

	if err := iterator.Err(); err != nil {
		log.Warnf("Failed to iterate NeInodeMap for cleanup: %v", err)
	}

	for _, k := range keysToDelete {
		if err := ne.NetworkEventsObjs.NeInodeMap.Delete(k); err != nil {
			log.Debugf("Failed to delete NeInodeMap entry during cleanup: %v", err)
		}
	}

	if len(keysToDelete) > 0 {
		log.Printf("Cleaned up %d port mappings for cgroup %d", len(keysToDelete), cgid)
	}
}

// detachAllNetworkEnforcers detaches the network enforcers from all pods
func (ne *NetworkEnforcer) detachAllNetworkEnforcers() {
	for podCgroupPath, entry := range ne.PodLinks {
		// If cgroup path doesn't exist, skip
		if _, err := os.Stat(podCgroupPath); os.IsNotExist(err) {
			continue
		}

		// Detach ingress
		closeLink := func(lnk interface{ Close() error }, direction string) {
			if lnk != nil {
				if err := lnk.Close(); err != nil {
					log.Debugf("Failed to close %s link for pod %s: %v", direction, podCgroupPath, err)
				}
			}
		}
		closeLink(entry.Ingress, "ingress")
		closeLink(entry.Egress, "egress")
		closeLink(entry.IngressDns, "ingress DNS")
		closeLink(entry.EgressDns, "egress DNS")
		entry.Ingress = nil
		entry.Egress = nil
		entry.IngressDns = nil
		entry.EgressDns = nil
	}

	log.Printf("Detached NetworkEnforcers from all pods")
}
