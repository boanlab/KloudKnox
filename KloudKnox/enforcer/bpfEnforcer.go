// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	BpfAlertWorkerPools = 2
	BpfAlertChanSize    = 100000

	flagEnabled uint32 = 1

	// Action constants (must match BPF-side #define values)
	actionAllow uint8 = 0
	actionAudit uint8 = 1
	actionBlock uint8 = 2

	// Domain constants (must match BPF-side #define values)
	domainProc   uint32 = 0
	domainFile   uint32 = 1
	domainCap    uint32 = 2
	domainUnix   uint32 = 3
	domainSignal uint32 = 4
	domainPtrace uint32 = 5
)

// bpfPodRules tracks the BPF map keys installed for a single pod.
// Used for diff-and-cleanup on policy updates and pod deletion.
//
// PodInodes holds the cgroup v2 inode for each container in the pod.
// bpf_get_current_cgroup_id() returns the DEEPEST (container-level) cgroup
// inode, so all rule keys and managed_cgroups entries use these per-container
// inodes rather than the parent pod cgroup inode.
type bpfPodRules struct {
	PodInodes   []uint64
	ProcKeys    []bpf_enforcerBpfeProcKey
	FileKeys    []bpf_enforcerBpfeFileKey
	CapKeys     []bpf_enforcerBpfeCapKey
	SignalKeys  []bpf_enforcerBpfeSignalKey
	PtraceKeys  []bpf_enforcerBpfePtraceKey
	UnixKeys    []bpf_enforcerBpfeUnixKey
	PostureKeys []bpf_enforcerBpfePostureKey
}

// BpfEnforcer is the BPF-LSM security enforcer.
type BpfEnforcer struct {
	objs  *bpf_enforcerObjects
	links []link.Link

	// Alert ring-buffer reader + worker pool (§1.5 / §4.6)
	AlertsRb   *ringbuf.Reader
	AlertsChan chan []byte
	stopChan   chan struct{}
	ReadersWg  sync.WaitGroup
	Wg         sync.WaitGroup
	alertDrops atomic.Uint64

	GlobalData *tp.GlobalData
	Exporter   tp.EventExporter

	// Per-pod installed key tracking (key: pod.CgroupPath)
	PodRules     map[string]*bpfPodRules
	PodRulesLock sync.Mutex

	// inodePaths caches inode→container-relative-path for alert formatting.
	// Populated when installing file/proc rules; never deleted (stale entries
	// are harmless since inodes don't repeat within a container's lifetime).
	inodePaths sync.Map // key: uint64, value: string
}

// NewBpfEnforcer loads the BPF-LSM object, attaches all LSM programs globally,
// and starts the alert worker pool.
func NewBpfEnforcer(globalData *tp.GlobalData, ex tp.EventExporter) (*BpfEnforcer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	be := &BpfEnforcer{
		AlertsChan: make(chan []byte, BpfAlertChanSize),
		stopChan:   make(chan struct{}),
		PodRules:   make(map[string]*bpfPodRules),
		GlobalData: globalData,
		Exporter:   ex,
	}

	objs := &bpf_enforcerObjects{}
	if err := loadBpf_enforcerObjects(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch,
			LogSizeStart: 1 << 24,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Errf("BPF-LSM enforcer verifier error: %v\n%s", err, strings.Join(ve.Log, "\n"))
		} else {
			log.Errf("BPF-LSM enforcer load error: %v", err)
		}
		return nil, err
	}
	be.objs = objs

	// Attach all LSM programs globally
	lsmProgs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"capable", objs.BpfeCapable},
		{"bprm_check_security", objs.BpfeBprmCheck},
		{"file_open", objs.BpfeFileOpen},
		{"file_permission", objs.BpfeFilePermission},
		{"mmap_file", objs.BpfeMmapFile},
		{"path_chmod", objs.BpfePathChmod},
		{"path_chown", objs.BpfePathChown},
		{"path_unlink", objs.BpfePathUnlink},
		{"path_rename", objs.BpfePathRename},
		{"path_link", objs.BpfePathLink},
		{"path_mkdir", objs.BpfePathMkdir},
		{"path_rmdir", objs.BpfePathRmdir},
		{"path_truncate", objs.BpfePathTruncate},
		{"path_symlink", objs.BpfePathSymlink},
		{"path_mknod", objs.BpfePathMknod},
		{"unix_stream_connect", objs.BpfeUnixStreamConnect},
		{"unix_may_send", objs.BpfeUnixMaySend},
		{"socket_post_create", objs.BpfeSocketPostCreate},
		{"sk_free_security", objs.BpfeSkFree},
		{"socket_bind", objs.BpfeSocketBind},
		{"socket_listen", objs.BpfeSocketListen},
		{"task_kill", objs.BpfeTaskKill},
		{"ptrace_access_check", objs.BpfePtraceAccess},
		{"ptrace_traceme", objs.BpfePtraceTraceme},
	}

	for _, p := range lsmProgs {
		l, err := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if err != nil {
			log.Errf("BPF-LSM attach failed for %s: %v", p.name, err)
			be.cleanup()
			return nil, fmt.Errorf("attach lsm/%s: %w", p.name, err)
		}
		be.links = append(be.links, l)
	}

	rb, err := ringbuf.NewReader(objs.BpfeAlertsRb)
	if err != nil {
		be.cleanup()
		return nil, fmt.Errorf("open alerts ring buffer: %w", err)
	}
	be.AlertsRb = rb

	be.startAlertWorkers()

	log.Print("Started BPF-LSM Enforcer")
	return be, nil
}

// cleanup releases partially-initialised BPF resources during error paths.
func (be *BpfEnforcer) cleanup() {
	for _, l := range be.links {
		_ = l.Close()
	}
	if be.objs != nil {
		_ = be.objs.Close()
	}
}

// StopBpfEnforcer detaches programs, drains the alert pipeline, and
// releases BPF objects.
func (be *BpfEnforcer) StopBpfEnforcer() error {
	if be == nil {
		return nil
	}

	// 1. Signal goroutines to stop.
	close(be.stopChan)

	// 2. Flush managed_cgroups — LSM programs will see empty map and return 0.
	be.PodRulesLock.Lock()
	for _, rules := range be.PodRules {
		for _, ino := range rules.PodInodes {
			_ = be.objs.BpfeManagedCgroups.Delete(&ino)
		}
	}
	be.PodRulesLock.Unlock()

	// 3. Close ring buffer to unblock the reader goroutine.
	if be.AlertsRb != nil {
		_ = be.AlertsRb.Close()
	}

	// 4. Wait for reader to exit before closing the channel it writes to.
	be.ReadersWg.Wait()
	close(be.AlertsChan)

	// 5. Detach LSM links in reverse order.
	for i := len(be.links) - 1; i >= 0; i-- {
		_ = be.links[i].Close()
	}

	// 6. Close BPF objects.
	if be.objs != nil {
		_ = be.objs.Close()
	}

	// 7. Wait for workers.
	be.Wg.Wait()

	log.Print("Stopped BPF-LSM Enforcer")
	return nil
}

// AttachBpfEnforcer registers a pod's cgroup in the managed-cgroups map
// so that LSM programs begin enforcing it.  The actual rule installation
// happens in UpdateBPFMaps — this is a no-op if called before that.
func (e *RuntimeEnforcer) AttachBpfEnforcer(pod tp.Pod) error {
	if e == nil || e.BpfEnforcer == nil {
		return nil
	}
	if pod.CgroupPath == "" {
		return nil
	}
	// Registration happens atomically at the end of UpdateBPFMaps.
	return nil
}

// DetachBpfEnforcer removes all BPF map entries for a pod and unregisters
// its cgroup from the managed-cgroups map.
func (e *RuntimeEnforcer) DetachBpfEnforcer(pod tp.Pod) error {
	if e == nil || e.BpfEnforcer == nil {
		return nil
	}

	be := e.BpfEnforcer
	be.PodRulesLock.Lock()
	defer be.PodRulesLock.Unlock()

	rules, ok := be.PodRules[pod.CgroupPath]
	if !ok {
		return nil
	}

	// Use stored container inodes; try refreshing if the pod is still alive.
	inodes := rules.PodInodes
	if fresh := containerCgroupInodes(be.GlobalData, pod); len(fresh) > 0 {
		inodes = fresh
	}

	// 1. Unregister all container cgroups first — enforcement stops immediately.
	for _, ino := range inodes {
		_ = be.objs.BpfeManagedCgroups.Delete(&ino)
	}

	// 2. Clean up all rule entries.
	be.diffAndCleanup(pod.CgroupPath, &bpfPodRules{})
	delete(be.PodRules, pod.CgroupPath)
	return nil
}

// UpdateBPFMaps

// UpdateBPFMaps translates the pod's policy rules into BPF map entries.
// Rules are keyed by the per-container cgroup inode because
// bpf_get_current_cgroup_id() returns the deepest (container-level) cgroup
// inode, not the parent pod cgroup inode.
// Follows "rules first, register last" to avoid enforcement gaps.
func (e *RuntimeEnforcer) UpdateBPFMaps(pod tp.Pod) error {
	if e == nil || e.BpfEnforcer == nil {
		return nil
	}

	be := e.BpfEnforcer

	// Collect container-level cgroup inodes. Fall back to pod cgroup inode if
	// containers haven't written their cgroup paths yet (very early call).
	containerInodes := containerCgroupInodes(be.GlobalData, pod)
	if len(containerInodes) == 0 {
		podInode, err := cgroupInode(pod.CgroupPath)
		if err != nil {
			return fmt.Errorf("UpdateBPFMaps: no container cgroups and pod cgroup unavailable: %w", err)
		}
		containerInodes = []uint64{podInode}
	}

	be.PodRulesLock.Lock()
	defer be.PodRulesLock.Unlock()

	// 1. Install all rules for each container's cgroup inode.
	//    During this phase no inode is in bpfe_managed_cgroups yet,
	//    so LSM programs return 0 immediately.
	next := &bpfPodRules{PodInodes: containerInodes}

	for _, cInode := range containerInodes {
		if err := be.installProcRules(pod, cInode, next); err != nil {
			return err
		}
		if err := be.installFileRules(pod, cInode, next); err != nil {
			return err
		}
		if err := be.installCapRules(pod, cInode, next); err != nil {
			return err
		}
		if err := be.installSignalRules(pod, cInode, next); err != nil {
			return err
		}
		if err := be.installPtraceRules(pod, cInode, next); err != nil {
			return err
		}
		if err := be.installUnixRules(pod, cInode, next); err != nil {
			return err
		}
		if err := be.installPostures(pod, cInode, next); err != nil {
			return err
		}
	}

	// 2. Register all container cgroups — enforcement begins after this point.
	enabled := flagEnabled
	for _, cInode := range containerInodes {
		if err := be.objs.BpfeManagedCgroups.Update(&cInode, &enabled, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("register managed cgroup %d: %w", cInode, err)
		}
	}

	// 3. Remove stale entries from the previous policy revision.
	be.diffAndCleanup(pod.CgroupPath, next)
	be.PodRules[pod.CgroupPath] = next
	return nil
}

// Capability Rules

// encodeAction converts a policy action string to the BPF uint8 constant.
func encodeAction(action string) uint8 {
	switch action {
	case "Audit":
		return actionAudit
	case "Block":
		return actionBlock
	default:
		return actionAllow
	}
}

// installCapRules populates bpfe_cap_rules from pod.CapabilityRules.
func (be *BpfEnforcer) installCapRules(pod tp.Pod, podInode uint64, next *bpfPodRules) error {
	// Track which caps have fromSource-specific Allow rules so we can add
	// a default Block for every other source (allow-list semantics).
	fromSourceAllowCaps := make(map[uint32]uint32) // capID → policyID

	for src, inner := range pod.CapabilityRules.OuterRules {
		srcInode := uint64(0)
		if src != "default" {
			ino, err := resolveInodeInPod(be.GlobalData, pod, src)
			if err != nil {
				log.Debugf("installCapRules: skip source %q: %v", src, err)
				continue
			}
			srcInode = ino
		}

		for capID, rule := range inner.InnerRules {
			key := bpf_enforcerBpfeCapKey{
				PodInode: podInode,
				SrcInode: srcInode,
				CapId:    capID,
			}
			val := bpf_enforcerBpfeRuleVal{
				Action:   encodeAction(rule.Action),
				PolicyId: rule.Policy.PolicyID,
			}
			if err := be.objs.BpfeCapRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update cap_rules: %w", err)
			}
			next.CapKeys = append(next.CapKeys, key)

			// Track fromSource Allow rules so we can synthesize a default Block
			// for the wildcard source, making this an allow-list for the cap.
			if srcInode != 0 && rule.Action == "Allow" {
				fromSourceAllowCaps[capID] = rule.Policy.PolicyID
			}
		}
	}

	// For each cap with fromSource Allow rules but no explicit wildcard Block,
	// install a Block rule for srcInode=0 (all other sources blocked).
	for capID, policyID := range fromSourceAllowCaps {
		defaultKey := bpf_enforcerBpfeCapKey{
			PodInode: podInode,
			SrcInode: 0,
			CapId:    capID,
		}
		defaultVal := bpf_enforcerBpfeRuleVal{
			Action:   actionBlock,
			PolicyId: policyID,
		}
		if err := be.objs.BpfeCapRules.Update(&defaultKey, &defaultVal, ebpf.UpdateAny); err != nil {
			log.Debugf("installCapRules: default-block cap %d: %v", capID, err)
		}
		next.CapKeys = append(next.CapKeys, defaultKey)
	}
	return nil
}

// Posture Installation

// postureForGlobal converts a policy-level GlobalAction to the BPF posture
// action. Semantics are inverted from the rule action:
//   - Allow policy (allow-list) → posture = Block  (block everything not listed)
//   - Block policy (block-list) → posture = Allow  (allow everything not listed)
//
// The BPF fallback_posture() returns 0 when no entry is found, so we only need
// to install entries whose inverted action is Block (the non-trivial case).
func postureForGlobal(globalAction string) string {
	if globalAction == "Allow" {
		return "Block"
	}
	return "Allow"
}

// firstAllowPolicyID returns the PolicyID of the first Allow-action policy in
// the pod, or 0 if none exist. Used to tag posture entries so that
// fallback_posture can emit alerts with a traceable policy_id.
func firstAllowPolicyID(pod tp.Pod) uint32 {
	for _, p := range pod.RuntimePolicies {
		if p.Action == "Allow" {
			return p.PolicyID
		}
	}
	return 0
}

// installPostures sets the default posture entries for domains whose policy
// is an allow-list (GlobalAction == "Allow") — the only case that needs an
// explicit BPF map entry because the BPF fallback returns 0 (allow) when no
// posture is present, which is already correct for block-list policies.
func (be *BpfEnforcer) installPostures(pod tp.Pod, podInode uint64, next *bpfPodRules) error {
	type postureEntry struct {
		domain       uint32
		globalAction string
		src          uint64
	}

	// File domain posture is only installed when the policy actually contains
	// file access (read/write) rules. A proc-only allow policy must not install
	// a Block file posture — that would block runc's procfs reads during exec.
	fileGlobal := pod.FileRules.GlobalAction
	if !hasFileRules(pod.FileRules) {
		fileGlobal = "" // leave file domain at BPF default (allow)
	}

	// Proc domain posture is only installed when there are explicit process rules.
	// A file-only allow policy must not install Block proc posture — that would
	// block all process execution (cat, ls, etc.) that isn't explicitly listed.
	procGlobal := pod.FileRules.GlobalAction
	if !hasProcRules(pod.FileRules) {
		procGlobal = "" // leave proc domain at BPF default (allow)
	}

	// For IPC sub-domains, only install Block posture when the policy actually
	// contains rules for that specific sub-domain. A ptrace-only policy must
	// not set Block signal/unix posture — that would block all signal/unix
	// operations not explicitly listed.
	ipcGlobal := pod.IPCRules.GlobalAction
	signalGlobal := ipcGlobal
	if !hasSignalRules(pod.IPCRules) {
		signalGlobal = ""
	}
	ptraceGlobal := ipcGlobal
	if !hasPtraceIPCRules(pod.IPCRules) {
		ptraceGlobal = ""
	}
	unixGlobal := ipcGlobal
	if !hasUnixRules(pod.IPCRules) {
		unixGlobal = ""
	}

	entries := []postureEntry{
		{domainProc, procGlobal, 0},
		{domainFile, fileGlobal, 0},
		{domainCap, pod.CapabilityRules.GlobalAction, 0},
		{domainSignal, signalGlobal, 0},
		{domainPtrace, ptraceGlobal, 0},
		{domainUnix, unixGlobal, 0},
	}

	postureID := firstAllowPolicyID(pod)

	for _, e := range entries {
		posture := postureForGlobal(e.globalAction)
		if posture != "Block" {
			// Allow posture == BPF default; skip to keep maps small.
			continue
		}
		key := bpf_enforcerBpfePostureKey{
			PodInode: podInode,
			SrcInode: e.src,
			Domain:   e.domain,
		}
		val := bpf_enforcerBpfePostureVal{
			Action:   encodeAction(posture),
			PolicyId: postureID,
		}
		if err := be.objs.BpfePosture.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update posture: %w", err)
		}
		next.PostureKeys = append(next.PostureKeys, key)
	}
	return nil
}

// Diff and Cleanup

// diffAndCleanup deletes entries that were in the old rule set but not in next.
func (be *BpfEnforcer) diffAndCleanup(cgroupPath string, next *bpfPodRules) {
	old, ok := be.PodRules[cgroupPath]
	if !ok {
		return
	}

	// Unregister container cgroup inodes that are no longer active.
	for _, ino := range old.PodInodes {
		stillPresent := false
		for _, newIno := range next.PodInodes {
			if ino == newIno {
				stillPresent = true
				break
			}
		}
		if !stillPresent {
			_ = be.objs.BpfeManagedCgroups.Delete(&ino)
		}
	}

	for _, key := range old.ProcKeys {
		if !containsBpfeProcKey(next.ProcKeys, key) {
			if err := be.objs.BpfeProcRules.Delete(&key); err != nil {
				log.Debugf("diffAndCleanup: delete proc_rules key: %v", err)
			}
		}
	}

	for _, key := range old.FileKeys {
		if !containsBpfeFileKey(next.FileKeys, key) {
			if err := be.objs.BpfeFileRules.Delete(&key); err != nil {
				log.Debugf("diffAndCleanup: delete file_rules key: %v", err)
			}
		}
	}

	for _, key := range old.CapKeys {
		if !containsBpfeCapKey(next.CapKeys, key) {
			if err := be.objs.BpfeCapRules.Delete(&key); err != nil {
				log.Debugf("diffAndCleanup: delete cap_rules key: %v", err)
			}
		}
	}

	for _, key := range old.SignalKeys {
		if !containsBpfeSignalKey(next.SignalKeys, key) {
			if err := be.objs.BpfeSignalRules.Delete(&key); err != nil {
				log.Debugf("diffAndCleanup: delete signal_rules key: %v", err)
			}
		}
	}

	for _, key := range old.PtraceKeys {
		if !containsBpfePtraceKey(next.PtraceKeys, key) {
			if err := be.objs.BpfePtraceRules.Delete(&key); err != nil {
				log.Debugf("diffAndCleanup: delete ptrace_rules key: %v", err)
			}
		}
	}

	for _, key := range old.UnixKeys {
		if !containsBpfeUnixKey(next.UnixKeys, key) {
			if err := be.objs.BpfeUnixRules.Delete(&key); err != nil {
				log.Debugf("diffAndCleanup: delete unix_rules key: %v", err)
			}
		}
	}

	for _, key := range old.PostureKeys {
		if !containsBpfePostureKey(next.PostureKeys, key) {
			if err := be.objs.BpfePosture.Delete(&key); err != nil {
				log.Debugf("diffAndCleanup: delete posture key: %v", err)
			}
		}
	}
}

func containsBpfeProcKey(keys []bpf_enforcerBpfeProcKey, k bpf_enforcerBpfeProcKey) bool {
	for _, v := range keys {
		if v == k {
			return true
		}
	}
	return false
}

func containsBpfeCapKey(keys []bpf_enforcerBpfeCapKey, k bpf_enforcerBpfeCapKey) bool {
	for _, v := range keys {
		if v == k {
			return true
		}
	}
	return false
}

func containsBpfeSignalKey(keys []bpf_enforcerBpfeSignalKey, k bpf_enforcerBpfeSignalKey) bool {
	for _, v := range keys {
		if v == k {
			return true
		}
	}
	return false
}

func containsBpfePtraceKey(keys []bpf_enforcerBpfePtraceKey, k bpf_enforcerBpfePtraceKey) bool {
	for _, v := range keys {
		if v == k {
			return true
		}
	}
	return false
}

func containsBpfeUnixKey(keys []bpf_enforcerBpfeUnixKey, k bpf_enforcerBpfeUnixKey) bool {
	for _, v := range keys {
		if v == k {
			return true
		}
	}
	return false
}

func containsBpfePostureKey(keys []bpf_enforcerBpfePostureKey, k bpf_enforcerBpfePostureKey) bool {
	for _, v := range keys {
		if v == k {
			return true
		}
	}
	return false
}

func containsBpfeFileKey(keys []bpf_enforcerBpfeFileKey, k bpf_enforcerBpfeFileKey) bool {
	for _, v := range keys {
		if v == k {
			return true
		}
	}
	return false
}

// Signal Rules

// installSignalRules populates bpfe_signal_rules from pod.IPCRules.
// Multiple rules targeting the same (src, target) are merged via bitmask OR.
func (be *BpfEnforcer) installSignalRules(pod tp.Pod, podInode uint64, next *bpfPodRules) error {
	type accumKey struct {
		srcInode uint64
		tgtInode uint64
	}
	type accumVal struct {
		blockMask uint32
		auditMask uint32
		policyID  uint32
	}

	for src, inner := range pod.IPCRules.OuterRules {
		if len(inner.Signal) == 0 {
			continue
		}
		srcInode := uint64(0)
		if src != "default" {
			ino, err := resolveInodeInPod(be.GlobalData, pod, src)
			if err != nil {
				log.Debugf("installSignalRules: skip source %q: %v", src, err)
				continue
			}
			srcInode = ino
		}

		acc := make(map[accumKey]*accumVal)
		for _, rule := range inner.Signal {
			tgtInode := uint64(0)
			if rule.Target != "" {
				ino, err := resolveInodeInPod(be.GlobalData, pod, rule.Target)
				if err != nil {
					log.Debugf("installSignalRules: skip target %q: %v", rule.Target, err)
					continue
				}
				tgtInode = ino
			}

			ak := accumKey{srcInode, tgtInode}
			v, ok := acc[ak]
			if !ok {
				v = &accumVal{}
				acc[ak] = v
			}

			var mask uint32
			if len(rule.Signals) == 0 {
				mask = 0x7FFFFFFF // all 31 real-time signals
			} else {
				for _, sig := range rule.Signals {
					if sig >= 1 && sig <= 31 {
						mask |= 1 << (uint32(sig) - 1)
					}
				}
			}

			switch rule.Action {
			case "Block":
				v.blockMask |= mask
			case "Audit":
				v.auditMask |= mask
			}
			v.policyID = rule.Policy.PolicyID
		}

		for ak, v := range acc {
			key := bpf_enforcerBpfeSignalKey{
				PodInode:    podInode,
				SrcInode:    ak.srcInode,
				TargetInode: ak.tgtInode,
			}
			val := bpf_enforcerBpfeSignalVal{
				BlockMask: v.blockMask,
				AuditMask: v.auditMask,
				PolicyId:  v.policyID,
			}
			if err := be.objs.BpfeSignalRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update signal_rules: %w", err)
			}
			next.SignalKeys = append(next.SignalKeys, key)
		}
	}
	return nil
}

// Ptrace Rules

// installPtraceRules populates bpfe_ptrace_rules from pod.IPCRules.
// Multiple rules for the same (src, target) pair are merged per permission field.
func (be *BpfEnforcer) installPtraceRules(pod tp.Pod, podInode uint64, next *bpfPodRules) error {
	type accumKey struct {
		srcInode uint64
		tgtInode uint64
	}
	type accumVal struct {
		actionTrace   uint8
		actionRead    uint8
		actionTraceby uint8
		actionReadby  uint8
		policyID      uint32
	}

	for src, inner := range pod.IPCRules.OuterRules {
		if len(inner.Ptrace) == 0 {
			continue
		}
		srcInode := uint64(0)
		if src != "default" {
			ino, err := resolveInodeInPod(be.GlobalData, pod, src)
			if err != nil {
				log.Debugf("installPtraceRules: skip source %q: %v", src, err)
				continue
			}
			srcInode = ino
		}

		acc := make(map[accumKey]*accumVal)
		for _, rule := range inner.Ptrace {
			tgtInode := uint64(0)
			if rule.Target != "" {
				ino, err := resolveInodeInPod(be.GlobalData, pod, rule.Target)
				if err != nil {
					log.Debugf("installPtraceRules: skip target %q: %v", rule.Target, err)
					continue
				}
				tgtInode = ino
			}

			ak := accumKey{srcInode, tgtInode}
			v, ok := acc[ak]
			if !ok {
				v = &accumVal{
					actionTrace:   actionAllow,
					actionRead:    actionAllow,
					actionTraceby: actionAllow,
					actionReadby:  actionAllow,
				}
				acc[ak] = v
			}

			action := encodeAction(rule.Action)
			switch rule.Permission {
			case "trace":
				v.actionTrace = action
			case "read":
				v.actionRead = action
			case "traceby":
				v.actionTraceby = action
			case "readby":
				v.actionReadby = action
			}
			v.policyID = rule.Policy.PolicyID
		}

		// Mirror traceby/readby rules to the tracer perspective so that
		// ptrace_access_check (tracer side) doesn't fall through to Block posture.
		// For each traceby/readby rule {src=tracee, tgt=tracer}, synthesize a
		// trace/read rule {src=tracer, tgt=tracee} with the same action.
		reverseAcc := make(map[accumKey]*accumVal)
		for ak, v := range acc {
			if v.actionTraceby == actionAllow && v.actionReadby == actionAllow {
				continue
			}
			rak := accumKey{ak.tgtInode, ak.srcInode}
			if _, exists := acc[rak]; exists {
				continue // explicit rule already covers the tracer side
			}
			rv, ok := reverseAcc[rak]
			if !ok {
				rv = &accumVal{
					actionTrace:   actionAllow,
					actionRead:    actionAllow,
					actionTraceby: actionAllow,
					actionReadby:  actionAllow,
					policyID:      v.policyID,
				}
				reverseAcc[rak] = rv
			}
			if v.actionTraceby != actionAllow {
				rv.actionTrace = v.actionTraceby
			}
			if v.actionReadby != actionAllow {
				rv.actionRead = v.actionReadby
			}
		}
		for rak, rv := range reverseAcc {
			acc[rak] = rv
		}

		for ak, v := range acc {
			key := bpf_enforcerBpfePtraceKey{
				PodInode:    podInode,
				SrcInode:    ak.srcInode,
				TargetInode: ak.tgtInode,
			}
			val := bpf_enforcerBpfePtraceVal{
				ActionTrace:   v.actionTrace,
				ActionRead:    v.actionRead,
				ActionTraceby: v.actionTraceby,
				ActionReadby:  v.actionReadby,
				PolicyId:      v.policyID,
			}
			if err := be.objs.BpfePtraceRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update ptrace_rules: %w", err)
			}
			next.PtraceKeys = append(next.PtraceKeys, key)
		}
	}
	return nil
}

// Process Exec Rules

// walkDirAndInstallProcRule enumerates all executable regular files under
// dirPath inside each container and inserts one bpfe_proc_rules entry per
// binary. It also records a file-read Allow rule for each binary (and its ELF
// shared-library dependencies) so the ELF loader can open them when the binary
// is exec'd under a Block file posture.
func (be *BpfEnforcer) walkDirAndInstallProcRule(pod tp.Pod, podInode, srcInode uint64, dirPath string, rule tp.FileRule, next *bpfPodRules) {
	if be.GlobalData == nil {
		return
	}
	for cid := range pod.Containers {
		be.GlobalData.ContainersLock.RLock()
		c, exists := be.GlobalData.Containers[cid]
		be.GlobalData.ContainersLock.RUnlock()
		if !exists || c.RootPID == 0 {
			continue
		}
		root := fmt.Sprintf("/proc/%d/root", c.RootPID)
		fullDir := root + dirPath
		pathSeen := make(map[string]struct{})

		_ = filepath.Walk(fullDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if path == fullDir {
					return nil
				}
				if !rule.Recursive {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
				return nil // skip non-regular and non-executable files
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			binIno := st.Ino
			containerRelPath := strings.TrimPrefix(path, root)
			be.cacheInodePath(binIno, containerRelPath)

			// Proc Allow rule so the binary can be exec'd.
			procKey := bpf_enforcerBpfeProcKey{
				PodInode: podInode,
				SrcInode: srcInode,
				TgtInode: binIno,
			}
			procVal := bpf_enforcerBpfeRuleVal{
				Action:   encodeAction(rule.Action),
				PolicyId: rule.Policy.PolicyID,
			}
			if err2 := be.objs.BpfeProcRules.Update(&procKey, &procVal, ebpf.UpdateAny); err2 != nil {
				log.Debugf("walkDir proc: inode %d: %v", binIno, err2)
			} else {
				next.ProcKeys = append(next.ProcKeys, procKey)
			}

			// File READ Allow rules so the ELF loader can open the binary and
			// all its shared-library dependencies under a Block file posture.
			fileVal := bpf_enforcerBpfeRuleVal{Action: actionAllow}
			for _, depPath := range collectELFDependencies(path, root, 3, pathSeen) {
				depInfo, err2 := os.Stat(depPath)
				if err2 != nil {
					continue
				}
				depSt, ok2 := depInfo.Sys().(*syscall.Stat_t)
				if !ok2 {
					continue
				}
				fileKey := bpf_enforcerBpfeFileKey{
					PodInode:   podInode,
					SrcInode:   0,
					TgtInode:   depSt.Ino,
					Permission: permFileRead,
				}
				if err2 := be.objs.BpfeFileRules.Update(&fileKey, &fileVal, ebpf.UpdateNoExist); err2 != nil {
					if !errors.Is(err2, ebpf.ErrKeyExist) {
						log.Debugf("walkDir file-read: inode %d: %v", depSt.Ino, err2)
					}
				}
				next.FileKeys = append(next.FileKeys, fileKey)
			}
			return nil
		})
	}
}

// installProcRules populates bpfe_proc_rules from pod.FileRules (exec permissions).
// When the global action is Block and explicit Allow rules are present, the
// container's entrypoint binary is auto-allowed so the container can start.
func (be *BpfEnforcer) installProcRules(pod tp.Pod, podInode uint64, next *bpfPodRules) error {
	for src, inner := range pod.FileRules.OuterRules {
		srcInode := uint64(0)
		if src != "default" {
			ino, err := resolveInodeInPod(be.GlobalData, pod, src)
			if err != nil {
				log.Debugf("installProcRules: skip source %q: %v", src, err)
				continue
			}
			srcInode = ino
		}

		for tgtPath, rule := range inner.InnerRules {
			if rule.Permission != "x" && rule.Permission != "X" {
				continue
			}

			// Directory-scoped proc rules: enumerate each binary in the dir.
			if rule.IsDir {
				be.walkDirAndInstallProcRule(pod, podInode, srcInode, tgtPath, rule, next)
				continue
			}

			tgtInode, err := resolveInodeInPod(be.GlobalData, pod, tgtPath)
			if err != nil {
				log.Debugf("installProcRules: skip target %q: %v", tgtPath, err)
				continue
			}
			be.cacheInodePath(tgtInode, tgtPath)
			if src != "default" {
				be.cacheInodePath(srcInode, src)
			}
			key := bpf_enforcerBpfeProcKey{
				PodInode: podInode,
				SrcInode: srcInode,
				TgtInode: tgtInode,
			}
			val := bpf_enforcerBpfeRuleVal{
				Action:   encodeAction(rule.Action),
				PolicyId: rule.Policy.PolicyID,
			}
			if err := be.objs.BpfeProcRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update proc_rules: %w", err)
			}
			next.ProcKeys = append(next.ProcKeys, key)
		}
	}

	// Entrypoint auto-allow: for allow-list policies (GlobalAction == "Allow")
	// the posture blocks everything not explicitly listed, so insert an explicit
	// Allow for the container's root binary so the container can start.
	if pod.FileRules.GlobalAction == "Allow" {
		for _, epInode := range be.collectProcEntrypoints(pod) {
			key := bpf_enforcerBpfeProcKey{
				PodInode: podInode,
				SrcInode: 0,
				TgtInode: epInode,
			}
			val := bpf_enforcerBpfeRuleVal{Action: actionAllow}
			if err := be.objs.BpfeProcRules.Update(&key, &val, ebpf.UpdateNoExist); err != nil {
				if !errors.Is(err, ebpf.ErrKeyExist) {
					log.Debugf("installProcRules: entrypoint inode %d update failed: %v", epInode, err)
				}
				// Key already exists (explicit rule wins) — still track so
				// diffAndCleanup does not delete the existing entry.
			}
			next.ProcKeys = append(next.ProcKeys, key)
		}
	}
	return nil
}

// entrypointShells lists the shell paths that are implicitly allowed in
// allow-list mode so that kubectl exec (which always injects a shell) continues
// to work. Only paths that actually exist inside the container are included.
var entrypointShells = []string{
	"/bin/bash", "/usr/bin/bash",
	"/bin/sh", "/usr/bin/sh",
	"/bin/dash", "/usr/bin/dash",
}

// execInfraFiles are always auto-allowed for reading when the file domain
// runs as a Block allow-list. These files are opened by ld-linux and runc
// during any process exec and must not be blocked by file posture.
var execInfraFiles = []string{
	"/etc/ld.so.cache",
	"/etc/ld.so.preload",
	"/etc/ld.so.conf",
	"/etc/localtime",
	"/usr/lib/locale/locale-archive",
}

// execSetupNSSFiles are NSS / exec-setup files that the exec infrastructure
// (runc on the host, shell wrappers in the container) must read to resolve
// UIDs and hostnames during exec setup. They are allowed only for those
// specific source binaries, NOT for arbitrary user processes, so that
// explicit policy blocks (e.g. "cat /etc/passwd" expected blocked) still work.
var execSetupNSSFiles = []string{
	"/etc/passwd",
	"/etc/group",
	"/etc/nsswitch.conf",
	"/etc/hosts",
}

// standardLibDirs is the ordered search path used when resolving DT_NEEDED
// library names to absolute paths inside a container.
var standardLibDirs = []string{
	"/lib/x86_64-linux-gnu",
	"/usr/lib/x86_64-linux-gnu",
	"/lib64",
	"/usr/lib64",
	"/lib",
	"/usr/lib",
}

// elfDirectDependencies returns the full host paths (containerRoot-prefixed) of
// the ELF PT_INTERP program and all DT_NEEDED libraries for binaryPath. It does
// NOT recurse into those libraries; callers use collectELFDependencies for that.
func elfDirectDependencies(binaryPath, containerRoot string) []string {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var result []string

	// PT_INTERP — the dynamic linker/loader (ld-linux-x86-64.so.2, etc.)
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			data := make([]byte, prog.Filesz)
			if _, err := prog.ReadAt(data, 0); err == nil {
				interp := strings.TrimRight(string(data), "\x00")
				if interp != "" {
					result = append(result, containerRoot+interp)
				}
			}
			break
		}
	}

	// DT_NEEDED — shared libraries linked at build time
	libs, _ := f.ImportedLibraries()
	for _, lib := range libs {
		for _, dir := range standardLibDirs {
			candidate := containerRoot + dir + "/" + lib
			if _, err := os.Stat(candidate); err == nil {
				result = append(result, candidate)
				break
			}
		}
	}
	return result
}

// collectELFDependencies returns binaryPath plus all transitive ELF
// dependencies (PT_INTERP + DT_NEEDED) needed to load and execute it.
// maxDepth caps recursion; pathSeen prevents visiting the same path twice.
func collectELFDependencies(binaryPath, containerRoot string, maxDepth int, pathSeen map[string]struct{}) []string {
	if maxDepth <= 0 {
		return nil
	}
	if _, visited := pathSeen[binaryPath]; visited {
		return nil
	}
	pathSeen[binaryPath] = struct{}{}
	result := []string{binaryPath}
	for _, dep := range elfDirectDependencies(binaryPath, containerRoot) {
		result = append(result, collectELFDependencies(dep, containerRoot, maxDepth-1, pathSeen)...)
	}
	return result
}

// collectProcEntrypoints returns the inode numbers of binaries that must be
// implicitly allowed for an allow-list policy pod to remain operable:
//   - The container's PID-1 binary (so the container does not crash).
//   - Standard shells found in the container's filesystem (so kubectl exec
//     and any test harness that runs commands via a shell continues to work).
//
// All paths are resolved through /proc/<pid>/root to use the container's
// overlay-filesystem inodes, consistent with resolveInodeInPod.
func (be *BpfEnforcer) collectProcEntrypoints(pod tp.Pod) []uint64 {
	if be.GlobalData == nil {
		return nil
	}
	seen := make(map[uint64]struct{})
	var inodes []uint64

	addInode := func(path string) {
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return
		}
		if _, dup := seen[st.Ino]; dup {
			return
		}
		seen[st.Ino] = struct{}{}
		inodes = append(inodes, st.Ino)
	}

	for cid := range pod.Containers {
		be.GlobalData.ContainersLock.RLock()
		c, exists := be.GlobalData.Containers[cid]
		be.GlobalData.ContainersLock.RUnlock()
		if !exists || c.RootPID == 0 {
			continue
		}
		root := fmt.Sprintf("/proc/%d/root", c.RootPID)
		// pathSeen is per-container so different containers with the same
		// library layout each get their own inode recorded.
		pathSeen := make(map[string]struct{})

		addWithDeps := func(fullPath string) {
			for _, p := range collectELFDependencies(fullPath, root, 3, pathSeen) {
				addInode(p)
			}
		}

		// PID-1 binary — keep the container alive.
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", c.RootPID)); err == nil && exe != "" {
			addWithDeps(root + exe)
		}

		// Standard shells — keep kubectl exec and shell-based test harnesses
		// working even when none of them appear in the policy's process rules.
		// collectELFDependencies also adds the dynamic linker (ld-linux) and
		// all shared libraries each shell needs so the Block file posture does
		// not deny the ELF loader when bash/sh is exec'd.
		for _, sh := range entrypointShells {
			addWithDeps(root + sh)
		}
	}
	return inodes
}

// File R/W Rules

const (
	permFileRead  uint8 = 0
	permFileWrite uint8 = 1
)

// walkDirAndInstallFileRule walks a directory inside the container and
// installs one BPF file-rule entry per regular file found. This is the only
// way to express directory-scoped rules in an inode-keyed map: the BPF hook
// inode_from_file() only returns regular-file inodes, so a directory inode
// in the key would never match.
func (be *BpfEnforcer) walkDirAndInstallFileRule(pod tp.Pod, podInode, srcInode uint64, dirPath string, rule tp.FileRule, next *bpfPodRules) {
	if be.GlobalData == nil {
		return
	}
	perm := rule.Permission
	wantRead := perm == "r" || perm == "R" || perm == "rw" || perm == "RW"
	wantWrite := perm == "w" || perm == "W" || perm == "rw" || perm == "RW"

	for cid := range pod.Containers {
		be.GlobalData.ContainersLock.RLock()
		c, exists := be.GlobalData.Containers[cid]
		be.GlobalData.ContainersLock.RUnlock()
		if !exists || c.RootPID == 0 {
			continue
		}
		root := fmt.Sprintf("/proc/%d/root", c.RootPID)
		fullDir := root + dirPath
		upperDir := containerOverlayUpperDir(int(c.RootPID))

		_ = filepath.Walk(fullDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if path == fullDir {
					return nil
				}
				if !rule.Recursive {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			fileIno := st.Ino
			containerRelPath := strings.TrimPrefix(path, root)
			be.cacheInodePath(fileIno, containerRelPath)
			inodes := overlayBackingInodes(upperDir, containerRelPath, fileIno)
			val := bpf_enforcerBpfeRuleVal{
				Action:   encodeAction(rule.Action),
				PolicyId: rule.Policy.PolicyID,
			}
			for _, ino := range inodes {
				if wantRead {
					key := bpf_enforcerBpfeFileKey{
						PodInode:   podInode,
						SrcInode:   srcInode,
						TgtInode:   ino,
						Permission: permFileRead,
					}
					if err2 := be.objs.BpfeFileRules.Update(&key, &val, ebpf.UpdateAny); err2 != nil {
						log.Debugf("walkDir: update file_rules (read) inode %d: %v", ino, err2)
					} else {
						next.FileKeys = append(next.FileKeys, key)
					}
				}
				if wantWrite {
					key := bpf_enforcerBpfeFileKey{
						PodInode:   podInode,
						SrcInode:   srcInode,
						TgtInode:   ino,
						Permission: permFileWrite,
					}
					if err2 := be.objs.BpfeFileRules.Update(&key, &val, ebpf.UpdateAny); err2 != nil {
						log.Debugf("walkDir: update file_rules (write) inode %d: %v", ino, err2)
					} else {
						next.FileKeys = append(next.FileKeys, key)
					}
				}
			}
			return nil
		})
	}
}

// installFileRules populates bpfe_file_rules from pod.FileRules (read/write permissions).
// "x"/"X" entries are skipped — those are handled by installProcRules.
func (be *BpfEnforcer) installFileRules(pod tp.Pod, podInode uint64, next *bpfPodRules) error {
	for src, inner := range pod.FileRules.OuterRules {
		srcInode := uint64(0)
		if src != "default" {
			ino, err := resolveInodeInPod(be.GlobalData, pod, src)
			if err != nil {
				log.Debugf("installFileRules: skip source %q: %v", src, err)
				continue
			}
			srcInode = ino
		}

		for tgtPath, rule := range inner.InnerRules {
			perm := rule.Permission
			wantRead := perm == "r" || perm == "R" || perm == "rw" || perm == "RW"
			wantWrite := perm == "w" || perm == "W" || perm == "rw" || perm == "RW"
			if !wantRead && !wantWrite {
				continue
			}

			// Directory-scoped rules: walk all regular files under the dir
			// because inode_from_file() in BPF only returns regular-file inodes.
			if rule.IsDir {
				be.walkDirAndInstallFileRule(pod, podInode, srcInode, tgtPath, rule, next)
				continue
			}

			tgtInodes, err := resolveInodesInPod(be.GlobalData, pod, tgtPath)
			if err != nil {
				log.Debugf("installFileRules: skip target %q: %v", tgtPath, err)
				continue
			}
			for _, ino := range tgtInodes {
				be.cacheInodePath(ino, tgtPath)
			}

			val := bpf_enforcerBpfeRuleVal{
				Action:   encodeAction(rule.Action),
				PolicyId: rule.Policy.PolicyID,
			}

			for _, tgtInode := range tgtInodes {
				if wantRead {
					key := bpf_enforcerBpfeFileKey{
						PodInode:   podInode,
						SrcInode:   srcInode,
						TgtInode:   tgtInode,
						Permission: permFileRead,
					}
					if err := be.objs.BpfeFileRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
						return fmt.Errorf("update file_rules (read): %w", err)
					}
					next.FileKeys = append(next.FileKeys, key)
				}
				if wantWrite {
					key := bpf_enforcerBpfeFileKey{
						PodInode:   podInode,
						SrcInode:   srcInode,
						TgtInode:   tgtInode,
						Permission: permFileWrite,
					}
					if err := be.objs.BpfeFileRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
						return fmt.Errorf("update file_rules (write): %w", err)
					}
					next.FileKeys = append(next.FileKeys, key)
				}
			}
		}
	}

	// When the file domain runs as an allow-list (GlobalAction == "Allow"),
	// the Block posture would prevent the kernel ELF loader from reading
	// allowed executables before exec completes. Add an explicit Allow read
	// rule for each proc-domain entrypoint so the loader can open them.
	if hasFileRules(pod.FileRules) && pod.FileRules.GlobalAction == "Allow" {
		// Exec-infrastructure files (ld.so.cache, passwd, localtime, etc.) are
		// opened by ld-linux and runc during any process exec and must be readable.
		for cid := range pod.Containers {
			be.GlobalData.ContainersLock.RLock()
			c, exists := be.GlobalData.Containers[cid]
			be.GlobalData.ContainersLock.RUnlock()
			if !exists || c.RootPID == 0 {
				continue
			}
			root := fmt.Sprintf("/proc/%d/root", c.RootPID)
			for _, infraPath := range execInfraFiles {
				fullPath := root + infraPath
				info, err := os.Stat(fullPath)
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				st, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					continue
				}
				key := bpf_enforcerBpfeFileKey{
					PodInode:   podInode,
					SrcInode:   0,
					TgtInode:   st.Ino,
					Permission: permFileRead,
				}
				val := bpf_enforcerBpfeRuleVal{Action: actionAllow}
				if err := be.objs.BpfeFileRules.Update(&key, &val, ebpf.UpdateNoExist); err != nil {
					if !errors.Is(err, ebpf.ErrKeyExist) {
						log.Debugf("installFileRules: infra read inode %d: %v", st.Ino, err)
					}
				}
				next.FileKeys = append(next.FileKeys, key)
			}

			// Source-specific allows for exec-setup NSS files: allow runc (host)
			// and container shells to read /etc/passwd, /etc/nsswitch.conf, etc.
			// so that exec setup doesn't generate spurious block alerts, while
			// still blocking those files when accessed by arbitrary user processes.
			var execSrcInodes []uint64

			// Detect host runc binary inode (constant across containers)
			if runcInfo, err := os.Stat("/usr/bin/runc"); err == nil {
				if st, ok := runcInfo.Sys().(*syscall.Stat_t); ok {
					execSrcInodes = append(execSrcInodes, st.Ino)
				}
			}
			// Add container shell inodes
			for _, shellPath := range entrypointShells {
				if info, err := os.Stat(root + shellPath); err == nil {
					if st, ok := info.Sys().(*syscall.Stat_t); ok {
						execSrcInodes = append(execSrcInodes, st.Ino)
					}
				}
			}

			for _, nssPath := range execSetupNSSFiles {
				nssInfo, err := os.Stat(root + nssPath)
				if err != nil || !nssInfo.Mode().IsRegular() {
					continue
				}
				nssSt, ok := nssInfo.Sys().(*syscall.Stat_t)
				if !ok {
					continue
				}
				nssVal := bpf_enforcerBpfeRuleVal{Action: actionAllow}
				for _, srcIno := range execSrcInodes {
					key := bpf_enforcerBpfeFileKey{
						PodInode:   podInode,
						SrcInode:   srcIno,
						TgtInode:   nssSt.Ino,
						Permission: permFileRead,
					}
					if err := be.objs.BpfeFileRules.Update(&key, &nssVal, ebpf.UpdateNoExist); err != nil {
						if !errors.Is(err, ebpf.ErrKeyExist) {
							log.Debugf("installFileRules: exec-setup src=%d tgt=%d: %v", srcIno, nssSt.Ino, err)
						}
					}
					next.FileKeys = append(next.FileKeys, key)
				}
			}
		}

		for _, epInode := range be.collectProcEntrypoints(pod) {
			key := bpf_enforcerBpfeFileKey{
				PodInode:   podInode,
				SrcInode:   0,
				TgtInode:   epInode,
				Permission: permFileRead,
			}
			val := bpf_enforcerBpfeRuleVal{Action: actionAllow}
			if err := be.objs.BpfeFileRules.Update(&key, &val, ebpf.UpdateNoExist); err != nil {
				if !errors.Is(err, ebpf.ErrKeyExist) {
					log.Debugf("installFileRules: entrypoint read inode %d: %v", epInode, err)
				}
			}
			next.FileKeys = append(next.FileKeys, key)
		}

		// Also allow reading explicitly allowed executables (proc Allow rules).
		for src, inner := range pod.FileRules.OuterRules {
			srcInode := uint64(0)
			if src != "default" {
				ino, err := resolveInodeInPod(be.GlobalData, pod, src)
				if err != nil {
					continue
				}
				srcInode = ino
			}
			for tgtPath, rule := range inner.InnerRules {
				if rule.Permission != "X" {
					continue
				}
				tgtInode, err := resolveInodeInPod(be.GlobalData, pod, tgtPath)
				if err != nil {
					continue
				}
				key := bpf_enforcerBpfeFileKey{
					PodInode:   podInode,
					SrcInode:   srcInode,
					TgtInode:   tgtInode,
					Permission: permFileRead,
				}
				val := bpf_enforcerBpfeRuleVal{Action: actionAllow}
				if err := be.objs.BpfeFileRules.Update(&key, &val, ebpf.UpdateNoExist); err != nil {
					if !errors.Is(err, ebpf.ErrKeyExist) {
						log.Debugf("installFileRules: proc-allow read inode %d: %v", tgtInode, err)
					}
				}
				next.FileKeys = append(next.FileKeys, key)
			}
		}

		// fromSource binaries must themselves be readable for exec (the kernel
		// opens the binary via file_open before bprm_check fires). Add
		// file-read allows for every non-default source path plus all its ELF
		// dependencies so the ELF loader can map the binary and its libraries.
		for src := range pod.FileRules.OuterRules {
			if src == "default" {
				continue
			}
			for cid := range pod.Containers {
				be.GlobalData.ContainersLock.RLock()
				c, exists := be.GlobalData.Containers[cid]
				be.GlobalData.ContainersLock.RUnlock()
				if !exists || c.RootPID == 0 {
					continue
				}
				root := fmt.Sprintf("/proc/%d/root", c.RootPID)
				pathSeen := make(map[string]struct{})
				fileVal := bpf_enforcerBpfeRuleVal{Action: actionAllow}
				for _, depPath := range collectELFDependencies(root+src, root, 3, pathSeen) {
					depInfo, err := os.Stat(depPath)
					if err != nil {
						continue
					}
					depSt, ok := depInfo.Sys().(*syscall.Stat_t)
					if !ok {
						continue
					}
					key := bpf_enforcerBpfeFileKey{
						PodInode:   podInode,
						SrcInode:   0,
						TgtInode:   depSt.Ino,
						Permission: permFileRead,
					}
					if err := be.objs.BpfeFileRules.Update(&key, &fileVal, ebpf.UpdateNoExist); err != nil {
						if !errors.Is(err, ebpf.ErrKeyExist) {
							log.Debugf("installFileRules: fromSource dep inode %d: %v", depSt.Ino, err)
						}
					}
					next.FileKeys = append(next.FileKeys, key)
				}
			}
		}
	}
	return nil
}

// Unix IPC Rules

// fnv1aUnixPath computes the FNV-1a hash of the first 64 bytes of a
// null-terminated Unix socket path. Must match the BPF-side bpfe_unix_hash().
func fnv1aUnixPath(path string) uint32 {
	const hashLen = 64
	h := uint32(2166136261)
	for i := 0; i < hashLen && i < len(path); i++ {
		c := path[i]
		if c == 0 {
			break
		}
		h = (h ^ uint32(c)) * 16777619
	}
	return h
}

func encodeSockType(t string) uint8 {
	switch t {
	case "stream":
		return 1 // SOCK_STREAM
	case "dgram":
		return 2 // SOCK_DGRAM
	default:
		return 0 // any
	}
}

func encodeUnixPerm(p string) uint8 {
	switch p {
	case "connect":
		return 0
	case "send":
		return 1
	case "receive":
		return 2
	case "bind":
		return 3
	case "listen":
		return 4
	default:
		return 0
	}
}

// installUnixRules populates bpfe_unix_rules from pod.IPCRules.
// Each UnixRule (one permission per entry) maps directly to one BPF map entry.
func (be *BpfEnforcer) installUnixRules(pod tp.Pod, podInode uint64, next *bpfPodRules) error {
	for src, inner := range pod.IPCRules.OuterRules {
		if len(inner.Unix) == 0 {
			continue
		}
		srcInode := uint64(0)
		if src != "default" {
			ino, err := resolveInodeInPod(be.GlobalData, pod, src)
			if err != nil {
				log.Debugf("installUnixRules: skip source %q: %v", src, err)
				continue
			}
			srcInode = ino
		}

		for _, rule := range inner.Unix {
			key := bpf_enforcerBpfeUnixKey{
				PodInode:   podInode,
				SrcInode:   srcInode,
				PathHash:   fnv1aUnixPath(rule.Path),
				SockType:   encodeSockType(rule.Type),
				Permission: encodeUnixPerm(rule.Permission),
			}
			val := bpf_enforcerBpfeRuleVal{
				Action:   encodeAction(rule.Action),
				PolicyId: rule.Policy.PolicyID,
			}
			if err := be.objs.BpfeUnixRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("update unix_rules: %w", err)
			}
			next.UnixKeys = append(next.UnixKeys, key)
		}
	}
	return nil
}
