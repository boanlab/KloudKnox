// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// FQDN Resolver

const (
	fqdnDefaultTTL   = 30 * time.Second // minimum re-resolution interval
	fqdnGracePeriod  = 10 * time.Second // keep old IPs this long after TTL expires
	fqdnRefreshAhead = 5 * time.Second  // resolve this early before TTL expires
)

// fqdn_notify_event type constants (must match BPF FQDN_NOTIFY_* defines)
const (
	fqdnNotifyIPInstalled = uint8(0)
	fqdnNotifyDNSQuery    = uint8(1)
	fqdnNotifyDNSResponse = uint8(2)
)

// fqdnNotifyEvent mirrors the BPF struct fqdn_notify_event.
// Total size: 8+1+1+2+4+4+4+4+2+2+4+1+3+4+256 = 300 bytes.
type fqdnNotifyEvent struct {
	Ts           uint64
	EventType    uint8
	Direction    uint8
	Pad          [2]uint8
	PidNsID      uint32
	MntNsID      uint32
	QuerierIP    uint32 // network byte order
	DNSServerIP  uint32 // network byte order
	QuerierPort  uint16
	TXID         uint16
	ResolvedIP   uint32 // network byte order
	PolicyAction int8
	Pad2         [3]uint8
	PolicyID     uint32
	Reversed     [256]byte // null-terminated reversed FQDN
}

// fqdnEntry records an active FQDN rule and its installed IPs.
type fqdnEntry struct {
	Direction string // "egress" or "ingress"
	Inode     uint64
	Rule      tp.NetworkRule
	IPs       map[uint32]time.Time // IP (network-byte-order uint32) → expiry time
	Expiry    time.Time
}

// FqdnResolver manages the FQDN→IP mappings for network policy enforcement.
// BPF directly updates ne_fqdn_egress/ingress_map on DNS response interception.
// Go side handles: initial net.LookupHost fallback, TTL refresh, and DNS event logging.
type FqdnResolver struct {
	objs       *net_enforcerObjects
	GlobalData *tp.GlobalData
	Exporter   tp.EventExporter

	mu       sync.RWMutex
	ipToFqdn map[uint32]string     // network-byte-order IP → FQDN (for event enrichment)
	entries  map[string]*fqdnEntry // reversed FQDN → fqdnEntry (TTL tracking)

	notifyRb *ringbuf.Reader // ne_fqdn_notify_rb reader
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewFqdnResolver creates a FqdnResolver and starts its background goroutines.
func NewFqdnResolver(objs *net_enforcerObjects, globalData *tp.GlobalData, exporter tp.EventExporter) (*FqdnResolver, error) {
	if objs.NeFqdnNotifyRb == nil {
		return nil, fmt.Errorf("ne_fqdn_notify_rb map not available — BPF rebuild required")
	}
	notifyRb, err := ringbuf.NewReader(objs.NeFqdnNotifyRb)
	if err != nil {
		return nil, fmt.Errorf("failed to open FQDN notify ring buffer: %w", err)
	}
	r := &FqdnResolver{
		objs:       objs,
		GlobalData: globalData,
		Exporter:   exporter,
		ipToFqdn:   make(map[uint32]string),
		entries:    make(map[string]*fqdnEntry),
		notifyRb:   notifyRb,
		stopCh:     make(chan struct{}),
	}
	r.wg.Add(2)
	go r.fqdnNotifyLoop()
	go r.ttlRefreshLoop()
	return r, nil
}

// Stop shuts down the FqdnResolver and waits for all goroutines to exit.
func (r *FqdnResolver) Stop() {
	close(r.stopCh)
	if err := r.notifyRb.Close(); err != nil {
		log.Warnf("FQDN resolver: error closing notify ring buffer: %v", err)
	}
	r.wg.Wait()
}

// LookupFqdn returns the FQDN for a network-byte-order IP (for event enrichment).
func (r *FqdnResolver) LookupFqdn(netIP uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ipToFqdn[netIP]
}

// RegisterFqdnRule installs an FQDN policy rule into ne_fqdn_rules_map (BPF)
// and performs the initial DNS lookup fallback asynchronously.
// mu must be the lock that guards rules (e.g. NetworkEnforcer.NetRulesLock).
func (r *FqdnResolver) RegisterFqdnRule(fqdn, direction string, inode uint64, rule tp.NetworkRule, rules *netPodRules, mu *sync.Mutex) {
	reversed := reverseDNSLabels(fqdn)

	// Write rule into ne_fqdn_rules_map so BPF can look it up on DNS response
	ruleKey := net_enforcerFqdnRuleKey{}
	for i, c := range []byte(reversed) {
		if i >= len(ruleKey.Reversed) {
			break
		}
		ruleKey.Reversed[i] = int8(c) // #nosec G115
	}

	action := int8(0)
	switch rule.Action {
	case "Audit":
		action = 1
	case "Block":
		action = -1
	}
	dir := uint8(0)
	if direction == "ingress" {
		dir = 1
	}
	ruleVal := net_enforcerFqdnRuleVal{
		Inode:     inode,
		Action:    action,
		Direction: dir,
		PolicyId:  rule.Policy.PolicyID,
	}
	if r.objs.NeFqdnRulesMap != nil {
		if err := r.objs.NeFqdnRulesMap.Update(&ruleKey, &ruleVal, ebpf.UpdateAny); err != nil {
			log.Warnf("FQDN resolver: rules map update failed for %q: %v", fqdn, err)
		}
	}

	entry := &fqdnEntry{
		Direction: direction,
		Inode:     inode,
		Rule:      rule,
		IPs:       make(map[uint32]time.Time),
		Expiry:    time.Now().Add(fqdnDefaultTTL),
	}

	r.mu.Lock()
	r.entries[reversed] = entry
	r.mu.Unlock()

	// Track reversed key for cleanup
	if direction == "egress" {
		rules.EgressFqdnRuleKeys = append(rules.EgressFqdnRuleKeys, reversed)
	} else {
		rules.IngressFqdnRuleKeys = append(rules.IngressFqdnRuleKeys, reversed)
	}

	// Asynchronous initial resolution as fallback (before any DNS is observed by BPF)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		keys := r.resolveAndInstall(fqdn, reversed, entry)
		r.mu.Lock()
		entry.Expiry = time.Now().Add(fqdnDefaultTTL)
		r.mu.Unlock()
		mu.Lock()
		if direction == "egress" {
			rules.EgressFqdnKeys = append(rules.EgressFqdnKeys, keys...)
		} else {
			rules.IngressFqdnKeys = append(rules.IngressFqdnKeys, keys...)
		}
		mu.Unlock()
	}()
}

// resolveAndInstall performs a DNS lookup and installs all resolved IPs into
// the BPF FQDN map, evicting stale IPs. Returns installed IP keys.
// reversed is the reversed-label form of fqdn (used for ipToFqdn lookups via BPF path).
func (r *FqdnResolver) resolveAndInstall(fqdn, _ string, entry *fqdnEntry) []net_enforcerFqdnIpKey {
	addrs, err := net.LookupHost(fqdn)
	if err != nil {
		log.Warnf("FQDN resolver: lookup %q failed: %v", fqdn, err)
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	expiry := time.Now().Add(fqdnDefaultTTL)
	newIPs := make(map[uint32]struct{}, len(addrs))
	var installed []net_enforcerFqdnIpKey

	for _, addr := range addrs {
		ip4 := net.ParseIP(addr).To4()
		if ip4 == nil {
			continue
		}
		netIP := binary.BigEndian.Uint32(ip4)
		newIPs[netIP] = struct{}{}
		key := r.installFqdnIP(entry, netIP, expiry)
		r.ipToFqdn[netIP] = fqdn
		installed = append(installed, key)
	}

	// Evict IPs no longer in DNS response (after grace period)
	for oldIP, oldExpiry := range entry.IPs {
		if _, ok := newIPs[oldIP]; !ok && time.Now().After(oldExpiry.Add(fqdnGracePeriod)) {
			r.evictFqdnIP(entry, oldIP)
			delete(r.ipToFqdn, oldIP)
		}
	}

	return installed
}

// installFqdnIP writes one (inode, IP)→policy_val entry into the BPF FQDN map.
func (r *FqdnResolver) installFqdnIP(entry *fqdnEntry, netIP uint32, expiry time.Time) net_enforcerFqdnIpKey {
	key := net_enforcerFqdnIpKey{
		Inode: entry.Inode,
		Addr:  netIP,
		Pad:   0,
	}

	action := int8(0)
	switch entry.Rule.Action {
	case "Audit":
		action = 1
	case "Block":
		action = -1
	}

	val := net_enforcerPolicyVal{
		Inode:    entry.Inode,
		Action:   action,
		PolicyId: entry.Rule.Policy.PolicyID,
	}

	var fqdnMap *ebpf.Map
	if entry.Direction == "egress" {
		fqdnMap = r.objs.NeFqdnEgressMap
	} else {
		fqdnMap = r.objs.NeFqdnIngressMap
	}
	if fqdnMap == nil {
		return key
	}
	if err := fqdnMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		log.Warnf("FQDN resolver: BPF map update failed for ip %d: %v", netIP, err)
		return key
	}
	entry.IPs[netIP] = expiry
	return key
}

// UnregisterFqdn removes the resolver entry for a reversed-label FQDN and
// evicts every IP that BPF (or the initial Go lookup) installed for it.
// Must be called whenever a policy referencing this FQDN is deleted,
// otherwise BPF-installed IP→policy entries in ne_fqdn_{egress,ingress}_map
// outlive the policy and attribute blocks to a stale policyID — which then
// fails PolicyName resolution in the Go matcher and drops the alert.
func (r *FqdnResolver) UnregisterFqdn(reversed string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[reversed]
	if !ok {
		return
	}
	for ip := range entry.IPs {
		r.evictFqdnIP(entry, ip)
		delete(r.ipToFqdn, ip)
	}
	delete(r.entries, reversed)
}

// evictFqdnIP removes one IP from the BPF FQDN map and flushes related session cache.
func (r *FqdnResolver) evictFqdnIP(entry *fqdnEntry, netIP uint32) {
	key := net_enforcerFqdnIpKey{
		Inode: entry.Inode,
		Addr:  netIP,
		Pad:   0,
	}
	var fqdnMap *ebpf.Map
	if entry.Direction == "egress" {
		fqdnMap = r.objs.NeFqdnEgressMap
	} else {
		fqdnMap = r.objs.NeFqdnIngressMap
	}
	if fqdnMap != nil {
		if err := fqdnMap.Delete(&key); err != nil {
			log.Debugf("FQDN resolver: BPF map delete failed for ip %d: %v", netIP, err)
		}
	}
	delete(entry.IPs, netIP)
	r.flushSessionCacheForIP(entry.Direction, netIP)
}

// flushSessionCacheForIP iterates ne_sk_cache and removes entries matching the evicted IP.
func (r *FqdnResolver) flushSessionCacheForIP(direction string, netIP uint32) {
	if r.objs.NeSkCache == nil {
		return
	}
	iter := r.objs.NeSkCache.Iterate()
	var key net_enforcerSessionKey
	var val net_enforcerRetVal
	var toDelete []net_enforcerSessionKey
	for iter.Next(&key, &val) {
		if direction == "egress" && key.Daddr == netIP {
			toDelete = append(toDelete, key)
		} else if direction == "ingress" && key.Saddr == netIP {
			toDelete = append(toDelete, key)
		}
	}
	for _, k := range toDelete {
		_ = r.objs.NeSkCache.Delete(&k)
	}
}

// Notify Loop

// fqdnNotifyLoop reads fqdn_notify_event records from ne_fqdn_notify_rb
// and dispatches them by event type.
func (r *FqdnResolver) fqdnNotifyLoop() {
	defer r.wg.Done()
	for {
		rec, err := r.notifyRb.Read()
		if err != nil {
			return // ring buffer closed on shutdown
		}
		r.handleFqdnNotify(rec.RawSample)
	}
}

func (r *FqdnResolver) handleFqdnNotify(raw []byte) {
	var ev fqdnNotifyEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return
	}
	switch ev.EventType {
	case fqdnNotifyIPInstalled:
		r.handleIPInstalled(&ev)
	case fqdnNotifyDNSQuery:
		r.handleDNSQueryEvent(&ev)
	case fqdnNotifyDNSResponse:
		r.handleDNSResponseEvent(&ev)
	}
}

// handleIPInstalled updates ipToFqdn and entry IP TTL when BPF installs a new IP.
func (r *FqdnResolver) handleIPInstalled(ev *fqdnNotifyEvent) {
	fqdn := reverseReversedLabels(nullTermStr(ev.Reversed[:]))
	reversed := nullTermStr(ev.Reversed[:])

	r.mu.Lock()
	r.ipToFqdn[ev.ResolvedIP] = fqdn
	if entry, ok := r.entries[reversed]; ok {
		entry.IPs[ev.ResolvedIP] = time.Now().Add(fqdnDefaultTTL)
	}
	r.mu.Unlock()
}

// handleDNSQueryEvent builds a category="dns" EventData for a DNS query.
func (r *FqdnResolver) handleDNSQueryEvent(ev *fqdnNotifyEvent) {
	if r.Exporter == nil || r.GlobalData == nil {
		return
	}
	fqdn := reverseReversedLabels(nullTermStr(ev.Reversed[:]))
	querierIPStr := netIPToStr(ev.QuerierIP)
	dnsServerStr := netIPToStr(ev.DNSServerIP)

	evData := tp.EventData{
		Timestamp: r.monoNSToWallTime(ev.Ts),
		NodeName:  cfg.GlobalCfg.Node,
		Category:  "dns",
		Operation: "query",
		Resource:  fmt.Sprintf("dns/%s:%d->%s:53", querierIPStr, ev.QuerierPort, dnsServerStr),
		Data:      fmt.Sprintf("domain: %s, server: %s", fqdn, dnsServerStr),
	}

	// Pod attribution via NsMap (reliable in egress context)
	nsKey := (uint64(ev.PidNsID) << 32) | uint64(ev.MntNsID)
	r.GlobalData.NsMapLock.RLock()
	if container, ok := r.GlobalData.NsMap[nsKey]; ok {
		evData.NamespaceName = container.NamespaceName
		evData.PodName = container.PodName
		evData.ContainerName = container.ContainerName
	}
	r.GlobalData.NsMapLock.RUnlock()

	if err := r.Exporter.ExportEvent(evData); err != nil {
		log.Debugf("FQDN resolver: DNS query event export error: %v", err)
	}
}

// handleDNSResponseEvent builds a category="dns" EventData for a DNS A record response.
func (r *FqdnResolver) handleDNSResponseEvent(ev *fqdnNotifyEvent) {
	if r.Exporter == nil || r.GlobalData == nil {
		return
	}
	fqdn := reverseReversedLabels(nullTermStr(ev.Reversed[:]))
	querierIPStr := netIPToStr(ev.QuerierIP)
	dnsServerStr := netIPToStr(ev.DNSServerIP)
	resolvedStr := netIPToStr(ev.ResolvedIP)

	dataStr := fmt.Sprintf("domain: %s, resolved: %s", fqdn, resolvedStr)
	if ev.PolicyID != 0 {
		dataStr += fmt.Sprintf(", policy: %s (id=%d)", actionToString(ev.PolicyAction), ev.PolicyID)
	}

	evData := tp.EventData{
		Timestamp: r.monoNSToWallTime(ev.Ts),
		NodeName:  cfg.GlobalCfg.Node,
		Category:  "dns",
		Operation: "response",
		Resource:  fmt.Sprintf("dns/%s:53->%s:%d", dnsServerStr, querierIPStr, ev.QuerierPort),
		Data:      dataStr,
	}

	// Pod attribution via IPMap (ingress context: task context unreliable)
	r.GlobalData.IPMapLock.RLock()
	if ipEntry, ok := r.GlobalData.IPMap[querierIPStr]; ok && ipEntry.Type == "pod" {
		evData.NamespaceName = ipEntry.Pod.NamespaceName
		evData.PodName = ipEntry.Pod.PodName
	}
	r.GlobalData.IPMapLock.RUnlock()

	if err := r.Exporter.ExportEvent(evData); err != nil {
		log.Debugf("FQDN resolver: DNS response event export error: %v", err)
	}
}

// monoNSToWallTime converts a BPF monotonic nanosecond timestamp to wall-clock Unix nanoseconds.
func (r *FqdnResolver) monoNSToWallTime(ktimeNS uint64) uint64 {
	base := r.GlobalData.MonoBaseNS.Load()
	ts := int64(ktimeNS) + base // #nosec G115
	if ts < 0 {
		return 0
	}
	return uint64(ts)
}

// TTL Refresh

// ttlRefreshLoop periodically re-resolves FQDNs whose TTL is about to expire.
func (r *FqdnResolver) ttlRefreshLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.refreshExpiring()
		}
	}
}

func (r *FqdnResolver) refreshExpiring() {
	now := time.Now()
	r.mu.RLock()
	type toRefreshItem struct {
		reversed string
		entry    *fqdnEntry
	}
	var toRefresh []toRefreshItem
	for reversed, entry := range r.entries {
		if now.After(entry.Expiry.Add(-fqdnRefreshAhead)) {
			toRefresh = append(toRefresh, toRefreshItem{reversed, entry})
		}
	}
	r.mu.RUnlock()

	for _, item := range toRefresh {
		fqdn := reverseReversedLabels(item.reversed)
		r.resolveAndInstall(fqdn, item.reversed, item.entry)
		r.mu.Lock()
		item.entry.Expiry = now.Add(fqdnDefaultTTL)
		r.mu.Unlock()
	}
}

// Helper Functions

// reverseDNSLabels reverses DNS labels: "sub.api.test.com" → "com.test.api.sub"
// Strips wildcard prefix: "*.api.test.com" → "com.test.api"
func reverseDNSLabels(fqdn string) string {
	name := strings.TrimPrefix(fqdn, "*.")
	labels := strings.Split(name, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// reverseReversedLabels reverses reversed labels back: "com.test.api" → "api.test.com"
func reverseReversedLabels(reversed string) string {
	labels := strings.Split(reversed, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// nullTermStr reads a null-terminated C string from a byte slice.
func nullTermStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b)
	}
	return string(b[:n])
}

// netIPToStr converts a network-byte-order uint32 IP to dotted-decimal string.
func netIPToStr(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF)
}

// actionToString maps int8 action to human-readable string.
func actionToString(action int8) string {
	switch action {
	case 1:
		return "Audit"
	case -1:
		return "Block"
	default:
		return "Allow"
	}
}
