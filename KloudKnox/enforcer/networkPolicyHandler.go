// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"encoding/binary"
	"net"
	"strings"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	"github.com/cilium/ebpf"
)

// Policy Management

// UpdateNetworkPolicies updates network policies for a pod based on CNI type
func (e *RuntimeEnforcer) UpdateNetworkPolicies(pod tp.Pod) error {
	if e == nil || e.NetworkEnforcer == nil {
		return nil
	}

	e.NetworkEnforcer.NetRulesLock.Lock()
	defer e.NetworkEnforcer.NetRulesLock.Unlock()

	oldRules := e.NetworkEnforcer.NetRules[pod.CgroupPath]
	newRules := &netPodRules{}

	// Add/Update new egress rules
	for source, innerRules := range pod.NetworkRules.EgressRules {
		inode := uint64(0) // default (no fromSource)

		if source != "default" {
			if ino, err := e.NetworkEnforcer.getInodeByPath(pod, source); err != nil {
				continue
			} else {
				inode = ino
			}
		}

		for target, rule := range innerRules.InnerRules {
			e.NetworkEnforcer.enforceNetworkRule(newRules, "egress", pod, inode, target, rule)
		}

		dpKey := e.NetworkEnforcer.setDefaultPosture("egress", pod, inode, innerRules.DefaultPosture)
		newRules.EgressPostureKeys = append(newRules.EgressPostureKeys, dpKey)
	}

	if len(pod.NetworkRules.EgressRules) == 0 {
		dpKey := e.NetworkEnforcer.setDefaultPosture("egress", pod, 0, "Allow")
		newRules.EgressPostureKeys = append(newRules.EgressPostureKeys, dpKey)
	}

	// Add/Update new ingress rules
	for source, innerRules := range pod.NetworkRules.IngressRules {
		inode := uint64(0) // default (no fromSource)

		if source != "default" {
			if ino, err := e.NetworkEnforcer.getInodeByPath(pod, source); err != nil {
				continue
			} else {
				inode = ino
			}
		}

		for target, rule := range innerRules.InnerRules {
			e.NetworkEnforcer.enforceNetworkRule(newRules, "ingress", pod, inode, target, rule)
		}

		dpKey := e.NetworkEnforcer.setDefaultPosture("ingress", pod, inode, innerRules.DefaultPosture)
		newRules.IngressPostureKeys = append(newRules.IngressPostureKeys, dpKey)
	}

	if len(pod.NetworkRules.IngressRules) == 0 {
		dpKey := e.NetworkEnforcer.setDefaultPosture("ingress", pod, 0, "Allow")
		newRules.IngressPostureKeys = append(newRules.IngressPostureKeys, dpKey)
	}

	// Cleanup obsolete rules from old policy (Delete phase)
	if oldRules != nil {
		// Cleanup Egress LPM
		for _, oldKey := range oldRules.EgressLpmKeys {
			if !containsLpmKey(newRules.EgressLpmKeys, oldKey) {
				if err := e.NetworkEnforcer.NetworkEventsObjs.NeEgressLpmMap.Delete(oldKey); err != nil {
					log.Debugf("Failed to delete stale egress LPM policy key: %v", err)
				}
			}
		}
		// Cleanup Egress Hash
		for _, oldKey := range oldRules.EgressHashKeys {
			if !containsHashKey(newRules.EgressHashKeys, oldKey) {
				if err := e.NetworkEnforcer.NetworkEventsObjs.NeEgressPolicyMap.Delete(oldKey); err != nil {
					log.Debugf("Failed to delete stale egress hash policy key: %v", err)
				}
			}
		}
		// Cleanup Ingress LPM
		for _, oldKey := range oldRules.IngressLpmKeys {
			if !containsLpmKey(newRules.IngressLpmKeys, oldKey) {
				if err := e.NetworkEnforcer.NetworkEventsObjs.NeIngressLpmMap.Delete(oldKey); err != nil {
					log.Debugf("Failed to delete stale ingress LPM policy key: %v", err)
				}
			}
		}
		// Cleanup Ingress Hash
		for _, oldKey := range oldRules.IngressHashKeys {
			if !containsHashKey(newRules.IngressHashKeys, oldKey) {
				if err := e.NetworkEnforcer.NetworkEventsObjs.NeIngressPolicyMap.Delete(oldKey); err != nil {
					log.Debugf("Failed to delete stale ingress hash policy key: %v", err)
				}
			}
		}
		// Cleanup Egress Posture
		for _, oldKey := range oldRules.EgressPostureKeys {
			if !containsPostureKey(newRules.EgressPostureKeys, oldKey) {
				if err := e.NetworkEnforcer.NetworkEventsObjs.NeEgressDefaultPostureMap.Delete(oldKey); err != nil {
					log.Debugf("Failed to delete stale egress posture policy key: %v", err)
				}
			}
		}
		// Cleanup Ingress Posture
		for _, oldKey := range oldRules.IngressPostureKeys {
			if !containsPostureKey(newRules.IngressPostureKeys, oldKey) {
				if err := e.NetworkEnforcer.NetworkEventsObjs.NeIngressDefaultPostureMap.Delete(oldKey); err != nil {
					log.Debugf("Failed to delete stale ingress posture policy key: %v", err)
				}
			}
		}
		// Cleanup Egress FQDN IP map entries.
		// Skip keys still present in newRules — RegisterFqdnRule may have just
		// re-installed the same (inode, IP) pair, and unconditional deletion
		// would wipe out the entry we just wrote.
		if e.NetworkEnforcer.NetworkEventsObjs.NeFqdnEgressMap != nil {
			for _, key := range oldRules.EgressFqdnKeys {
				if !containsFqdnIpKey(newRules.EgressFqdnKeys, key) {
					_ = e.NetworkEnforcer.NetworkEventsObjs.NeFqdnEgressMap.Delete(key)
				}
			}
		}
		// Cleanup Ingress FQDN IP map entries
		if e.NetworkEnforcer.NetworkEventsObjs.NeFqdnIngressMap != nil {
			for _, key := range oldRules.IngressFqdnKeys {
				if !containsFqdnIpKey(newRules.IngressFqdnKeys, key) {
					_ = e.NetworkEnforcer.NetworkEventsObjs.NeFqdnIngressMap.Delete(key)
				}
			}
		}
		// Cleanup FQDN rules map (reversed FQDN keys). Same guard: do not
		// delete a reversed-FQDN key that the new rule set still references,
		// otherwise BPF DNS interception will drop responses for that FQDN.
		// UnregisterFqdn additionally evicts every IP the BPF DNS interceptor
		// installed into ne_fqdn_{egress,ingress}_map for that FQDN — those
		// are not tracked in EgressFqdnKeys and would otherwise leak, causing
		// blocks under a stale policyID that the Go matcher can't resolve.
		if e.NetworkEnforcer.NetworkEventsObjs.NeFqdnRulesMap != nil {
			for _, rev := range oldRules.EgressFqdnRuleKeys {
				if containsString(newRules.EgressFqdnRuleKeys, rev) {
					continue
				}
				rk := net_enforcerFqdnRuleKey{}
				for i, c := range []byte(rev) {
					if i >= len(rk.Reversed) {
						break
					}
					rk.Reversed[i] = int8(c) // #nosec G115
				}
				_ = e.NetworkEnforcer.NetworkEventsObjs.NeFqdnRulesMap.Delete(&rk)
				if e.NetworkEnforcer.FqdnResolver != nil {
					e.NetworkEnforcer.FqdnResolver.UnregisterFqdn(rev)
				}
			}
			for _, rev := range oldRules.IngressFqdnRuleKeys {
				if containsString(newRules.IngressFqdnRuleKeys, rev) {
					continue
				}
				rk := net_enforcerFqdnRuleKey{}
				for i, c := range []byte(rev) {
					if i >= len(rk.Reversed) {
						break
					}
					rk.Reversed[i] = int8(c) // #nosec G115
				}
				_ = e.NetworkEnforcer.NetworkEventsObjs.NeFqdnRulesMap.Delete(&rk)
				if e.NetworkEnforcer.FqdnResolver != nil {
					e.NetworkEnforcer.FqdnResolver.UnregisterFqdn(rev)
				}
			}
		}
	}

	e.NetworkEnforcer.NetRules[pod.CgroupPath] = newRules

	return nil
}

// cleanupNetworkPoliciesByCgroup removes all policy-related BPF map entries for a given cgroup path
func (ne *NetworkEnforcer) cleanupNetworkPoliciesByCgroup(cgroupPath string) {
	ne.NetRulesLock.Lock()
	rules, ok := ne.NetRules[cgroupPath]
	if !ok {
		ne.NetRulesLock.Unlock()
		return
	}

	// Remove all keys from BPF maps
	for _, key := range rules.EgressLpmKeys {
		_ = ne.NetworkEventsObjs.NeEgressLpmMap.Delete(key)
	}
	for _, key := range rules.EgressHashKeys {
		_ = ne.NetworkEventsObjs.NeEgressPolicyMap.Delete(key)
	}
	for _, key := range rules.IngressLpmKeys {
		_ = ne.NetworkEventsObjs.NeIngressLpmMap.Delete(key)
	}
	for _, key := range rules.IngressHashKeys {
		_ = ne.NetworkEventsObjs.NeIngressPolicyMap.Delete(key)
	}
	for _, key := range rules.EgressPostureKeys {
		_ = ne.NetworkEventsObjs.NeEgressDefaultPostureMap.Delete(key)
	}
	for _, key := range rules.IngressPostureKeys {
		_ = ne.NetworkEventsObjs.NeIngressDefaultPostureMap.Delete(key)
	}
	// Remove FQDN IP map entries
	if ne.NetworkEventsObjs.NeFqdnEgressMap != nil {
		for _, key := range rules.EgressFqdnKeys {
			_ = ne.NetworkEventsObjs.NeFqdnEgressMap.Delete(key)
		}
	}
	if ne.NetworkEventsObjs.NeFqdnIngressMap != nil {
		for _, key := range rules.IngressFqdnKeys {
			_ = ne.NetworkEventsObjs.NeFqdnIngressMap.Delete(key)
		}
	}
	// Remove FQDN rules map entries and evict BPF-installed IPs (see
	// enforceNetworkPolicies for why UnregisterFqdn is required).
	if ne.NetworkEventsObjs.NeFqdnRulesMap != nil {
		for _, rev := range rules.EgressFqdnRuleKeys {
			rk := net_enforcerFqdnRuleKey{}
			for i, c := range []byte(rev) {
				if i >= len(rk.Reversed) {
					break
				}
				rk.Reversed[i] = int8(c) // #nosec G115
			}
			_ = ne.NetworkEventsObjs.NeFqdnRulesMap.Delete(&rk)
			if ne.FqdnResolver != nil {
				ne.FqdnResolver.UnregisterFqdn(rev)
			}
		}
		for _, rev := range rules.IngressFqdnRuleKeys {
			rk := net_enforcerFqdnRuleKey{}
			for i, c := range []byte(rev) {
				if i >= len(rk.Reversed) {
					break
				}
				rk.Reversed[i] = int8(c) // #nosec G115
			}
			_ = ne.NetworkEventsObjs.NeFqdnRulesMap.Delete(&rk)
			if ne.FqdnResolver != nil {
				ne.FqdnResolver.UnregisterFqdn(rev)
			}
		}
	}

	delete(ne.NetRules, cgroupPath)
	ne.NetRulesLock.Unlock()

	log.Printf("Cleaned up network policies for cgroup %s", cgroupPath)
}

func containsLpmKey(slice []net_enforcerLpmKey, item net_enforcerLpmKey) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func containsHashKey(slice []net_enforcerPolicyKey, item net_enforcerPolicyKey) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func containsPostureKey(slice []net_enforcerDefaultPostureKey, item net_enforcerDefaultPostureKey) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func containsFqdnIpKey(slice []net_enforcerFqdnIpKey, item net_enforcerFqdnIpKey) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func containsString(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// enforceNetworkRule enforces a single rule and installs it into the appropriate BPF maps
func (ne *NetworkEnforcer) enforceNetworkRule(rules *netPodRules, direction string, pod tp.Pod, inode uint64, target string, rule tp.NetworkRule) {
	if strings.HasPrefix(target, "selector:") {
		selectorStr := strings.TrimPrefix(target, "selector:")

		// Find target pods
		ne.GlobalData.PodsLock.RLock()
		for _, targetPod := range ne.GlobalData.Pods {
			if targetPod.NamespaceName != pod.NamespaceName {
				continue
			}

			if lib.IsSubset(selectorStr, targetPod.Identities) {
				if targetPod.PodIP != "" {
					ne.installIPRule(rules, direction, inode, pod.PodIP, targetPod.PodIP+"/32", rule)
				}
			}
		}
		ne.GlobalData.PodsLock.RUnlock()

		// Find target services
		ne.GlobalData.ServicesLock.RLock()
		defer ne.GlobalData.ServicesLock.RUnlock()
		for _, targetSvc := range ne.GlobalData.Services {
			if targetSvc.NamespaceName != pod.NamespaceName {
				continue
			}

			if lib.IsSubset(selectorStr, targetSvc.Identities) {
				for _, clusterIP := range targetSvc.ClusterIPs {
					if clusterIP != "" && clusterIP != "None" {
						ne.installIPRule(rules, direction, inode, pod.PodIP, clusterIP+"/32", rule)
					}
				}
			}
		}
	} else if strings.HasPrefix(target, "cidr:") {
		cidrStr := strings.TrimPrefix(target, "cidr:")
		if !strings.Contains(cidrStr, "/") {
			cidrStr += "/32"
		}

		ne.installIPRule(rules, direction, inode, pod.PodIP, cidrStr, rule)

		// Install except-CIDR rules with the inverse action via LPM.
		// BPF LPM trie uses longest-prefix-match, so a more-specific except-CIDR
		// automatically takes precedence over the main CIDR.
		if len(rule.CIDRExcept) > 0 {
			exceptRule := rule
			switch rule.Action {
			case "Allow":
				exceptRule.Action = "Block"
			case "Block", "Audit":
				exceptRule.Action = "Allow"
			}
			for _, exceptCIDR := range rule.CIDRExcept {
				if !strings.Contains(exceptCIDR, "/") {
					exceptCIDR += "/32"
				}
				ne.installIPRule(rules, direction, inode, pod.PodIP, exceptCIDR, exceptRule)
			}
		}
	} else if strings.HasPrefix(target, "fqdn:") {
		fqdnStr := strings.TrimPrefix(target, "fqdn:")
		if ne.FqdnResolver != nil {
			ne.FqdnResolver.RegisterFqdnRule(fqdnStr, direction, inode, rule, rules, &ne.NetRulesLock)
		}
	}
}

// podIPToBPFKey encodes an IPv4 string as the host-endian u32 whose in-memory
// bytes are in network order. net_enforcer.bpf.c assigns `key.saddr = ip->saddr`
// without ntohl, so policy map keys must match that raw packet layout. On
// little-endian hosts this differs from lib.IPv4ToUint32, which packs the
// first octet in the MSB and is meant for event-path values that have already
// been bpf_ntohl'd.
func podIPToBPFKey(podIP string) uint32 {
	ip4 := net.ParseIP(podIP).To4()
	if ip4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip4)
}

// installIPRule parses CIDR and installs it into BPF maps
func (ne *NetworkEnforcer) installIPRule(rules *netPodRules, direction string, inode uint64, podIP, cidrStr string, rule tp.NetworkRule) {
	sourceIP := podIPToBPFKey(podIP)

	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		log.Warnf("Invalid CIDR '%s': %v", cidrStr, err)
		return
	}

	// IPs are stored in BPF maps in host byte order (little-endian on x86).
	targetIP := binary.LittleEndian.Uint32(ip.To4())
	prefixInt, _ := ipNet.Mask.Size()
	prefix := uint32(0)

	if prefixInt >= 0 && prefixInt <= 32 {
		prefix = uint32(prefixInt)
	}

	type ruleEntry struct {
		proto uint8
		port  uint16
	}

	entries := []ruleEntry{}

	if len(rule.Ports) == 0 {
		entries = append(entries, ruleEntry{proto: 0, port: 0})
	} else {
		for protoStr, portList := range rule.Ports {
			var proto uint8
			switch strings.ToUpper(protoStr) {
			case "TCP":
				proto = IPProtoTCP
			case "UDP":
				proto = IPProtoUDP
			default:
				continue
			}
			if len(portList) == 0 {
				entries = append(entries, ruleEntry{proto: proto, port: 0})
			} else {
				for _, port := range portList {
					entries = append(entries, ruleEntry{proto: proto, port: port})
				}
			}
		}
	}

	action := int8(0)

	switch rule.Action {
	case "Audit":
		action = 1
	case "Block":
		action = -1
	}

	var lpmMap *ebpf.Map
	var hashMap *ebpf.Map

	if direction == "egress" {
		lpmMap = ne.NetworkEventsObjs.NeEgressLpmMap
		hashMap = ne.NetworkEventsObjs.NeEgressPolicyMap
	} else { // ingress
		lpmMap = ne.NetworkEventsObjs.NeIngressLpmMap
		hashMap = ne.NetworkEventsObjs.NeIngressPolicyMap
	}

	for _, entry := range entries {
		val := net_enforcerPolicyVal{Inode: inode, Proto: entry.proto, Port: entry.port, Action: action, PolicyId: rule.Policy.PolicyID}
		if prefix == 32 {
			if direction == "egress" {
				pKey := net_enforcerPolicyKey{Inode: inode, Saddr: sourceIP, Daddr: targetIP, Proto: uint32(entry.proto), Port: uint32(entry.port)}
				if err := hashMap.Update(&pKey, &val, ebpf.UpdateAny); err == nil {
					rules.EgressHashKeys = append(rules.EgressHashKeys, pKey)
				}
			} else { // ingress
				pKey := net_enforcerPolicyKey{Inode: inode, Saddr: targetIP, Daddr: sourceIP, Proto: uint32(entry.proto), Port: uint32(entry.port)}
				if err := hashMap.Update(&pKey, &val, ebpf.UpdateAny); err == nil {
					rules.IngressHashKeys = append(rules.IngressHashKeys, pKey)
				}
			}
		} else {
			lpmKey := net_enforcerLpmKey{Prefixlen: prefix + 128, Inode: inode, Laddr: sourceIP, Proto: uint16(entry.proto), Port: entry.port, Raddr: targetIP}
			if err := lpmMap.Update(&lpmKey, &val, ebpf.UpdateAny); err == nil {
				if direction == "egress" {
					rules.EgressLpmKeys = append(rules.EgressLpmKeys, lpmKey)
				} else { // ingress
					rules.IngressLpmKeys = append(rules.IngressLpmKeys, lpmKey)
				}
			}
		}
	}
}

// getInodeByPath returns the inode number for a given path within a process's
// root filesystem. Thin wrapper over resolveInodeInPod (which is shared with
// the IPC enforcer path in inode.go) so existing network callsites keep
// their current receiver-style API.
func (ne *NetworkEnforcer) getInodeByPath(pod tp.Pod, path string) (uint64, error) {
	return resolveInodeInPod(ne.GlobalData, pod, path)
}

// setDefaultPosture sets the default posture for a network rule and returns the key
func (ne *NetworkEnforcer) setDefaultPosture(direction string, pod tp.Pod, inode uint64, defaultPosture string) net_enforcerDefaultPostureKey {
	var defaultPostureMap *ebpf.Map

	if direction == "egress" {
		defaultPostureMap = ne.NetworkEventsObjs.NeEgressDefaultPostureMap
	} else { // ingress
		defaultPostureMap = ne.NetworkEventsObjs.NeIngressDefaultPostureMap
	}

	key := net_enforcerDefaultPostureKey{
		Inode: inode,
		Addr:  uint64(podIPToBPFKey(pod.PodIP)),
	}

	switch defaultPosture {
	case "Allow":
		val := net_enforcerRetVal{Action: 0, PolicyId: 1}
		if err := defaultPostureMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			log.Errf("Failed to update default posture map: %v", err)
		}
	case "Block":
		val := net_enforcerRetVal{Action: -1, PolicyId: 2}
		if err := defaultPostureMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			log.Errf("Failed to update default posture map: %v", err)
		}
	}

	return key
}
