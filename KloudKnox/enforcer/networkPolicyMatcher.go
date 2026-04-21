// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package enforcer

import (
	"sort"
	"strings"

	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// collectAllowPolicyNames returns the sorted, comma-joined names of the Allow
// policies in the given direction. A default-posture Block (policyID=2) is only
// triggered when a source has at least one Allow rule flipping its posture, so
// those Allow policies are the origin of the alert.
func collectAllowPolicyNames(networkRules *tp.NetworkRules, operation string) string {
	var direction map[string]tp.InnerNetworkRules
	switch operation {
	case "connect", "udp_sendmsg", "egress":
		direction = networkRules.EgressRules
	case "accept", "udp_recvmsg", "ingress":
		direction = networkRules.IngressRules
	default:
		return ""
	}

	names := make(map[string]struct{})
	for _, inner := range direction {
		for _, rule := range inner.InnerRules {
			if rule.Action == "Allow" && rule.Policy.PolicyName != "" {
				names[rule.Policy.PolicyName] = struct{}{}
			}
		}
	}
	if len(names) == 0 {
		return ""
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// UpdateMatchedNetworkPolicy sets evData.PolicyName and evData.PolicyAction from
// the matched policyID, and appends an "fqdn=<name>" annotation to evData.Data
// when the remote IP is known to the FQDN resolver.
func (ne *NetworkEnforcer) UpdateMatchedNetworkPolicy(networkRules *tp.NetworkRules, evData *tp.EventData, policyID uint32) {
	switch policyID {
	case 1:
		evData.PolicyName = "DefaultPosture"
		evData.PolicyAction = "Allow"
	case 2:
		evData.PolicyAction = "Block"
		if origins := collectAllowPolicyNames(networkRules, evData.Operation); origins != "" {
			evData.PolicyName = origins
		} else {
			evData.PolicyName = "DefaultPosture"
		}
	default:
		switch evData.Operation {
		case "connect", "udp_sendmsg", "egress":
			for _, innerRules := range networkRules.EgressRules {
				for _, rule := range innerRules.InnerRules {
					if rule.Policy.PolicyID == policyID {
						evData.PolicyName = rule.Policy.PolicyName
						evData.PolicyAction = rule.Action
						break
					}
				}
			}

		case "accept", "udp_recvmsg", "ingress":
			for _, innerRules := range networkRules.IngressRules {
				for _, rule := range innerRules.InnerRules {
					if rule.Policy.PolicyID == policyID {
						evData.PolicyName = rule.Policy.PolicyName
						evData.PolicyAction = rule.Action
						break
					}
				}
			}
		}
	}

	// FQDN enrichment: annotate the matched event with the domain name of the remote endpoint
	if ne.FqdnResolver != nil {
		var remoteIP uint32
		switch evData.Operation {
		case "connect", "udp_sendmsg", "egress":
			remoteIP = evData.Daddr
		case "accept", "udp_recvmsg", "ingress":
			remoteIP = evData.Saddr
		}
		if remoteIP != 0 {
			if fqdn := ne.FqdnResolver.LookupFqdn(remoteIP); fqdn != "" {
				if evData.Data != "" {
					evData.Data += " fqdn=" + fqdn
				} else {
					evData.Data = "fqdn=" + fqdn
				}
			}
		}
	}
}
