// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"fmt"
	"time"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	securityv1 "github.com/boanlab/KloudKnox/operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// policyMatchesPod returns true when the policy's selector matches the pod's
// identities, or when the policy is flagged ApplyToAll and the runtime mode
// makes host-wide application meaningful (docker / hybrid). In pure kubernetes
// mode ApplyToAll is ignored — operators are expected to use namespace
// selectors instead, and ValidateSpec rejects applyToAll at admission.
func policyMatchesPod(policy tp.KloudKnoxPolicy, pod tp.Pod) bool {
	if policy.ApplyToAll && cfg.GlobalCfg.Mode != cfg.ModeKubernetes {
		return true
	}
	return lib.IsSubset(policy.Identities, pod.Identities)
}

// KloudKnoxPolicy

func (k8s *K8sHandler) watchPolicies(knox *KloudKnox) {
	knox.WgDaemon.Add(1)
	go func() {
		defer knox.WgDaemon.Done()

		backoff := time.Second
		maxBackoff := time.Minute

		for {
			select {
			case <-k8s.ctx.Done():
				return
			default:
				if err := k8s.watchKloudKnoxPolicyLoop(knox); err != nil {
					select {
					case <-k8s.ctx.Done():
						return
					case <-time.After(backoff):
						backoff = time.Duration(float64(backoff) * 2)
						if backoff > maxBackoff {
							backoff = maxBackoff
						}
					}
					continue
				}
				backoff = time.Second
			}
		}
	}()
}

func (k8s *K8sHandler) watchKloudKnoxPolicyLoop(knox *KloudKnox) error {
	// Process the list of policies applied before running KloudKnox
	policyList, err := k8s.dynamicClient.Resource(k8s.gvr).List(k8s.ctx, metav1.ListOptions{})
	if err == nil {
		for _, item := range policyList.Items {
			policy := &securityv1.KloudKnoxPolicy{}
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, policy); err != nil {
				log.Errf("Failed to convert policy: %v", err)
				continue
			}

			// Convert policy (CRD -> internal)
			securityPolicy := convertKloudKnoxPolicy(policy)

			// Update policy
			k8s.updateKloudKnoxPolicy(knox, securityPolicy)
			log.Printf("Added a KloudKnoxPolicy (%s/%s)", policy.Namespace, policy.Name)

			// Update policy to pods
			k8s.updateKloudKnoxPolicyToPods(knox, securityPolicy)
		}
	} else {
		return fmt.Errorf("failed to list KloudKnoxPolicies: %v", err)
	}

	watchOptions := metav1.ListOptions{
		ResourceVersion: policyList.GetResourceVersion(),
	}

	// Start watching with the resource version
	for {
		select {
		case <-k8s.ctx.Done():
			return nil
		default:
			watch, err := k8s.dynamicClient.Resource(k8s.gvr).Watch(k8s.ctx, watchOptions)
			if err != nil {
				return fmt.Errorf("failed to watch KloudKnoxPolicies: %v", err)
			}

			for {
				select {
				case <-k8s.ctx.Done():
					watch.Stop()
					return nil

				case event, ok := <-watch.ResultChan():
					if !ok {
						watch.Stop()
						return fmt.Errorf("watch channel closed")
					}

					if event.Type == "ERROR" {
						watch.Stop()
						return fmt.Errorf("watch error event")
					}

					unstructuredObj, ok := event.Object.(*unstructured.Unstructured)
					if !ok {
						continue
					}

					policy := &securityv1.KloudKnoxPolicy{}
					if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policy); err != nil {
						log.Errf("Failed to convert policy: %v", err)
						continue
					}

					k8s.handlePolicyEvent(knox, string(event.Type), policy)
				}
			}
		}
	}
}

// handlePolicyEvent routes policy events to appropriate handlers
func (k8s *K8sHandler) handlePolicyEvent(knox *KloudKnox, eventType string, policy *securityv1.KloudKnoxPolicy) {
	securityPolicy := convertKloudKnoxPolicy(policy)

	switch eventType {
	case "ADDED":
		// Update policy
		k8s.updateKloudKnoxPolicy(knox, securityPolicy)
		log.Printf("Added a KloudKnoxPolicy (%s/%s)", policy.Namespace, policy.Name)

		// Update policy to pods
		k8s.updateKloudKnoxPolicyToPods(knox, securityPolicy)

	case "MODIFIED":
		// Update policy
		k8s.updateKloudKnoxPolicy(knox, securityPolicy)
		log.Printf("Updated a KloudKnoxPolicy (%s/%s)", policy.Namespace, policy.Name)

		// Update policy to pods
		k8s.updateKloudKnoxPolicyToPods(knox, securityPolicy)

	case "DELETED":
		// Delete policy
		k8s.deleteKloudKnoxPolicy(knox, securityPolicy)
		log.Printf("Deleted a KloudKnoxPolicy (%s/%s)", policy.Namespace, policy.Name)

		// Delete policy from pods
		k8s.deleteKloudKnoxPolicyFromPods(knox, securityPolicy)

	case "ERROR":
		log.Printf("Error event received while watching policies: %v", policy)

	default:
		log.Debugf("Unknown event type: %s for policy %s/%s", eventType, policy.Namespace, policy.Name)
	}
}

// convertKloudKnoxPolicy converts a KloudKnoxPolicy CRD to an internal KloudKnoxPolicy
func convertKloudKnoxPolicy(policy *securityv1.KloudKnoxPolicy) tp.KloudKnoxPolicy {
	identities := lib.ConvertKVsToString(policy.Spec.Selector)

	convertedPolicy := tp.KloudKnoxPolicy{
		NamespaceName: policy.Namespace,
		PolicyID:      lib.HashStringToUint32(string(policy.UID)),
		PolicyName:    policy.Name,
		Selector:      policy.Spec.Selector,
		Identities:    identities,
		ApplyToAll:    policy.Spec.ApplyToAll,
		Process:       convertProcessRules(policy.Spec.Process),
		File:          convertFileRules(policy.Spec.File),
		Network:       convertNetworkRules(policy.Spec.Network),
		Capability:    convertCapabilityRules(policy.Spec.Capability),
		IPC:           convertIPCRules(policy.Spec.IPC),
		Action:        policy.Spec.Action,
	}

	return convertedPolicy
}

// convertIPCRules converts the CRD `spec.ipc` block to its internal form. Nil
// input yields a zero-valued KloudKnoxIPCRules so the converter can treat
// policies with and without an ipc block uniformly.
func convertIPCRules(ipc *securityv1.IPCRules) tp.KloudKnoxIPCRules {
	if ipc == nil {
		return tp.KloudKnoxIPCRules{}
	}

	unix := make([]tp.KloudKnoxUnixRule, 0, len(ipc.Unix))
	for _, r := range ipc.Unix {
		unix = append(unix, tp.KloudKnoxUnixRule{
			Type:        r.Type,
			Path:        r.Path,
			Permissions: append([]string(nil), r.Permissions...),
			FromSource:  convertSourceMatches(r.FromSource),
			Action:      r.Action,
		})
	}

	signal := make([]tp.KloudKnoxSignalRule, 0, len(ipc.Signal))
	for _, r := range ipc.Signal {
		signal = append(signal, tp.KloudKnoxSignalRule{
			Target:     r.Target,
			Signals:    append([]string(nil), r.Signals...),
			FromSource: convertSourceMatches(r.FromSource),
			Action:     r.Action,
		})
	}

	ptrace := make([]tp.KloudKnoxPtraceRule, 0, len(ipc.Ptrace))
	for _, r := range ipc.Ptrace {
		ptrace = append(ptrace, tp.KloudKnoxPtraceRule{
			Permission: r.Permission,
			Target:     r.Target,
			FromSource: convertSourceMatches(r.FromSource),
			Action:     r.Action,
		})
	}

	return tp.KloudKnoxIPCRules{Unix: unix, Signal: signal, Ptrace: ptrace}
}

// convertCapabilityRules converts a slice of CapabilityRule CRDs to internal
// KloudKnoxCapabilityRules. Unknown capability names are dropped with a warn
// log — ValidateSpec should reject them at admission, so this is a belt-and-
// suspenders guard for policies loaded via other channels (e.g. the Docker
// mode file watcher) that may bypass the validator.
func convertCapabilityRules(rules []securityv1.CapabilityRule) []tp.KloudKnoxCapabilityRule {
	result := make([]tp.KloudKnoxCapabilityRule, 0, len(rules))
	for _, rule := range rules {
		name, ok := lib.NormalizeCapabilityName(rule.Name)
		if !ok {
			log.Warnf("Dropping unknown capability: %s", rule.Name)
			continue
		}
		capID, _ := lib.CapabilityID(name)
		result = append(result, tp.KloudKnoxCapabilityRule{
			Name:       name,
			CapID:      capID,
			FromSource: convertSourceMatches(rule.FromSource),
			Action:     rule.Action,
		})
	}
	return result
}

// convertProcessRules converts a slice of ProcessRule CRDs to internal ProcessRules
func convertProcessRules(rules []securityv1.ProcessRule) []tp.KloudKnoxProcessRule {
	result := make([]tp.KloudKnoxProcessRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, tp.KloudKnoxProcessRule{
			Path:       rule.Path,
			Dir:        rule.Dir,
			Recursive:  rule.Recursive,
			FromSource: convertSourceMatches(rule.FromSource),
			Action:     rule.Action,
		})
	}
	return result
}

// convertFileRules converts a slice of FileRule CRDs to internal FileRules
func convertFileRules(rules []securityv1.FileRule) []tp.KloudKnoxFileRule {
	result := make([]tp.KloudKnoxFileRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, tp.KloudKnoxFileRule{
			Path:       rule.Path,
			Dir:        rule.Dir,
			Recursive:  rule.Recursive,
			ReadOnly:   rule.ReadOnly,
			FromSource: convertSourceMatches(rule.FromSource),
			Action:     rule.Action,
		})
	}
	return result
}

// convertNetworkRules converts a slice of NetworkRule CRDs to internal NetworkRules
func convertNetworkRules(rules []securityv1.NetworkRule) []tp.KloudKnoxNetworkRule {
	result := make([]tp.KloudKnoxNetworkRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, tp.KloudKnoxNetworkRule{
			Direction:  rule.Direction,
			Selector:   rule.Selector,
			IPBlock:    convertIPBlock(rule.IPBlock),
			FQDN:       rule.FQDN,
			Ports:      convertPorts(rule.Ports),
			FromSource: convertSourceMatches(rule.FromSource),
			Action:     rule.Action,
		})
	}
	return result
}

// convertIPBlock converts an IPBlock CRD to an internal IPBlock
func convertIPBlock(block securityv1.IPBlock) tp.IPBlock {
	return tp.IPBlock{
		CIDR:   block.CIDR,
		Except: block.Except,
	}
}

// convertPorts converts a slice of Port CRDs to internal Ports
func convertPorts(ports []securityv1.Port) []tp.Port {
	result := make([]tp.Port, 0, len(ports))
	for _, port := range ports {
		result = append(result, tp.Port{
			Protocol: port.Protocol,
			Port:     port.Port,
		})
	}
	return result
}

// convertSourceMatches converts a slice of SourceMatch CRDs to internal SourceMatches
func convertSourceMatches(matches []securityv1.SourceMatch) []tp.SourceMatch {
	result := make([]tp.SourceMatch, 0, len(matches))
	for _, match := range matches {
		result = append(result, tp.SourceMatch{
			Path: match.Path,
		})
	}
	return result
}

// updateKloudKnoxPolicy updates the policy list for a specific namespace
func (k8s *K8sHandler) updateKloudKnoxPolicy(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	upsertKloudKnoxPolicy(knox, securityPolicy)
}

// upsertKloudKnoxPolicy is the shared implementation of policy insert/replace,
// used by both the K8s watcher and the Docker-mode PolicyFileLoader.
func upsertKloudKnoxPolicy(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	knox.GlobalData.RuntimePoliciesLock.Lock()
	defer knox.GlobalData.RuntimePoliciesLock.Unlock()

	found := false

	if _, exists := knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName]; !exists {
		// Initialize namespace entry if it doesn't exist
		knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName] = []tp.KloudKnoxPolicy{}
	} else {
		// Find and append or update
		for idx, existingPolicy := range knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName] {
			if existingPolicy.PolicyName == securityPolicy.PolicyName {
				knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName][idx] = securityPolicy
				found = true
				break
			}
		}
	}

	if !found {
		knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName] = append(knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName], securityPolicy)
	}
}

// deleteKloudKnoxPolicy removes the policy from the policy list for a specific namespace
func (k8s *K8sHandler) deleteKloudKnoxPolicy(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	removeKloudKnoxPolicy(knox, securityPolicy)
}

// removeKloudKnoxPolicy is the shared implementation of policy deletion.
func removeKloudKnoxPolicy(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	knox.GlobalData.RuntimePoliciesLock.Lock()
	defer knox.GlobalData.RuntimePoliciesLock.Unlock()

	// Check if namespace exists
	if _, exists := knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName]; !exists {
		return
	}

	// Remove policy using swap-and-pop
	for idx, existingPolicy := range knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName] {
		if existingPolicy.PolicyName == securityPolicy.PolicyName {
			// Swap with last element and truncate
			lastIdx := len(knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName]) - 1
			knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName][idx] = knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName][lastIdx]
			knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName] = knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName][:lastIdx]

			// If no more policies in this namespace, optionally remove the namespace entry
			if len(knox.GlobalData.RuntimePolicies[securityPolicy.NamespaceName]) == 0 {
				delete(knox.GlobalData.RuntimePolicies, securityPolicy.NamespaceName)
			}

			break
		}
	}
}

// updateKloudKnoxPolicyToPods adds or updates policy in matching pods
func (k8s *K8sHandler) updateKloudKnoxPolicyToPods(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	applyKloudKnoxPolicyToPods(knox, securityPolicy)
}

// applyKloudKnoxPolicyToPods is the shared implementation of pod-level policy
// application; reconciliation is triggered inline (same behavior as before).
func applyKloudKnoxPolicyToPods(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	pods := []tp.Pod{}

	knox.GlobalData.PodsLock.RLock()
	for _, pod := range knox.GlobalData.Pods {
		if pod.NamespaceName != securityPolicy.NamespaceName {
			continue
		}
		pods = append(pods, pod)
	}
	knox.GlobalData.PodsLock.RUnlock()

	for _, pod := range pods {
		if !policyMatchesPod(securityPolicy, pod) {
			continue
		}

		// Hold WriteLock for the entire read-modify-write to avoid concurrent update loss
		knox.GlobalData.PodsLock.Lock()
		current, exists := knox.GlobalData.Pods[pod.NamespaceName+"/"+pod.PodName]
		if !exists {
			knox.GlobalData.PodsLock.Unlock()
			continue
		}

		found := false
		for idx, existingPolicy := range current.RuntimePolicies {
			if existingPolicy.PolicyName == securityPolicy.PolicyName {
				current.RuntimePolicies[idx] = securityPolicy
				found = true
				break
			}
		}
		if !found {
			current.RuntimePolicies = append(current.RuntimePolicies, securityPolicy)
		}

		current.FileRules = buildFileRules(current)
		current.NetworkRules = buildNetworkRules(current)
		current.CapabilityRules = buildCapabilityRules(current)
		current.IPCRules = buildIPCRules(current)
		knox.GlobalData.Pods[current.NamespaceName+"/"+current.PodName] = current
		knox.GlobalData.PodsLock.Unlock()

		// Enforce security policies for the pod
		if err := knox.RuntimeEnforcer.EnforceSecurityPolicies(current); err != nil {
			log.Errf("Failed to enforce security policies for pod %s: %v", current.PodName, err)
		}

		// Trigger reconciliation
		reconcileNetworkPoliciesGlobal(knox)

		log.Printf("Updated a KloudKnoxPolicy (%s) to pod %s/%s", securityPolicy.PolicyName, current.NamespaceName, current.PodName)
	}
}

// deleteKloudKnoxPolicyFromPods removes policy from matching pods
func (k8s *K8sHandler) deleteKloudKnoxPolicyFromPods(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	removeKloudKnoxPolicyFromPods(knox, securityPolicy)
}

// removeKloudKnoxPolicyFromPods is the shared implementation of policy
// detachment from matching pods.
func removeKloudKnoxPolicyFromPods(knox *KloudKnox, securityPolicy tp.KloudKnoxPolicy) {
	pods := []tp.Pod{}

	knox.GlobalData.PodsLock.RLock()
	for _, pod := range knox.GlobalData.Pods {
		if pod.NamespaceName != securityPolicy.NamespaceName {
			continue
		}
		pods = append(pods, pod)
	}
	knox.GlobalData.PodsLock.RUnlock()

	for _, pod := range pods {
		if !policyMatchesPod(securityPolicy, pod) {
			continue
		}

		// Hold WriteLock for the entire read-modify-write to avoid concurrent update loss
		knox.GlobalData.PodsLock.Lock()
		current, exists := knox.GlobalData.Pods[pod.NamespaceName+"/"+pod.PodName]
		if !exists {
			knox.GlobalData.PodsLock.Unlock()
			continue
		}

		for idx, existingPolicy := range current.RuntimePolicies {
			if existingPolicy.PolicyName == securityPolicy.PolicyName {
				lastIdx := len(current.RuntimePolicies) - 1
				current.RuntimePolicies[idx] = current.RuntimePolicies[lastIdx]
				current.RuntimePolicies = current.RuntimePolicies[:lastIdx]
				break
			}
		}

		current.FileRules = buildFileRules(current)
		current.NetworkRules = buildNetworkRules(current)
		current.CapabilityRules = buildCapabilityRules(current)
		current.IPCRules = buildIPCRules(current)
		knox.GlobalData.Pods[current.NamespaceName+"/"+current.PodName] = current
		knox.GlobalData.PodsLock.Unlock()

		// Enforce security policies for the pod
		if err := knox.RuntimeEnforcer.EnforceSecurityPolicies(current); err != nil {
			log.Errf("Failed to enforce security policies for pod %s: %v", current.PodName, err)
		}

		// Trigger reconciliation
		reconcileNetworkPoliciesGlobal(knox)

		log.Printf("Deleted a KloudKnoxPolicy (%s) from pod %s/%s", securityPolicy.PolicyName, current.NamespaceName, current.PodName)
	}
}
