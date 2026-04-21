// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// kloudknoxProfilePrefix is the profile name prefix that KloudKnox manages.
const kloudknoxProfilePrefix = "kloudknox-"

// extractAppArmorProfileFromAnnotation strips the "localhost/" prefix from a
// legacy AppArmor annotation value (e.g. "localhost/kloudknox-foo" → "kloudknox-foo").
func extractAppArmorProfileFromAnnotation(value string) string {
	return strings.TrimPrefix(value, "localhost/")
}

// extractAppArmorProfileFromSecCtx returns the profile name from a pod or
// container SecurityContext AppArmorProfile field.
// Returns "" when the type is not Localhost or the name is empty.
func extractAppArmorProfileFromSecCtx(p *corev1.AppArmorProfile) string {
	if p == nil || p.Type != corev1.AppArmorProfileTypeLocalhost {
		return ""
	}
	if p.LocalhostProfile == nil || *p.LocalhostProfile == "" {
		return ""
	}
	return *p.LocalhostProfile
}

// collectTemplateAppArmorProfiles returns the deduplicated list of
// kloudknox-managed AppArmor profile names declared in a pod template,
// checking both the legacy annotation and the SecurityContext field.
func collectTemplateAppArmorProfiles(annotations map[string]string, podSpec corev1.PodSpec) []string {
	seen := make(map[string]struct{})

	// Legacy annotation: container.apparmor.security.beta.kubernetes.io/<name>
	for k, v := range annotations {
		if !strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") {
			continue
		}
		if profile := extractAppArmorProfileFromAnnotation(v); strings.HasPrefix(profile, kloudknoxProfilePrefix) {
			seen[profile] = struct{}{}
		}
	}

	// Pod-level SecurityContext (K8s 1.28+, stable 1.30)
	if podSpec.SecurityContext != nil {
		if profile := extractAppArmorProfileFromSecCtx(podSpec.SecurityContext.AppArmorProfile); strings.HasPrefix(profile, kloudknoxProfilePrefix) {
			seen[profile] = struct{}{}
		}
	}

	// Container-level SecurityContext (overrides pod-level per container)
	for _, c := range podSpec.Containers {
		if c.SecurityContext == nil {
			continue
		}
		if profile := extractAppArmorProfileFromSecCtx(c.SecurityContext.AppArmorProfile); strings.HasPrefix(profile, kloudknoxProfilePrefix) {
			seen[profile] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	return result
}

// K8s Handler

// K8sHandler manages Kubernetes resource operations and event handling
type K8sHandler struct {
	// Context for managing lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	// Kubernetes API client for interacting with the cluster
	clientSet *kubernetes.Clientset

	// Map of resource watchers for monitoring Kubernetes resources
	watchers map[string]*cache.ListWatch

	// Map of resource informers for handling resource events
	informers map[string]cache.Controller

	// Dynamic Client for interacting with the cluster
	dynamicClient dynamic.Interface

	// GroupVersionResource for KloudKnoxPolicies
	gvr schema.GroupVersionResource
}

// NewK8sHandler creates and initializes a new Kubernetes handler
func NewK8sHandler(knox *KloudKnox) *K8sHandler {
	ctx, cancel := context.WithCancel(context.Background())

	kh := &K8sHandler{
		ctx:    ctx,
		cancel: cancel,

		watchers:  make(map[string]*cache.ListWatch),
		informers: make(map[string]cache.Controller),
	}

	config, err := lib.InitK8sConfig()
	if err != nil {
		log.Errf("Failed to initialize Kubernetes client: %v", err)
		kh.cancel()
		return nil
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errf("Failed to create Kubernetes client: %v", err)
		kh.cancel()
		return nil
	}
	kh.clientSet = clientset

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Errf("Failed to create dynamic client: %v", err)
		kh.cancel()
		return nil
	}
	kh.dynamicClient = dynamicClient

	gvr := schema.GroupVersionResource{
		Group:    "security.boanlab.com",
		Version:  "v1",
		Resource: "kloudknoxpolicies",
	}
	kh.gvr = gvr

	log.Print("Initialized Kubernetes handler")

	// Start watching various Kubernetes resources
	kh.watchNodes(knox)
	kh.watchDeployments(knox)
	kh.watchStatefulSets(knox)
	kh.watchDaemonSets(knox)
	kh.watchPods(knox)
	kh.watchServices(knox)
	kh.watchPolicies(knox)

	log.Print("Started to watch Kubernetes events")
	return kh
}

// Close gracefully shuts down the Kubernetes handler
func (k8s *K8sHandler) Close() {
	if k8s.clientSet == nil {
		return
	}

	// Cancel context to stop all goroutines
	k8s.cancel()

	// Clear the maps
	k8s.watchers = make(map[string]*cache.ListWatch)
	k8s.informers = make(map[string]cache.Controller)

	log.Print("Stopped Kubernetes handler")
}

// createInformer is a helper function to create informers with common configuration
func (k8s *K8sHandler) createInformer(
	resourceType string,
	restClient cache.Getter,
	objectType runtime.Object,
	handler cache.ResourceEventHandlerFuncs,
	knox *KloudKnox,
) {
	watchlist := cache.NewListWatchFromClient(
		restClient,
		resourceType,
		corev1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchlist,
		ObjectType:    objectType,
		ResyncPeriod:  0,
		Handler:       handler,
	})

	k8s.informers[resourceType] = controller

	// Add a new goroutine to run the informer
	knox.WgDaemon.Add(1)
	go func() {
		defer knox.WgDaemon.Done()
		controller.Run(k8s.ctx.Done())
	}()
}

// Node

// watchNodes sets up a watcher for Kubernetes nodes
func (k8s *K8sHandler) watchNodes(knox *KloudKnox) {
	k8s.createInformer(
		"nodes",
		k8s.clientSet.CoreV1().RESTClient(),
		&corev1.Node{},
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { k8s.addNode(knox, obj) },
			UpdateFunc: func(_, newObj any) { k8s.updateNode(knox, newObj) },
			DeleteFunc: func(obj any) { k8s.deleteNode(knox, obj) },
		},
		knox,
	)
}

// addNode handles the addition of a new node
func (k8s *K8sHandler) addNode(knox *KloudKnox, obj any) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}

	newNode := convertNode(node)

	// Update node
	knox.GlobalData.NodeLock.Lock()
	knox.GlobalData.Node[node.Name] = newNode
	knox.GlobalData.NodeLock.Unlock()

	// Update IP entry
	knox.GlobalData.IPMapLock.Lock()
	knox.GlobalData.IPMap[newNode.NodeIP] = tp.IPEntry{Type: "node", Node: newNode}
	knox.GlobalData.IPMapLock.Unlock()

	log.Debugf("Added a node (%s)", node.Name)
}

// updateNode handles the update of an existing node
func (k8s *K8sHandler) updateNode(knox *KloudKnox, obj any) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}

	newNode := convertNode(node)

	// Update node
	knox.GlobalData.NodeLock.Lock()
	knox.GlobalData.Node[node.Name] = newNode
	knox.GlobalData.NodeLock.Unlock()

	// Update IP entry
	knox.GlobalData.IPMapLock.Lock()
	knox.GlobalData.IPMap[newNode.NodeIP] = tp.IPEntry{Type: "node", Node: newNode}
	knox.GlobalData.IPMapLock.Unlock()

	log.Debugf("Updated a node (%s)", node.Name)
}

// convertNode converts a Kubernetes node to our internal node type
func convertNode(node *corev1.Node) tp.Node {
	nodeIP := ""
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			nodeIP = addr.Address
			break
		}
	}

	return tp.Node{
		ClusterName: cfg.GlobalCfg.Cluster,
		NodeName:    node.Name,
		Annotations: node.Annotations,
		Labels:      node.Labels,
		Identities:  lib.ConvertKVsToString(node.Labels),
		NodeIP:      nodeIP,
	}
}

// deleteNode handles the deletion of a node
func (k8s *K8sHandler) deleteNode(knox *KloudKnox, obj any) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}

	// Delete node
	knox.GlobalData.NodeLock.Lock()
	deletedNode := knox.GlobalData.Node[node.Name]
	delete(knox.GlobalData.Node, node.Name)
	knox.GlobalData.NodeLock.Unlock()

	// Remove IP entry
	knox.GlobalData.IPMapLock.Lock()
	delete(knox.GlobalData.IPMap, deletedNode.NodeIP)
	knox.GlobalData.IPMapLock.Unlock()

	log.Debugf("Deleted a node (%s)", node.Name)
}

// Deployment

func (k8s *K8sHandler) watchDeployments(knox *KloudKnox) {
	k8s.createInformer(
		"deployments",
		k8s.clientSet.AppsV1().RESTClient(),
		&appsv1.Deployment{},
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { k8s.addDeployment(knox, obj) },
			UpdateFunc: func(oldObj, newObj any) { k8s.updateDeployment(knox, oldObj, newObj) },
			DeleteFunc: func(obj any) { k8s.deleteDeployment(knox, obj) },
		},
		knox,
	)
}

func (k8s *K8sHandler) addDeployment(knox *KloudKnox, obj any) {
	deploy, ok := obj.(*appsv1.Deployment)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
		for _, profile := range collectTemplateAppArmorProfiles(deploy.Spec.Template.Annotations, deploy.Spec.Template.Spec) {
			if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(profile); err != nil {
				log.Errf("Failed to register AppArmor profile: %v", err)
			}
		}
	}
}

func (k8s *K8sHandler) updateDeployment(knox *KloudKnox, oldObj, newObj any) {
	oldDeploy, ok := oldObj.(*appsv1.Deployment)
	if !ok {
		return
	}
	newDeploy, ok := newObj.(*appsv1.Deployment)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer == nil || knox.RuntimeEnforcer.EnforcerType != "apparmor" {
		return
	}

	oldProfiles := collectTemplateAppArmorProfiles(oldDeploy.Spec.Template.Annotations, oldDeploy.Spec.Template.Spec)
	newProfiles := collectTemplateAppArmorProfiles(newDeploy.Spec.Template.Annotations, newDeploy.Spec.Template.Spec)

	newSet := make(map[string]struct{}, len(newProfiles))
	for _, p := range newProfiles {
		newSet[p] = struct{}{}
		if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(p); err != nil {
			log.Errf("Failed to register AppArmor profile: %v", err)
		}
	}
	for _, p := range oldProfiles {
		if _, exists := newSet[p]; !exists {
			if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(p); err != nil {
				log.Errf("Failed to unregister AppArmor profile: %v", err)
			}
		}
	}
}

func (k8s *K8sHandler) deleteDeployment(knox *KloudKnox, obj any) {
	deploy, ok := obj.(*appsv1.Deployment)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
		for _, profile := range collectTemplateAppArmorProfiles(deploy.Spec.Template.Annotations, deploy.Spec.Template.Spec) {
			if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(profile); err != nil {
				log.Errf("Failed to unregister AppArmor profile: %v", err)
			}
		}
	}
}

// StatefulSet

func (k8s *K8sHandler) watchStatefulSets(knox *KloudKnox) {
	k8s.createInformer(
		"statefulsets",
		k8s.clientSet.AppsV1().RESTClient(),
		&appsv1.StatefulSet{},
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { k8s.addStatefulSet(knox, obj) },
			UpdateFunc: func(oldObj, newObj any) { k8s.updateStatefulSet(knox, oldObj, newObj) },
			DeleteFunc: func(obj any) { k8s.deleteStatefulSet(knox, obj) },
		},
		knox,
	)
}

func (k8s *K8sHandler) addStatefulSet(knox *KloudKnox, obj any) {
	sts, ok := obj.(*appsv1.StatefulSet)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
		for _, profile := range collectTemplateAppArmorProfiles(sts.Spec.Template.Annotations, sts.Spec.Template.Spec) {
			if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(profile); err != nil {
				log.Errf("Failed to register AppArmor profile: %v", err)
			}
		}
	}
}

func (k8s *K8sHandler) updateStatefulSet(knox *KloudKnox, oldObj, newObj any) {
	oldSts, ok := oldObj.(*appsv1.StatefulSet)
	if !ok {
		return
	}
	newSts, ok := newObj.(*appsv1.StatefulSet)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer == nil || knox.RuntimeEnforcer.EnforcerType != "apparmor" {
		return
	}

	oldProfiles := collectTemplateAppArmorProfiles(oldSts.Spec.Template.Annotations, oldSts.Spec.Template.Spec)
	newProfiles := collectTemplateAppArmorProfiles(newSts.Spec.Template.Annotations, newSts.Spec.Template.Spec)

	newSet := make(map[string]struct{}, len(newProfiles))
	for _, p := range newProfiles {
		newSet[p] = struct{}{}
		if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(p); err != nil {
			log.Errf("Failed to register AppArmor profile: %v", err)
		}
	}
	for _, p := range oldProfiles {
		if _, exists := newSet[p]; !exists {
			if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(p); err != nil {
				log.Errf("Failed to unregister AppArmor profile: %v", err)
			}
		}
	}
}

func (k8s *K8sHandler) deleteStatefulSet(knox *KloudKnox, obj any) {
	sts, ok := obj.(*appsv1.StatefulSet)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
		for _, profile := range collectTemplateAppArmorProfiles(sts.Spec.Template.Annotations, sts.Spec.Template.Spec) {
			if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(profile); err != nil {
				log.Errf("Failed to unregister AppArmor profile: %v", err)
			}
		}
	}
}

// DaemonSet

func (k8s *K8sHandler) watchDaemonSets(knox *KloudKnox) {
	k8s.createInformer(
		"daemonsets",
		k8s.clientSet.AppsV1().RESTClient(),
		&appsv1.DaemonSet{},
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { k8s.addDaemonSet(knox, obj) },
			UpdateFunc: func(oldObj, newObj any) { k8s.updateDaemonSet(knox, oldObj, newObj) },
			DeleteFunc: func(obj any) { k8s.deleteDaemonSet(knox, obj) },
		},
		knox,
	)
}

func (k8s *K8sHandler) addDaemonSet(knox *KloudKnox, obj any) {
	dms, ok := obj.(*appsv1.DaemonSet)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
		for _, profile := range collectTemplateAppArmorProfiles(dms.Spec.Template.Annotations, dms.Spec.Template.Spec) {
			if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(profile); err != nil {
				log.Errf("Failed to register AppArmor profile: %v", err)
			}
		}
	}
}

func (k8s *K8sHandler) updateDaemonSet(knox *KloudKnox, oldObj, newObj any) {
	oldDms, ok := oldObj.(*appsv1.DaemonSet)
	if !ok {
		return
	}
	newDms, ok := newObj.(*appsv1.DaemonSet)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer == nil || knox.RuntimeEnforcer.EnforcerType != "apparmor" {
		return
	}

	oldProfiles := collectTemplateAppArmorProfiles(oldDms.Spec.Template.Annotations, oldDms.Spec.Template.Spec)
	newProfiles := collectTemplateAppArmorProfiles(newDms.Spec.Template.Annotations, newDms.Spec.Template.Spec)

	newSet := make(map[string]struct{}, len(newProfiles))
	for _, p := range newProfiles {
		newSet[p] = struct{}{}
		if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(p); err != nil {
			log.Errf("Failed to register AppArmor profile: %v", err)
		}
	}
	for _, p := range oldProfiles {
		if _, exists := newSet[p]; !exists {
			if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(p); err != nil {
				log.Errf("Failed to unregister AppArmor profile: %v", err)
			}
		}
	}
}

func (k8s *K8sHandler) deleteDaemonSet(knox *KloudKnox, obj any) {
	dms, ok := obj.(*appsv1.DaemonSet)
	if !ok {
		return
	}

	if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
		for _, profile := range collectTemplateAppArmorProfiles(dms.Spec.Template.Annotations, dms.Spec.Template.Spec) {
			if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(profile); err != nil {
				log.Errf("Failed to unregister AppArmor profile: %v", err)
			}
		}
	}
}

// Pod

// watchPods sets up a watcher for Kubernetes pods
func (k8s *K8sHandler) watchPods(knox *KloudKnox) {
	k8s.createInformer(
		"pods",
		k8s.clientSet.CoreV1().RESTClient(),
		&corev1.Pod{},
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { k8s.addPod(knox, obj) },
			UpdateFunc: func(oldObj, newObj any) { k8s.updatePod(knox, oldObj, newObj) },
			DeleteFunc: func(obj any) { k8s.deletePod(knox, obj) },
		},
		knox,
	)
}

// addPod handles the addition of a new pod
func (k8s *K8sHandler) addPod(knox *KloudKnox, obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}

	newPod := convertPod(knox, pod)

	// Update pod
	knox.GlobalData.PodsLock.Lock()
	knox.GlobalData.Pods[newPod.NamespaceName+"/"+newPod.PodName] = newPod
	knox.GlobalData.PodsLock.Unlock()

	// Update IP entry
	knox.GlobalData.IPMapLock.Lock()
	knox.GlobalData.IPMap[newPod.PodIP] = tp.IPEntry{Type: "pod", Pod: newPod}
	knox.GlobalData.IPMapLock.Unlock()

	if newPod.NodeName == cfg.GlobalCfg.Node {
		if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
			// Register AppArmor profiles for the containers of the pod
			for profile, action := range newPod.AppArmorProfiles {
				if action {
					if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(profile); err != nil {
						log.Errf("Failed to register AppArmor profile %s: %v", profile, err)
					}
				}
			}

			// Attach Network Enforcer for the pod
			if err := knox.RuntimeEnforcer.AttachNetworkEnforcer(newPod); err != nil {
				log.Errf("Failed to attach Network Enforcer to pod %s: %v", newPod.PodName, err)
			}
		}

		if len(newPod.RuntimePolicies) != 0 {
			// Enforce security policies for the pod
			if err := knox.RuntimeEnforcer.EnforceSecurityPolicies(newPod); err != nil {
				log.Errf("Failed to enforce security policies for pod %s: %v", newPod.PodName, err)
			}

			if len(newPod.RuntimePolicies) == 1 {
				log.Printf("Applied 1 security policy to pod %s/%s", newPod.NamespaceName, newPod.PodName)
			} else if len(newPod.RuntimePolicies) > 1 {
				log.Printf("Applied %d security policies to pod %s/%s", len(newPod.RuntimePolicies), newPod.NamespaceName, newPod.PodName)
			}
		}
	}

	// Trigger reconciliation as this new pod might be a target for existing policies
	k8s.reconcileNetworkPolicies(knox)

	log.Printf("pod=%s/%s event=added", newPod.NamespaceName, newPod.PodName)
}

// updatePod handles the update of an existing pod
func (k8s *K8sHandler) updatePod(knox *KloudKnox, oldObj, obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}

	var prevPhase corev1.PodPhase
	if oldPod, ok := oldObj.(*corev1.Pod); ok {
		prevPhase = oldPod.Status.Phase
	}

	newPod := convertPod(knox, pod)

	// Snapshot old pod before overwriting (for change detection)
	knox.GlobalData.PodsLock.RLock()
	prevPod, hadPrevPod := knox.GlobalData.Pods[newPod.NamespaceName+"/"+newPod.PodName]
	knox.GlobalData.PodsLock.RUnlock()

	// Update pod
	knox.GlobalData.PodsLock.Lock()
	knox.GlobalData.Pods[newPod.NamespaceName+"/"+newPod.PodName] = newPod
	knox.GlobalData.PodsLock.Unlock()

	// Update IP entry when PodIP changes (e.g., pod transitions from Pending to Running)
	if newPod.PodIP != "" && (!hadPrevPod || prevPod.PodIP != newPod.PodIP) {
		knox.GlobalData.IPMapLock.Lock()
		if hadPrevPod && prevPod.PodIP != "" {
			delete(knox.GlobalData.IPMap, prevPod.PodIP)
		}
		knox.GlobalData.IPMap[newPod.PodIP] = tp.IPEntry{Type: "pod", Pod: newPod}
		knox.GlobalData.IPMapLock.Unlock()
	}

	if newPod.NodeName == cfg.GlobalCfg.Node {
		if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
			// Register AppArmor profiles (idempotent — handles the case where addPod
			// fired before the pod was scheduled and NodeName was empty)
			for profile, action := range newPod.AppArmorProfiles {
				if action {
					if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(profile); err != nil {
						log.Errf("Failed to register AppArmor profile %s: %v", profile, err)
					}
				}
			}

			// Attach Network Enforcer for the pod (retry if it failed during addPod)
			if err := knox.RuntimeEnforcer.AttachNetworkEnforcer(newPod); err != nil {
				log.Errf("Failed to attach Network Enforcer to pod %s: %v", newPod.PodName, err)
			}
		}

		if len(newPod.RuntimePolicies) != 0 {
			// Enforce security policies for the pod
			if err := knox.RuntimeEnforcer.EnforceSecurityPolicies(newPod); err != nil {
				log.Errf("Failed to enforce security policies for pod %s: %v", newPod.PodName, err)
			}

			if len(newPod.RuntimePolicies) == 1 {
				log.Printf("Applied 1 security policy to pod %s/%s", newPod.NamespaceName, newPod.PodName)
			} else if len(newPod.RuntimePolicies) > 1 {
				log.Printf("Applied %d security policies to pod %s/%s", len(newPod.RuntimePolicies), newPod.NamespaceName, newPod.PodName)
			}
		}
	}

	// Trigger reconciliation as this updated pod might be a target for existing policies
	k8s.reconcileNetworkPolicies(knox)

	// Log only meaningful state transitions; suppress noise from status-only updates
	var changes []string
	if hadPrevPod {
		if prevPod.NodeName != newPod.NodeName {
			changes = append(changes, fmt.Sprintf("nodeName=%s→%s", prevPod.NodeName, newPod.NodeName))
		}
		if prevPod.PodIP != newPod.PodIP {
			changes = append(changes, fmt.Sprintf("podIP=%s→%s", prevPod.PodIP, newPod.PodIP))
		}
		if len(prevPod.Containers) != len(newPod.Containers) {
			changes = append(changes, fmt.Sprintf("containers=%d→%d", len(prevPod.Containers), len(newPod.Containers)))
		}
	}
	if prevPhase != pod.Status.Phase {
		changes = append(changes, fmt.Sprintf("phase=%s→%s", prevPhase, pod.Status.Phase))
	}

	if len(changes) > 0 {
		log.Printf("pod=%s/%s event=updated %s", newPod.NamespaceName, newPod.PodName, strings.Join(changes, " "))
	} else {
		log.Debugf("pod=%s/%s event=updated", newPod.NamespaceName, newPod.PodName)
	}
}

// convertPod converts a Kubernetes pod to our internal pod type
func convertPod(knox *KloudKnox, pod *corev1.Pod) tp.Pod {
	newPod := tp.Pod{
		NamespaceName: pod.Namespace,
		PodName:       pod.Name,
		NodeName:      pod.Spec.NodeName,

		Annotations: pod.Annotations,
		Labels:      pod.Labels,
		Identities:  lib.ConvertKVsToString(pod.Labels),

		PodIP:  pod.Status.PodIP,
		NodeIP: pod.Status.HostIP,

		Containers:       make(map[string]string),
		AppArmorProfiles: make(map[string]bool),

		RuntimePolicies: []tp.KloudKnoxPolicy{},
		FileRules:       tp.FileRules{},
		NetworkRules:    tp.NetworkRules{},
	}

	// Add container to pod
	for _, containerStatus := range pod.Status.ContainerStatuses {
		containerID := strings.TrimPrefix(containerStatus.ContainerID, "containerd://")
		if containerID == "" {
			continue
		}

		containerName := containerStatus.Name
		if containerName == "" {
			containerName = containerID[:12]
		}

		newPod.Containers[containerID] = containerName
	}

	// Add AppArmor profiles to pod.
	// Check both the legacy annotation and the SecurityContext field (K8s 1.28+).
	// Container-level SecurityContext is processed last so it can override
	// a pod-level entry for the same profile name.
	profiles := collectTemplateAppArmorProfiles(pod.Annotations, pod.Spec)
	for _, profile := range profiles {
		newPod.AppArmorProfiles[profile] = strings.HasPrefix(profile, kloudknoxProfilePrefix)
	}

	// Set cgroup paths for pod
	newPod.CgroupPath = podCgroupPath(pod)

	// Get security policies for the pod
	knox.GlobalData.RuntimePoliciesLock.RLock()
	if policies, exists := knox.GlobalData.RuntimePolicies[newPod.NamespaceName]; exists {
		for _, policy := range policies {
			if policyMatchesPod(policy, newPod) {
				newPod.RuntimePolicies = append(newPod.RuntimePolicies, policy)
			}
		}
	}
	knox.GlobalData.RuntimePoliciesLock.RUnlock()

	// Build file, network, capability, and IPC rules
	newPod.FileRules = buildFileRules(newPod)
	newPod.NetworkRules = buildNetworkRules(newPod)
	newPod.CapabilityRules = buildCapabilityRules(newPod)
	newPod.IPCRules = buildIPCRules(newPod)

	return newPod
}

// podCgroupPath returns the cgroup path for a given pod
func podCgroupPath(pod *corev1.Pod) string {
	uid := strings.ReplaceAll(string(pod.UID), "-", "_")
	qos := pod.Status.QOSClass

	switch qos {
	case corev1.PodQOSGuaranteed:
		return fmt.Sprintf(
			"%s/kubepods.slice/kubepods-pod%s.slice",
			cfg.GlobalCfg.CgroupDir,
			uid,
		)
	case corev1.PodQOSBurstable:
		return fmt.Sprintf(
			"%s/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod%s.slice",
			cfg.GlobalCfg.CgroupDir,
			uid,
		)
	case corev1.PodQOSBestEffort:
		return fmt.Sprintf(
			"%s/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod%s.slice",
			cfg.GlobalCfg.CgroupDir,
			uid,
		)
	default:
		return ""
	}
}

// deletePod handles the deletion of a pod
func (k8s *K8sHandler) deletePod(knox *KloudKnox, obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}

	// Delete pod
	knox.GlobalData.PodsLock.Lock()
	deletedPod, exists := knox.GlobalData.Pods[pod.Namespace+"/"+pod.Name]
	if !exists {
		knox.GlobalData.PodsLock.Unlock()
		log.Debugf("Pod %s/%s not found in GlobalData, skipping cleanup", pod.Namespace, pod.Name)
		return
	}
	delete(knox.GlobalData.Pods, pod.Namespace+"/"+pod.Name)
	knox.GlobalData.PodsLock.Unlock()

	// Remove IP entry
	knox.GlobalData.IPMapLock.Lock()
	delete(knox.GlobalData.IPMap, deletedPod.PodIP)
	knox.GlobalData.IPMapLock.Unlock()

	if deletedPod.NodeName == cfg.GlobalCfg.Node {
		if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
			// Unregister AppArmor profiles
			for profile, action := range deletedPod.AppArmorProfiles {
				if action {
					if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(profile); err != nil {
						log.Errf("Failed to unregister AppArmor profile %s: %v", profile, err)
					}
				}
			}

			// Detach Network Enforcer
			if err := knox.RuntimeEnforcer.DetachNetworkEnforcer(deletedPod); err != nil {
				log.Errf("Failed to detach Network Enforcer from pod %s: %v", deletedPod.PodName, err)
			}
		}

		if len(deletedPod.RuntimePolicies) != 0 {
			// Remove security policies for the pod
			deletedPod.RuntimePolicies = []tp.KloudKnoxPolicy{}
			deletedPod.FileRules = tp.FileRules{}
			deletedPod.NetworkRules = tp.NetworkRules{}

			// Enforce security policies for the pod
			if err := knox.RuntimeEnforcer.EnforceSecurityPolicies(deletedPod); err != nil {
				log.Errf("Failed to enforce security policies for pod %s: %v", deletedPod.PodName, err)
			}

			if len(deletedPod.RuntimePolicies) == 1 {
				log.Printf("Removed 1 security policy from pod %s/%s", deletedPod.NamespaceName, deletedPod.PodName)
			} else if len(deletedPod.RuntimePolicies) > 1 {
				log.Printf("Removed %d security policies from pod %s/%s", len(deletedPod.RuntimePolicies), deletedPod.NamespaceName, deletedPod.PodName)
			}
		}

		// BPF-LSM GC: remove cgroup from managed_cgroups and wipe all per-pod
		// map entries. Runs unconditionally (covers the RuntimePolicies==0 case
		// and finalises the managed_cgroups entry that UpdateBPFMaps left behind).
		if knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "bpf" {
			if err := knox.RuntimeEnforcer.DetachBpfEnforcer(deletedPod); err != nil {
				log.Errf("Failed to detach BPF Enforcer from pod %s: %v", deletedPod.PodName, err)
			}
		}
	}

	// Trigger reconciliation as the deleted pod might have been a target for existing policies
	k8s.reconcileNetworkPolicies(knox)

	log.Printf("pod=%s/%s event=removed", pod.Namespace, pod.Name)
}

// reconcileNetworkPolicies re-evaluates network policies for all local pods
func (k8s *K8sHandler) reconcileNetworkPolicies(knox *KloudKnox) {
	reconcileNetworkPoliciesGlobal(knox)
}

// reconcileNetworkPoliciesGlobal is the shared implementation used by both
// the K8s watcher and the Docker-mode policy loader.
func reconcileNetworkPoliciesGlobal(knox *KloudKnox) {
	localPods := []tp.Pod{}

	knox.GlobalData.PodsLock.RLock()
	for _, pod := range knox.GlobalData.Pods {
		if pod.NodeName == cfg.GlobalCfg.Node {
			localPods = append(localPods, pod)
		}
	}
	knox.GlobalData.PodsLock.RUnlock()

	for _, pod := range localPods {
		// Only reconcile pods that have network policies
		if len(pod.RuntimePolicies) == 0 {
			continue
		}

		// Re-build rules as they might depend on other pods' IPs (via selectors).
		// Use the stale copy's RuntimePolicies — those are what determine the rules.
		newFileRules := buildFileRules(pod)
		newNetworkRules := buildNetworkRules(pod)
		newCapRules := buildCapabilityRules(pod)
		newIPCRules := buildIPCRules(pod)

		// Merge only the rebuilt rules into the current (possibly updated) pod to
		// avoid overwriting concurrent changes made between the snapshot and here.
		knox.GlobalData.PodsLock.Lock()
		current, exists := knox.GlobalData.Pods[pod.NamespaceName+"/"+pod.PodName]
		if !exists {
			knox.GlobalData.PodsLock.Unlock()
			continue
		}
		current.FileRules = newFileRules
		current.NetworkRules = newNetworkRules
		current.CapabilityRules = newCapRules
		current.IPCRules = newIPCRules
		knox.GlobalData.Pods[pod.NamespaceName+"/"+pod.PodName] = current
		knox.GlobalData.PodsLock.Unlock()

		// Enforce security policies for the pod (this updates BPF maps)
		if err := knox.RuntimeEnforcer.EnforceSecurityPolicies(current); err != nil {
			log.Errf("Failed to reconcile security policies for pod %s: %v", current.PodName, err)
		}
	}
}

// Service

// watchServices sets up a watcher for Kubernetes services
func (k8s *K8sHandler) watchServices(knox *KloudKnox) {
	k8s.createInformer(
		"services",
		k8s.clientSet.CoreV1().RESTClient(),
		&corev1.Service{},
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { k8s.addService(knox, obj) },
			UpdateFunc: func(_, newObj any) { k8s.updateService(knox, newObj) },
			DeleteFunc: func(obj any) { k8s.deleteService(knox, obj) },
		},
		knox,
	)
}

// addService handles the addition of a new service
func (k8s *K8sHandler) addService(knox *KloudKnox, obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return
	}

	newService := convertService(svc)

	// Update service
	knox.GlobalData.ServicesLock.Lock()
	knox.GlobalData.Services[newService.NamespaceName+"/"+newService.ServiceName] = newService
	knox.GlobalData.ServicesLock.Unlock()

	// Update IP entry
	knox.GlobalData.IPMapLock.Lock()
	for _, clusterIP := range newService.ClusterIPs {
		knox.GlobalData.IPMap[clusterIP] = tp.IPEntry{Type: "service", Service: newService}
	}
	for _, externalIP := range newService.ExternalIPs {
		knox.GlobalData.IPMap[externalIP] = tp.IPEntry{Type: "service", Service: newService}
	}
	knox.GlobalData.IPMapLock.Unlock()

	// Trigger reconciliation as this new service might be a target for existing policies
	k8s.reconcileNetworkPolicies(knox)

	log.Printf("service=%s/%s event=added", newService.NamespaceName, newService.ServiceName)
}

// updateService handles the update of an existing service
func (k8s *K8sHandler) updateService(knox *KloudKnox, obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return
	}

	newService := convertService(svc)

	// Update service
	knox.GlobalData.ServicesLock.Lock()
	knox.GlobalData.Services[newService.NamespaceName+"/"+newService.ServiceName] = newService
	knox.GlobalData.ServicesLock.Unlock()

	// Update IP entry
	knox.GlobalData.IPMapLock.Lock()
	for _, clusterIP := range newService.ClusterIPs {
		knox.GlobalData.IPMap[clusterIP] = tp.IPEntry{Type: "service", Service: newService}
	}
	for _, externalIP := range newService.ExternalIPs {
		knox.GlobalData.IPMap[externalIP] = tp.IPEntry{Type: "service", Service: newService}
	}
	knox.GlobalData.IPMapLock.Unlock()

	// Trigger reconciliation as this updated service might be a target for existing policies
	k8s.reconcileNetworkPolicies(knox)

	log.Printf("service=%s/%s event=updated", newService.NamespaceName, newService.ServiceName)
}

// convertService converts a Kubernetes service to our internal service type
func convertService(svc *corev1.Service) tp.Service {
	clusterIPs := []string{}
	externalIPs := []string{}
	ports := []tp.ServicePort{}

	// Get cluster IPs
	clusterIPs = append(clusterIPs, svc.Spec.ClusterIPs...)

	// Get external IPs
	if svc.Status.LoadBalancer.Ingress != nil {
		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				externalIPs = append(externalIPs, ingress.IP)
			}
		}
	}

	// Get ports
	for _, port := range svc.Spec.Ports {
		servicePort := tp.ServicePort{
			Name:       port.Name,
			Protocol:   string(port.Protocol),
			Port:       int(port.Port),
			TargetPort: int(port.TargetPort.IntVal),
		}

		if port.NodePort != 0 {
			servicePort.NodePort = int(port.NodePort)
		}

		ports = append(ports, servicePort)
	}

	// A KloudKnoxPolicy selector matches the *target pods* of a Service,
	// not the Service object itself — e2e Services in this repo (and most
	// real-world cases) leave metadata.labels empty. Use spec.selector so
	// that a Service's ClusterIP resolves to the same identity set as the
	// pods it fronts; this lets peer-selector network policies install
	// ClusterIP entries in the BPF map alongside pod IPs.
	return tp.Service{
		NamespaceName: svc.Namespace,
		ServiceName:   svc.Name,
		Annotations:   svc.Annotations,
		Labels:        svc.Labels,
		Identities:    lib.ConvertKVsToString(svc.Spec.Selector),
		Type:          string(svc.Spec.Type),
		ClusterIPs:    clusterIPs,
		ExternalIPs:   externalIPs,
		Ports:         ports,
	}
}

// deleteService handles the deletion of a service
func (k8s *K8sHandler) deleteService(knox *KloudKnox, obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return
	}

	// Delete service
	knox.GlobalData.ServicesLock.Lock()
	deletedService := knox.GlobalData.Services[svc.Namespace+"/"+svc.Name]
	delete(knox.GlobalData.Services, svc.Namespace+"/"+svc.Name)
	knox.GlobalData.ServicesLock.Unlock()

	// Remove IP entry
	knox.GlobalData.IPMapLock.Lock()
	for _, clusterIP := range deletedService.ClusterIPs {
		delete(knox.GlobalData.IPMap, clusterIP)
	}
	for _, externalIP := range deletedService.ExternalIPs {
		delete(knox.GlobalData.IPMap, externalIP)
	}
	knox.GlobalData.IPMapLock.Unlock()

	// Trigger reconciliation as the deleted service might have been a target for existing policies
	k8s.reconcileNetworkPolicies(knox)

	log.Printf("Removed a service (%s/%s)", svc.Namespace, svc.Name)
}
