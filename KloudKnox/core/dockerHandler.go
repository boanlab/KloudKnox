// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// Docker Handler

// DockerHandler watches container lifecycle events from the Docker Engine and
// mirrors each container into KloudKnox's internal Pod/Container model so that
// the enforcer / monitor / exporter code paths are identical to the Kubernetes
// mode. The handler is intentionally implemented on top of net/http over a
// Unix socket to keep the dependency graph narrow; the subset of the Engine
// API we need (/events streaming + /containers/{id}/json inspect) is stable
// across Docker 20.10+.
type DockerHandler struct {
	ctx    context.Context
	cancel context.CancelFunc

	http     *http.Client
	endpoint string // scheme://host prefix used in request URLs ("http://docker")

	// labelPolicies tracks inline policies that each container contributed via
	// `kloudknox.policy[.N].b64` labels so they can be removed cleanly on stop.
	// Keyed by container ID. See features.md §26.
	labelMu       sync.Mutex
	labelPolicies map[string][]tp.KloudKnoxPolicy
}

// NewDockerHandler dials the Docker Engine, verifies reachability, and spins
// up the background event-watch goroutine. Returns nil on error so that the
// dispatcher in KloudKnoxDaemon can abort cleanly.
func NewDockerHandler(knox *KloudKnox) *DockerHandler {
	ctx, cancel := context.WithCancel(context.Background())

	netProto, addr, err := parseDockerEndpoint(cfg.GlobalCfg.DockerEndpoint)
	if err != nil {
		log.Errf("Invalid dockerEndpoint %q: %v", cfg.GlobalCfg.DockerEndpoint, err)
		cancel()
		return nil
	}

	dh := &DockerHandler{
		ctx:      ctx,
		cancel:   cancel,
		endpoint: "http://docker",
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.Dial(netProto, addr)
				},
			},
		},
		labelPolicies: make(map[string][]tp.KloudKnoxPolicy),
	}

	// Quick liveness probe so we fail fast with a clear message rather than
	// silently never emitting events.
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pingCancel()
	if err := dh.ping(pingCtx); err != nil {
		log.Errf("Failed to reach Docker daemon at %s: %v", cfg.GlobalCfg.DockerEndpoint, err)
		cancel()
		return nil
	}

	log.Print("Initialized Docker Handler")

	knox.WgDaemon.Add(1)
	go func() {
		defer knox.WgDaemon.Done()
		dh.watch(knox)
	}()

	return dh
}

// Close cancels ongoing HTTP streams and tears down the handler.
func (dh *DockerHandler) Close() {
	if dh == nil {
		return
	}
	dh.cancel()
	log.Print("Stopped Docker Handler")
}

// parseDockerEndpoint accepts unix:// or tcp:// style endpoints and returns
// the (network, address) pair for net.Dialer.
func parseDockerEndpoint(ep string) (string, string, error) {
	u, err := url.Parse(ep)
	if err != nil {
		return "", "", err
	}
	switch u.Scheme {
	case "unix":
		if u.Path == "" {
			return "", "", fmt.Errorf("unix endpoint missing path")
		}
		return "unix", u.Path, nil
	case "tcp":
		return "tcp", u.Host, nil
	default:
		return "", "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
}

// ping issues a `GET /_ping` request — returns nil when the daemon answers 200.
func (dh *DockerHandler) ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, dh.endpoint+"/_ping", nil)
	resp, err := dh.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Engine API DTOs

// dockerEventMsg is a subset of Docker Engine event payload fields we care
// about — container lifecycle actions.
type dockerEventMsg struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// dockerInspect is a minimal shape of the /containers/{id}/json response.
type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		CgroupParent string   `json:"CgroupParent"`
		SecurityOpt  []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	State struct {
		Pid     int    `json:"Pid"`
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
	NetworkSettings struct {
		IPAddress string                        `json:"IPAddress"`
		Networks  map[string]dockerNetworkEntry `json:"Networks"`
	} `json:"NetworkSettings"`
	AppArmorProfile string `json:"AppArmorProfile"`
}

type dockerNetworkEntry struct {
	IPAddress string `json:"IPAddress"`
}

// dockerContainerSummary is the shape returned by /containers/json (list).
type dockerContainerSummary struct {
	ID string `json:"Id"`
}

// Event Watch

// watch connects to /events and translates container lifecycle messages into
// handler callbacks. Reconnects with exponential backoff when the stream drops.
func (dh *DockerHandler) watch(knox *KloudKnox) {
	// Sync current state first so the in-memory view matches reality even if
	// KloudKnox was started after the containers.
	dh.syncContainers(knox)

	backoff := time.Second
	max := 30 * time.Second

	for {
		if err := dh.streamEvents(knox); err != nil {
			select {
			case <-dh.ctx.Done():
				return
			default:
				log.Errf("Docker event stream disconnected: %v (retry in %s)", err, backoff)
				select {
				case <-dh.ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < max {
					backoff *= 2
					if backoff > max {
						backoff = max
					}
				}
				continue
			}
		}
		backoff = time.Second
	}
}

// streamEvents opens a single long-lived NDJSON stream and dispatches each
// message. Returns the error that caused the stream to close.
func (dh *DockerHandler) streamEvents(knox *KloudKnox) error {
	// Filters value is JSON-encoded map[string][]string in the Engine API.
	q := url.Values{}
	q.Set("filters", `{"type":["container"]}`)
	u := dh.endpoint + "/events?" + q.Encode()

	req, err := http.NewRequestWithContext(dh.ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := dh.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	log.Print("Started to watch Docker events")

	dec := json.NewDecoder(resp.Body)
	for {
		var msg dockerEventMsg
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		if msg.Type != "container" {
			continue
		}
		switch msg.Action {
		case "start":
			dh.onContainerStart(knox, msg.Actor.ID)
		case "die", "kill", "destroy", "stop":
			dh.onContainerStop(knox, msg.Actor.ID)
		}
	}
}

// syncContainers enumerates already-running containers at startup and
// promotes them into KloudKnox state.
func (dh *DockerHandler) syncContainers(knox *KloudKnox) {
	ctx, cancel := context.WithTimeout(dh.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dh.endpoint+"/containers/json", nil)
	if err != nil {
		log.Errf("Failed to build container list request: %v", err)
		return
	}
	resp, err := dh.http.Do(req)
	if err != nil {
		log.Errf("Failed to list containers: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		log.Errf("List containers: unexpected status %d", resp.StatusCode)
		return
	}

	var list []dockerContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Errf("Failed to decode container list: %v", err)
		return
	}
	for _, c := range list {
		dh.onContainerStart(knox, c.ID)
	}
}

// inspect retrieves the full JSON for a container. Returns zero value when
// the request fails so callers can continue with other containers.
func (dh *DockerHandler) inspect(id string) (dockerInspect, error) {
	ctx, cancel := context.WithTimeout(dh.ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		dh.endpoint+"/containers/"+id+"/json", nil)
	if err != nil {
		return dockerInspect{}, err
	}
	resp, err := dh.http.Do(req)
	if err != nil {
		return dockerInspect{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return dockerInspect{}, fmt.Errorf("status %d", resp.StatusCode)
	}

	var info dockerInspect
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return dockerInspect{}, err
	}
	return info, nil
}

// Lifecycle

// onContainerStart inspects a just-started container and registers it with
// KloudKnox's global state.
func (dh *DockerHandler) onContainerStart(knox *KloudKnox, id string) {
	info, err := dh.inspect(id)
	if err != nil {
		log.Debugf("Failed to inspect container %s: %v", id, err)
		return
	}

	// Hybrid-mode guard: if the container is managed by Kubernetes (its
	// cgroup sits under kubepods.slice), defer to the containerd/K8s
	// handlers to avoid double registration with mismatched metadata.
	if cfg.GlobalCfg.Mode == cfg.ModeHybrid {
		if strings.Contains(info.HostConfig.CgroupParent, "kubepods") {
			log.Debugf("Skipping k8s-managed container %s in docker handler", id)
			return
		}
	}

	container, pod := dh.buildPodAndContainer(info)
	if container.ContainerID == "" {
		return
	}

	// Ingest inline label policies (features.md §26) before pod matching so
	// the new container can immediately see policies it ships with itself.
	if inline := collectLabelPolicies(info); len(inline) > 0 {
		for _, p := range inline {
			upsertKloudKnoxPolicy(knox, p)
			applyKloudKnoxPolicyToPods(knox, p)
			log.Printf("Registered inline label policy %s/%s from container %s",
				p.NamespaceName, p.PolicyName, container.ContainerName)
		}
		dh.labelMu.Lock()
		dh.labelPolicies[info.ID] = inline
		dh.labelMu.Unlock()
	}

	// Register container.
	knox.GlobalData.ContainersLock.Lock()
	knox.GlobalData.Containers[container.ContainerID] = container
	knox.GlobalData.ContainersLock.Unlock()

	// NsMap entry.
	if container.PidNS != 0 && container.MntNS != 0 {
		nsKey := uint64(container.PidNS)<<32 | uint64(container.MntNS)
		knox.GlobalData.NsMapLock.Lock()
		knox.GlobalData.NsMap[nsKey] = container
		knox.GlobalData.NsMapLock.Unlock()
	}

	// Attach runtime policies whose selector matches this pod.
	pod.RuntimePolicies = matchRuntimePoliciesForPod(knox, pod)
	pod.FileRules = buildFileRules(pod)
	pod.NetworkRules = buildNetworkRules(pod)
	pod.CapabilityRules = buildCapabilityRules(pod)
	pod.IPCRules = buildIPCRules(pod)

	// Register pod.
	key := pod.NamespaceName + "/" + pod.PodName
	knox.GlobalData.PodsLock.Lock()
	knox.GlobalData.Pods[key] = pod
	knox.GlobalData.PodsLock.Unlock()

	if pod.PodIP != "" {
		knox.GlobalData.IPMapLock.Lock()
		knox.GlobalData.IPMap[pod.PodIP] = tp.IPEntry{Type: "pod", Pod: pod}
		knox.GlobalData.IPMapLock.Unlock()
	}

	if knox.RuntimeEnforcer != nil {
		if knox.RuntimeEnforcer.EnforcerType == "apparmor" {
			for profile, managed := range pod.AppArmorProfiles {
				if !managed {
					continue
				}
				if err := knox.RuntimeEnforcer.RegisterAppArmorProfile(profile); err != nil {
					log.Errf("Failed to register AppArmor profile %s: %v", profile, err)
				}
			}
			if err := knox.RuntimeEnforcer.AttachNetworkEnforcer(pod); err != nil {
				log.Errf("Failed to attach Network Enforcer to pod %s: %v", pod.PodName, err)
			}
		}
		if len(pod.RuntimePolicies) != 0 {
			if err := knox.RuntimeEnforcer.EnforceSecurityPolicies(pod); err != nil {
				log.Errf("Failed to enforce security policies for pod %s: %v", pod.PodName, err)
			}
		}
	}

	if cfg.GlobalCfg.AutoAttachAppArmor {
		auditAppArmorAttachment(knox, info, pod)
	}

	log.Printf("container=%s/%s/%s event=added state=%s",
		container.NamespaceName, container.PodName, container.ContainerName, container.Status)
}

// onContainerStop removes container state from KloudKnox and detaches any
// enforcer resources.
func (dh *DockerHandler) onContainerStop(knox *KloudKnox, id string) {
	knox.GlobalData.ContainersLock.Lock()
	container, ok := knox.GlobalData.Containers[id]
	if !ok {
		knox.GlobalData.ContainersLock.Unlock()
		return
	}
	delete(knox.GlobalData.Containers, id)
	knox.GlobalData.ContainersLock.Unlock()

	if container.PidNS != 0 && container.MntNS != 0 {
		nsKey := uint64(container.PidNS)<<32 | uint64(container.MntNS)
		knox.GlobalData.NsMapLock.Lock()
		delete(knox.GlobalData.NsMap, nsKey)
		knox.GlobalData.NsMapLock.Unlock()
	}

	key := container.NamespaceName + "/" + container.PodName
	knox.GlobalData.PodsLock.Lock()
	deletedPod, had := knox.GlobalData.Pods[key]
	delete(knox.GlobalData.Pods, key)
	knox.GlobalData.PodsLock.Unlock()

	if had && deletedPod.PodIP != "" {
		knox.GlobalData.IPMapLock.Lock()
		delete(knox.GlobalData.IPMap, deletedPod.PodIP)
		knox.GlobalData.IPMapLock.Unlock()
	}

	if had && knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "apparmor" {
		for profile, managed := range deletedPod.AppArmorProfiles {
			if !managed {
				continue
			}
			if err := knox.RuntimeEnforcer.UnregisterAppArmorProfile(profile); err != nil {
				log.Errf("Failed to unregister AppArmor profile %s: %v", profile, err)
			}
		}
		if err := knox.RuntimeEnforcer.DetachNetworkEnforcer(deletedPod); err != nil {
			log.Errf("Failed to detach Network Enforcer from pod %s: %v", deletedPod.PodName, err)
		}
	}

	if had && knox.RuntimeEnforcer != nil && knox.RuntimeEnforcer.EnforcerType == "bpf" {
		if err := knox.RuntimeEnforcer.DetachNetworkEnforcer(deletedPod); err != nil {
			log.Errf("Failed to detach Network Enforcer from pod %s: %v", deletedPod.PodName, err)
		}
		if err := knox.RuntimeEnforcer.DetachBpfEnforcer(deletedPod); err != nil {
			log.Errf("Failed to detach BPF Enforcer from pod %s: %v", deletedPod.PodName, err)
		}
	}

	// Tear down any inline label policies this container contributed.
	dh.labelMu.Lock()
	inline := dh.labelPolicies[id]
	delete(dh.labelPolicies, id)
	dh.labelMu.Unlock()
	for _, p := range inline {
		removeKloudKnoxPolicy(knox, p)
		removeKloudKnoxPolicyFromPods(knox, p)
		log.Printf("Removed inline label policy %s/%s with container %s",
			p.NamespaceName, p.PolicyName, container.ContainerName)
	}

	log.Printf("container=%s/%s/%s event=removed",
		container.NamespaceName, container.PodName, container.ContainerName)
}

// Pod Mapping

// buildPodAndContainer converts a docker inspect payload into KloudKnox's
// tp.Container and tp.Pod types. The rules follow features.md §27.2.
func (dh *DockerHandler) buildPodAndContainer(info dockerInspect) (tp.Container, tp.Pod) {
	if info.ID == "" || info.State.Pid <= 0 || info.State.Pid > math.MaxUint32 {
		return tp.Container{}, tp.Pod{}
	}

	name := strings.TrimPrefix(info.Name, "/")
	labels := info.Config.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	ns := labels["kloudknox.namespace"]
	if ns == "" {
		ns = cfg.GlobalCfg.DefaultNS
		if ns == "" {
			ns = "docker"
		}
	}

	imageName, imageTag := parseDockerImageInfo(info.Config.Image)
	if imageName == "" {
		imageName, imageTag = parseDockerImageInfo(info.Image)
	}

	shortID := info.ID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}

	profile := labels["kloudknox.profile.name"]
	if profile == "" {
		profile = fmt.Sprintf("kloudknox-docker-%s", shortID)
	}

	container := tp.Container{
		NodeName:           cfg.GlobalCfg.Node,
		NamespaceName:      ns,
		PodName:            name,
		ContainerID:        info.ID,
		ContainerName:      name,
		ContainerImageName: imageName,
		ContainerImageTag:  imageTag,
		Status:             dockerStatus(info),
		RootPID:            uint32(info.State.Pid),
		CgroupPath:         lib.DockerCgroupPath(info.ID, info.HostConfig.CgroupParent),
		AppArmorProfile:    profile,
	}
	container.PidNS, container.MntNS, container.NetNS =
		lib.GetNamespaceIDs(strconv.Itoa(info.State.Pid))

	// Build identity string for selector matching (§29).
	identityKVs := make(map[string]string, len(labels)+4)
	for k, v := range labels {
		identityKVs[k] = v
	}
	identityKVs["docker.image"] = info.Config.Image
	identityKVs["docker.name"] = name
	if imageName != "" {
		identityKVs["image"] = info.Config.Image
	}
	if p := labels["com.docker.compose.project"]; p != "" {
		identityKVs["docker.compose.project"] = p
	}
	if s := labels["com.docker.compose.service"]; s != "" {
		identityKVs["docker.compose.service"] = s
	}

	pod := tp.Pod{
		NamespaceName:    ns,
		PodName:          name,
		NodeName:         cfg.GlobalCfg.Node,
		Annotations:      map[string]string{},
		Labels:           labels,
		Identities:       lib.ConvertKVsToString(identityKVs),
		PodIP:            primaryIP(info),
		Containers:       map[string]string{info.ID: name},
		AppArmorProfiles: map[string]bool{profile: true},
		CgroupPath:       container.CgroupPath,
		RuntimePolicies:  []tp.KloudKnoxPolicy{},
	}

	return container, pod
}

func dockerStatus(info dockerInspect) string {
	if info.State.Running {
		return "Running"
	}
	if info.State.Status != "" {
		// Capitalize to match containerd handler conventions ("Created", "Running", ...).
		return strings.ToUpper(info.State.Status[:1]) + info.State.Status[1:]
	}
	return "Unknown"
}

func primaryIP(info dockerInspect) string {
	if info.NetworkSettings.IPAddress != "" {
		return info.NetworkSettings.IPAddress
	}
	// Pick the first network entry deterministically (sorted by name) to keep
	// IPMap assignments stable across restarts.
	names := make([]string, 0, len(info.NetworkSettings.Networks))
	for k := range info.NetworkSettings.Networks {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		if ip := info.NetworkSettings.Networks[n].IPAddress; ip != "" {
			return ip
		}
	}
	return ""
}

// parseDockerImageInfo splits "repo:tag" or "repo@sha256:..." into (name, tag).
// Falls back to "latest" when no tag is specified. Handles registry ports
// (e.g. "localhost:5000/foo") so the colon inside the authority is not
// mistaken for a tag separator.
func parseDockerImageInfo(image string) (string, string) {
	if image == "" {
		return "", ""
	}
	if at := strings.Index(image, "@"); at != -1 {
		return image[:at], image[at+1:]
	}
	colon := strings.LastIndex(image, ":")
	if colon == -1 {
		return image, "latest"
	}
	// Guard against a port number in a registry host ("repo:5000/image").
	if strings.Contains(image[colon:], "/") {
		return image, "latest"
	}
	return image[:colon], image[colon+1:]
}

// matchRuntimePoliciesForPod returns the subset of cached policies that apply
// to the given pod — either via selector subset match or via ApplyToAll in
// docker/hybrid mode. Used when a container appears after policies have
// already been loaded.
func matchRuntimePoliciesForPod(knox *KloudKnox, pod tp.Pod) []tp.KloudKnoxPolicy {
	matched := []tp.KloudKnoxPolicy{}
	knox.GlobalData.RuntimePoliciesLock.RLock()
	defer knox.GlobalData.RuntimePoliciesLock.RUnlock()

	if policies, ok := knox.GlobalData.RuntimePolicies[pod.NamespaceName]; ok {
		for _, p := range policies {
			if policyMatchesPod(p, pod) {
				matched = append(matched, p)
			}
		}
	}
	return matched
}

// validDockerSelectorKey matches the selector key forms accepted by the
// docker.* convention in §28 (e.g. "docker.image", "docker.compose.project").
var validDockerSelectorKey = regexp.MustCompile(`^docker\.[a-z][a-z0-9._-]*$`)

// IsValidDockerSelectorKey is exported so webhook validation can reuse the
// same regex.
func IsValidDockerSelectorKey(k string) bool {
	return validDockerSelectorKey.MatchString(k)
}
