// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	lib "github.com/boanlab/KloudKnox/KloudKnox/common"
	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"

	"github.com/containerd/containerd/api/events"
	pb "github.com/containerd/containerd/api/services/containers/v1"
	pe "github.com/containerd/containerd/api/services/events/v1"
	pt "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl/v2"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	// Blank import to register containerd types with the typeurl registry
	_ "github.com/containerd/containerd/api/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// init registers the OpenContainer runtime specification types with containerd's type system
func init() {
	major := strconv.Itoa(specs.VersionMajor)
	typeurl.Register(&specs.Spec{}, "types.containerd.io", "opencontainers/runtime-spec", major, "Spec")
	typeurl.Register(&specs.Process{}, "types.containerd.io", "opencontainers/runtime-spec", major, "Process")
}

// ContainerdHandler manages the connection and operations with the containerd daemon
type ContainerdHandler struct {
	// Context for managing lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	// gRPC connection to the containerd daemon
	conn *grpc.ClientConn

	// Client for container lifecycle management
	containerClient pb.ContainersClient

	// Client for container process management
	taskClient pt.TasksClient

	// Client for containerd events
	eventClient pe.EventsClient

	// Base context for containerd operations
	source context.Context
}

// NewContainerdHandler creates and initializes a new containerd handler instance
func NewContainerdHandler(knox *KloudKnox) *ContainerdHandler {
	ctx, cancel := context.WithCancel(context.Background())

	ch := &ContainerdHandler{
		ctx:    ctx,
		cancel: cancel,
	}

	// Create connection context with timeout (10 seconds)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()

	// Use grpc.DialContext with modern credentials API
	conn, err := grpc.DialContext( //nolint:staticcheck
		dialCtx,
		cfg.GlobalCfg.CRISocket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), //nolint:staticcheck
	)
	if err != nil {
		log.Errf("Failed to connect to containerd at %s: %v", cfg.GlobalCfg.CRISocket, err)
		ch.cancel()
		return nil
	}
	ch.conn = conn

	// Initialize container client
	ch.containerClient = pb.NewContainersClient(ch.conn)

	// Initialize task client
	ch.taskClient = pt.NewTasksClient(ch.conn)

	// Initialize event client
	ch.eventClient = pe.NewEventsClient(ch.conn)

	// Set up namespace for containerd (usually "k8s.io" for Kubernetes)
	ch.source = namespaces.WithNamespace(ch.ctx, "k8s.io")

	log.Print("Initialized Containerd Handler")

	// Start watching containerd events
	knox.WgDaemon.Add(1)
	go func() {
		defer knox.WgDaemon.Done()
		ch.WatchEvents(knox)
	}()

	return ch
}

// Close terminates the containerd connection and cleans up resources
func (ch *ContainerdHandler) Close() {
	if ch.conn != nil {
		// Cancel context to stop all goroutines
		ch.cancel()

		if err := ch.conn.Close(); err != nil {
			log.Debugf("Failed to close gRPC connection: %v", err)
		}
		ch.conn = nil
		log.Print("Stopped Containerd Handler")
	}
}

// parseImageInfo efficiently parses image information using string operations
func parseImageInfo(image string) (name, tag string) {
	if image == "" {
		return "", ""
	}

	// Find : symbol for tag
	colonIndex := strings.LastIndex(image, ":")
	if colonIndex == -1 {
		return image, "latest"
	}

	return image[:colonIndex], image[colonIndex+1:]
}

// getNetworkInterfaces retrieves network interface information using netlink
func getNetworkInterfaces(pid uint32) ([]tp.NetworkInterface, error) {
	if pid == 0 {
		return nil, fmt.Errorf("invalid PID: 0")
	}

	// Get the network namespace handle for the process
	nsHandle, err := netns.GetFromPid(int(pid))
	if err != nil {
		return nil, fmt.Errorf("failed to get netns for PID %d: %w", pid, err)
	}
	defer func() { _ = nsHandle.Close() }()

	// Save current network namespace
	origns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get current netns: %w", err)
	}
	defer func() { _ = origns.Close() }()

	// Switch to container's network namespace
	if err := netns.Set(nsHandle); err != nil {
		return nil, fmt.Errorf("failed to set netns: %w", err)
	}
	defer func() { _ = netns.Set(origns) }()

	// Get all network links in the container's namespace
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list network links: %w", err)
	}

	// Pre-allocate slice with actual capacity
	interfaces := make([]tp.NetworkInterface, 0, len(links))

	for _, link := range links {
		attr := link.Attrs()
		if attr == nil {
			continue
		}

		netInterface := tp.NetworkInterface{
			IntfName:  attr.Name,
			HWAddress: attr.HardwareAddr.String(),
		}

		// Get IP addresses for this interface
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err == nil && len(addrs) > 0 {
			// Use the first IPv4 address
			netInterface.IPAddress = addrs[0].IP.String()
		}

		// Get peer name for veth pairs
		if attr.ParentIndex != 0 {
			peerLink, err := netlink.LinkByIndex(attr.ParentIndex)
			if err == nil && peerLink.Attrs() != nil {
				netInterface.PeerName = peerLink.Attrs().Name
			}
		}

		interfaces = append(interfaces, netInterface)
	}

	return interfaces, nil
}

// parseCgroupPath constructs the cgroup path
func parseCgroupPath(cgroupsPath string) string {
	if cgroupsPath == "" {
		return ""
	}

	parts := strings.Split(cgroupsPath, ":")
	if len(parts) < 3 {
		return ""
	}

	qosClass := parts[0]
	podID := parts[1]
	containerID := parts[2]

	baseDir := "/sys/fs/cgroup/kubepods.slice"

	switch {
	case strings.HasPrefix(qosClass, "kubepods-besteffort"):
		return fmt.Sprintf("%s/kubepods-besteffort.slice/%s/%s-%s.scope",
			baseDir, qosClass, podID, containerID)
	case strings.HasPrefix(qosClass, "kubepods-burstable"):
		return fmt.Sprintf("%s/kubepods-burstable.slice/%s/%s-%s.scope",
			baseDir, qosClass, podID, containerID)
	case strings.HasPrefix(qosClass, "kubepods-pod"):
		return fmt.Sprintf("%s/%s/%s-%s.scope",
			baseDir, qosClass, podID, containerID)
	default:
		return ""
	}
}

// GetContainerInfo retrieves comprehensive information about a container from containerd
func (ch *ContainerdHandler) GetContainerInfo(containerID string, pid uint32) tp.Container {
	if ch == nil || containerID == "" {
		return tp.Container{}
	}

	// Create context with timeout for API call (5 seconds)
	ctx, cancel := context.WithTimeout(ch.source, 5*time.Second)
	defer cancel()

	// Get container information from containerd
	req := pb.GetContainerRequest{ID: containerID}
	res, err := ch.containerClient.Get(ctx, &req)
	if err != nil || res.Container == nil {
		return tp.Container{}
	}

	// Create context with timeout for task API call (5 seconds)
	taskCtx, taskCancel := context.WithTimeout(ch.source, 5*time.Second)
	defer taskCancel()

	// Get process information for the container
	taskReq := pt.ListPidsRequest{ContainerID: containerID}
	taskRes, err := ch.taskClient.ListPids(taskCtx, &taskReq)
	if err != nil || len(taskRes.Processes) == 0 {
		return tp.Container{}
	}

	iface, err := typeurl.UnmarshalAny(res.Container.Spec)
	if err != nil || iface == nil {
		return tp.Container{}
	}

	spec, ok := iface.(*specs.Spec)
	if !ok || spec == nil {
		return tp.Container{}
	}

	// Initialize container with basic information
	container := tp.Container{
		NodeName:          cfg.GlobalCfg.Node,
		ContainerID:       containerID,
		RootPID:           pid,
		NetworkInterfaces: []tp.NetworkInterface{},
	}

	// Extract labels from container spec
	for key, value := range res.Container.Labels {
		switch key {
		case "io.kubernetes.pod.namespace":
			container.NamespaceName = value
		case "io.kubernetes.pod.name":
			container.PodName = value
		case "io.kubernetes.container.name":
			container.ContainerName = value
		}
	}

	if container.ContainerName == "" {
		container.ContainerName = "-"
	}

	// Extract image information
	container.ContainerImageName, container.ContainerImageTag = parseImageInfo(res.Container.Image)

	// Get PID and mount namespace information
	container.PidNS, container.MntNS, container.NetNS = lib.GetNamespaceIDs(strconv.Itoa(int(container.RootPID)))

	// Get network interfaces using netlink (more efficient than external command)
	if netInterfaces, err := getNetworkInterfaces(container.RootPID); err == nil {
		container.NetworkInterfaces = netInterfaces
	}

	// Extract and parse cgroup path from container spec
	if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
		container.CgroupPath = parseCgroupPath(spec.Linux.CgroupsPath)
	}

	// Extract AppArmor profile from container spec
	if spec.Process != nil {
		container.AppArmorProfile = spec.Process.ApparmorProfile
	}

	return container
}

// WatchEvents subscribes to and processes real-time containerd events
func (ch *ContainerdHandler) WatchEvents(knox *KloudKnox) {
	if ch == nil || ch.eventClient == nil {
		return
	}

	// Get all containers and update them before starting to watch events
	ch.syncContainers(knox)

	// Create subscription request with possible filters
	// Empty filter receives all events in the namespace
	req := &pe.SubscribeRequest{
		Filters: []string{`namespace=="k8s.io"`},
	}

	// Subscribe to events
	stream, err := ch.eventClient.Subscribe(ch.source, req)
	if err != nil {
		log.Errf("Failed to subscribe to containerd events: %v", err)
		return
	}

	log.Printf("Started to watch containerd events in namespace 'k8s.io'")

	for {
		res, err := stream.Recv()
		if err != nil {
			select {
			case <-ch.ctx.Done():
				return
			default:
				log.Errf("Failed to receive containerd event: %v", err)
				return
			}
		}

		ev, err := typeurl.UnmarshalAny(res.Event)
		if err != nil {
			log.Errf("Failed to unmarshal event %s: %v", res.Event.TypeUrl, err)
			continue
		}

		// Handle events based on type
		switch e := ev.(type) {
		case *events.TaskCreate:
			if container := ch.GetContainerInfo(e.ContainerID, e.Pid); container.ContainerID != "" {
				// Add container
				knox.GlobalData.ContainersLock.Lock()
				container.Status = "Created"
				knox.GlobalData.Containers[container.ContainerID] = container
				knox.GlobalData.ContainersLock.Unlock()

				// Update NSMap
				if container.PidNS != 0 && container.MntNS != 0 {
					nsKey := uint64(container.PidNS)<<32 | uint64(container.MntNS)
					knox.GlobalData.NsMapLock.Lock()
					knox.GlobalData.NsMap[nsKey] = container
					knox.GlobalData.NsMapLock.Unlock()
				}

				log.Printf("container=%s/%s/%s event=added state=Created",
					container.NamespaceName, container.PodName, container.ContainerName)
			}

		case *events.TaskStart:
			// Update container
			knox.GlobalData.ContainersLock.Lock()
			container, exists := knox.GlobalData.Containers[e.ContainerID]
			if !exists {
				log.Debugf("Container %s not found (TaskStart)", e.ContainerID)
				continue
			}
			container.Status = "Running"
			knox.GlobalData.Containers[e.ContainerID] = container
			knox.GlobalData.ContainersLock.Unlock()

			log.Printf("container=%s/%s/%s event=updated state=Started",
				container.NamespaceName, container.PodName, container.ContainerName)

		case *events.TaskDelete:
			// Delete container
			knox.GlobalData.ContainersLock.Lock()
			container, exists := knox.GlobalData.Containers[e.ContainerID]
			if !exists {
				log.Debugf("Container %s not found (TaskDelete)", e.ContainerID)
				knox.GlobalData.ContainersLock.Unlock()
				continue
			}
			delete(knox.GlobalData.Containers, e.ContainerID)
			knox.GlobalData.ContainersLock.Unlock()

			// Update NSMap
			if container.PidNS != 0 && container.MntNS != 0 {
				nsKey := uint64(container.PidNS)<<32 | uint64(container.MntNS)
				knox.GlobalData.NsMapLock.Lock()
				delete(knox.GlobalData.NsMap, nsKey)
				knox.GlobalData.NsMapLock.Unlock()
			}

			log.Printf("container=%s/%s/%s event=removed state=Exited",
				container.NamespaceName, container.PodName, container.ContainerName)

		default:
			// Log unhandled events for debugging
			log.Debugf("Unhandled containerd event type: %T (Topic: %s)", ev, res.Topic)
		}
	}
}

func (ch *ContainerdHandler) syncContainers(knox *KloudKnox) {
	ctx, cancel := context.WithTimeout(ch.source, 10*time.Second)
	defer cancel()

	// List all tasks
	req := &pt.ListTasksRequest{}
	resp, err := ch.taskClient.List(ctx, req)
	if err != nil {
		log.Errf("Failed to list containerd tasks: %v", err)
		return
	}

	for _, task := range resp.Tasks {
		if container := ch.GetContainerInfo(task.ID, task.Pid); container.ContainerID != "" {
			// Add container
			knox.GlobalData.ContainersLock.Lock()
			container.Status = "Running"
			knox.GlobalData.Containers[container.ContainerID] = container
			knox.GlobalData.ContainersLock.Unlock()

			// Update NSMap
			if container.PidNS != 0 && container.MntNS != 0 {
				nsKey := uint64(container.PidNS)<<32 | uint64(container.MntNS)
				knox.GlobalData.NsMapLock.Lock()
				knox.GlobalData.NsMap[nsKey] = container
				knox.GlobalData.NsMapLock.Unlock()
			}

			log.Printf("container=%s/%s/%s event=synced state=Running",
				container.NamespaceName, container.PodName, container.ContainerName)
		}
	}
}
