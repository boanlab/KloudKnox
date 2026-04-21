// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package types

// NetworkInterface represents a network interface configuration for containers and nodes
type NetworkInterface struct {
	IntfName string // Interface name in the network namespace
	PeerName string // Peer interface name for veth pairs

	IPAddress string // IPv4 address assigned to the interface
	HWAddress string // MAC address of the network interface
}

// Node represents the metadata and runtime characteristics of a Kubernetes node
type Node struct {
	ClusterName string // Kubernetes cluster identifier
	NodeName    string // Unique node identifier within the cluster

	Annotations map[string]string // Kubernetes node annotations
	Labels      map[string]string // Kubernetes node labels
	Identities  string            // Security identity string for policy enforcement

	NodeIP string // Node IP address
}

// Container represents a running container instance within a Kubernetes pod
type Container struct {
	NamespaceName string // Kubernetes namespace identifier
	PodName       string // Parent pod identifier
	NodeName      string // Host node identifier

	ContainerID        string // Unique container runtime identifier
	ContainerName      string // Container name within the pod
	ContainerImageName string // Container image repository name
	ContainerImageTag  string // Container image tag/version
	Status             string // Container status

	RootPID uint32 // PID of the container's init process
	PidNS   uint32 // PID namespace identifier
	MntNS   uint32 // Mount namespace identifier
	NetNS   uint32 // Network namespace identifier

	NetworkInterfaces []NetworkInterface // Container network interface configurations

	CgroupPath      string // Cgroup path for the container
	AppArmorProfile string // Active AppArmor security profile
}

// Pod represents a Kubernetes pod and its associated security context
type Pod struct {
	NamespaceName string // Kubernetes namespace identifier
	PodName       string // Unique pod identifier
	NodeName      string // Host node identifier

	Annotations map[string]string // Kubernetes pod annotations
	Labels      map[string]string // Kubernetes pod labels
	Identities  string            // Security identity string for policy enforcement

	PodIP  string // Pod's primary IP address
	NodeIP string // Node IP address

	Containers       map[string]string // Map of container IDs to container names
	AppArmorProfiles map[string]bool   // Map of AppArmor profiles
	CgroupPath       string

	RuntimePolicies []KloudKnoxPolicy // List of runtime policies applied to the pod
	FileRules       FileRules         // List of file access rules applied to the pod
	NetworkRules    NetworkRules      // List of network access rules applied to the pod
	CapabilityRules CapabilityRules   // List of capability rules applied to the pod
	IPCRules        IPCRules          // List of IPC (unix/signal/ptrace) rules applied to the pod
}

// ServicePort represents a port of a Kubernetes service
type ServicePort struct {
	Name       string
	Protocol   string
	Port       int
	TargetPort int
	NodePort   int
}

// Service represents a Kubernetes service
type Service struct {
	NamespaceName string // Kubernetes namespace identifier
	ServiceName   string // Unique service identifier

	Annotations map[string]string // Kubernetes service annotations
	Labels      map[string]string // Kubernetes service labels
	Identities  string            // Security identity string for policy enforcement

	Type        string        // Service type
	ClusterIPs  []string      // Service IP addresses
	ExternalIPs []string      // Service external IP addresses
	Ports       []ServicePort // Service ports
}
