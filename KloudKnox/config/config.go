// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package config

import (
	"fmt"
	"os"
	"strings"

	"flag"

	"github.com/boanlab/KloudKnox/KloudKnox/log"
	"github.com/spf13/viper"
)

// KloudKnoxConfig defines the main configuration structure for KloudKnox
type KloudKnoxConfig struct {
	Cluster   string // Kubernetes cluster identifier for system operation
	Node      string // Kubernetes node identifier where KloudKnox is deployed
	SAFile    string // Path to the Kubernetes service account token file
	CRISocket string // Container Runtime Interface (CRI) socket path (e.g., containerd.sock)
	CgroupDir string // Path to the cgroup directory
	ProcDir   string // Path to the /proc directory
	Coverage  string // Range of system calls to monitor (e.g., "extended", "default")
	LogLevel  string // Logging verbosity level (debug, info, warn, error)
	LogPath   string // Log output destination (file path or stdout)
	GRPCPort  int    // Port number for gRPC service endpoint

	// Standalone / Docker mode
	Mode           string // Operation mode: "kubernetes" (default), "docker", or "hybrid"
	DockerEndpoint string // Docker Engine API endpoint (unix:///var/run/docker.sock)
	PolicyDir      string // Directory watched for local KloudKnoxPolicy YAML files
	DefaultNS      string // Default namespace name used by Docker mode

	// AutoAttachAppArmor enables the audit path: when a Docker-mode container
	// starts with matching policies but no kloudknox AppArmor profile in
	// HostConfig.SecurityOpt, KloudKnox logs a degraded-enforcement warning
	// with the `--security-opt apparmor=<profile>` hint. Docker's Engine API
	// does not allow changing SecurityOpt post-create, so this is advisory
	// only — the operator must restart the container with the right flag.
	AutoAttachAppArmor bool
}

// GlobalCfg represents the application-wide configuration instance
var GlobalCfg KloudKnoxConfig

// Configuration key constants for system settings
const (
	ConfigCluster   = "cluster"   // Kubernetes cluster identifier key
	ConfigNode      = "node"      // Kubernetes node identifier key
	ConfigSAFile    = "saFile"    // Service account token file path key
	ConfigCRISocket = "criSocket" // Container Runtime Interface socket path key
	ConfigCgroupDir = "cgroupDir" // Path to the cgroup directory key
	ConfigProcDir   = "procDir"   // Path to the /proc directory key
	ConfigCoverage  = "coverage"  // System call coverage range key
	ConfigLogLevel  = "logLevel"  // Logging verbosity level key
	ConfigLogPath   = "logPath"   // Log output destination key
	ConfigGRPCPort  = "grpcPort"  // gRPC service port key

	ConfigMode               = "mode"               // Operation mode key
	ConfigDockerEndpoint     = "dockerEndpoint"     // Docker Engine endpoint key
	ConfigPolicyDir          = "policyDir"          // Policy YAML directory key
	ConfigDefaultNS          = "defaultNamespace"   // Default namespace key for Docker mode
	ConfigAutoAttachAppArmor = "autoAttachAppArmor" // Enable Docker-mode AppArmor audit warnings
)

// Mode values accepted by ConfigMode.
const (
	ModeKubernetes = "kubernetes"
	ModeDocker     = "docker"
	ModeHybrid     = "hybrid"
)

// readCmdLineParams initializes and processes command-line arguments with predefined defaults
func readCmdLineParams() bool {
	// Define command-line flags with default values and descriptions
	clusterStr := flag.String(ConfigCluster, "default", "Cluster Name")

	// Get hostname for default node name
	nodeName := os.Getenv("KLOUDKNOX_NODENAME")
	if nodeName == "" {
		if hostname, err := os.Hostname(); err == nil {
			nodeName = hostname
		} else {
			log.Errf("Failed to get hostname: %v", err)
			return false
		}
	}

	// Define all configuration flags with their default values and descriptions
	nodeStr := flag.String(ConfigNode, nodeName, "Node Name")
	saFile := flag.String(ConfigSAFile, "/var/run/secrets/kubernetes.io/serviceaccount/token", "Path to Kubernetes service account token")
	criSocket := flag.String(ConfigCRISocket, "unix:///var/run/containerd/containerd.sock", "CRI Socket Path (format: unix:///path/to/file.sock)")
	cgroupDir := flag.String(ConfigCgroupDir, "/sys/fs/cgroup", "Path to the cgroup directory")
	procDir := flag.String(ConfigProcDir, "/proc", "Path to the /proc directory")
	coverage := flag.String(ConfigCoverage, "default", "Range of system calls to monitor (e.g., 'extended', 'default')")
	logLevel := flag.String(ConfigLogLevel, "info", "Log Level (debug, info, warn, error)")
	logPath := flag.String(ConfigLogPath, "stdout", "Log Path, {stdout|path}")
	grpcPort := flag.Int(ConfigGRPCPort, 36890, "gRPC port to listen for connections")
	mode := flag.String(ConfigMode, ModeKubernetes, "Operation mode: kubernetes | docker | hybrid")
	dockerEndpoint := flag.String(ConfigDockerEndpoint, "unix:///var/run/docker.sock", "Docker Engine API endpoint (used in docker/hybrid mode)")
	policyDir := flag.String(ConfigPolicyDir, "/etc/kloudknox/policies", "Directory of KloudKnoxPolicy YAML files (used in docker/hybrid mode)")
	defaultNS := flag.String(ConfigDefaultNS, "docker", "Default namespace name for Docker-mode containers")
	autoAttachAppArmor := flag.Bool(ConfigAutoAttachAppArmor, false, "Warn when Docker-mode containers start without the expected AppArmor profile")

	// Collect all flag values for logging purposes
	flags := []string{}
	flag.VisitAll(func(f *flag.Flag) {
		kv := fmt.Sprintf("%s:%v", f.Name, f.Value)
		flags = append(flags, kv)
	})
	log.Debugf("Arguments [%s]", strings.Join(flags, " "))

	// Parse command-line arguments
	flag.Parse()

	// Initialize viper with command-line argument values as defaults
	viper.SetDefault(ConfigCluster, *clusterStr)
	viper.SetDefault(ConfigNode, *nodeStr)
	viper.SetDefault(ConfigSAFile, *saFile)
	viper.SetDefault(ConfigCRISocket, *criSocket)
	viper.SetDefault(ConfigCgroupDir, *cgroupDir)
	viper.SetDefault(ConfigProcDir, *procDir)
	viper.SetDefault(ConfigCoverage, *coverage)
	viper.SetDefault(ConfigLogLevel, *logLevel)
	viper.SetDefault(ConfigLogPath, *logPath)
	viper.SetDefault(ConfigGRPCPort, *grpcPort)
	viper.SetDefault(ConfigMode, *mode)
	viper.SetDefault(ConfigDockerEndpoint, *dockerEndpoint)
	viper.SetDefault(ConfigPolicyDir, *policyDir)
	viper.SetDefault(ConfigDefaultNS, *defaultNS)
	viper.SetDefault(ConfigAutoAttachAppArmor, *autoAttachAppArmor)

	return true
}

// LoadConfig initializes the system configuration by loading settings from multiple sources
func LoadConfig() bool {
	// Read command-line parameters first
	if !readCmdLineParams() {
		return false
	}

	// Configure and load configuration file
	viper.SetConfigName("kloudknox")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/kloudknox/")

	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}

	// Initialize global configuration with values from all sources
	GlobalCfg = KloudKnoxConfig{
		Cluster:            viper.GetString(ConfigCluster),
		Node:               viper.GetString(ConfigNode),
		SAFile:             viper.GetString(ConfigSAFile),
		CRISocket:          viper.GetString(ConfigCRISocket),
		CgroupDir:          viper.GetString(ConfigCgroupDir),
		ProcDir:            viper.GetString(ConfigProcDir),
		Coverage:           viper.GetString(ConfigCoverage),
		LogLevel:           viper.GetString(ConfigLogLevel),
		LogPath:            viper.GetString(ConfigLogPath),
		GRPCPort:           viper.GetInt(ConfigGRPCPort),
		Mode:               viper.GetString(ConfigMode),
		DockerEndpoint:     viper.GetString(ConfigDockerEndpoint),
		PolicyDir:          viper.GetString(ConfigPolicyDir),
		DefaultNS:          viper.GetString(ConfigDefaultNS),
		AutoAttachAppArmor: viper.GetBool(ConfigAutoAttachAppArmor),
	}

	switch GlobalCfg.Mode {
	case ModeKubernetes, ModeDocker, ModeHybrid:
	default:
		log.Errf("Invalid %s=%q (expected kubernetes|docker|hybrid)", ConfigMode, GlobalCfg.Mode)
		return false
	}

	// Log the final configuration for verification
	log.Printf("[Configuration] Mode: %s, Cluster: %s, Node: %s", GlobalCfg.Mode, GlobalCfg.Cluster, GlobalCfg.Node)
	log.Printf("[Configuration] SAFile: %s", GlobalCfg.SAFile)
	log.Printf("[Configuration] CRISocket: %s, DockerEndpoint: %s", GlobalCfg.CRISocket, GlobalCfg.DockerEndpoint)
	log.Printf("[Configuration] Coverage: %s, CgroupDir: %s, ProcDir: %s", GlobalCfg.Coverage, GlobalCfg.CgroupDir, GlobalCfg.ProcDir)
	log.Printf("[Configuration] gRPC: %d, LogLevel: %s, LogPath: %s", GlobalCfg.GRPCPort, GlobalCfg.LogLevel, GlobalCfg.LogPath)
	log.Printf("[Configuration] PolicyDir: %s, DefaultNS: %s", GlobalCfg.PolicyDir, GlobalCfg.DefaultNS)

	return true
}
