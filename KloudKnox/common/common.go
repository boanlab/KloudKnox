// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ConvertKVsToString transforms a map of Kubernetes labels into a single string
func ConvertKVsToString(kvs map[string]string) string {
	if len(kvs) == 0 {
		return ""
	}

	// Create a slice to store sorted key-value pairs
	pairs := make([]string, 0, len(kvs))
	for k, v := range kvs {
		// Exclude the following keys from the identity string
		if k == "pod-template-hash" {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}

	// Sort the pairs alphabetically
	sort.Strings(pairs)

	// Join the pairs with commas
	return strings.Join(pairs, ",")
}

// IsSubset determines if one set of label identities is a subset of another by comparing key-value pairs for exact matches
func IsSubset(subset, superset string) bool {
	if subset == "" { // empty subset is always a subset of any superset
		return true
	}

	if superset == "" { // empty superset is never a subset of any subset
		return false
	}

	// Split the identity strings into maps
	subsetMap := make(map[string]string)
	supersetMap := make(map[string]string)

	// Parse subset labels
	for _, pair := range strings.Split(subset, ",") {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			subsetMap[parts[0]] = parts[1]
		}
	}

	// Parse superset labels
	for _, pair := range strings.Split(superset, ",") {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			supersetMap[parts[0]] = parts[1]
		}
	}

	// Check if all subset key-value pairs exist in superset
	for k, v := range subsetMap {
		if supersetV, exists := supersetMap[k]; !exists || supersetV != v {
			return false
		}
	}

	return true
}

// MatchExact checks if target matches any comma-separated value in filterVal
func MatchExact(target, filterVal string) bool {
	if filterVal == "" {
		return true
	}
	for _, v := range strings.Split(filterVal, ",") {
		v = strings.TrimSpace(v)
		if v != "" && target == v {
			return true
		}
	}
	return false
}

// MatchPrefix checks if target has the filterVal prefix
func MatchPrefix(target, filterVal string) bool {
	if filterVal == "" {
		return true
	}
	return strings.HasPrefix(target, filterVal)
}

// MatchSubset checks if target contains filterVal
func MatchSubset(target, filterVal string) bool {
	if filterVal == "" {
		return true
	}
	return strings.Contains(target, filterVal)
}

// GetCommandOutputWithErr executes a shell command and returns both its output and any error that occurred during execution
func GetCommandOutputWithErr(cmd string, args []string) (string, error) {
	// #nosec
	res := exec.Command(cmd, args...)
	stdin, err := res.StdinPipe()
	if err != nil {
		return "", err
	}

	if err = stdin.Close(); err != nil {
		log.Debugf("Error closing stdin %s", err)
	}

	out, err := res.CombinedOutput()
	if err != nil {
		return string(out), err
	}

	return string(out), nil
}

// RunCommandAndWaitWithErr executes a shell command and blocks until the command completes
func RunCommandAndWaitWithErr(cmd string, args []string) error {
	// #nosec
	res := exec.Command(cmd, args...)
	if err := res.Start(); err != nil {
		return err
	}

	if err := res.Wait(); err != nil {
		return err
	}

	return nil
}

// fileExists checks if a file exists at the specified path
func fileExists(path string) bool {
	// #nosec
	if _, err := os.Stat(filepath.Clean(path)); err == nil {
		return true
	}
	return false
}

// IsInK8sCluster checks if running inside a Kubernetes cluster
func IsInK8sCluster() bool {
	// Check for service account token
	if !fileExists(cfg.GlobalCfg.SAFile) {
		return false
	}

	// Check for service host
	if _, exists := os.LookupEnv("KUBERNETES_SERVICE_HOST"); !exists {
		return false
	}

	return true
}

// IsK8sLocal checks if running in a local Kubernetes environment
func IsK8sLocal() bool {
	// Get the kubeconfig path from environment variable
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		// If not set, use the default path in the user's home directory
		kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}

	// Clean and verify the path
	kubeconfig = filepath.Clean(kubeconfig)

	return fileExists(kubeconfig)
}

// InitK8sConfig initializes the Kubernetes client configuration
func InitK8sConfig() (*rest.Config, error) {
	var config *rest.Config
	var err error

	if IsInK8sCluster() {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
		}
	} else if IsK8sLocal() {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
		kubeconfig = filepath.Clean(kubeconfig)

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to get local config: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported Kubernetes environment")
	}

	return config, nil
}

var (
	namespaceRegex = regexp.MustCompile(`^(\w+):\[(\d+)\]$`)
)

// parseNamespaceInfo efficiently parses namespace information from symlink data
func parseNamespaceInfo(data string) (int64, error) {
	matches := namespaceRegex.FindStringSubmatch(data)
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid namespace format: %s", data)
	}
	return strconv.ParseInt(matches[2], 10, 64)
}

// readNamespaceID reads and parses the namespace ID from the given path
func readNamespaceID(path string, nsType string) uint32 {
	if data, err := os.Readlink(path); err == nil {
		if ns64, err := parseNamespaceInfo(data); err == nil {
			// Check for integer overflow before conversion
			if ns64 >= 0 && ns64 <= 0xFFFFFFFF { // uint32 max value
				return uint32(ns64)
			}
			log.Warnf("%s value out of range for uint32: %d", nsType, ns64)
		}
	}
	return 0
}

// GetNamespaceIDs returns the PID and mount namespace IDs for a given PID
func GetNamespaceIDs(pidStr string) (uint32, uint32, uint32) {
	// Read PID namespace information using optimized path handling
	pidNSPath := filepath.Join(cfg.GlobalCfg.ProcDir, pidStr, "ns", "pid")
	pidNS := readNamespaceID(pidNSPath, "PidNS")

	// Read mount namespace information using optimized path handling
	mntNSPath := filepath.Join(cfg.GlobalCfg.ProcDir, pidStr, "ns", "mnt")
	mntNS := readNamespaceID(mntNSPath, "MntNS")

	// Read network namespace information using optimized path handling
	netNSPath := filepath.Join(cfg.GlobalCfg.ProcDir, pidStr, "ns", "net")
	netNS := readNamespaceID(netNSPath, "NetNS")

	return pidNS, mntNS, netNS
}

// GetIfName returns the name of the interface with the given index
func GetIfName(ifIndex uint32) string {
	if ifi, err := net.InterfaceByIndex(int(ifIndex)); err == nil {
		return ifi.Name
	}
	return fmt.Sprintf("unknown(%d)", ifIndex)
}

// Uint32ToIPv4 converts a 32-bit unsigned integer to an IPv4 address string
func Uint32ToIPv4(addr uint32) string {
	ip := net.IPv4(
		byte((addr>>24)&0xFF),
		byte((addr>>16)&0xFF),
		byte((addr>>8)&0xFF),
		byte(addr&0xFF),
	)

	return ip.String()
}

// IPv4ToUint32 converts an IPv4 address string to a 32-bit unsigned integer
func IPv4ToUint32(addr string) uint32 {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}

	// big-endian / network byte order: ip[0] is most significant
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// HashStringToUint32 hashes a string to a 32-bit unsigned integer using FNV-1a
func HashStringToUint32(s string) uint32 {
	h := fnv.New32a()
	if _, err := h.Write([]byte(s)); err != nil {
		return 0
	}
	return h.Sum32()
}
