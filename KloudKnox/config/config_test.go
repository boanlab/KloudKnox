// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package config

import (
	"testing"
)

// =================================== //
// ==  Configuration key constants  == //
// =================================== //

func TestConfigKeyConstants(t *testing.T) {
	pairs := []struct {
		name string
		got  string
		want string
	}{
		{"ConfigCluster", ConfigCluster, "cluster"},
		{"ConfigNode", ConfigNode, "node"},
		{"ConfigSAFile", ConfigSAFile, "saFile"},
		{"ConfigCRISocket", ConfigCRISocket, "criSocket"},
		{"ConfigCgroupDir", ConfigCgroupDir, "cgroupDir"},
		{"ConfigProcDir", ConfigProcDir, "procDir"},
		{"ConfigCoverage", ConfigCoverage, "coverage"},
		{"ConfigLogLevel", ConfigLogLevel, "logLevel"},
		{"ConfigLogPath", ConfigLogPath, "logPath"},
		{"ConfigGRPCPort", ConfigGRPCPort, "grpcPort"},
		{"ConfigMode", ConfigMode, "mode"},
		{"ConfigDockerEndpoint", ConfigDockerEndpoint, "dockerEndpoint"},
		{"ConfigPolicyDir", ConfigPolicyDir, "policyDir"},
		{"ConfigDefaultNS", ConfigDefaultNS, "defaultNamespace"},
	}

	for _, p := range pairs {
		if p.got != p.want {
			t.Errorf("%s = %q, want %q", p.name, p.got, p.want)
		}
	}

	// Every key must be unique — duplicate viper keys would silently clobber.
	seen := make(map[string]string)
	for _, p := range pairs {
		if dup, ok := seen[p.got]; ok {
			t.Errorf("duplicate key %q used by both %s and %s", p.got, p.name, dup)
		}
		seen[p.got] = p.name
	}
}

// ============================ //
// ==  KloudKnoxConfig type  == //
// ============================ //

func TestKloudKnoxConfigZeroValue(t *testing.T) {
	var c KloudKnoxConfig
	if c.Cluster != "" || c.Node != "" || c.SAFile != "" || c.GRPCPort != 0 {
		t.Errorf("zero-value KloudKnoxConfig has unexpected fields: %+v", c)
	}
}

func TestKloudKnoxConfigAssignment(t *testing.T) {
	c := KloudKnoxConfig{
		Cluster:   "prod",
		Node:      "node-1",
		SAFile:    "/var/run/secrets/kubernetes.io/serviceaccount/token",
		CRISocket: "unix:///var/run/containerd/containerd.sock",
		CgroupDir: "/sys/fs/cgroup",
		ProcDir:   "/proc",
		Coverage:  "default",
		LogLevel:  "info",
		LogPath:   "stdout",
		GRPCPort:  36890,
	}

	checks := []struct {
		field, got, want string
	}{
		{"Cluster", c.Cluster, "prod"},
		{"Node", c.Node, "node-1"},
		{"SAFile", c.SAFile, "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		{"CRISocket", c.CRISocket, "unix:///var/run/containerd/containerd.sock"},
		{"CgroupDir", c.CgroupDir, "/sys/fs/cgroup"},
		{"ProcDir", c.ProcDir, "/proc"},
		{"Coverage", c.Coverage, "default"},
		{"LogLevel", c.LogLevel, "info"},
		{"LogPath", c.LogPath, "stdout"},
	}
	for _, ck := range checks {
		if ck.got != ck.want {
			t.Errorf("%s = %q, want %q", ck.field, ck.got, ck.want)
		}
	}
	if c.GRPCPort != 36890 {
		t.Errorf("GRPCPort = %d, want %d", c.GRPCPort, 36890)
	}
}

// ===================== //
// ==  GlobalCfg var  == //
// ===================== //

func TestGlobalCfgIsSettable(t *testing.T) {
	saved := GlobalCfg
	t.Cleanup(func() { GlobalCfg = saved })

	GlobalCfg = KloudKnoxConfig{
		Cluster:  "test-cluster",
		Node:     "test-node",
		GRPCPort: 12345,
	}

	if GlobalCfg.Cluster != "test-cluster" {
		t.Errorf("GlobalCfg.Cluster = %q, want %q", GlobalCfg.Cluster, "test-cluster")
	}
	if GlobalCfg.Node != "test-node" {
		t.Errorf("GlobalCfg.Node = %q, want %q", GlobalCfg.Node, "test-node")
	}
	if GlobalCfg.GRPCPort != 12345 {
		t.Errorf("GlobalCfg.GRPCPort = %d, want %d", GlobalCfg.GRPCPort, 12345)
	}
}
