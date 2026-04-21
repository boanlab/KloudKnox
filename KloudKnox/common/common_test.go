// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
)

// ================================ //
// ==  ConvertKVsToString Tests  == //
// ================================ //

func TestConvertKVsToString(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
		want string
	}{
		{"nil map", nil, ""},
		{"empty map", map[string]string{}, ""},
		{"single pair", map[string]string{"app": "web"}, "app=web"},
		{
			"sorted order",
			map[string]string{"b": "2", "a": "1", "c": "3"},
			"a=1,b=2,c=3",
		},
		{
			"excludes pod-template-hash",
			map[string]string{"app": "web", "pod-template-hash": "abc123"},
			"app=web",
		},
		{
			"only pod-template-hash",
			map[string]string{"pod-template-hash": "abc123"},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertKVsToString(tt.in)
			if got != tt.want {
				t.Errorf("ConvertKVsToString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ====================== //
// ==  IsSubset Tests  == //
// ====================== //

func TestIsSubset(t *testing.T) {
	tests := []struct {
		name     string
		subset   string
		superset string
		want     bool
	}{
		{"empty subset", "", "a=1,b=2", true},
		{"empty superset non-empty subset", "a=1", "", false},
		{"both empty", "", "", true},
		{"exact match", "a=1,b=2", "a=1,b=2", true},
		{"true subset", "a=1", "a=1,b=2", true},
		{"missing key", "c=3", "a=1,b=2", false},
		{"different value", "a=2", "a=1,b=2", false},
		{"multiple matches", "a=1,b=2", "a=1,b=2,c=3", true},
		{"malformed pair ignored", "a=1", "a=1,bad", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSubset(tt.subset, tt.superset)
			if got != tt.want {
				t.Errorf("IsSubset(%q, %q) = %v, want %v", tt.subset, tt.superset, got, tt.want)
			}
		})
	}
}

// ======================== //
// ==  Match* Functions  == //
// ======================== //

func TestMatchExact(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		filterVal string
		want      bool
	}{
		{"empty filter always matches", "anything", "", true},
		{"single exact match", "foo", "foo", true},
		{"single no match", "foo", "bar", false},
		{"multi match first", "foo", "foo,bar,baz", true},
		{"multi match middle with spaces", "bar", "foo, bar ,baz", true},
		{"multi no match", "qux", "foo,bar,baz", false},
		{"empty entries skipped", "foo", ",,foo,,", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchExact(tt.target, tt.filterVal); got != tt.want {
				t.Errorf("MatchExact(%q, %q) = %v, want %v", tt.target, tt.filterVal, got, tt.want)
			}
		})
	}
}

func TestMatchPrefix(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		filterVal string
		want      bool
	}{
		{"empty filter matches", "abc", "", true},
		{"prefix match", "abcdef", "abc", true},
		{"not prefix", "xabc", "abc", false},
		{"equal string", "abc", "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchPrefix(tt.target, tt.filterVal); got != tt.want {
				t.Errorf("MatchPrefix(%q, %q) = %v, want %v", tt.target, tt.filterVal, got, tt.want)
			}
		})
	}
}

func TestMatchSubset(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		filterVal string
		want      bool
	}{
		{"empty filter matches", "hello", "", true},
		{"contains", "hello world", "lo wo", true},
		{"not contains", "hello", "xyz", false},
		{"equal string", "abc", "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchSubset(tt.target, tt.filterVal); got != tt.want {
				t.Errorf("MatchSubset(%q, %q) = %v, want %v", tt.target, tt.filterVal, got, tt.want)
			}
		})
	}
}

// ======================= //
// ==  Command helpers  == //
// ======================= //

func TestGetCommandOutputWithErr(t *testing.T) {
	out, err := GetCommandOutputWithErr("echo", []string{"hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Errorf("output = %q, want %q", strings.TrimSpace(out), "hello")
	}
}

func TestGetCommandOutputWithErrFailure(t *testing.T) {
	_, err := GetCommandOutputWithErr("/nonexistent/binary/xyzzy", nil)
	if err == nil {
		t.Error("expected error for nonexistent command, got nil")
	}
}

func TestRunCommandAndWaitWithErr(t *testing.T) {
	if err := RunCommandAndWaitWithErr("true", nil); err != nil {
		t.Errorf("unexpected error on 'true': %v", err)
	}
	if err := RunCommandAndWaitWithErr("false", nil); err == nil {
		t.Error("expected error on 'false', got nil")
	}
}

// ======================== //
// ==  fileExists Tests  == //
// ======================== //

func TestFileExists(t *testing.T) {
	tmp, err := os.CreateTemp("", "kloudknox-fileexists-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(path) }()

	if !fileExists(path) {
		t.Errorf("expected fileExists(%q) = true", path)
	}

	missing := filepath.Join(os.TempDir(), "kloudknox-missing-xyzzy-404")
	_ = os.Remove(missing)
	if fileExists(missing) {
		t.Errorf("expected fileExists(%q) = false", missing)
	}
}

// ============================== //
// ==  K8s environment probes  == //
// ============================== //

func TestIsInK8sCluster(t *testing.T) {
	// Missing SA file -> false
	cfg.GlobalCfg.SAFile = filepath.Join(os.TempDir(), "kloudknox-absent-sa-token")
	_ = os.Remove(cfg.GlobalCfg.SAFile)
	if IsInK8sCluster() {
		t.Error("expected IsInK8sCluster=false when SA file missing")
	}

	// SA file present but no KUBERNETES_SERVICE_HOST env -> false
	tmp, err := os.CreateTemp("", "kloudknox-sa-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	cfg.GlobalCfg.SAFile = tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(cfg.GlobalCfg.SAFile) }()

	orig, hadOrig := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
	defer func() {
		if hadOrig {
			_ = os.Setenv("KUBERNETES_SERVICE_HOST", orig)
		} else {
			_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
		}
	}()
	if IsInK8sCluster() {
		t.Error("expected IsInK8sCluster=false when KUBERNETES_SERVICE_HOST unset")
	}

	// Both present -> true
	_ = os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if !IsInK8sCluster() {
		t.Error("expected IsInK8sCluster=true with SA file and env set")
	}
}

func TestIsK8sLocal(t *testing.T) {
	origKube, hadKube := os.LookupEnv("KUBECONFIG")
	origHome, hadHome := os.LookupEnv("HOME")
	defer func() {
		if hadKube {
			_ = os.Setenv("KUBECONFIG", origKube)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if hadHome {
			_ = os.Setenv("HOME", origHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()

	// Pointed at an existing temp file -> true
	tmp, err := os.CreateTemp("", "kloudknox-kubeconfig-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	kubeconfig := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(kubeconfig) }()

	_ = os.Setenv("KUBECONFIG", kubeconfig)
	if !IsK8sLocal() {
		t.Error("expected IsK8sLocal=true for existing KUBECONFIG")
	}

	// Pointed at nonexistent path -> false
	_ = os.Setenv("KUBECONFIG", filepath.Join(os.TempDir(), "kloudknox-no-kubeconfig"))
	if IsK8sLocal() {
		t.Error("expected IsK8sLocal=false for missing KUBECONFIG")
	}

	// No KUBECONFIG, HOME pointing at tmpdir without ~/.kube/config -> false
	_ = os.Unsetenv("KUBECONFIG")
	tmpHome, err := os.MkdirTemp("", "kloudknox-home-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpHome) }()
	_ = os.Setenv("HOME", tmpHome)
	if IsK8sLocal() {
		t.Error("expected IsK8sLocal=false when HOME has no ~/.kube/config")
	}
}

func TestInitK8sConfigUnsupported(t *testing.T) {
	// Make both IsInK8sCluster and IsK8sLocal return false.
	cfg.GlobalCfg.SAFile = filepath.Join(os.TempDir(), "kloudknox-absent-sa-2")
	_ = os.Remove(cfg.GlobalCfg.SAFile)

	origKube, hadKube := os.LookupEnv("KUBECONFIG")
	origHome, hadHome := os.LookupEnv("HOME")
	origHost, hadHost := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	defer func() {
		if hadKube {
			_ = os.Setenv("KUBECONFIG", origKube)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
		if hadHome {
			_ = os.Setenv("HOME", origHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
		if hadHost {
			_ = os.Setenv("KUBERNETES_SERVICE_HOST", origHost)
		} else {
			_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
		}
	}()

	tmpHome, err := os.MkdirTemp("", "kloudknox-home-unsup-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpHome) }()
	_ = os.Setenv("HOME", tmpHome)
	_ = os.Setenv("KUBECONFIG", filepath.Join(tmpHome, "nope"))
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")

	c, err := InitK8sConfig()
	if err == nil || c != nil {
		t.Errorf("expected (nil, err) for unsupported env, got (%v, %v)", c, err)
	}
}

// ============================ //
// ==  Namespace ID parsing  == //
// ============================ //

func TestParseNamespaceInfo(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{"valid pid ns", "pid:[4026531836]", 4026531836, false},
		{"valid mnt ns", "mnt:[12345]", 12345, false},
		{"invalid format", "not a namespace", 0, true},
		{"missing id", "pid:[]", 0, true},
		{"missing brackets", "pid:4026531836", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNamespaceInfo(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseNamespaceInfo(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadNamespaceID(t *testing.T) {
	dir := t.TempDir()

	// Valid symlink
	ok := filepath.Join(dir, "ok")
	if err := os.Symlink("pid:[4026531836]", ok); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if got := readNamespaceID(ok, "PidNS"); got != 4026531836 {
		t.Errorf("readNamespaceID(valid) = %d, want 4026531836", got)
	}

	// Out-of-range value -> 0
	oor := filepath.Join(dir, "oor")
	if err := os.Symlink("pid:[99999999999]", oor); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if got := readNamespaceID(oor, "PidNS"); got != 0 {
		t.Errorf("readNamespaceID(out-of-range) = %d, want 0", got)
	}

	// Unreadable path -> 0
	if got := readNamespaceID(filepath.Join(dir, "missing"), "PidNS"); got != 0 {
		t.Errorf("readNamespaceID(missing) = %d, want 0", got)
	}
}

// ================== //
// ==  IP helpers  == //
// ================== //

func TestUint32ToIPv4(t *testing.T) {
	tests := []struct {
		name string
		in   uint32
		want string
	}{
		{"zero", 0, "0.0.0.0"},
		{"all ones", 0xFFFFFFFF, "255.255.255.255"},
		{"192.168.1.1", 0xC0A80101, "192.168.1.1"},
		{"10.0.0.1", 0x0A000001, "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Uint32ToIPv4(tt.in); got != tt.want {
				t.Errorf("Uint32ToIPv4(%#x) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIPv4ToUint32(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want uint32
	}{
		{"zero", "0.0.0.0", 0},
		{"192.168.1.1", "192.168.1.1", uint32(192)<<24 | uint32(168)<<16 | uint32(1)<<8 | uint32(1)},
		{"invalid ip", "not-an-ip", 0},
		{"empty string", "", 0},
		{"ipv6 returns 0", "::1", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPv4ToUint32(tt.in); got != tt.want {
				t.Errorf("IPv4ToUint32(%q) = %#x, want %#x", tt.in, got, tt.want)
			}
		})
	}
}

func TestIPv4RoundTrip(t *testing.T) {
	cases := []string{"1.2.3.4", "192.168.1.1", "10.0.0.1", "0.0.0.0", "255.255.255.255"}
	for _, addr := range cases {
		if got := Uint32ToIPv4(IPv4ToUint32(addr)); got != addr {
			t.Errorf("round-trip(%q) = %q", addr, got)
		}
	}
}

// ========================== //
// ==  HashStringToUint32  == //
// ========================== //

func TestHashStringToUint32(t *testing.T) {
	a := HashStringToUint32("kloudknox")
	b := HashStringToUint32("kloudknox")
	if a != b {
		t.Errorf("hash not deterministic: %d vs %d", a, b)
	}

	c := HashStringToUint32("different")
	if a == c {
		t.Errorf("expected distinct hashes for different inputs, both = %d", a)
	}

	// Empty string: FNV-1a 32 offset basis
	if got := HashStringToUint32(""); got != 2166136261 {
		t.Errorf("HashStringToUint32(\"\") = %d, want 2166136261", got)
	}
}

// ================= //
// ==  GetIfName  == //
// ================= //

func TestGetIfNameUnknown(t *testing.T) {
	// Use an index that is almost certainly not present on any host.
	name := GetIfName(0xFFFFFFFE)
	if !strings.HasPrefix(name, "unknown(") {
		t.Errorf("GetIfName(0xFFFFFFFE) = %q, want prefix \"unknown(\"", name)
	}
}
