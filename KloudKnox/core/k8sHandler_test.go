// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// ========================= //
// ==  convertNode Tests  == //
// ========================= //

func TestConvertNode(t *testing.T) {
	cfg.GlobalCfg.Cluster = "test-cluster"

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
			Labels: map[string]string{
				"role": "worker",
			},
			Annotations: map[string]string{
				"note": "test",
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "192.168.1.10"},
				{Type: corev1.NodeExternalIP, Address: "10.0.0.1"},
			},
		},
	}

	result := convertNode(node)

	if result.ClusterName != "test-cluster" {
		t.Errorf("ClusterName = %q, want %q", result.ClusterName, "test-cluster")
	}
	if result.NodeName != "node-1" {
		t.Errorf("NodeName = %q, want %q", result.NodeName, "node-1")
	}
	if result.NodeIP != "192.168.1.10" {
		t.Errorf("NodeIP = %q, want %q (should prefer InternalIP)", result.NodeIP, "192.168.1.10")
	}
}

func TestConvertNodeNoInternalIP(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "10.0.0.2"},
			},
		},
	}

	result := convertNode(node)

	// No InternalIP address → NodeIP should remain empty
	if result.NodeIP != "" {
		t.Errorf("NodeIP = %q, want empty when no InternalIP exists", result.NodeIP)
	}
}

// ============================== //
// ==  podCgroupPath Tests     == //
// ============================== //

func TestPodCgroupPathGuaranteed(t *testing.T) {
	cfg.GlobalCfg.CgroupDir = "/sys/fs/cgroup"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID: types.UID("aabbccdd-1122-3344-5566-778899aabbcc"),
		},
		Status: corev1.PodStatus{
			QOSClass: corev1.PodQOSGuaranteed,
		},
	}

	got := podCgroupPath(pod)
	uid := "aabbccdd_1122_3344_5566_778899aabbcc"
	want := "/sys/fs/cgroup/kubepods.slice/kubepods-pod" + uid + ".slice"

	if got != want {
		t.Errorf("podCgroupPath(Guaranteed)\ngot:  %q\nwant: %q", got, want)
	}
}

func TestPodCgroupPathBurstable(t *testing.T) {
	cfg.GlobalCfg.CgroupDir = "/sys/fs/cgroup"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-123"},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBurstable},
	}

	got := podCgroupPath(pod)
	if got == "" {
		t.Error("expected non-empty cgroup path for Burstable QOS")
	}
}

func TestPodCgroupPathBestEffort(t *testing.T) {
	cfg.GlobalCfg.CgroupDir = "/sys/fs/cgroup"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-456"},
		Status:     corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort},
	}

	got := podCgroupPath(pod)
	if got == "" {
		t.Error("expected non-empty cgroup path for BestEffort QOS")
	}
}

func TestPodCgroupPathUnknown(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-789"},
		Status:     corev1.PodStatus{}, // no QOSClass
	}

	got := podCgroupPath(pod)
	if got != "" {
		t.Errorf("expected empty cgroup path for unknown QOS, got %q", got)
	}
}

// ============================= //
// ==  convertService Tests   == //
// ============================= //

func TestConvertService(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc",
			Namespace: "default",
			Labels:    map[string]string{"app": "nginx"},
		},
		Spec: corev1.ServiceSpec{
			Type:       corev1.ServiceTypeClusterIP,
			ClusterIPs: []string{"10.96.0.1"},
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     80,
				},
			},
		},
	}

	result := convertService(svc)

	if result.ServiceName != "my-svc" {
		t.Errorf("ServiceName = %q, want my-svc", result.ServiceName)
	}
	if result.NamespaceName != "default" {
		t.Errorf("NamespaceName = %q, want default", result.NamespaceName)
	}
	if len(result.ClusterIPs) != 1 || result.ClusterIPs[0] != "10.96.0.1" {
		t.Errorf("ClusterIPs = %v, want [10.96.0.1]", result.ClusterIPs)
	}
	if len(result.Ports) != 1 || result.Ports[0].Port != 80 {
		t.Errorf("Ports = %v, expected port 80", result.Ports)
	}
}

func TestConvertServiceLoadBalancer(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "lb-svc", Namespace: "prod"},
		Spec: corev1.ServiceSpec{
			Type:       corev1.ServiceTypeLoadBalancer,
			ClusterIPs: []string{"10.96.1.1"},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{IP: "203.0.113.5"},
				},
			},
		},
	}

	result := convertService(svc)

	if len(result.ExternalIPs) != 1 || result.ExternalIPs[0] != "203.0.113.5" {
		t.Errorf("ExternalIPs = %v, want [203.0.113.5]", result.ExternalIPs)
	}
}

// suppress unused import
var _ = resource.MustParse

// ============================================== //
// ==  AppArmor SecurityContext Support Tests  == //
// ============================================== //

// ============================================== //
// ==  extractAppArmorProfileFromAnnotation    == //
// ============================================== //

func TestExtractAppArmorProfileFromAnnotation(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"localhost/kloudknox-foo", "kloudknox-foo"},
		{"localhost/runtime-default", "runtime-default"},
		{"runtime/default", "runtime/default"}, // no localhost/ prefix → unchanged
		{"", ""},
	}
	for _, c := range cases {
		got := extractAppArmorProfileFromAnnotation(c.input)
		if got != c.want {
			t.Errorf("extractAppArmorProfileFromAnnotation(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ============================================== //
// ==  extractAppArmorProfileFromSecCtx        == //
// ============================================== //

func ptrStr(s string) *string { return &s }

func TestExtractAppArmorProfileFromSecCtx_Localhost(t *testing.T) {
	p := &corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: ptrStr("kloudknox-bar"),
	}
	got := extractAppArmorProfileFromSecCtx(p)
	if got != "kloudknox-bar" {
		t.Errorf("got %q, want %q", got, "kloudknox-bar")
	}
}

func TestExtractAppArmorProfileFromSecCtx_RuntimeDefault(t *testing.T) {
	p := &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}
	if got := extractAppArmorProfileFromSecCtx(p); got != "" {
		t.Errorf("RuntimeDefault type should return \"\", got %q", got)
	}
}

func TestExtractAppArmorProfileFromSecCtx_Unconfined(t *testing.T) {
	p := &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
	if got := extractAppArmorProfileFromSecCtx(p); got != "" {
		t.Errorf("Unconfined type should return \"\", got %q", got)
	}
}

func TestExtractAppArmorProfileFromSecCtx_Nil(t *testing.T) {
	if got := extractAppArmorProfileFromSecCtx(nil); got != "" {
		t.Errorf("nil input should return \"\", got %q", got)
	}
}

func TestExtractAppArmorProfileFromSecCtx_EmptyProfileName(t *testing.T) {
	p := &corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: ptrStr(""),
	}
	if got := extractAppArmorProfileFromSecCtx(p); got != "" {
		t.Errorf("empty LocalhostProfile should return \"\", got %q", got)
	}
}

func TestExtractAppArmorProfileFromSecCtx_NilProfilePtr(t *testing.T) {
	p := &corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: nil,
	}
	if got := extractAppArmorProfileFromSecCtx(p); got != "" {
		t.Errorf("nil LocalhostProfile ptr should return \"\", got %q", got)
	}
}

// ============================================== //
// ==  collectTemplateAppArmorProfiles         == //
// ============================================== //

func TestCollectTemplateAppArmorProfiles_AnnotationOnly(t *testing.T) {
	anns := map[string]string{
		"container.apparmor.security.beta.kubernetes.io/app": "localhost/kloudknox-app",
	}
	spec := corev1.PodSpec{}
	profiles := collectTemplateAppArmorProfiles(anns, spec)
	if len(profiles) != 1 || profiles[0] != "kloudknox-app" {
		t.Errorf("got %v, want [kloudknox-app]", profiles)
	}
}

func TestCollectTemplateAppArmorProfiles_SecCtxContainerLevel(t *testing.T) {
	anns := map[string]string{}
	spec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type:             corev1.AppArmorProfileTypeLocalhost,
						LocalhostProfile: ptrStr("kloudknox-secctx"),
					},
				},
			},
		},
	}
	profiles := collectTemplateAppArmorProfiles(anns, spec)
	if len(profiles) != 1 || profiles[0] != "kloudknox-secctx" {
		t.Errorf("got %v, want [kloudknox-secctx]", profiles)
	}
}

func TestCollectTemplateAppArmorProfiles_SecCtxPodLevel(t *testing.T) {
	anns := map[string]string{}
	spec := corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			AppArmorProfile: &corev1.AppArmorProfile{
				Type:             corev1.AppArmorProfileTypeLocalhost,
				LocalhostProfile: ptrStr("kloudknox-pod"),
			},
		},
	}
	profiles := collectTemplateAppArmorProfiles(anns, spec)
	if len(profiles) != 1 || profiles[0] != "kloudknox-pod" {
		t.Errorf("got %v, want [kloudknox-pod]", profiles)
	}
}

func TestCollectTemplateAppArmorProfiles_DeduplicationBothMethods(t *testing.T) {
	// Same profile name specified via annotation AND SecurityContext → deduplicated
	anns := map[string]string{
		"container.apparmor.security.beta.kubernetes.io/app": "localhost/kloudknox-same",
	}
	spec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type:             corev1.AppArmorProfileTypeLocalhost,
						LocalhostProfile: ptrStr("kloudknox-same"),
					},
				},
			},
		},
	}
	profiles := collectTemplateAppArmorProfiles(anns, spec)
	if len(profiles) != 1 {
		t.Errorf("expected 1 deduplicated profile, got %d: %v", len(profiles), profiles)
	}
}

func TestCollectTemplateAppArmorProfiles_NonKloudknoxIgnored(t *testing.T) {
	// Non-kloudknox profiles (runtime/default, custom) must not be returned
	anns := map[string]string{
		"container.apparmor.security.beta.kubernetes.io/app": "runtime/default",
	}
	spec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "sidecar",
				SecurityContext: &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type: corev1.AppArmorProfileTypeRuntimeDefault,
					},
				},
			},
		},
	}
	profiles := collectTemplateAppArmorProfiles(anns, spec)
	if len(profiles) != 0 {
		t.Errorf("expected no kloudknox profiles, got %v", profiles)
	}
}

func TestCollectTemplateAppArmorProfiles_MultipleContainers(t *testing.T) {
	anns := map[string]string{}
	spec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type:             corev1.AppArmorProfileTypeLocalhost,
						LocalhostProfile: ptrStr("kloudknox-a"),
					},
				},
			},
			{
				Name: "sidecar",
				SecurityContext: &corev1.SecurityContext{
					AppArmorProfile: &corev1.AppArmorProfile{
						Type:             corev1.AppArmorProfileTypeLocalhost,
						LocalhostProfile: ptrStr("kloudknox-b"),
					},
				},
			},
		},
	}
	profiles := collectTemplateAppArmorProfiles(anns, spec)
	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d: %v", len(profiles), profiles)
	}
	seen := make(map[string]bool)
	for _, p := range profiles {
		seen[p] = true
	}
	if !seen["kloudknox-a"] || !seen["kloudknox-b"] {
		t.Errorf("missing expected profiles in %v", profiles)
	}
}

// ============================================== //
// ==  convertPod AppArmorProfiles population  == //
// ============================================== //

// newMinimalPod returns a minimal *corev1.Pod suitable for convertPod tests.
// It sets only fields that convertPod reads without side effects.
func newMinimalPod(namespace, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{},
		},
		Spec:   corev1.PodSpec{},
		Status: corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort},
	}
}

// newTestKnox returns a minimal *KloudKnox with initialised GlobalData,
// sufficient for convertPod calls that do not require a live K8s connection.
func newTestKnox() *KloudKnox {
	return &KloudKnox{GlobalData: tp.NewGlobalData()}
}

func TestConvertPod_AppArmorProfiles_AnnotationKloudknox(t *testing.T) {
	pod := newMinimalPod("default", "pod-ann")
	pod.Annotations["container.apparmor.security.beta.kubernetes.io/app"] = "localhost/kloudknox-ann"

	result := convertPod(newTestKnox(), pod)

	managed, ok := result.AppArmorProfiles["kloudknox-ann"]
	if !ok {
		t.Fatalf("profile kloudknox-ann not found in AppArmorProfiles: %v", result.AppArmorProfiles)
	}
	if !managed {
		t.Error("kloudknox- prefixed profile should be marked managed (true)")
	}
}

func TestConvertPod_AppArmorProfiles_AnnotationNonKloudknox(t *testing.T) {
	// Non-kloudknox profiles in annotations must not appear in AppArmorProfiles.
	// Only kloudknox-prefixed profiles are tracked in the map.
	pod := newMinimalPod("default", "pod-ann-other")
	pod.Annotations["container.apparmor.security.beta.kubernetes.io/app"] = "localhost/custom-profile"

	result := convertPod(newTestKnox(), pod)

	if _, ok := result.AppArmorProfiles["custom-profile"]; ok {
		t.Error("non-kloudknox profile must not be stored in AppArmorProfiles")
	}
	if len(result.AppArmorProfiles) != 0 {
		t.Errorf("expected empty AppArmorProfiles for non-kloudknox annotation, got %v", result.AppArmorProfiles)
	}
}

func TestConvertPod_AppArmorProfiles_SecCtxContainerLevel(t *testing.T) {
	pod := newMinimalPod("default", "pod-secctx")
	pod.Spec.Containers = []corev1.Container{
		{
			Name: "app",
			SecurityContext: &corev1.SecurityContext{
				AppArmorProfile: &corev1.AppArmorProfile{
					Type:             corev1.AppArmorProfileTypeLocalhost,
					LocalhostProfile: ptrStr("kloudknox-sc"),
				},
			},
		},
	}

	result := convertPod(newTestKnox(), pod)

	managed, ok := result.AppArmorProfiles["kloudknox-sc"]
	if !ok {
		t.Fatalf("profile kloudknox-sc not found in AppArmorProfiles: %v", result.AppArmorProfiles)
	}
	if !managed {
		t.Error("kloudknox- prefixed profile should be marked managed (true)")
	}
}

func TestConvertPod_AppArmorProfiles_SecCtxPodLevel(t *testing.T) {
	pod := newMinimalPod("default", "pod-secctx-pod")
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		AppArmorProfile: &corev1.AppArmorProfile{
			Type:             corev1.AppArmorProfileTypeLocalhost,
			LocalhostProfile: ptrStr("kloudknox-podlevel"),
		},
	}

	result := convertPod(newTestKnox(), pod)

	managed, ok := result.AppArmorProfiles["kloudknox-podlevel"]
	if !ok {
		t.Fatalf("profile kloudknox-podlevel not found in AppArmorProfiles: %v", result.AppArmorProfiles)
	}
	if !managed {
		t.Error("kloudknox- prefixed profile should be marked managed (true)")
	}
}

func TestConvertPod_AppArmorProfiles_SecCtxOverridesAnnotation(t *testing.T) {
	// Annotation and SecurityContext specify different profile names.
	// Both must appear in AppArmorProfiles.
	pod := newMinimalPod("default", "pod-both")
	pod.Annotations["container.apparmor.security.beta.kubernetes.io/app"] = "localhost/kloudknox-from-ann"
	pod.Spec.Containers = []corev1.Container{
		{
			Name: "app",
			SecurityContext: &corev1.SecurityContext{
				AppArmorProfile: &corev1.AppArmorProfile{
					Type:             corev1.AppArmorProfileTypeLocalhost,
					LocalhostProfile: ptrStr("kloudknox-from-sc"),
				},
			},
		},
	}

	result := convertPod(newTestKnox(), pod)

	if _, ok := result.AppArmorProfiles["kloudknox-from-ann"]; !ok {
		t.Errorf("annotation profile kloudknox-from-ann missing: %v", result.AppArmorProfiles)
	}
	if _, ok := result.AppArmorProfiles["kloudknox-from-sc"]; !ok {
		t.Errorf("secctx profile kloudknox-from-sc missing: %v", result.AppArmorProfiles)
	}
}

func TestConvertPod_AppArmorProfiles_SameProfileBothMethods(t *testing.T) {
	// Same profile name via both methods → single map entry, no duplicate.
	pod := newMinimalPod("default", "pod-dedup")
	pod.Annotations["container.apparmor.security.beta.kubernetes.io/app"] = "localhost/kloudknox-same"
	pod.Spec.Containers = []corev1.Container{
		{
			Name: "app",
			SecurityContext: &corev1.SecurityContext{
				AppArmorProfile: &corev1.AppArmorProfile{
					Type:             corev1.AppArmorProfileTypeLocalhost,
					LocalhostProfile: ptrStr("kloudknox-same"),
				},
			},
		},
	}

	result := convertPod(newTestKnox(), pod)

	if len(result.AppArmorProfiles) != 1 {
		t.Errorf("expected 1 deduplicated profile, got %d: %v", len(result.AppArmorProfiles), result.AppArmorProfiles)
	}
}

func TestConvertPod_AppArmorProfiles_RuntimeDefaultIgnored(t *testing.T) {
	// RuntimeDefault type must not be added to AppArmorProfiles.
	pod := newMinimalPod("default", "pod-rtdefault")
	pod.Spec.Containers = []corev1.Container{
		{
			Name: "app",
			SecurityContext: &corev1.SecurityContext{
				AppArmorProfile: &corev1.AppArmorProfile{
					Type: corev1.AppArmorProfileTypeRuntimeDefault,
				},
			},
		},
	}

	result := convertPod(newTestKnox(), pod)

	if len(result.AppArmorProfiles) != 0 {
		t.Errorf("expected no profiles for RuntimeDefault, got %v", result.AppArmorProfiles)
	}
}

func TestConvertPod_AppArmorProfiles_NilSecurityContext(t *testing.T) {
	// Container with nil SecurityContext must not panic.
	pod := newMinimalPod("default", "pod-nilsc")
	pod.Spec.Containers = []corev1.Container{
		{Name: "app", SecurityContext: nil},
	}

	// Should not panic
	result := convertPod(newTestKnox(), pod)
	if len(result.AppArmorProfiles) != 0 {
		t.Errorf("expected empty AppArmorProfiles, got %v", result.AppArmorProfiles)
	}
}
