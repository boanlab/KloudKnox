// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"strings"

	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
)

// AppArmor auto-attach audit.
//
// Docker's Engine API does NOT allow changing HostConfig.SecurityOpt after
// container creation — `POST /containers/{id}/update` only accepts resource
// fields (CPU, memory, pids, restart policy). That means we cannot actually
// inject `apparmor=<profile>` at runtime. The best we can do is *visibility*:
// when a matched container starts without the expected profile, surface a
// clear warning so the operator can fix their run/compose invocation.
//
// This file is the detection + logging side of that audit. It is a no-op
// unless `autoAttachAppArmor` is enabled in config.

// hasAppArmorAttachment reports whether Docker's SecurityOpt list carries any
// explicit apparmor=... entry. The special value "apparmor=unconfined" counts
// as attached — the operator has explicitly opted out, and silently replacing
// that with our managed profile would be surprising.
func hasAppArmorAttachment(securityOpt []string) bool {
	for _, opt := range securityOpt {
		if strings.HasPrefix(strings.TrimSpace(opt), "apparmor=") {
			return true
		}
	}
	return false
}

// auditAppArmorAttachment logs a degraded-enforcement warning when a container
// carries matched policies but is missing the expected AppArmor profile in
// its SecurityOpt. Silent in these cases:
//
//   - feature disabled (`autoAttachAppArmor=false`)
//   - enforcer is not AppArmor (BPF-LSM enforcer does not need attachment)
//   - pod has no matched runtime policies (nothing to enforce in the first place)
//   - SecurityOpt already sets some apparmor=... entry (operator is in control)
//
// The warning names the profile so the fix is copy-paste.
func auditAppArmorAttachment(knox *KloudKnox, info dockerInspect, pod tp.Pod) {
	if knox.RuntimeEnforcer == nil || knox.RuntimeEnforcer.EnforcerType != "apparmor" {
		return
	}
	if len(pod.RuntimePolicies) == 0 {
		return
	}
	if hasAppArmorAttachment(info.HostConfig.SecurityOpt) {
		return
	}

	profile := ""
	for name := range pod.AppArmorProfiles {
		profile = name
		break
	}
	if profile == "" {
		return
	}

	shortID := info.ID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}

	log.Errf("AppArmor profile %s is loaded but not attached to container %s — "+
		"restart the container with --security-opt apparmor=%s (or compose "+
		"security_opt: [\"apparmor=%s\"]). Enforcement is degraded until this is fixed.",
		profile, shortID, profile, profile)
}
