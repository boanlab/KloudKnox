// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package core

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	cfg "github.com/boanlab/KloudKnox/KloudKnox/config"
	"github.com/boanlab/KloudKnox/KloudKnox/log"
	tp "github.com/boanlab/KloudKnox/KloudKnox/types"
	securityv1 "github.com/boanlab/KloudKnox/operator/api/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

// Docker label inline policy channel (features.md §26). A container can
// carry one or more KloudKnoxPolicy definitions directly on its labels:
//
//	kloudknox.policy.b64      = <base64 YAML>     // single-policy shorthand
//	kloudknox.policy.0.b64    = <base64 YAML>     // numbered for multi-policy
//	kloudknox.policy.1.b64    = <base64 YAML>
//
// Policies are registered in GlobalData.RuntimePolicies under a
// per-container UID and removed when the container dies. When a policy
// omits selector, it is auto-scoped to the owning container via
// docker.name, so sibling compose services are not accidentally enrolled.

const (
	labelPolicySingle = "kloudknox.policy.b64"
	labelPolicyPrefix = "kloudknox.policy."
	labelPolicySuffix = ".b64"
)

// isLabelPolicyKey reports whether a container label key carries an inline
// policy payload. The single form (`kloudknox.policy.b64`) is accepted
// alongside the numbered form (`kloudknox.policy.<n>.b64`).
func isLabelPolicyKey(k string) bool {
	if k == labelPolicySingle {
		return true
	}
	return strings.HasPrefix(k, labelPolicyPrefix) && strings.HasSuffix(k, labelPolicySuffix)
}

// collectLabelPolicies decodes every inline policy carried by the given
// container and returns the converted internal representation. Individual
// parse failures are logged and skipped so a single bad label cannot block
// container registration.
func collectLabelPolicies(info dockerInspect) []tp.KloudKnoxPolicy {
	labels := info.Config.Labels
	if len(labels) == 0 {
		return nil
	}

	keys := make([]string, 0)
	for k := range labels {
		if isLabelPolicyKey(k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys) // deterministic upsert order

	shortID := info.ID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	containerName := strings.TrimPrefix(info.Name, "/")

	out := make([]tp.KloudKnoxPolicy, 0, len(keys))
	for _, k := range keys {
		p, err := decodeLabelPolicy(labels[k])
		if err != nil {
			log.Errf("container %s: label %s: %v", shortID, k, err)
			continue
		}

		// Default namespace — prefer the container's explicit namespace
		// label, then the daemon's default.
		if p.Namespace == "" {
			if ns := labels["kloudknox.namespace"]; ns != "" {
				p.Namespace = ns
			} else if ns := cfg.GlobalCfg.DefaultNS; ns != "" {
				p.Namespace = ns
			} else {
				p.Namespace = "docker"
			}
		}

		// Auto-scope selector-less policies to the owning container so
		// sibling compose services do not inherit them implicitly. Users
		// that want sibling scope set an explicit selector (e.g.
		// docker.compose.project: shop). Done before ValidateSpec so the
		// selector-must-be-non-empty check does not reject inline policies
		// that intentionally elide a selector.
		if len(p.Spec.Selector) == 0 {
			p.Spec.Selector = map[string]string{"docker.name": containerName}
		}

		if err := securityv1.ValidateSpec(&p.Spec); err != nil {
			log.Errf("container %s: label %s: spec invalid: %v", shortID, k, err)
			continue
		}

		// Prefix the policy name with the short ID so two containers that
		// ship the same label-encoded policy do not collide in the global
		// RuntimePolicies map (which dedups by policy name).
		p.Name = shortID + "-" + p.Name

		// Deterministic UID per (container, label) — matches features.md §26.2.
		p.UID = k8stypes.UID(fmt.Sprintf("docker-label:%s:%s", info.ID, k))

		out = append(out, convertKloudKnoxPolicy(&p))
	}
	return out
}

// decodeLabelPolicy performs the format-only parse of a single label value:
// base64 → YAML → KloudKnoxPolicy with a Kind/Name sanity check. Selector and
// rule validation is intentionally deferred to collectLabelPolicies so that
// auto-scoping can fill in the selector before ValidateSpec runs.
func decodeLabelPolicy(encoded string) (securityv1.KloudKnoxPolicy, error) {
	var p securityv1.KloudKnoxPolicy

	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return p, fmt.Errorf("empty label value")
	}

	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return p, fmt.Errorf("not valid base64: %w", err)
	}
	if err := yaml.Unmarshal(decoded, &p); err != nil {
		return p, fmt.Errorf("YAML parse failed: %w", err)
	}
	if p.Kind != "" && p.Kind != "KloudKnoxPolicy" {
		return p, fmt.Errorf("unexpected kind %q", p.Kind)
	}
	if p.Name == "" {
		return p, fmt.Errorf("metadata.name is required")
	}
	return p, nil
}
