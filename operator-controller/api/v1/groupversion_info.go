// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package v1 contains API Schema definitions for the security v1 API group.
// +kubebuilder:object:generate=true
// +groupName=security.boanlab.com
package v1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion identifies the API group and version served by this package.
	GroupVersion = schema.GroupVersion{Group: "security.boanlab.com", Version: "v1"}
	// SchemeBuilder registers the package's types with a runtime.Scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	// AddToScheme is a shorthand for SchemeBuilder.AddToScheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
