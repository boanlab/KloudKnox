// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package controller implements the KloudKnoxPolicy reconciliation loop.
// The reconciler validates each policy spec, normalises directory paths so
// that node-side agents receive consistent trailing-slash-terminated values,
// and updates the status subresource to reflect Active or Invalid state.
package controller

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/boanlab/KloudKnox/operator/api/v1"
)

// KloudKnoxPolicyReconciler reconciles KloudKnoxPolicy objects.
type KloudKnoxPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.boanlab.com,resources=kloudknoxpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.boanlab.com,resources=kloudknoxpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.boanlab.com,resources=kloudknoxpolicies/finalizers,verbs=update

// normalizeDir ensures dir ends with "/"; node agents require this form for
// prefix-matching to work correctly.
func normalizeDir(dir string) string {
	if dir != "" && !strings.HasSuffix(dir, "/") {
		return dir + "/"
	}
	return dir
}

// Reconcile validates a KloudKnoxPolicy, normalises directory paths in place,
// and sets status.status to Active or Invalid: <reason>.
func (r *KloudKnoxPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var policy securityv1.KloudKnoxPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("reconciling policy", "policy", req.NamespacedName)

	if err := securityv1.ValidateSpec(&policy.Spec); err != nil {
		log.Error(err, "Invalid policy spec", "policy", req.NamespacedName)
		policy.Status.PolicyStatus = fmt.Sprintf("%s: %v", securityv1.PolicyStatusInvalid, err)
		if updateErr := r.Status().Update(ctx, &policy); updateErr != nil {
			log.Error(updateErr, "Failed to update policy status", "policy", req.NamespacedName)
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}
	// applyToAll is a docker/hybrid-only construct — in a pure K8s cluster,
	// host-wide application is not meaningful (DaemonSet-scoped agents,
	// per-namespace RBAC). Reject it here rather than silently no-op.
	if policy.Spec.ApplyToAll {
		msg := "applyToAll is not supported in kubernetes mode; use a namespace selector instead"
		log.Error(nil, msg, "policy", req.NamespacedName)
		policy.Status.PolicyStatus = fmt.Sprintf("%s: %s", securityv1.PolicyStatusInvalid, msg)
		if updateErr := r.Status().Update(ctx, &policy); updateErr != nil {
			log.Error(updateErr, "Failed to update policy status", "policy", req.NamespacedName)
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, nil
	}

	normalized := false
	for i := range policy.Spec.Process {
		if policy.Spec.Process[i].Dir != "" {
			before := policy.Spec.Process[i].Dir
			policy.Spec.Process[i].Dir = normalizeDir(before)
			if policy.Spec.Process[i].Dir != before {
				normalized = true
			}
		}
	}
	for i := range policy.Spec.File {
		if policy.Spec.File[i].Dir != "" {
			before := policy.Spec.File[i].Dir
			policy.Spec.File[i].Dir = normalizeDir(before)
			if policy.Spec.File[i].Dir != before {
				normalized = true
			}
		}
	}

	if normalized {
		if err := r.Update(ctx, &policy); err != nil {
			log.Error(err, "Failed to persist normalized policy spec", "policy", req.NamespacedName)
			return ctrl.Result{}, err
		}
	}

	policy.Status.PolicyStatus = securityv1.PolicyStatusActive
	if err := r.Status().Update(ctx, &policy); err != nil {
		log.Error(err, "Failed to update policy status", "policy", req.NamespacedName)
		return ctrl.Result{}, err
	}

	log.Info("policy validated and active", "policy", req.NamespacedName)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with mgr so that it is notified of
// KloudKnoxPolicy create, update, and delete events.
func (r *KloudKnoxPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KloudKnoxPolicy{}).
		Named("kloudknoxpolicy").
		Complete(r)
}
