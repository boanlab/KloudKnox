# operator-controller

The Kubernetes operator for [KloudKnox](../README.md). It watches `KloudKnoxPolicy` custom resources across all namespaces, validates and normalises each policy, and updates the status subresource so that KloudKnox agents running on each node know when a policy is ready to enforce.

## Overview

The controller is built with [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) and manages the `KloudKnoxPolicy` CRD under the `security.boanlab.com/v1` API group.

```
kubectl apply -f policy.yaml   →   reconciler validates & normalises
                               →   status: Active or Invalid: <reason>
                               →   node agents enforce
```

Spec validation runs inside the reconciler. Malformed policies are accepted by the API server but surface as `status.status = Invalid: <reason>` on the resource.

## KloudKnoxPolicy Specification

The full `KloudKnoxPolicy` field reference, validation rules, action semantics, and examples live in [../getting-started/policy-authoring.md](../getting-started/policy-authoring.md). Recipes for common enforcement patterns are in [../getting-started/use-cases.md](../getting-started/use-cases.md).

In short, a policy selects pods by label and defines `process`, `file`, `network`, `capability`, and `ipc` (`unix` / `signal` / `ptrace`) rules with actions `Allow`, `Audit`, or `Block`. The reconciler writes one of `Active`, `Pending`, or `Invalid: <reason>` to `status.status`.

## Prerequisites

- Go 1.24.0+
- Kubernetes cluster (1.26+) with containerd runtime
- `KloudKnoxPolicy` CRD installed — see [`deployments/01_kloudknoxpolicy.yaml`](../deployments/01_kloudknoxpolicy.yaml)

## Build

```bash
make build        # format, lint, security scan, generate, compile
make test         # run all unit and integration tests
```

### Container Image

```bash
make build-image TAG=v0.1.0       # IMAGE defaults to boanlab/kloudknox-operator
make push-image  TAG=v0.1.0
```

## Running Locally

```bash
make run
```

This starts the controller against the cluster referenced by the current kubeconfig.

## Deployment

Apply the pre-built manifests in order:

```bash
kubectl apply -f ../deployments/00_kloudknox_namespace.yaml   # Namespace
kubectl apply -f ../deployments/01_kloudknoxpolicy.yaml       # CRD
kubectl apply -f ../deployments/02_operator-controller.yaml   # Deployment
```

Verify the operator is running:

```bash
kubectl get deployment -n kloudknox
kubectl logs -n kloudknox deployment/kloudknox-operator
```

## Testing

```bash
make test
```

Tests cover validation edge cases (all rule types, CIDR and FQDN boundaries) and reconciliation logic (normalisation, status transitions).

## License

Apache License 2.0 — see the [LICENSE](../LICENSE) file for details.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
