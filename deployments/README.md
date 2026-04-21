# Deployments

This directory contains Kubernetes manifests for deploying KloudKnox and its components.

## Manifest Overview

| File | Description |
|---|---|
| `00_kloudknox_namespace.yaml` | Creates the `kloudknox` namespace |
| `01_kloudknoxpolicy.yaml` | Installs the `KloudKnoxPolicy` CustomResourceDefinition (CRD) |
| `02_operator-controller.yaml` | Deploys the KloudKnox policy operator (sources under `operator-controller/`) |
| `03_apparmor-webhook.yaml` | Deploys the AppArmor MutatingAdmissionWebhook that injects profiles into matching pods (AppArmor-mode nodes only; skip on pure BPF-LSM clusters) |
| `04_kloudknox.yaml` | Deploys the KloudKnox agent as a DaemonSet |

Components that live in their own repositories:

- Relay server — [kloudknox-relay-server](https://github.com/boanlab/kloudknox-relay-server) (manifest: `deployments/relay-server.yaml`) — optional, for multi-node stream aggregation
- `kkctl` CLI RBAC — [kloudknox-cli](https://github.com/boanlab/kloudknox-cli) (manifest: `deployments/kloudknox-cli.yaml`) — optional, for in-cluster `kkctl` deployment

## Prerequisites

- Kubernetes cluster with Containerd runtime
- Linux kernel 5.15+ with eBPF support
- BPF-LSM enabled on all nodes (preferred — check `/sys/kernel/security/lsm`), or AppArmor as a fallback
- `kubectl` with cluster admin privileges
- [cert-manager](https://cert-manager.io/) installed in the cluster — required
  only when deploying `03_apparmor-webhook.yaml`; the webhook's TLS cert and
  `MutatingWebhookConfiguration` caBundle are provisioned by cert-manager. Pure
  BPF-LSM clusters can skip cert-manager.

### Verify Prerequisites

```bash
# Check kernel version
uname -r

# Check which LSMs the kernel has active (BPF-LSM preferred)
cat /sys/kernel/security/lsm

# Verify AppArmor is enabled (only needed for the AppArmor fallback path)
sudo aa-status

# Check Containerd is in use
kubectl get nodes -o wide

# Install cert-manager (skip on pure BPF-LSM clusters, or if already present)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=available --timeout=180s deployment --all
```

## Installation

Apply the manifests in the order indicated by their numeric prefix:

```bash
kubectl apply -f 00_kloudknox_namespace.yaml
kubectl apply -f 01_kloudknoxpolicy.yaml
kubectl apply -f 02_operator-controller.yaml
kubectl apply -f 03_apparmor-webhook.yaml   # skip on pure BPF-LSM clusters
kubectl apply -f 04_kloudknox.yaml
```

> On BPF-LSM-only clusters the agent detects `bpf` in `/sys/kernel/security/lsm`
> at startup and enforces directly through LSM hooks, without loading AppArmor
> profiles — the webhook and cert-manager are not required.

Wait for all components to become ready:

```bash
kubectl wait --for=condition=ready pod \
  -l boanlab.com/app=kloudknox \
  -n kloudknox \
  --timeout=120s
```

### Optional: Relay Server

The relay server aggregates event and alert streams from all KloudKnox nodes and exposes a single gRPC endpoint for downstream consumers. Deploy it from the [kloudknox-relay-server](https://github.com/boanlab/kloudknox-relay-server) repository when centralized stream access is required.

## Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n kloudknox -o wide

# Check the DaemonSet covers all nodes
kubectl get daemonset -n kloudknox

# Check the operator deployment
kubectl get deployment -n kloudknox
```

Expected output:

```
NAME                                  READY   STATUS    RESTARTS   AGE
kloudknox-operator-xxxxxxxxxx-xxxxx   1/1     Running   0          2m
kloudknox-xxxxx                       1/1     Running   0          2m
kloudknox-xxxxx                       1/1     Running   0          2m
```

## Accessing the gRPC API

The KloudKnox agent exposes a gRPC API on port `36890`. To access it from a local machine:

```bash
kubectl port-forward -n kloudknox daemonset/kloudknox 36890:36890
```

Then use the CLI client:

```bash
./kkctl stream events --server localhost:36890
./kkctl stream alerts --server localhost:36890
```

## Applying Security Policies

After deployment, apply `KloudKnoxPolicy` resources to enforce security rules on workloads:

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: block-shell
  namespace: default
spec:
  selector:
    app: myapp
  process:
    - path: /bin/bash
      action: Block
  action: Audit
```

```bash
kubectl apply -f my-policy.yaml
```

## Uninstallation

Remove all KloudKnox components from the cluster:

```bash
kubectl delete -f 04_kloudknox.yaml
kubectl delete -f 03_apparmor-webhook.yaml   # skip if it was never applied (BPF-LSM clusters)
kubectl delete -f 02_operator-controller.yaml
kubectl delete -f 01_kloudknoxpolicy.yaml
kubectl delete -f 00_kloudknox_namespace.yaml
```

To remove the relay server, use the manifest published in the [kloudknox-relay-server](https://github.com/boanlab/kloudknox-relay-server) repository.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
