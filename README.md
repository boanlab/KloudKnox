# KloudKnox

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue.svg)](https://golang.org/)
[![BPF](https://img.shields.io/badge/BPF-eBPF-green.svg)](https://ebpf.io/)

KloudKnox is a cloud-native security observability and policy enforcement system designed to monitor and control the behavior of containers at the system level. It uses eBPF for low-overhead monitoring of process execution, file access, network activity, Linux capability use, and IPC (Unix sockets, signals, ptrace), and enforces policies in real time with BPF-LSM (AppArmor as fallback) for process, file, capability, and IPC domains, and cgroup-BPF for network.

KloudKnox supports three deployment modes:

| Mode | Container source | Policy source |
|---|---|---|
| `kubernetes` (default) | containerd CRI | `KloudKnoxPolicy` CRDs (via operator) |
| `docker` | Docker Engine API | local YAML directory (hot-reloaded) |
| `hybrid` | both | both |

---

## Documentation

New to KloudKnox? Start here:

| Doc | Purpose |
|---|---|
| [getting-started/README.md](getting-started/README.md) | 15-minute Kubernetes quickstart with first policy |
| [getting-started/policy-authoring.md](getting-started/policy-authoring.md) | Full `KloudKnoxPolicy` spec and validation rules |
| [getting-started/use-cases.md](getting-started/use-cases.md) | Copy-paste recipes for common enforcement patterns |
| [getting-started/docker-mode.md](getting-started/docker-mode.md) | Docker and hybrid-mode deployment and policy lifecycle |
| [getting-started/integrations.md](getting-started/integrations.md) | Ship events/alerts to Loki, ES, Slack, PagerDuty, etc. |
| [getting-started/troubleshooting.md](getting-started/troubleshooting.md) | Symptom-indexed diagnostics for install & streaming |
| [contribution/README.md](contribution/README.md) | Development environment setup and contribution guide |

## Components

| Component | Location |
|---|---|
| `KloudKnox` (agent) | Core DaemonSet; eBPF monitoring + enforcement on every node |
| `operator-controller` | [operator-controller/README.md](operator-controller/README.md) |
| `apparmor-webhook` | [deployments/03_apparmor-webhook.yaml](deployments/03_apparmor-webhook.yaml) |
| `relay-server` | https://github.com/boanlab/kloudknox-relay-server |
| `kloudknox-cli` (`kkctl`) | https://github.com/boanlab/kloudknox-cli |
| `protobuf` | [protobuf/README.md](protobuf/README.md) |

---

## Quick Deploy (Kubernetes)

### Prerequisites

- Kubernetes cluster with Containerd runtime
- Linux kernel 5.15+ with eBPF support
- BPF-LSM enabled on all nodes (preferred — check `/sys/kernel/security/lsm`), or AppArmor as a fallback
- [cert-manager](https://cert-manager.io/docs/installation/) installed in the cluster — required only when deploying the AppArmor webhook (TLS bootstrap); skip on pure BPF-LSM clusters
- `kubectl` with cluster-admin privileges

### Install

```bash
git clone https://github.com/boanlab/KloudKnox.git
cd KloudKnox

kubectl apply -f deployments/00_kloudknox_namespace.yaml   # 1. Namespace
kubectl apply -f deployments/01_kloudknoxpolicy.yaml       # 2. KloudKnoxPolicy CRD
kubectl apply -f deployments/02_operator-controller.yaml   # 3. Policy operator
kubectl apply -f deployments/03_apparmor-webhook.yaml      # 4. AppArmor admission webhook (skip on pure BPF-LSM clusters)
kubectl apply -f deployments/04_kloudknox.yaml             # 5. KloudKnox DaemonSet
```

Optional relay server (multi-node stream aggregation) — manifest is published in the [kloudknox-relay-server](https://github.com/boanlab/kloudknox-relay-server) repository:

```bash
kubectl apply -f https://raw.githubusercontent.com/boanlab/kloudknox-relay-server/main/deployments/relay-server.yaml
```

Or install everything with the CLI:

```bash
kkctl install
```

For the Docker-mode install path, see [getting-started/docker-mode.md](getting-started/docker-mode.md).

### Verify

```bash
kubectl get pods -n kloudknox -o wide
```

---

## Policy Enforcement

Policies are declarative YAML under the `security.boanlab.com/v1` API group. Every policy selects pods by label and defines `process`, `file`, `network`, `capability`, and `ipc` (`unix` / `signal` / `ptrace`) rules with actions `Allow`, `Audit`, or `Block`.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: example-policy
  namespace: default
spec:
  selector:
    app: myapp
  process:
    - path: /bin/bash
      action: Block
  file:
    - path: /etc/shadow
      action: Block
  capability:
    - name: CAP_NET_RAW
      action: Block
  ipc:
    signal:
      - permission: send
        signals: [SIGKILL]
        action: Block
  action: Audit
```

```bash
kubectl apply -f my-policy.yaml
# or
kkctl apply -f my-policy.yaml
```

For the full spec and validation rules, see [getting-started/policy-authoring.md](getting-started/policy-authoring.md). For ready-to-use recipes, see [getting-started/use-cases.md](getting-started/use-cases.md).

---

## Streaming Events, Alerts, and Logs

KloudKnox exposes a gRPC API on port `36890` for real-time streaming. The optional [relay server](https://github.com/boanlab/kloudknox-relay-server) aggregates streams from every node on port `36900`.

```bash
kubectl port-forward -n kloudknox daemonset/kloudknox 36890:36890

kkctl stream events --server localhost:36890
kkctl stream alerts --server localhost:36890
kkctl stream logs   --server localhost:36890
```

See the [kloudknox-cli repo](https://github.com/boanlab/kloudknox-cli) for the full CLI reference and [protobuf/README.md](protobuf/README.md) for the wire-format message definitions.

---

## Development

See [contribution/README.md](contribution/README.md) for the development environment, build instructions, and contribution guidelines.

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
