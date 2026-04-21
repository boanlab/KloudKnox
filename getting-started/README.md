# Getting Started with KloudKnox

This guide gets you from zero to a running KloudKnox installation with active policy enforcement in about 15 minutes. By the end you will have:

- KloudKnox deployed on a Kubernetes cluster
- Real-time system event streaming via `kkctl`
- A security policy that blocks and audits container activity
- Confirmed alert output for policy violations

---

## Table of Contents

- [What is KloudKnox?](#what-is-kloudknox)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Step 1 — Clone the Repository](#step-1--clone-the-repository)
- [Step 2 — Deploy KloudKnox](#step-2--deploy-kloudknox)
- [Step 3 — Build kkctl](#step-3--build-kkctl)
- [Step 4 — Stream System Events](#step-4--stream-system-events)
- [Step 5 — Apply a Security Policy](#step-5--apply-a-security-policy)
- [Step 6 — Test Policy Enforcement](#step-6--test-policy-enforcement)
- [Policy Reference](#policy-reference)
- [Troubleshooting](#troubleshooting)
- [Cleanup](#cleanup)
- [Next Steps](#next-steps)

---

## What is KloudKnox?

KloudKnox is a cloud-native security observability and policy enforcement system for Kubernetes. It monitors container activity at the system call level using eBPF and enforces declarative security policies through BPF-LSM (with AppArmor as a fallback) and cgroup-BPF — with zero code changes required in the workload.

**Key capabilities:**

| Capability | Description |
|---|---|
| eBPF monitoring | Low-overhead tracing of process execution, file access, network connections, Linux capability use, and IPC (Unix sockets, signals, ptrace) |
| Policy enforcement | Declarative `KloudKnoxPolicy` CRDs with `Allow`, `Audit`, and `Block` actions |
| Real-time streaming | gRPC event and alert streams for integration with SIEM and observability tools |
| Auto-injection | On AppArmor-mode nodes, profiles are applied to pods via a MutatingAdmissionWebhook; BPF-LSM nodes enforce directly through LSM hooks and need no annotation injection |

---

## Architecture Overview

```
┌──────────────────────────────────────────────┐
│  Kubernetes Node                             │
│                                              │
│  ┌────────────────────┐                      │
│  │  KloudKnox Agent   │  ◄── DaemonSet       │
│  │  (eBPF + enforcer) │                      │
│  └────────┬───────────┘                      │
│           │ gRPC :36890                      │
└───────────┼──────────────────────────────────┘
            │
  ┌─────────▼──────────┐     ┌────────────────┐
  │   kkctl / custom   │     │  Relay Server  │
  │   gRPC consumer    │     │  (fan-in/out)  │
  └────────────────────┘     └────────────────┘

  ┌────────────────────────────────────────────────────┐
  │  Kubernetes Control Plane                          │
  │  operator-controller  ──►  policies                │
  │  apparmor-webhook     ──►  pod mutation            │
  │     (AppArmor-mode clusters only; skip on BPF-LSM) │
  └────────────────────────────────────────────────────┘
```

| Component | Role |
|---|---|
| `KloudKnox` agent | DaemonSet; eBPF monitoring + enforcement on every node |
| `operator-controller` | Watches `KloudKnoxPolicy` CRDs and distributes policies to agents |
| `apparmor-webhook` | MutatingAdmissionWebhook; injects AppArmor annotations at pod creation — only needed on AppArmor-mode clusters, skip on pure BPF-LSM clusters |
| `relay-server` | Optional; aggregates streams from all nodes into one gRPC endpoint |
| `kkctl` | CLI for policy management and event/alert streaming |

---

## Prerequisites

| Requirement | Version |
|---|---|
| Kubernetes with Containerd runtime | 1.24+ |
| Linux kernel with eBPF support | 5.15+ |
| LSM backend | BPF-LSM preferred (check `/sys/kernel/security/lsm`); AppArmor acceptable as a fallback |
| `kubectl` | cluster-admin privileges |
| Go (for building `kkctl`) | 1.24+ |

**Verify your environment before proceeding:**

```bash
# Kernel version
uname -r
# Expected: 5.15.x or higher

# LSM backend — BPF-LSM is preferred; AppArmor works as a fallback
cat /sys/kernel/security/lsm
# Expected: comma-separated list containing `bpf` (and/or `apparmor`)

# AppArmor status (only required when relying on the AppArmor fallback path)
sudo aa-status | head -5
# Expected: apparmor module is loaded

# Containerd is the container runtime
kubectl get nodes -o wide | awk '{print $1, $NF}'
# Expected: containerd runtime listed for each node

# kubectl access
kubectl auth whoami
```

> **Tip:** Once `kkctl` is built ([Step 3](#step-3--build-kkctl)), `../kloudknox-cli/kloudknox-cli/bin/kkctl probe` runs all of the above prerequisite checks at once (kernel, BTF, cgroup v2, BPF-LSM/AppArmor, kubeconfig).

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/boanlab/KloudKnox.git
cd KloudKnox
```

---

## Step 2 — Deploy KloudKnox

Apply the manifests in numbered order. Each step depends on the previous one.

```bash
# 1. Create the kloudknox namespace
kubectl apply -f deployments/00_kloudknox_namespace.yaml

# 2. Install the KloudKnoxPolicy CRD
kubectl apply -f deployments/01_kloudknoxpolicy.yaml

# 3. Deploy the policy operator
kubectl apply -f deployments/02_operator-controller.yaml

# 4. Deploy the AppArmor admission webhook (skip on pure BPF-LSM clusters)
kubectl apply -f deployments/03_apparmor-webhook.yaml

# 5. Deploy the KloudKnox agent DaemonSet
kubectl apply -f deployments/04_kloudknox.yaml
```

> **Shortcut:** If you have already built `kkctl` ([Step 3](#step-3--build-kkctl)), a single `../kloudknox-cli/kloudknox-cli/bin/kkctl install` applies all five manifests, waits for rollout, and auto-detects whether the target is Kubernetes or Docker. Use `--image <ref>` to override the default image (`ghcr.io/boanlab/kloudknox:v0.1.0`).

Wait for all components to become ready (up to 2 minutes):

```bash
kubectl wait --for=condition=ready pod \
  -l boanlab.com/app=kloudknox \
  -n kloudknox \
  --timeout=120s
```

Verify the deployment:

```bash
kubectl get pods -n kloudknox -o wide
```

Expected output (one `kloudknox` pod per node):

```
NAME                                   READY   STATUS    RESTARTS   AGE   NODE
kloudknox-operator-7d9f8b6c4d-xkp2q   1/1     Running   0          90s   node-1
kloudknox-fj7qn                        1/1     Running   0          60s   node-1
kloudknox-r8mt2                        1/1     Running   0          60s   node-2
```

> **Optional:** Deploy the relay server if you need a single aggregated gRPC endpoint across nodes (manifest published in the [kloudknox-relay-server](https://github.com/boanlab/kloudknox-relay-server) repo):
> ```bash
> kubectl apply -f https://raw.githubusercontent.com/boanlab/kloudknox-relay-server/main/deployments/relay-server.yaml
> ```

---

## Step 3 — Build kkctl

`kkctl` is the KloudKnox CLI. It mirrors `kubectl`'s verb-noun pattern and handles both policy management (via a Unix socket REST API) and event/alert streaming (via gRPC).

`kkctl` lives in its own repository. Clone it alongside the main repo:

```bash
git clone https://github.com/boanlab/kloudknox-cli.git ../kloudknox-cli
cd ../kloudknox-cli/kloudknox-cli
make
cd -
```

Confirm it built correctly:

```bash
../kloudknox-cli/kloudknox-cli/bin/kkctl version
# Output:
#   kkctl version: dev
#   server version: <agent version, or "(unreachable)">
```

**kkctl command reference:**

```
kkctl probe                              Pre-flight environment check
kkctl install    [--image <img>]         Deploy KloudKnox (auto-detects k8s/docker)
kkctl uninstall  [--purge-policies]      Remove KloudKnox
kkctl upgrade    --image <img>           Upgrade KloudKnox image
kkctl status                             Show KloudKnox status
kkctl apply      -f <file>               Upsert policies from YAML
kkctl delete     policy <name>... | -f <file>   Delete one or more policies
kkctl get        policies|containers|nodes      List resources
kkctl describe   policy|container|node <name>   Show resource detail
kkctl label      container|pod <name> <key=val> Inject labels
kkctl inject     -f <policy> --target container|pod   Inject policy labels
kkctl policy     validate -f <file>      Validate policy YAML offline
kkctl stream     events|alerts|logs [flags]     Stream over gRPC
kkctl sysdump    [-o <file.tar.gz>]      Collect debug bundle
kkctl completion bash|zsh                Print shell completion script
kkctl version                            Print client/server version
```

Global flags (place **before** the verb): `--env`, `--kubeconfig`, `--kube-context`, `--namespace`, `--server`, `-o`. See `kkctl --help` for details.

---

## Step 4 — Stream System Events

Port-forward to a KloudKnox agent and start streaming events in real time:

```bash
# Port-forward in the background
kubectl port-forward -n kloudknox daemonset/kloudknox 36890:36890 &

# Stream all system events as JSON
../kloudknox-cli/kloudknox-cli/bin/kkctl stream events --server localhost:36890
```

You will see a continuous JSON stream of system activity from all containers on the node. Each event includes the process, the operation's target (file path, network peer, capability name, or IPC peer depending on the category), the container identity, and the syscall return code. Press `Ctrl+C` to stop.

**Filter events by namespace or pod:**

```bash
../kloudknox-cli/kloudknox-cli/bin/kkctl stream events \
  --server localhost:36890 \
  --namespaceName default \
  --podName my-pod
```

**Filter by activity category** (values are lowercase; the filter is case-sensitive):

```bash
# Available categories: process, file, network, capability, ipc
../kloudknox-cli/kloudknox-cli/bin/kkctl stream events --server localhost:36890 --category network
../kloudknox-cli/kloudknox-cli/bin/kkctl stream events --server localhost:36890 --category file
../kloudknox-cli/kloudknox-cli/bin/kkctl stream events --server localhost:36890 --category capability
../kloudknox-cli/kloudknox-cli/bin/kkctl stream events --server localhost:36890 --category ipc
```

Full filter set: `--eventName`, `--source`, `--category`, `--operation`, `--resource`, `--data`, `--nodeName`, `--namespaceName`, `--podName`, `--containerName`, `--labels`. Empty filters match everything.

---

## Step 5 — Apply a Security Policy

A `KloudKnoxPolicy` selects pods by label and defines rules for processes, files, network connections, Linux capabilities, and IPC (Unix sockets, signals, ptrace). Each rule specifies a path or target and an action (`Allow`, `Audit`, or `Block`).

Create a policy that blocks execution of `/bin/sleep` in pods labeled `app=demo`:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: block-sleep
  namespace: default
spec:
  selector:
    app: demo
  process:
    - path: /bin/sleep
      action: Block
  action: Audit
EOF
```

Confirm the policy is active (`kkctl get policies` lists KloudKnoxPolicy CRDs via the Kubernetes API in k8s mode, or scans `/etc/kloudknox/policies/` in docker mode):

```bash
../kloudknox-cli/kloudknox-cli/bin/kkctl get policies -o wide
```

Expected output:

```
NAMESPACE  NAME         ACTION  PROCESS  FILE  NETWORK
default    block-sleep  Audit   1        0     0
```

The default (non-`wide`) table shows `NAMESPACE NAME ACTION` only. `-o json` and `-o yaml` print the full spec, including any capability or IPC rules not surfaced in the wide table.

---

## Step 6 — Test Policy Enforcement

Start streaming alerts in one terminal:

```bash
../kloudknox-cli/kloudknox-cli/bin/kkctl stream alerts --server localhost:36890
```

In a second terminal, deploy a test pod and trigger the blocked operation. The pod's main command is a simple `tail` so the policy does not affect pod startup — only the manual `exec` of `/bin/sleep` trips the block rule:

```bash
# Deploy the demo pod (main command is tail, not sleep)
kubectl run demo \
  --image=ubuntu \
  --labels="app=demo" \
  --command -- tail -f /dev/null

# Wait for the pod to be running
kubectl wait --for=condition=ready pod/demo --timeout=60s

# Attempt the blocked operation — this will be denied
kubectl exec demo -- /bin/sleep 60
```

The `exec` command will fail. Switch back to the first terminal and confirm the alert appeared (JSON fields use camelCase; PID/UID/GID/PPID/TID are uppercase):

```json
{
  "timestamp": 1744000000000000000,
  "PID": 12345,
  "eventName": "execve",
  "category": "process",
  "operation": "Exec",
  "resource": "/bin/sleep",
  "podName": "demo",
  "namespaceName": "default",
  "policyName": "block-sleep",
  "policyAction": "Block"
}
```

---

## Policy Reference

### Process Rules

Block or audit process execution by path or directory:

```yaml
spec:
  selector:
    app: my-app
  process:
    # Block a specific binary
    - path: /bin/bash
      action: Block

    # Block all binaries under /usr/bin/
    - dir: /usr/bin/
      recursive: false
      action: Block

    # Restrict based on the parent process
    - path: /usr/bin/wget
      fromSource:
        - path: /bin/sh
      action: Block
```

### File Rules

Restrict file access by path or directory:

```yaml
spec:
  selector:
    app: my-app
  file:
    # Block read and write to a sensitive file
    - path: /etc/shadow
      action: Block

    # Enforce read-only access to a configuration directory
    - dir: /etc/ssl/
      recursive: true
      readOnly: true
      action: Audit

    # Allow a specific process to write to a path
    - path: /var/log/app.log
      fromSource:
        - path: /usr/bin/app
      action: Allow
```

### Network Rules

Control outbound and inbound connections:

```yaml
spec:
  selector:
    app: my-app
  network:
    # Audit all outbound HTTPS traffic
    - direction: egress
      ports:
        - port: 443
          protocol: TCP
      action: Audit

    # Block connections to a specific IP range
    - direction: egress
      ipBlock:
        cidr: 10.0.0.0/8
        except:
          - 10.1.0.0/16
      action: Block

    # Block connections to a known-bad domain
    - direction: egress
      fqdn: malicious.example.com
      action: Block
```

### Capability Rules

Restrict Linux capability use by name. `name` accepts the canonical `CAP_*`
form or the short form (e.g. `NET_RAW`); both normalize to the same rule.

```yaml
spec:
  selector:
    app: my-app
  capability:
    # Block raw-socket capability outright
    - name: CAP_NET_RAW
      action: Block

    # Allow NET_BIND_SERVICE only for a trusted binary
    - name: NET_BIND_SERVICE
      fromSource:
        - path: /usr/sbin/nginx
      action: Allow
```

### IPC Rules

`spec.ipc` groups three inter-process-communication sub-domains. Each
sub-domain is an independent list.

```yaml
spec:
  selector:
    app: my-app
  ipc:
    # Unix domain socket: control connect/send/receive/bind/listen on a
    # filesystem ("/...") or abstract ("@...") address.
    unix:
      - type: stream
        path: /var/run/docker.sock
        permission: [connect]
        action: Block

    # Signal delivery: LSM hooks are send-side only, so permission is
    # always "send". Empty signals / target matches any.
    signal:
      - permission: send
        target: /usr/bin/sleep
        signals: [SIGKILL]
        action: Block

    # Ptrace: trace/read (source is the tracer) vs traceby/readby
    # (source is the tracee).
    ptrace:
      - permission: trace
        action: Block
```

### Policy Actions

| Action | Behavior |
|---|---|
| `Allow` | Explicitly permit; overrides a more permissive default posture |
| `Audit` | Log the activity as an event without blocking it |
| `Block` | Deny the operation and generate an alert |

The top-level `action` field sets the default posture for rules that do not specify their own action.

---

## Troubleshooting

**Pods stay in `Pending` after deploy**

```bash
kubectl describe pod -n kloudknox -l boanlab.com/app=kloudknox
# Check Events section for resource or scheduling errors
```

**No events appear in `kkctl stream events`**

```bash
# Confirm the port-forward is still running
jobs

# Check agent logs
kubectl logs -n kloudknox daemonset/kloudknox --tail=50
```

**AppArmor webhook blocking pod creation** (AppArmor-mode clusters only)

```bash
kubectl logs -n kloudknox deploy/kloudknox-operator --tail=50
# Look for admission webhook errors
```

**Policy not enforced after `kkctl apply`**

```bash
# Confirm the policy was received by the agent
../kloudknox-cli/kloudknox-cli/bin/kkctl get policies

# Check operator logs for reconciliation errors
kubectl logs -n kloudknox deploy/kloudknox-operator --tail=50

# For a full diagnostic bundle (logs, policies, node info)
../kloudknox-cli/kloudknox-cli/bin/kkctl sysdump -o kloudknox-sysdump.tar.gz
```

**Kernel version too old**

KloudKnox requires kernel 5.15 or later for the BPF ring buffer API. On Ubuntu:

```bash
uname -r
# If below 5.15, upgrade: sudo apt install --install-recommends linux-generic-hwe-22.04
```

---

## Cleanup

Remove the test resources:

```bash
kubectl delete pod demo
kubectl delete kloudknoxpolicy block-sleep -n default
```

Kill the background port-forward:

```bash
pkill -f "kubectl port-forward"
```

Remove KloudKnox entirely:

```bash
kubectl delete -f deployments/04_kloudknox.yaml
kubectl delete -f deployments/03_apparmor-webhook.yaml   # skip if never applied (BPF-LSM clusters)
kubectl delete -f deployments/02_operator-controller.yaml
kubectl delete -f deployments/01_kloudknoxpolicy.yaml
kubectl delete -f deployments/00_kloudknox_namespace.yaml
```

---

## Next Steps

| Topic | Location |
|---|---|
| Full `KloudKnoxPolicy` spec reference | [policy-authoring.md](policy-authoring.md) |
| Ready-to-use policy recipes | [use-cases.md](use-cases.md) |
| Docker and hybrid-mode deployment | [docker-mode.md](docker-mode.md) |
| Routing events to SIEM, logging, alerting | [integrations.md](integrations.md) |
| Symptom-indexed troubleshooting | [troubleshooting.md](troubleshooting.md) |
| Full deployment reference | [deployments/README.md](../deployments/README.md) |
| Full `kkctl` CLI reference | https://github.com/boanlab/kloudknox-cli |
| gRPC API and Protobuf definitions | [protobuf/README.md](../protobuf/README.md) |
| Development environment setup | [contribution/README.md](../contribution/README.md) |
| Contributing to the project | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Reporting security issues | [SECURITY.md](../SECURITY.md) |

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
