# Authoring KloudKnox Policies

This document is the full reference for writing a `KloudKnoxPolicy`. It covers every field, every validation rule, action semantics, and common authoring patterns.

For a guided first run, see [README.md](README.md). For end-to-end recipes, see [use-cases.md](use-cases.md).

---

## Table of Contents

- [Policy Anatomy](#policy-anatomy)
- [Metadata](#metadata)
- [Selector](#selector)
- [Process Rules](#process-rules)
- [File Rules](#file-rules)
- [Network Rules](#network-rules)
- [Capability Rules](#capability-rules)
- [IPC Rules](#ipc-rules)
  - [Unix Socket Rules](#unix-socket-rules)
  - [Signal Rules](#signal-rules)
  - [Ptrace Rules](#ptrace-rules)
- [Actions and Defaults](#actions-and-defaults)
- [`fromSource`](#fromsource)
- [Path and Directory Syntax](#path-and-directory-syntax)
- [Policy Status](#policy-status)
- [Validation Errors](#validation-errors)
- [Applying and Inspecting Policies](#applying-and-inspecting-policies)

---

## Policy Anatomy

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: <policy-name>
  namespace: <target-namespace>
spec:
  selector:
    <label-key>: <label-value>
  applyToAll: false        # docker/hybrid only — see Selector
  process:
    - ...
  file:
    - ...
  network:
    - ...
  capability:
    - ...
  ipc:
    unix:
      - ...
    signal:
      - ...
    ptrace:
      - ...
  action: Allow | Audit | Block
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `spec.selector` | `map[string]string` | Yes (unless `applyToAll`) | At least one entry |
| `spec.applyToAll` | bool | No | `docker`/`hybrid` modes only — apply to every container without a selector. Rejected in `kubernetes` mode |
| `spec.process` | list | No | Process execution rules |
| `spec.file` | list | No | File access rules |
| `spec.network` | list | No | Network rules |
| `spec.capability` | list | No | Linux capability rules |
| `spec.ipc` | object | No | Unix socket / signal / ptrace sub-lists |
| `spec.action` | `Allow \| Audit \| Block` | See [Actions](#actions-and-defaults) | Default for rules without their own action |

A policy with no rules in any of `process`, `file`, `network`, `capability`, or `ipc` is accepted as long as `spec.action` is set, but it has no effect.

---

## Metadata

The CRD is **namespaced** (`scope: Namespaced`). A policy applies only to pods in the same namespace as the policy object.

```yaml
metadata:
  name: block-sleep
  namespace: default
```

Standard Kubernetes metadata rules apply to `name` (DNS-1123 subdomain, 253 characters max).

---

## Selector

`spec.selector` is a label map. A pod matches the policy when **every** selector key-value pair is present in the pod's labels.

```yaml
spec:
  selector:
    app: web
    tier: frontend
```

Multiple policies can select the same pod; all matching rules apply.

### `applyToAll` (docker / hybrid only)

Setting `spec.applyToAll: true` makes the policy match every container on the host without needing `spec.selector`. This is useful for baseline guards in standalone Docker deployments. The reconciler rejects `applyToAll: true` in Kubernetes mode — for cluster-wide enforcement, use a namespace selector instead.

```yaml
spec:
  applyToAll: true
  file:
    - path: /var/run/docker.sock
      action: Block
  action: Audit
```

### Reserved `docker.*` keys

Keys prefixed with `docker.` are reserved for identifying Docker-mode containers (for example, `docker.name`, `docker.image`). They must match the pattern `^docker\.[a-z][a-z0-9._-]*$`. Non-conforming `docker.*` keys are rejected by the operator in both modes, which keeps the same policy file usable in Kubernetes, Docker, and hybrid mode.

See [docker-mode.md](docker-mode.md) for Docker-mode selector examples.

---

## Process Rules

A process rule restricts binary execution inside matched pods.

```yaml
spec:
  process:
    - path: /bin/bash
      action: Block

    - dir: /usr/local/bin/
      recursive: true
      action: Audit

    - path: /usr/bin/wget
      fromSource:
        - path: /bin/sh
      action: Block
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `path` | string | One of `path`/`dir` | Absolute path of the executable |
| `dir` | string | One of `path`/`dir` | Absolute directory; **must end with `/`** |
| `recursive` | bool | No | Only valid when `dir` is set |
| `fromSource` | list | No | Limit to processes spawned by a listed executable; see [fromSource](#fromsource) |
| `action` | `Allow \| Audit \| Block` | No | Falls back to `spec.action` |

Exactly one of `path` or `dir` must be set; using both is a validation error. `recursive: true` on a plain `path` rule is also an error.

---

## File Rules

A file rule restricts read, write, or read-write access to files and directories.

```yaml
spec:
  file:
    - path: /etc/shadow
      action: Block

    - dir: /etc/ssl/
      recursive: true
      readOnly: true
      action: Allow

    - path: /var/log/app.log
      fromSource:
        - path: /usr/bin/app
      action: Allow
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `path` | string | One of `path`/`dir` | Absolute path of the file |
| `dir` | string | One of `path`/`dir` | Absolute directory; **must end with `/`** |
| `recursive` | bool | No | Only valid when `dir` is set |
| `readOnly` | bool | No | With `action: Allow`, enforces read-only access |
| `fromSource` | list | No | Limit to processes spawned by a listed executable; see [fromSource](#fromsource) |
| `action` | `Allow \| Audit \| Block` | No | Falls back to `spec.action` |

### `readOnly`

`readOnly: true` combined with `action: Allow` permits reads and blocks writes to the matched path or directory. Without `readOnly`, `Allow` permits both reads and writes.

---

## Network Rules

A network rule restricts ingress or egress connections.

```yaml
spec:
  network:
    - direction: egress
      ports:
        - port: 443
          protocol: TCP
      action: Audit

    - direction: egress
      ipBlock:
        cidr: 10.0.0.0/8
        except:
          - 10.1.0.0/16
      action: Block

    - direction: egress
      fqdn: api.example.com
      ports:
        - port: 443
          protocol: TCP
      action: Allow

    - direction: ingress
      selector:
        app: frontend
      action: Allow
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `direction` | `ingress \| egress` | Yes | |
| `selector` | `map[string]string` | One of `selector`/`ipBlock`/`fqdn` | Pod label selector (Kubernetes mode) |
| `ipBlock.cidr` | string | One of `selector`/`ipBlock`/`fqdn` | IPv4 CIDR |
| `ipBlock.except` | list of string | No | IPv4 CIDRs excluded from the match |
| `fqdn` | string | One of `selector`/`ipBlock`/`fqdn` | DNS name |
| `ports` | list of `{protocol, port}` | No | See [Ports](#ports) |
| `fromSource` | list | No | Restrict to processes spawned by a listed executable |
| `action` | `Allow \| Audit \| Block` | No | Falls back to `spec.action` |

Exactly one of `selector`, `ipBlock`, or `fqdn` must be set.

### IPv4 only

Network rules match IPv4 traffic. `ipBlock.cidr` must be a valid IPv4 CIDR (`0.0.0.0/0` to `255.255.255.255/32`) and each `except` entry must also be valid IPv4.

### FQDN

- Maximum length: 253 characters
- Each label: 1–63 characters, starts and ends with an alphanumeric
- At least two labels (a TLD of 2+ characters is required)

### Ports

```yaml
ports:
  - port: 443
    protocol: TCP
```

| Field | Values |
|---|---|
| `protocol` | `TCP`, `UDP`, `ICMP`, `SCTP` |
| `port` | 1–65535 |

For `ICMP`, `port` must be omitted (ICMP has no port concept). Leaving `ports` empty matches all ports for the selected remote.

---

## Capability Rules

A capability rule restricts Linux capability use. `name` accepts either the canonical `CAP_*` symbol or the short form (e.g. `NET_RAW` vs `CAP_NET_RAW`); the validator normalizes both.

```yaml
spec:
  capability:
    - name: CAP_NET_RAW
      action: Block

    - name: NET_BIND_SERVICE
      fromSource:
        - path: /usr/sbin/nginx
      action: Allow
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | Yes | `CAP_*` or short form; matched case-insensitively |
| `fromSource` | list | No | Restrict to processes spawned by a listed executable |
| `action` | `Allow \| Audit \| Block` | No | Falls back to `spec.action` |

### Supported capability names

The full set accepted by the validator is the canonical Linux 5.x capability list (sourced from `include/uapi/linux/capability.h`). Common entries include `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_BPF`, `CAP_PERFMON`, `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL`. Unknown names are rejected with `unknown capability: <name>`.

---

## IPC Rules

`spec.ipc` groups three inter-process-communication sub-domains under a single block. Each sub-list is optional; rules from all three are applied independently.

```yaml
spec:
  ipc:
    unix:   [ ... ]
    signal: [ ... ]
    ptrace: [ ... ]
```

### Unix Socket Rules

Restrict Unix domain socket operations. `path` accepts either a filesystem socket (`/var/run/...`) or an abstract-namespace socket prefixed with `@`.

```yaml
spec:
  ipc:
    unix:
      - type: stream
        path: /var/run/docker.sock
        permission: [connect]
        action: Block

      - type: dgram
        path: "@/kloudknox-control"
        permission: [send, receive]
        fromSource:
          - path: /usr/local/bin/kk-agent
        action: Allow
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | `stream \| dgram` | Yes | Socket type |
| `path` | string | No | Must start with `/` or `@`; empty matches any |
| `permission` | list of string | Yes | Any of `connect`, `send`, `receive`, `bind`, `listen`; a single string is coerced to a singleton list |
| `fromSource` | list | No | Restrict to processes spawned by a listed executable |
| `action` | `Allow \| Audit \| Block` | No | Falls back to `spec.action` |

Multi-permission rules fan out internally — one enforcement rule per permission token — so authors can list them together in the CRD.

### Signal Rules

Restrict signal delivery. LSM hooks intercept only the send side, so `permission` is fixed to `send`. An empty `signals` list or empty `target` means "match any".

```yaml
spec:
  ipc:
    signal:
      # Block SIGKILL to /usr/bin/sleep from any source
      - permission: send
        target: /usr/bin/sleep
        signals: [SIGKILL]
        action: Block

      # Allow only kk-signaler to send SIGTERM/SIGHUP to sleep
      - permission: send
        target: /usr/bin/sleep
        signals: [SIGTERM, SIGHUP]
        fromSource:
          - path: /usr/local/bin/kk-signaler
        action: Allow
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `permission` | `send` | Yes | Only `send` is accepted |
| `target` | string | No | Absolute path of the recipient binary; empty matches any |
| `signals` | list of string | No | Symbolic names (`SIGHUP`…`SIGSYS`); empty matches any |
| `fromSource` | list | No | Restrict to processes spawned by a listed executable |
| `action` | `Allow \| Audit \| Block` | No | Falls back to `spec.action` |

> **Signal `Block` semantics:** the `security_task_kill` LSM hook fires on every `kill(2)` / `tgkill(2)`. A top-level `spec.action: Block` is **not** a fall-through for signals — to block signals that no `Allow` rule covers, add an explicit `Block` rule (for example, the SIGKILL rule above). See `tests/policies/ubuntu-1-ipc-signal-allow-fs.yaml` for a worked example.
>
> **Same-profile sender (AppArmor fallback):** on AppArmor-mode nodes, AppArmor permits signals delivered between processes sharing the same profile, so a rule that only names the sender misses intra-container signals. BPF-LSM nodes do not have this quirk, but for portability always name the `target` explicitly.

### Ptrace Rules

Restrict `ptrace(2)`-class operations. The four permission tokens flip the source/target interpretation: `trace` / `read` apply when the rule's source is the **tracer**; `traceby` / `readby` apply when the source is the **tracee**.

```yaml
spec:
  ipc:
    ptrace:
      # Block any process in this pod from tracing any peer
      - permission: trace
        action: Block

      # Audit reads of process memory by /usr/bin/gdb
      - permission: read
        target: /usr/bin/gdb
        action: Audit

      # Block anything from being traced by /usr/bin/strace
      - permission: traceby
        target: /usr/bin/strace
        action: Block
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `permission` | `trace \| read \| traceby \| readby` | Yes | See source/target interpretation above |
| `target` | string | No | Peer binary path (tracer for `*by`, tracee otherwise); empty matches any |
| `fromSource` | list | No | Restrict to processes spawned by a listed executable |
| `action` | `Allow \| Audit \| Block` | No | Falls back to `spec.action` |

---

## Actions and Defaults

Every policy must have at least one action somewhere — either `spec.action` or on at least one rule. A policy with no action anywhere is rejected.

| Action | Behavior |
|---|---|
| `Allow` | Permit the operation |
| `Audit` | Permit the operation and emit an alert |
| `Block` | Deny the operation (returns `EACCES` / `-13`) and emit an alert |

Rule-level `action` always overrides `spec.action`. If a rule omits `action`, it inherits `spec.action`.

### Default posture

When a pod is matched by at least one policy, the default posture is:

- **Deny unless allowed** if no matching policy sets `spec.action: Allow`.
- **Allow unless denied** if any matching policy sets `spec.action: Allow`.

To build a strict allowlist, give the policy `spec.action: Block` and enumerate every permitted operation with `action: Allow` rules. To layer audit-only observation on top of a permissive default, use `spec.action: Audit`.

---

## `fromSource`

`fromSource` narrows a rule to operations initiated by a specific parent executable. For example, "only block `/bin/sleep` when invoked from `/bin/sh`":

```yaml
spec:
  process:
    - path: /bin/sleep
      fromSource:
        - path: /bin/sh
      action: Block
```

- Each `fromSource` entry must set `path` (absolute, no whitespace).
- Multiple entries form a logical OR (any match applies).
- A rule without `fromSource` matches regardless of the calling process.

`fromSource` is supported on every rule type: process, file, network, capability, unix, signal, and ptrace rules.

---

## Path and Directory Syntax

All paths are **absolute** and must contain no whitespace.

| Field | Requirement | Example |
|---|---|---|
| `path` | Absolute; no trailing `/` | `/bin/bash`, `/etc/ssh/sshd_config` |
| `dir` | Absolute; must end with `/` | `/usr/bin/`, `/etc/ssl/` |

`recursive: true` on a `dir` rule extends matching to all subdirectories; without it, the rule matches only immediate children.

The operator normalizes directory paths by appending `/` if it is missing, so file-based Docker-mode policies do not need to be reformatted.

---

## Policy Status

The operator writes one of the following values to `.status.status`:

| Status | Meaning |
|---|---|
| `Active` | Spec is valid; agents will enforce the rules |
| `Invalid: <reason>` | Spec failed validation; rules are not enforced |
| `Pending` | Spec has been accepted but is not yet reconciled |

Inspect status with:

```bash
kubectl get kloudknoxpolicy -A
kubectl describe kloudknoxpolicy <name> -n <namespace>
```

Or with `kkctl`:

```bash
kkctl get policies
kkctl describe policy <name>
```

In Docker mode, policies are read from files and there is no status subresource; check agent logs for load errors.

---

## Validation Errors

Typical validator messages and what triggers them:

| Error | Cause |
|---|---|
| `selector must be non-empty` | `spec.selector` is missing or empty |
| `no action defined` | Neither `spec.action` nor any rule sets `action` |
| `must specify one of path or dir` | Process/file rule with both or neither set |
| `recursive can only be set when dir is specified` | `recursive: true` on a `path` rule |
| `must specify one of selector, ipBlock, or fqdn` | Network rule with zero or multiple target types |
| `invalid CIDR in ipBlock` | Non-IPv4 or malformed CIDR |
| `invalid FQDN` | Not matching the DNS label grammar or over 253 characters |
| `ICMP does not use port numbers` | `protocol: ICMP` with a non-zero `port` |
| `capability name must be set` | Capability rule with empty `name` |
| `unknown capability: <name>` | Capability name not in the supported list |
| `invalid unix type` | Unix rule `type` is neither `stream` nor `dgram` |
| `unix path must start with '/' or '@'` | Unix rule `path` not a filesystem or abstract socket |
| `unix permission must be set` | Unix rule with empty `permission` list |
| `invalid unix permission` | Unix permission token outside `connect/send/receive/bind/listen` |
| `invalid signal permission` | Signal rule `permission` is not `send` |
| `unknown signal` | Symbol not in `SIGHUP`…`SIGSYS` |
| `invalid ptrace permission` | Ptrace `permission` outside `trace/read/traceby/readby` |
| `fromSource entry must have a path set` | `fromSource:` element with an empty `path` |
| `invalid docker selector key` | Key prefixed `docker.` but not matching `^docker\.[a-z][a-z0-9._-]*$` |

Validate a policy offline before applying:

```bash
kkctl policy validate -f my-policy.yaml
```

---

## Applying and Inspecting Policies

### Kubernetes mode

```bash
kubectl apply -f my-policy.yaml
kubectl get kloudknoxpolicy -A
kubectl describe kloudknoxpolicy <name> -n <namespace>
```

Or via `kkctl` (uses the same Kubernetes API):

```bash
kkctl apply    -f my-policy.yaml
kkctl get      policies
kkctl describe policy <name>
kkctl delete   -f my-policy.yaml
kkctl delete   policy <name>
```

### Docker mode

`kkctl` writes YAML files under `/etc/kloudknox/policies/`, which the agent hot-reloads.

```bash
kkctl apply  -f my-policy.yaml
kkctl get    policies
kkctl delete policy <name>
```

See [docker-mode.md](docker-mode.md) for the full Docker-mode lifecycle.

---

## See also

- [README.md](README.md) — 15-minute quickstart
- [use-cases.md](use-cases.md) — recipes for common enforcement patterns
- [kloudknox-cli](https://github.com/boanlab/kloudknox-cli) — full `kkctl` reference
- [../protobuf/README.md](../protobuf/README.md) — gRPC streaming API for alerts generated by `Audit` and `Block` actions
