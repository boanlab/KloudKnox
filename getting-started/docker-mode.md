# Running KloudKnox in Docker Mode

KloudKnox supports three deployment modes:

| Mode | Container source | Policy source |
|---|---|---|
| `kubernetes` (default) | containerd CRI | `KloudKnoxPolicy` CRDs (via operator) |
| `docker` | Docker Engine API | local YAML files in a watched directory |
| `hybrid` | both | both |

This document covers the `docker` and `hybrid` modes. For the Kubernetes walkthrough, see [README.md](README.md).

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Install with `kkctl`](#install-with-kkctl)
- [Install with `docker compose`](#install-with-docker-compose)
- [Configuration Flags](#configuration-flags)
- [Policy Directory](#policy-directory)
- [Selectors in Docker Mode](#selectors-in-docker-mode)
- [Authoring and Applying Policies](#authoring-and-applying-policies)
- [Streaming Events and Alerts](#streaming-events-and-alerts)
- [Hybrid Mode](#hybrid-mode)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Version |
|---|---|
| Linux kernel with eBPF support | 5.15+ |
| LSM backend | BPF-LSM preferred (check `/sys/kernel/security/lsm`); AppArmor acceptable as a fallback |
| Docker Engine | 20.10+ |
| `docker compose` (for the compose path) | v2 |
| `kkctl` (for the CLI path) | see [README.md](README.md) step 3 |

The KloudKnox container runs with `--privileged`, `--pid=host`, `--network=host`, and several capabilities (`SYS_ADMIN`, `BPF`, `PERFMON`, `NET_ADMIN`, `MAC_ADMIN`). These are required for eBPF programs (including BPF-LSM attachment) and — on AppArmor-fallback hosts — AppArmor profile loading.

---

## Install with `kkctl`

`kkctl install` auto-detects the environment (Kubernetes vs. Docker) from the presence of `kubeconfig` and `/var/run/docker.sock`. Force Docker with `--env docker` if both are present.

```bash
kkctl install --env docker
```

The installer pulls `ghcr.io/boanlab/kloudknox:v0.1.0` by default, creates `/etc/kloudknox/policies/` if needed, and launches a container named `kloudknox` with the correct mounts, capabilities, and command-line flags.

Override the image:

```bash
kkctl install --env docker --image ghcr.io/boanlab/kloudknox:<tag>
```

Verify:

```bash
docker ps --filter name=kloudknox
kkctl status
```

---

## Install with `docker compose`

A ready-to-run compose file lives at [`deployments/docker/docker-compose.yml`](../deployments/docker/docker-compose.yml):

```bash
git clone https://github.com/boanlab/KloudKnox.git
cd KloudKnox/deployments/docker
docker compose up -d
```

The compose file defines the service with the minimum set of mounts and capabilities. Edit it before bringing the service up if you need to change the image tag, policy directory, or default namespace.

---

## Configuration Flags

The KloudKnox daemon accepts the following flags in Docker mode:

| Flag | Default | Description |
|---|---|---|
| `-mode` | `kubernetes` | `kubernetes`, `docker`, or `hybrid` |
| `-dockerEndpoint` | `unix:///var/run/docker.sock` | Docker Engine API endpoint |
| `-policyDir` | `/etc/kloudknox/policies` | Directory watched for `KloudKnoxPolicy` YAML files |
| `-defaultNamespace` | `docker` | Namespace assigned to containers and policies that do not specify one |
| `-logPath` | `stdout` | Destination for daemon logs |
| `-autoAttachAppArmor` | `false` | Warn when a matched container starts without an `apparmor=...` entry in SecurityOpt |

Flags may be set in the container command line, through the Viper-compatible config file, or via environment variables.

---

## Policy Directory

KloudKnox watches `-policyDir` using inotify. Any YAML file placed in the directory is parsed, validated, and activated; editing a file re-loads the affected policies; removing a file withdraws them. No daemon restart is required.

```bash
sudo mkdir -p /etc/kloudknox/policies
sudo cp my-policy.yaml /etc/kloudknox/policies/
```

A single YAML file may contain multiple `KloudKnoxPolicy` documents separated by `---`. Policies loaded from files that omit `metadata.namespace` are assigned the configured `-defaultNamespace` (default: `docker`).

---

## Selectors in Docker Mode

In Docker mode, a policy selects containers by matching its `spec.selector` against the container's identity labels. KloudKnox automatically populates the following reserved keys for every container:

| Key | Source |
|---|---|
| `docker.name` | Container name |
| `docker.image` | `Config.Image` from the Docker inspect payload |
| `docker.compose.project` | `com.docker.compose.project` label (if present) |
| `docker.compose.service` | `com.docker.compose.service` label (if present) |
| `image` | Alias for `Config.Image` |

Any label applied via `docker run --label k=v` or `labels:` in a compose file is also matchable as a selector key.

### Example

Container launched with:

```bash
docker run -d --name web --label app=frontend nginx:1.25
```

Policy that selects it:

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: web-policy
spec:
  selector:
    app: frontend
    docker.image: nginx:1.25
  file:
    - path: /etc/nginx/nginx.conf
      readOnly: true
      action: Allow
  action: Audit
```

The `docker.` prefix is reserved. Selector keys that start with `docker.` must match the pattern `^docker\.[a-z][a-z0-9._-]*$`. Keys outside this prefix are treated as ordinary label keys, so the same policy file applies unchanged in Kubernetes mode.

### `applyToAll`

Set `spec.applyToAll: true` to apply a policy to every container on the host without a selector. Useful for host-wide baselines such as blocking access to `/var/run/docker.sock`. This field is honored only in `docker` and `hybrid` modes; the operator rejects it in `kubernetes` mode.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: host-baseline
spec:
  applyToAll: true
  file:
    - path: /var/run/docker.sock
      action: Block
  action: Audit
```

---

## Authoring and Applying Policies

Policies use the same `KloudKnoxPolicy` schema as in Kubernetes. See [policy-authoring.md](policy-authoring.md) for the full spec reference.

Apply with `kkctl`:

```bash
kkctl --env docker apply -f my-policy.yaml
kkctl --env docker get policies
kkctl --env docker describe policy <name>
kkctl --env docker delete -f my-policy.yaml
kkctl --env docker delete policy <name>
```

`kkctl apply` writes the YAML into `-policyDir`; `kkctl delete` removes it. Both operations are picked up by the file watcher without restarting the daemon.

Drop-in file management also works — any process that copies, edits, or removes YAML files under `-policyDir` triggers the same reload path.

### `metadata.namespace`

Docker mode does not use Kubernetes namespaces. A policy's `metadata.namespace` value is used as a logical grouping label inside KloudKnox. If omitted, the value of `-defaultNamespace` is used.

### Status

There is no Kubernetes CRD status subresource in Docker mode. Parse errors and validation failures are reported in the daemon logs:

```bash
docker logs kloudknox | grep -i policy
```

---

## Streaming Events and Alerts

The gRPC API is identical to Kubernetes mode and listens on the host's `:36890`:

```bash
kkctl stream events --server localhost:36890
kkctl stream alerts --server localhost:36890
kkctl stream logs   --server localhost:36890
```

Filter fields such as `--namespaceName`, `--containerName`, and `--labels` work against the Docker-mode identity keys described above. For multi-host aggregation, see the [kloudknox-relay-server](https://github.com/boanlab/kloudknox-relay-server) repository.

---

## Hybrid Mode

`-mode=hybrid` enables both backends at once:

- Containerd CRI watcher populates pods from Kubernetes.
- Docker Engine watcher populates pods from standalone containers on the same host.
- The CRD watcher and file watcher both feed the policy cache.

A single KloudKnox instance enforces policies uniformly across both sources. Use hybrid mode on hosts that run a mix of Kubernetes workloads and standalone Docker containers (for example, legacy sidecars or host-level tools).

Selector matching is global — a `KloudKnoxPolicy` with `selector: {app: web}` matches both a Kubernetes pod labeled `app=web` and a Docker container started with `--label app=web`.

---

## Uninstall

With `kkctl`:

```bash
kkctl uninstall --env docker
kkctl uninstall --env docker --purge-policies   # also deletes /etc/kloudknox/policies
```

With `docker compose`:

```bash
docker compose down
```

Manual removal:

```bash
docker rm -f kloudknox
```

The policy directory is not removed by default. Delete it explicitly if you want a clean slate:

```bash
sudo rm -rf /etc/kloudknox/policies
```

---

## Troubleshooting

See [troubleshooting.md §Docker-Mode Specific](troubleshooting.md#docker-mode-specific) for symptom-indexed diagnostics.

---

## See also

- [README.md](README.md) — Kubernetes quickstart
- [policy-authoring.md](policy-authoring.md) — full `KloudKnoxPolicy` reference
- [use-cases.md](use-cases.md) — recipes for common enforcement patterns
- [troubleshooting.md](troubleshooting.md) — symptom-indexed diagnostics for install & streaming
- [kloudknox-cli](https://github.com/boanlab/kloudknox-cli) — full `kkctl` reference
