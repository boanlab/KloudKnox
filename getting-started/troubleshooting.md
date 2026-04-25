# Troubleshooting KloudKnox

Symptom-indexed diagnostics for the most common install, enforcement, and streaming failures. Each entry lists how to recognize the symptom, the likely cause, and a fix.

For install and quickstart, see [README.md](README.md). For Docker-mode specifics, see [docker-mode.md](docker-mode.md).

---

## Table of Contents

- [Pre-flight and Install](#pre-flight-and-install)
- [Pods Do Not Come Up](#pods-do-not-come-up)
- [Events or Alerts Are Empty](#events-or-alerts-are-empty)
- [Policies Are Not Enforced](#policies-are-not-enforced)
- [AppArmor Webhook Issues](#apparmor-webhook-issues)
- [Docker-Mode Specific](#docker-mode-specific)
- [Uninstall and Cleanup](#uninstall-and-cleanup)
- [Collecting a Support Bundle](#collecting-a-support-bundle)

---

## Pre-flight and Install

### `kkctl probe` reports a failure

Run the full probe before filing a bug:

```bash
sudo kkctl probe
```

| Check | Failure meaning | Fix |
|---|---|---|
| `Kernel version` | Kernel older than 5.15 | Upgrade (on Ubuntu: `sudo apt install --install-recommends linux-generic-hwe-22.04`) |
| `BTF (vmlinux)` | `/sys/kernel/btf/vmlinux` missing | Rebuild kernel with `CONFIG_DEBUG_INFO_BTF=y`, or install a distro kernel that ships BTF |
| `cgroup v2` | Unified hierarchy not mounted | Boot with `systemd.unified_cgroup_hierarchy=1`, or mount `cgroup2` manually |
| `AppArmor` | Not enabled | Optional — BPF enforcer works without it. Enable kernel support + `aa-enabled` for the AppArmor path |
| `CAP_*` | Missing capability | Run `kkctl` with `sudo`, or grant the capability to the user |

### `kubectl apply` fails with `no matches for kind "Issuer"` or `"Certificate"`

The AppArmor webhook manifest (`deployments/03_apparmor-webhook.yaml`) requires cert-manager.

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl wait --for=condition=available --timeout=120s \
  deploy/cert-manager -n cert-manager
```

Then re-apply the webhook manifest.

### `kkctl install` reports `both kubeconfig and docker.sock detected`

You are on a host that has both. Pick the target explicitly:

```bash
kkctl install --env k8s      # force Kubernetes
kkctl install --env docker   # force Docker
```

---

## Pods Do Not Come Up

### DaemonSet pods stay `Pending`

```bash
kubectl describe pod -n kloudknox -l boanlab.com/app=kloudknox
```

Look at `Events:`. Common causes:

| Event | Cause | Fix |
|---|---|---|
| `0/N nodes available: ... node(s) didn't match ...` | NodeSelector/taint mismatch | Add a toleration or fix the label |
| `insufficient cpu/memory` | Requests exceed available capacity | Lower requests in the DaemonSet or add capacity |
| `image pull backoff` | Registry unreachable or tag wrong | Check `image:` tag and registry reachability |

### DaemonSet pod in `CrashLoopBackOff`

```bash
kubectl logs -n kloudknox daemonset/kloudknox --previous --tail=100
```

Common root causes:

- **`failed to load BPF program: operation not permitted`** — missing capabilities in the DaemonSet spec. Confirm the pod has `SYS_ADMIN`, `NET_ADMIN`, `MAC_ADMIN`, `SYS_PTRACE`, `SYS_RESOURCE`, and `BPF` (see `deployments/04_kloudknox.yaml`).
- **`BTF not available`** — kernel lacks BTF. See pre-flight fix above.
- **`failed to open .../tracing/events/...`** — `debugfs`/`tracefs` not mounted into the pod. Check the hostPath mounts in `deployments/04_kloudknox.yaml`.

### Operator (`kloudknox-operator`) pod in `CrashLoopBackOff`

```bash
kubectl logs -n kloudknox deploy/kloudknox-operator --tail=100
```

Most commonly: RBAC drift after a partial upgrade. Re-apply the full manifest:

```bash
kubectl apply -f deployments/02_operator-controller.yaml
```

---

## Events or Alerts Are Empty

### `kkctl stream events` prints nothing

Run through this order:

1. **Is the port-forward alive?**
   ```bash
   jobs
   # Expect: kubectl port-forward -n kloudknox daemonset/kloudknox 36890:36890
   ```

2. **Is the agent running?**
   ```bash
   kubectl get pods -n kloudknox -o wide
   # Expect: one kloudknox-<hash> pod per node in Running state
   ```

3. **Is the agent actually producing events?**
   ```bash
   kubectl logs -n kloudknox daemonset/kloudknox --tail=20
   # Expect: [Configuration] lines + no repeating BPF errors
   ```

4. **Is there a filter that is too narrow?**
   Filters like `--namespaceName=prod` reject everything from other namespaces. Start with no filters, then add them back.

5. **Are you port-forwarded to the wrong node?**
   `daemonset/kloudknox` picks one pod, so events from pods on other nodes never reach this stream. To target a specific node, forward that node's agent directly:
   ```bash
   kubectl port-forward -n kloudknox pod/kloudknox-abcde 36890:36890
   ```
   For cluster-wide streaming, deploy the [relay-server](https://github.com/boanlab/kloudknox-relay-server) and forward its service instead — see [integrations.md#aggregating-across-nodes](integrations.md#aggregating-across-nodes).

### Alerts never appear even though events do

An alert is an event that matched an `Audit` or `Block` rule. If events flow but alerts do not:

1. Confirm the policy is `Active`:
   ```bash
   kkctl get policies
   # STATUS column should show Active
   ```
2. Confirm the selector matches the running pod labels:
   ```bash
   kubectl get pod <pod> --show-labels
   ```
3. Confirm the workload actually performs the rule-matched operation. Tail events first (`--podName <pod>`) to see what it does.

---

## Policies Are Not Enforced

### Policy status is `Invalid: <reason>`

The reconciler rejected the spec. The `<reason>` string identifies the field. See [policy-authoring.md](policy-authoring.md) for the full validation rule set. Common cases:

| Reason | Fix |
|---|---|
| `selector must be non-empty` | Add at least one `selector` entry |
| `no action defined` | Set `spec.action` or add `action:` on at least one rule |
| `must specify one of path or dir` | Process/file rule has neither or both — pick one |
| `recursive can only be set when dir is specified` | Remove `recursive:` or switch to `dir:` |
| `must specify one of selector, ipBlock, or fqdn` | Network rule target count is not exactly one |
| `invalid CIDR in ipBlock` | Use a valid IPv4 CIDR (IPv6 is not supported) |

Validate offline before applying:

```bash
kkctl policy validate -f my-policy.yaml
```

### Policy status is `Active` but nothing is enforced

- **Policy applied after the pod started.** Policies take effect on future syscalls, not retroactive ones. Restart the pod to ensure profile load.
  ```bash
  kubectl delete pod <pod>
  ```
- **Selector mismatch.** Verify the pod carries every `selector` key=value pair:
  ```bash
  kubectl get pod <pod> --show-labels
  ```
- **AppArmor enforcer path failed.** Check the agent log for AppArmor-related errors (e.g. `AppArmor is not available`, `Failed to apply default profile`, `Failed to register profile on the fly`):
  ```bash
  kubectl logs -n kloudknox daemonset/kloudknox | grep -i apparmor
  ```
  If AppArmor is not enabled on the node, enable it or rely on the BPF enforcer path.

### A `Block` rule does not actually block

Two common causes:

1. **The test invokes the binary directly through `kubectl exec`.** AppArmor's `deny <path> x,` rule fires only when a process **inside** the kloudknox profile domain calls `execve` on the path. A direct `kubectl exec <pod> -- <binary>` is spawned by `containerd-shim`, which lives in `cri-containerd.apparmor.d` and is allowed to exec arbitrary binaries; the new process inherits the kloudknox profile only after the exec completes, so the deny is never evaluated. Wrap the test in a shell so the spawn happens inside the container, mirroring real workloads:

   ```bash
   kubectl exec <pod> -- bash -c '<binary> <args>'
   ```

2. **The matched operation raced the profile load.** Profiles are applied at pod creation; a syscall issued in the first few milliseconds may slip through. Retry once the pod has been running for a few seconds, then stream alerts in a second terminal:

   ```bash
   kubectl exec <pod> -- bash -c '<binary> <args>'
   ```

If the exec still succeeds after both checks, the alert stream will show whether the rule matched but returned success (meaning the enforcer path is broken) or whether the event is not being matched at all (meaning the policy/selector is wrong).

---

## AppArmor Webhook Issues

### Webhook rejects pods with `x509: certificate signed by unknown authority`

The cert-manager cert has not been issued or the `MutatingWebhookConfiguration` has no CA bundle.

```bash
# Did cert-manager issue the certificate?
kubectl get certificate -n kloudknox
# READY should be True

# Is the CA bundle present?
kubectl get mutatingwebhookconfiguration kloudknox-apparmor-webhook \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | wc -c
# Expect: > 1000 chars
```

If the bundle is missing, confirm the annotation is set:

```bash
kubectl get mutatingwebhookconfiguration kloudknox-apparmor-webhook \
  -o jsonpath='{.metadata.annotations}'
# Expect: "cert-manager.io/inject-ca-from": "kloudknox/kloudknox-apparmor-webhook-cert"
```

Re-apply the manifest if the annotation is absent.

### Webhook is not invoked on pod creation

The webhook only fires for namespaces labelled `kloudknox-inject=enabled`:

```bash
kubectl label namespace <ns> kloudknox-inject=enabled
```

### Webhook blocks all pod creation in the cluster

`failurePolicy: Fail` combined with a webhook outage causes cluster-wide pod admission failure. The shipped manifest uses `failurePolicy: Ignore` to avoid this. If you customized it to `Fail` and the webhook is unhealthy:

```bash
# Immediate mitigation: revert to Ignore
kubectl patch mutatingwebhookconfiguration kloudknox-apparmor-webhook \
  --type=json -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'

# Or remove the webhook entirely until it is fixed
kubectl delete mutatingwebhookconfiguration kloudknox-apparmor-webhook
```

---

## Docker-Mode Specific

### `Failed to reach Docker daemon`

The daemon probes `/var/run/docker.sock` at startup.

```bash
docker info
# Confirm Docker is running and the current user can reach the socket
```

If running the agent in a container, confirm the socket is bind-mounted.

### Policies in `/etc/kloudknox/policies/` do not load

```bash
# Are they readable by the daemon?
ls -la /etc/kloudknox/policies/

# Is the daemon watching the directory?
docker logs kloudknox | grep -iE 'policy|watch|reload'
```

Parse errors appear in the log as `failed to parse policy <file>: <reason>`.

### Selector matches no containers

List the identity keys KloudKnox detected for a container:

```bash
kkctl --env docker describe container <name-or-id>
```

Only labels set at container creation time plus the reserved `docker.*` keys are available. Labels added later via `docker update --label` are not re-synced.

### Events missing for short-lived containers

KloudKnox discovers containers on the `/events` stream plus a periodic resync. Containers that exit within milliseconds of starting may be missed. Raise log verbosity with `-logLevel=debug` to confirm the `start` event was observed.

### `-dockerEndpoint` over TCP

KloudKnox supports `tcp://host:port` endpoints. For non-local endpoints, use TLS-terminated connections and restrict access at the network layer.

---

## Uninstall and Cleanup

### `kloudknox` namespace stuck in `Terminating`

A `KloudKnoxPolicy` with a finalizer, or a pod waiting on a webhook response, can hold a namespace. Remove both:

```bash
# Drop any lingering finalizers on policies
kubectl get kloudknoxpolicy -A -o name | \
  xargs -I{} kubectl patch {} --type=merge -p '{"metadata":{"finalizers":null}}'

# Remove the webhook configuration if it is answering 5xx
kubectl delete mutatingwebhookconfiguration kloudknox-apparmor-webhook
```

### Residual AppArmor profiles on nodes

KloudKnox loads profiles under `/etc/apparmor.d/kloudknox-*`. They remain after uninstall. Remove them per node:

```bash
sudo rm /etc/apparmor.d/kloudknox-*
sudo systemctl reload apparmor
```

---

## Collecting a Support Bundle

Include this in any bug report:

```bash
kkctl sysdump -o kloudknox-$(date +%F).tar.gz
```

The bundle contains probe results, pod/node status, policies, agent logs, and (if available) relay-server logs. Review the archive and redact anything sensitive before sharing.

---

## See also

- [README.md](README.md) — quickstart
- [policy-authoring.md](policy-authoring.md) — spec and validation rules
- [docker-mode.md](docker-mode.md) — Docker and hybrid mode
- [integrations.md](integrations.md) — routing events to external systems
