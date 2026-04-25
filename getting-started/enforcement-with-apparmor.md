# AppArmor Enforcement (Fallback Path)

KloudKnox enforces policies through one of two LSM backends:

- **BPF-LSM** (primary) — direct kernel hook attachment via the BPF LSM. Selected when `bpf` appears in `/sys/kernel/security/lsm`.
- **AppArmor** (fallback) — AppArmor profile generation and `apparmor_parser` load. Selected on hosts that do not expose `bpf` in `/sys/kernel/security/lsm`.

`kkctl probe` reports which backend the agent picked at startup. This document covers the AppArmor fallback path: how it works and which limitations are inherent to AppArmor's transition model. On the BPF-LSM primary path no AppArmor profile is generated and the limitations below do not apply.

## How it works

For each pod that matches a `KloudKnoxPolicy`, the agent generates an AppArmor profile under `/etc/apparmor.d/kloudknox-<namespace>-<workload>-<container>` and loads it with `apparmor_parser`. The `apparmor-webhook` MutatingAdmissionWebhook injects the profile reference into the pod spec at admission time, so containerd applies the profile when starting the container.

Once the container is running, every syscall it issues is mediated by the AppArmor profile. Process, file, capability, and IPC rules in the policy translate to corresponding `deny` lines in the profile. Network rules use cgroup-BPF regardless of the LSM backend.

## Known limitations

### Direct `kubectl exec <pod> -- <binary>` is not blocked by `deny <path> x,`

AppArmor's `deny <path> x,` rule fires only when a process **inside** the profile's domain calls `execve` on the path. With `kubectl exec demo -- /bin/sleep`, the new process is spawned by `containerd-shim`, which lives in `cri-containerd.apparmor.d` and is allowed to exec arbitrary binaries; the new process inherits the kloudknox profile only **after** the exec completes, so the deny is never evaluated.

Real workloads always fork+exec from inside the container (e.g. nginx spawning a CGI script, an app spawning a shell), so this is not a runtime threat. To verify a `Block` rule from a test pod, wrap the command in a shell so the spawn happens inside the profile:

```bash
# ✓ Blocked — bash spawns sleep from inside the profile
kubectl exec demo -- bash -c '/bin/sleep 60'

# ✗ Not blocked — containerd-shim spawns sleep, AppArmor evaluates against shim's profile
kubectl exec demo -- /bin/sleep 60
```

The BPF-LSM path enforces at the kernel hook regardless of the parent process and does not have this asymmetry.

## See also

- [Policy authoring](policy-authoring.md) for the full `KloudKnoxPolicy` spec
- [Troubleshooting](troubleshooting.md) for symptom-indexed diagnostics
- [Top-level README](../README.md#prerequisites) for enabling BPF-LSM (`/sys/kernel/security/lsm` must contain `bpf`)
