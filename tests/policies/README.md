# tests/policies

`KloudKnoxPolicy` YAML fixtures consumed by the e2e cases in [`../cases/test-cases.yaml`](../cases/test-cases.yaml). Each file is one policy; a case applies exactly one policy and exercises it across one or more steps. The subdirectory `k8s-live/` holds a separate, smaller set used only by `k8s-live.sh` for operator and `kkctl` validation.

## Naming convention

```
<target>-<resource>-<shape>[-<variant>][-<action>].yaml
```

| Segment | Values |
|---|---|
| `target` | `group-1`, `group-2` — selector matches multiple pods by `group=` label<br>`ubuntu-1` … `ubuntu-3` — selector matches one pod by `container=` label |
| `resource` | `proc` (process), `file`, `net` (network), `cap` (capabilities), `ipc` (signal / ptrace) |
| `shape` | `path`, `dir`, `dir-recursive`, `dir-readonly`, `cidr`, `fqdn`, `peer`, `port-udp`, `signal`, `ptrace`, `multikey-selector`, `per-rule-action-mixed`, `combined-file-proc-net` |
| `variant` | `fs` — `fromSource` rule (matches only when invoked by a specific exe path, compiled under [`../build/`](../build/))<br>`except` — `except:` list test<br>Absent — plain rule |
| `action` | `allow`, `block`, `audit`. If omitted, the policy's top-level `action` applies uniformly. |

Examples:

| Filename | Reading |
|---|---|
| `ubuntu-1-file-path-block.yaml` | ubuntu-1 pod, file-path Block |
| `group-1-proc-path-allow-fs.yaml` | group-1 pods, process-path Allow with fromSource |
| `ubuntu-1-net-cidr-egress-except.yaml` | ubuntu-1 pod, network CIDR egress with `except:` carve-out |
| `ubuntu-3-file-dir-readonly-audit-fs.yaml` | ubuntu-3, file-directory readOnly Audit with fromSource |
| `ubuntu-3-per-rule-action-mixed.yaml` | per-rule `action:` override (rule-level beats policy-level) |
| `ubuntu-3-combined-file-proc-net.yaml` | multi-resource policy exercising all three rule blocks |

## Coverage by resource

| Resource | Files | Notes |
|---|---|---|
| Process | `*-proc-path-*`, `*-proc-dir-*` | `dir` = exact directory, `dir-recursive` = recursive |
| File | `*-file-path-*`, `*-file-dir-*`, `*-file-dir-readonly-*` | `readonly` fixtures test the readOnly qualifier |
| Network | `*-net-cidr-*`, `*-net-fqdn-*`, `*-net-peer-*`, `*-net-port-udp-*` | Both egress and ingress for CIDR/peer; egress-only for FQDN/UDP |
| Capabilities | `ubuntu-1-cap-block.yaml`, `ubuntu-1-cap-allow-fs.yaml` | `fs` variant uses `kk-capraw` as the fromSource exe |
| IPC | `*-ipc-signal-*`, `*-ipc-ptrace-*` | Signal/ptrace need kprobe events; see `getting-started/policy-authoring.md`. Unix-socket IPC coverage lives in [`../docker-only/policies/`](../docker-only/policies/) (scenario 8). |
| Mixed | `*-multikey-selector-*`, `*-per-rule-action-*`, `*-combined-*` | Selector semantics and per-rule action override |

The case ↔ policy mapping lives in [`../cases/test-cases.yaml`](../cases/test-cases.yaml) (57 cases total). Use `../e2e.sh list` to print the registered case IDs.

## CIDR rewriting at apply time

Every ingress CIDR in these fixtures is written as `10.0.0.0/8`. The case runner rewrites it to the cluster's actual pod CIDR (`<oct1>.<oct2>.0.0/16`) via `sed` before `kubectl apply` — see `_case_detect_ingress_cidr` in [`../lib/case-runner.sh`](../lib/case-runner.sh). **Do not** hard-code cluster-specific CIDRs in new fixtures; keep `10.0.0.0/8` as the placeholder.

## `k8s-live/`

Three small policies used only by [`../k8s-live.sh`](../k8s-live.sh) to verify the operator-controller and admission webhook reconcile paths:

| File | Used for |
|---|---|
| `valid-policy.yaml` | Process Block — expected to reach `status.status = Active` |
| `valid-file-policy.yaml` | File Block — same path, different resource type |
| `invalid-no-selector.yaml` | Missing `spec.selector` — must be rejected by the webhook or marked `Invalid` by the reconciler |

These policies target the `ubuntu-1` label but do not need the e2e workloads deployed; the check is on reconciler status, not enforcement.

## Adding a new policy

1. Pick a filename that matches the naming convention.
2. Keep ingress CIDRs as `10.0.0.0/8` (see above).
3. For `fromSource` rules, the exe path must already exist in the `e2e-workloads` image — add a new helper under [`../build/helpers/`](../build/helpers/) and rebuild if needed.
4. Register the policy in [`../cases/test-cases.yaml`](../cases/test-cases.yaml) with one or more steps. Each step declares `expect: allowed | blocked | audited`.
5. Run `../e2e.sh run <your-case-id>` to verify.

## License

Apache License 2.0. See the [LICENSE](../../LICENSE) file for details.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
