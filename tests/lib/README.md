# tests/lib

Shared shell and Python libraries sourced by the e2e suites. Not user-facing — consumed by [`../e2e.sh`](../e2e.sh) and [`../k8s-live.sh`](../k8s-live.sh). This README is for contributors extending the suites.

## Files

| File | Role | Consumed by |
|---|---|---|
| `bootstrap.sh` | Daemon lifecycle: build, start/stop KloudKnox + `kkctl stream alerts`, CRD install, pod deploy | `e2e.sh up` / `down` / `status` |
| `case-runner.sh` | Runs a single case from `cases/test-cases.yaml`: apply policy → wait for commit → exec steps → assert → cleanup | `e2e.sh run` / `run-all` |
| `cases.py` | Minimal YAML parser for `cases/test-cases.yaml` (strict 2-space indent, no PyYAML dep). Sub-commands: `ids`, `ids-excluding <tag>`, `list`, `get <id>` | `case-runner.sh` |
| `assert.sh` | Judges a step against `alerts.jsonl`: offset snapshot + windowed match → PASS/FAIL with reason | `case-runner.sh` |
| `report.sh` | Appends PASS/FAIL rows to `artifacts/report.md` as cases run | `case-runner.sh` |
| `k8s_live.sh` | Component integration checks: daemonset health, apparmor-webhook injection, operator reconcile, relay gRPC, `kkctl` | `k8s-live.sh` |

## Contract with the entrypoints

Every file except `cases.py` is `source`d — never executed directly — and relies on globals set by the caller. Adding a new helper means either (a) accepting the same globals, or (b) declaring new ones at the top of the entrypoint script.

### Globals set by `e2e.sh`

```
E2E_ROOT                repo-relative tests/ directory
REPO_ROOT               tests/../..
ART_DIR                 tests/artifacts (log/alert/report sink)
CASES_FILE              tests/cases/test-cases.yaml
KLOUDKNOX_DIR           KloudKnox/KloudKnox (agent source)
KLOUDKNOX_DEPLOY_DIR    KloudKnox/deployments (CRD manifest lives here)
KKCTL_DIR               ../kloudknox-cli/kloudknox-cli
E2E_WORKLOADS_YAML      tests/e2e-workloads_with_apparmor.yaml
POLICIES_DIR            tests/policies
```

### Globals set by `k8s-live.sh`

```
ART_DIR                  shared with e2e (artifact sink)
KKCTL_BIN                kkctl binary (local mode)
POLICIES_LIVE_DIR        tests/policies/k8s-live
E2E_WORKLOADS_PLAIN_YAML tests/e2e-workloads.yaml (no AppArmor annotations)
KL_NS                    target namespace (default: kloudknox)
KL_WEBHOOK_TEST_NS       namespace the webhook test labels + deploys into
KL_RELAY_LOCAL_PORT      local port for the relay-server port-forward
KL_RELAY_STREAM_SEC      how long to hold the kkctl → relay stream open
KL_CERT_MANAGER_VERSION  cert-manager release tag installed by `up`
KL_DEPLOY_DIR            path to KloudKnox deployments/ (CRD + daemonset)
KL_KKCTL_MODE            local | pod | both
KL_KKCTL_POD_DEPLOY      deployment name when KL_KKCTL_MODE includes pod
```

User-facing defaults and env-var descriptions live in the entrypoint's `usage()` output; the list here is the subset that the lib functions read.

## Assertion model (`assert.sh`)

Each step snapshots `stat -c%s alerts.jsonl` *before* the `kubectl exec`, then matches newline-delimited JSON records appearing after that byte offset within `--alert-window` seconds (default 3). The match is:

```
policyName == <policy under test>
  AND containerName ∈ { pod_label, pod_label+"-container", <ingress target>+"-container", null }
```

Ingress policies fire in the destination pod's context, so the matcher derives `<prefix>-container` from the policy name (`ubuntu-2-net-peer-ingress-block` → target `ubuntu-2-container`).

Verdict table (`ASSERT_VERDICT` / `ASSERT_REASON` exported for the runner):

| `expect` | PASS condition |
|---|---|
| `allowed` | `exit == 0` AND `total == 0` |
| `blocked` | any alert with `policyAction=Block` OR `retCode=Blocked` (Allow+whitelist denial) |
| `audited` | `exit == 0` AND any alert with `policyAction=Audit` |

## Case-runner mechanics worth knowing

- **`_case_detect_ingress_cidr`** rewrites `10.0.0.0/8` in policy YAMLs to the cluster's actual pod CIDR (`<oct1>.<oct2>.0.0/16`), so ingress cases work across GKE/kind/kubeadm without editing the fixtures.
- **`_case_snapshot_log_offset` + `_case_wait_policy_applied`** watch `kloudknox.log` for either `Updated a KloudKnoxPolicy (<name>) to pod` *or* `(Added|Updated) a KloudKnoxPolicy (default/<name>)`. Network-only policies never touch AppArmor, so the namespaced form is the only confirmation they produce.
- Each run deletes the previous case's policy before applying the next one — tests are **not** parallel-safe against the same daemon.

## `cases.py` schema

Strict 2-space-indent YAML subset — no PyYAML dependency so the suite runs on minimal CI images. Full schema lives in the file header; violations raise `SyntaxError` with a line number. See [`cases.py`](cases.py) for the canonical definition.

## License

Apache License 2.0. See the [LICENSE](../../LICENSE) file for details.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
