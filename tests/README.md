# KloudKnox End-to-End Tests

Three test flavors are provided.

| | **e2e local** | **docker-only** | **k8s-live** |
|---|---|---|---|
| Runtime target | K8s pods | `docker compose` containers | K8s pods |
| KloudKnox runtime | Host process (`sudo`) | Host process (`sudo`, `-mode=docker`) | K8s DaemonSet |
| Image build | Not required (build Go directly) | Not required | `make build-images` required |
| Policy enforcement verification | 57 cases (Block/Audit/Allow) | 8 scenarios (Docker-mode regressions) | Up to operator `Active` check |
| Component integration | webhook/relay excluded | Docker Engine only (no operator/webhook/relay) | Full component set |
| When to use | Agent feature dev/debug | Docker-mode enforcement regression | Pre-release integration, CI |

---

## 1. E2E local tests (`e2e.sh`)

Runs the KloudKnox agent as a host process and verifies policy enforcement directly.

### Prerequisites

- A working K8s cluster accessible via `kubectl`
- `jq`, `python3`, `go`
- `sudo` privileges (KloudKnox needs root to load eBPF programs)

### Quick start

```bash
# Bring the environment up (build + start agent + deploy pods)
./e2e.sh up

# Run a single case
./e2e.sh run test-07

# Run every case (CI entrypoint)
./e2e.sh run-all

# Skip external-network cases
./e2e.sh run-all --skip-tags external-network

# Tear the environment down
./e2e.sh down
```

`make up`, `make run CASE=test-07`, `make run-all`, and `make down` are equivalent.

### Bring-up flow

`e2e.sh up` performs:

1. `KloudKnox/make build` — build the Go binary on the host (BPF `.o` files are pre-compiled).
2. `../kloudknox-cli/make build` — build the `kkctl` binary (expects [kloudknox-cli](https://github.com/boanlab/kloudknox-cli) cloned as a sibling directory).
3. `sudo -E nohup ./kloudknox` — start the agent (port 36890).
4. `kkctl stream alerts` — tail alert stream in the background.
5. `kubectl apply e2e-workloads_with_apparmor.yaml` — deploy the test pods.

### Commands

| Command | Description |
|---|---|
| `e2e.sh up` | Build → start agent → deploy pods |
| `e2e.sh down` | Remove pods/policies → stop agent |
| `e2e.sh status` | Show daemon PID and latest alert |
| `e2e.sh list` | List registered cases |
| `e2e.sh run <id> [<id>...]` | Run cases (by id or policy name) |
| `e2e.sh run-all` | Run every case |
| `e2e.sh logs kloudknox\|alerts` | Tail the log file |

### `run` options

| Flag | Description |
|---|---|
| `--step` | Pause before each step (manual checkpoint) |
| `--no-assert` | Execute commands but skip PASS/FAIL judgement |
| `--alert-window <sec>` | Alert collection window (default 3s) |
| `--verbose` | Print exec stdout/stderr |
| `--dry-run` | Print the execution plan only — do not run |

### Test cases (57)

| Range | Cases |
|---|---|
| Process | test-01 ~ test-11 |
| File | test-12 ~ test-35 |
| Network | test-36 ~ test-50 (some tagged `external-network`) |
| Combined | test-51 ~ test-53 |
| Capability | test-54 ~ test-55 |
| IPC | test-56 ~ test-57 |

### Pass criteria

Each step declares `expect: allowed | blocked | audited`. The `alerts.jsonl`
offset is snapshotted before and after the step so only alerts produced during
the step are considered.

| expect | PASS condition |
|---|---|
| `allowed` | exit=0 **and** no matching alert |
| `blocked` | `policyAction=Block` alert present |
| `audited` | exit=0 **and** `policyAction=Audit` alert present |

### Output

`artifacts/report.md`

---

## 2. Docker-only e2e tests (`docker-only/run.sh`)

Regression scenarios that exercise KloudKnox running against a bare Docker Engine (no Kubernetes). Workloads come from `compose.test.yaml`; policies are applied via `kkctl --env docker apply` against the daemon's `-policyDir`.

The suite **does not manage the KloudKnox daemon** — start it in `-mode=docker` and redirect `kkctl stream alerts` to a file first. Then:

```bash
cd tests/docker-only
./run.sh
```

8 scenarios cover file Block / `applyToAll` / file `fromSource` / network egress / capability / IPC (signal, unix-connect) enforcement paths. Scenario 8 (ipc unix-connect) is gated on `ENABLE_IPC_SCENARIO=1` because it needs `socat` installed inside the test container.

See [`docker-only/README.md`](docker-only/README.md) for prerequisites, scenario map, AppArmor `file,` / `process Block` caveat, and env-var overrides (`KKCTL`, `ALERTS_FILE`, `ALERT_WINDOW_SEC`, `SETTLE_SEC`).

---

## 3. K8s live integration tests (`k8s-live.sh`)

Verifies the full component set once every piece is deployed inside K8s.

### Prerequisites

- `kubectl`, `jq`, `python3`
- `kkctl` built (`../kloudknox-cli/kloudknox-cli/bin/kkctl`, installed from [kloudknox-cli](https://github.com/boanlab/kloudknox-cli), or on PATH)
- `docker`, `sudo ctr` (only when building images locally)

### Quick start

```bash
cd tests

# 1. Build every image and import into containerd (no registry required)
make build-images

# 2. Deploy everything (main repo manifests, plus relay-server and kkctl
#    from sibling checkouts, falls back to GitHub if a checkout is missing)
make k8s-up

# 3. Run integration tests
make k8s-live
```

> **Deploying published images**: When images are available in a registry,
> `make build-images` is not needed — `make k8s-up` is sufficient
> (`imagePullPolicy: IfNotPresent`).

### What `make build-images` does

Runs `make build-image TAG=v0.1.0` in each component directory, then loads the
image into containerd via `docker save | sudo ctr -n k8s.io images import -`.

Sibling repos are checked out under `../` (see [kloudknox-apparmor-webhook](https://github.com/boanlab/kloudknox-apparmor-webhook), [kloudknox-relay-server](https://github.com/boanlab/kloudknox-relay-server), [kloudknox-cli](https://github.com/boanlab/kloudknox-cli)).

| Component | Image |
|---|---|
| `../kloudknox-apparmor-webhook/` | `boanlab/kloudknox-apparmor-webhook:v0.1.0` |
| `operator-controller/` | `boanlab/kloudknox-operator:v0.1.0` |
| `../kloudknox-relay-server/` | `boanlab/kloudknox-relay-server:v0.1.0` |
| `../kloudknox-cli/` | `boanlab/kloudknox-cli:v0.1.0` |
| `KloudKnox/` | `boanlab/kloudknox:v0.1.0` |

### Per-component checks

```bash
make k8s-live-components   # daemonset/deployment readiness
make k8s-live-webhook      # AppArmor annotation injection (e2e-workloads.yaml)
make k8s-live-operator     # policy validate / Active / Reject
make k8s-live-relay        # gRPC port-forward + kkctl stream connectivity
make k8s-live-kkctl        # kkctl version, status, validate, apply
```

### What is checked

| Check | Detail |
|---|---|
| component health | DaemonSet 1/1, 3 Deployments rolled out |
| apparmor-webhook | 4/4 pods receive AppArmor annotations after deploying `e2e-workloads.yaml` |
| operator-controller | Valid policy → `Active`; invalid policy → rejected by webhook |
| relay-server | Port-forward succeeds, `kkctl stream alerts` stays connected for 5s |
| kkctl | version, status (DaemonSet 1/1), policy validate/apply |

### Output

`artifacts/k8s-live-report.md`
