# Docker-mode e2e suite

Regression scenarios that exercise KloudKnox running against a bare Docker Engine (no Kubernetes). Complement to the Kubernetes-mode suite in [`../e2e.sh`](../e2e.sh) — this one does not depend on any of the K8s framework under [`../lib/`](../lib) and can be invoked on any host with Docker + `kkctl`.

## Layout

```
tests/docker-only/
├── compose.test.yaml        # three targets: nginx, alpine, ubuntu
├── policies/
│   ├── 01-nginx-hardening.yaml
│   ├── 02-docker-sock-block.yaml                # applyToAll=true (§27 regression)
│   ├── 03-file-fromsource-block.yaml            # LSM enforcer regression
│   ├── 04-network-egress-block.yaml             # Network enforcer regression
│   ├── 05-applyToAll-sys-admin.yaml             # §27 regression
│   ├── 06-capability-block.yaml                 # Part I (capability)
│   ├── 07-ipc-signal-allow-list.yaml            # Part II (signal) — cross-profile, uses e2e-attacker
│   └── 08-ipc-unix-docker-sock-block.yaml       # Part II (unix-connect) — gated, see below
├── assert.sh                # tail-based alerts.jsonl matcher
├── run.sh                   # compose up + apply + trigger + assert
└── README.md
```

## Scenario map

| # | Scenario | Policy type | Trigger | Regression |
|---|---|---|---|---|
| 1 | nginx hardening | `file` (Block) | `docker exec e2e-nginx cat /etc/nginx/nginx.conf` | features.md §30.2 |
| 2 | docker.sock block | `file` + `applyToAll` | `docker exec e2e-alpine cat /var/run/docker.sock` | §27 + §30.2 |
| 3 | file+fromSource block | `file.fromSource` | `docker exec e2e-ubuntu sh -c '/usr/bin/cat /etc/shadow'` | LSM enforcer |
| 4 | network egress block | `network` | `docker exec e2e-alpine wget http://1.1.1.1` | Network enforcer |
| 5 | applyToAll file block | `file` + `applyToAll` | `docker exec e2e-ubuntu cat /etc/hostname` | §27 |
| 6 | capability block | `capabilities` | `docker exec e2e-alpine ping 1.1.1.1` | `cap_capable` kprobe attribution |
| 7 | ipc signal allow-list | `ipc.signal` | `docker exec e2e-attacker sh -c 'kill -KILL 1'` | cross-profile signal mediation (see below) |
| 8 | ipc unix-connect block | `ipc.unix` | `docker exec e2e-alpine socat - UNIX-CONNECT:/var/run/docker.sock` | gated — `ENABLE_IPC_SCENARIO=1` (socat install) |

### Why scenarios 1 and 5 use `file` Block (not `process` Block)

The stub AppArmor profile emitted for every test container contains a blanket
`file,` allow rule, which is equivalent to `rwmlkx` on every path — including
the exec transition qualifiers `ix`, `px`, `cx`, `ux`. AppArmor's deny-rule
semantics do **not** let a plain `deny /bin/sh x,` subtract those transition
qualifiers from a `file,`-class allow (parser error: *"in deny rules 'x' must
not be preceded by exec qualifier 'i', 'p', or 'u'"*). So a `process: Block`
rule compiles but never actually denies exec, and no alert fires.

A `file: Block` on a read-only path exercises the same enforcement path
(policy matcher Block → AppArmor `deny ... r,` + kprobe `matchFileOpen`
verification) without that limitation. Scenarios 1 and 5 therefore test file
Block instead of process Block. The underlying generator issue — emitting
`file,` while also trying to deny exec — is tracked separately; these
scenarios will be switched back to `process` rules once the generator learns
to split the blanket allow.

### Scenario 7 / 8 setup notes

- **`07-ipc-signal-allow-list`** needs a **cross-profile** setup. AppArmor
  signal mediation is same-profile-permissive: a process can always signal
  another process confined by the **same** profile, regardless of the
  profile's signal rules. `compose.test.yaml` therefore defines a second
  container `e2e-attacker` that shares `e2e-alpine`'s PID namespace but runs
  under its own AppArmor profile (`kloudknox-docker-e2e-attacker`); run.sh
  triggers the kill from there so cross-profile mediation actually applies.
- **`08-ipc-unix-docker-sock-block`** needs `socat` inside `e2e-alpine`
  (busybox `nc` does not speak `-U`). run.sh installs it on-demand via apk,
  which is not guaranteed in every environment — gated on
  `ENABLE_IPC_SCENARIO=1` to keep the default run hermetic.

The "hybrid de-dup" path (Docker daemon *and* containerd/Kubernetes on the
same host) is not covered here; run the K8s suite in parallel to exercise
it.

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine 20.10+ | running on the host |
| `docker compose` v2 | for `compose.test.yaml` |
| `jq` | alert JSON parsing |
| `kkctl` | on `PATH`, or set `KKCTL=/path/to/kkctl` |
| Running KloudKnox daemon in docker mode | plus an alert stream redirected to `$ALERTS_FILE` |

The suite **does not manage the KloudKnox daemon**. Start it first, pointed at a clean policy directory:

```bash
sudo mkdir -p /etc/kloudknox/policies /var/log/kloudknox
sudo kloudknox -mode=docker \
  -policyDir=/etc/kloudknox/policies \
  -coverage=extended &

# Bridge alerts into a file the suite can tail. stdbuf -oL keeps kkctl
# line-buffered so the tailer in assert.sh sees each alert immediately.
stdbuf -oL kkctl stream alerts --server localhost:36890 \
  > /var/log/kloudknox/alerts.jsonl &
```

`-coverage=extended` attaches the file-modification and directory kprobes
(`filp_close`, `security_path_{chmod,chown,unlink,rename,link,mkdir,rmdir,chroot}`)
on top of the default set. The scenarios in this suite fire on probes
already in the default coverage (`security_bprm_check`, `security_file_open`,
`cap_capable`, `security_task_kill`, `security_unix_stream_connect`,
`security_unix_may_send`, `security_ptrace_access_check`), so
`-coverage=default` works too — the example above uses `extended` to mirror
the K8s suite. See `monitor/systemMonitor.go` for the canonical list.

## Running

```bash
cd tests/docker-only
./run.sh
```

Defaults can be overridden via env vars:

| Var | Default | Description |
|---|---|---|
| `KKCTL` | `kkctl` | `kkctl` binary to invoke |
| `ALERTS_FILE` | `/var/log/kloudknox/alerts.jsonl` | file consumed by `assert.sh` |
| `ALERT_WINDOW_SEC` | `5` | seconds to wait for an alert after the trigger |
| `SETTLE_SEC` | `2` | pause between compose-up / policy apply and the next step |

The run produces a `N passed, M failed` summary and exits non-zero if any scenario failed. On failure, the offending policy name and the tail of `alerts.jsonl` are written to stderr.

`./assert.sh <policyName> [window]` can also be invoked directly for manual checks against the whole alerts file.

## Cleanup

`run.sh` installs an `EXIT` trap that:

- `kkctl delete`s every policy in `policies/`
- `docker compose down --remove-orphans`s the three test targets

So an interrupted run leaves the host clean. The underlying KloudKnox daemon is untouched.
