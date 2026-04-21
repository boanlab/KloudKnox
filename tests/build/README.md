# tests/build

Builds the `boanlab/e2e-workloads` container image consumed by the e2e suites in [`../e2e.sh`](../e2e.sh) and [`../k8s-live.sh`](../k8s-live.sh). The resulting image provides a single PID-1 sleeper plus a small set of compiled C helpers used as stable exec sources for `fromSource`-style policies.

## Layout

```
tests/build/
├── Dockerfile                  # two-stage build (gcc in builder → minimal runner)
├── entrypoint.sh               # CMD — sleep infinity (PID 1)
├── build.sh                    # wrapper: docker build + optional push
├── helloworld/
│   └── helloworld.c            # no-op "hello world" — stable exec path for proc tests
├── readwrite/
│   └── readwrite.c             # append/read a single byte — file I/O probe
└── helpers/
    ├── kk-http-server.c        # single-process blocking HTTP server (serves :80 in ubuntu-2/3)
    ├── kk-signaler.c           # compiled kill(2) wrapper — stable exe for ipc.signal fromSource
    └── kk-capraw.c             # AF_INET/SOCK_RAW probe — CAP_NET_RAW fromSource tests
```

### Why compiled helpers instead of shell one-liners

`fromSource` rules match by the caller's executable path (`/proc/<pid>/exe`). Shell commands (`sh -c 'kill …'`, `ping`, etc.) resolve to busy-box / shell binaries that are shared across many call sites, so the policy can't isolate the call under test. Each helper compiles to a dedicated `/usr/local/bin/kk-*` path that is only exercised by its test case.

`kk-http-server` runs as a single blocking `accept()` loop so PID 1 is the only process the matcher ever sees — no worker/import subprocesses under AppArmor-narrowed profiles.

## Runner-stage image contents

| Path | Purpose |
|---|---|
| `/usr/local/bin/kk-http-server` | HTTP listener invoked as PID 1 for ingress/egress tests |
| `/usr/local/bin/kk-signaler` | Stable `kill(2)` exe for `ipc.signal` policies |
| `/usr/local/bin/kk-capraw` | Stable `socket(AF_INET, SOCK_RAW)` probe for capability tests |
| `/helloworld`, `/readwrite` | Root-owned copies used by process/file path tests |
| `/secret.txt`, `/plain.txt`, `/credentials/**` | File fixtures for allow/block/audit path tests |

Packages pulled into the runner stage (`curl`, `dnsutils`, `iptables`, `iputils-ping`, `net-tools`, `procps`, `socat`, `strace`, `tcpdump`) are used by various test steps as trigger commands — `ping` for ICMP egress, `socat` for unix-connect, etc.

## Building

```bash
cd tests/build
./build.sh                  # build + push boanlab/e2e-workloads:v0.1.0 and :latest
NO_PUSH=1 ./build.sh        # local build only
TAG=dev ./build.sh          # override the tag
```

`make build-images` from `tests/` invokes this script as part of the full multi-repo image set — see [`../README.md`](../README.md) for the k8s-live path.

## When to rebuild

- A helper under `helpers/` or a fixture path in the `Dockerfile` changed.
- A new test case needs a new stable exe path — add the source under `helpers/`, register it in the `COPY … /src/…` + `gcc` blocks of `Dockerfile`, install it under `/usr/local/bin/` in the runner stage.
- Entrypoint changed. The default is `sleep infinity`; pod specs under [`../e2e-workloads.yaml`](../e2e-workloads.yaml) and [`../e2e-workloads_with_apparmor.yaml`](../e2e-workloads_with_apparmor.yaml) override `command:` when a listener is needed.

## License

Apache License 2.0. See the [LICENSE](../../LICENSE) file for details.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
