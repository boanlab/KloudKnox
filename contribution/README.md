# Contribution Guide

This guide provides instructions for contributing to the KloudKnox project, including development environment setup, coding standards, and the pull request process.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Environment Setup](#development-environment-setup)
- [Build and Run](#build-and-run)
- [Codebase Map](#codebase-map)
- [Code Contribution Process](#code-contribution-process)
- [Commit Message Convention](#commit-message-convention)
- [Issue and Pull Request Guidelines](#issue-and-pull-request-guidelines)

## Prerequisites

Required to develop and run the agent:

- Go 1.24.0+
- Linux kernel 5.15+ with eBPF support
- Clang 19+
- LLVM 19+
- Containerd (the agent talks to the containerd gRPC socket at runtime)
- Kubernetes cluster with containerd as CRI (the agent watches `KloudKnoxPolicy` CRDs)
- BPF-LSM enabled on the host (check `/sys/kernel/security/lsm`), or AppArmor as a fallback

Additionally required only for container image builds:

- **Docker** — used by `make build-image` to package the agent

## Development Environment Setup

### Install Go

```bash
cd contribution/golang
./install-golang.sh
```

### Install BPF Development Tools

```bash
cd contribution/bpf
./install-deps.sh
```

> Alternative: `cd KloudKnox/BPF && make install-tools` installs the same toolchain idempotently (skips anything already on the host) using the rules in `KloudKnox/BPF/Makefile`.

### Install Containerd

Required — KloudKnox connects to the containerd gRPC socket to receive container lifecycle events.

```bash
cd contribution/containerd
./install-containerd.sh
```

### Install Kubernetes Tools

Required — KloudKnox watches `KloudKnoxPolicy` CRDs via the Kubernetes API, so a live cluster is needed to run the agent and verify changes end-to-end.

```bash
cd contribution/k8s
./install-kubeadm.sh
./initialize-kubeadm.sh
CNI=flannel ./deploy-cni.sh
```

### Install Docker (Optional)

Only required to build the KloudKnox container image. KloudKnox does **not** talk to the Docker daemon at runtime — it talks to containerd directly.

```bash
cd contribution/docker
./install-docker.sh
```

## Build and Run

### Build KloudKnox Agent

```bash
cd KloudKnox
make clean   # remove pre-compiled BPF object files
make         # runs gofmt, golangci-lint, gosec, compiles BPF programs, and builds the Go binary
```

The default `make` target (`build`) depends on `bpf`, `gofmt`, `golangci-lint`, and `gosec`, so you do not need to invoke them separately before a build.

### Run KloudKnox Agent

```bash
cd KloudKnox
make run
```

### Build the CLI Client

`kkctl` lives in its own repository:

```bash
git clone https://github.com/boanlab/kloudknox-cli.git
cd kloudknox-cli/kloudknox-cli
make
```

### Run the CLI Client

```bash
# Pre-flight environment check (kernel, BTF, cgroup v2, BPF-LSM/AppArmor, kubeconfig)
./kkctl probe

# Cluster lifecycle (auto-detects k8s vs docker)
./kkctl install | uninstall | upgrade | status

# Streaming (gRPC, defaults to localhost:36890)
./kkctl stream events
./kkctl stream alerts
./kkctl stream logs

# Policy CRUD (REST over Unix socket, or Kubernetes API fallback)
./kkctl apply -f policy.yaml
./kkctl get   policies [-o table|wide|json|yaml]
./kkctl delete policy <name>
```

See the [kloudknox-cli README](https://github.com/boanlab/kloudknox-cli/blob/main/README.md) for the full command surface and flag reference.

### Build the Container Image

Requires Docker. From the `KloudKnox/` directory:

```bash
make build-image        # builds <image>:<tag> and <image>:latest from ../Dockerfile
make push-image         # builds and pushes both tags to the configured registry
make clean-image        # removes local image tags
```

Image name and tag are controlled by the `IMAGE_NAME` and `TAG` variables in `KloudKnox/Makefile`.

### Build Other Components

Each component has its own `Makefile`. From the component directory:

```bash
make build
```

## Codebase Map

Understanding which part of the codebase to touch for a given change:

| Area | Location | Notes |
|---|---|---|
| eBPF monitor programs | `KloudKnox/BPF/monitor/` | Compiled with `make`; requires Clang 19 |
| eBPF enforcer programs | `KloudKnox/BPF/enforcer/` | `net_enforcer.bpf.c` (network, IPv4-only, kprobes + cgroup-skb) and `bpf_enforcer.bpf.c` (BPF-LSM hooks for process/file/capability/unix/signal/ptrace) |
| BPF shared headers | `KloudKnox/BPF/common/` | Shared between monitor and enforcer |
| Event parsing (userspace) | `KloudKnox/monitor/eventParser.go` | Decodes raw BPF ring-buffer events |
| Policy matching (monitor) | `KloudKnox/monitor/policyMatcher.go` | Matches events against active policies |
| Runtime enforcer dispatch | `KloudKnox/enforcer/enforcer.go` | Detects `/sys/kernel/security/lsm` and selects BPF-LSM (preferred) or AppArmor |
| BPF-LSM enforcer (process/file/capability/IPC) | `KloudKnox/enforcer/bpfEnforcer.go` | Loads `bpf_enforcer.bpf.o` and manages rule maps |
| AppArmor enforcer (fallback) | `KloudKnox/enforcer/appArmorEnforcer.go`, `appArmorProfile.go` | Profile generation and loading |
| Network enforcement | `KloudKnox/enforcer/networkEnforcer.go` | Entry point for BPF-based network policy |
| Network policy internals | `KloudKnox/enforcer/networkPolicyHandler.go`, `networkPolicyMatcher.go`, `networkEventHandler.go` | Rule-map sync and event fan-out |
| FQDN resolution | `KloudKnox/enforcer/fqdnResolver.go` | DNS → IP cache for `fqdn:` rules |
| Policy ingestion | `KloudKnox/core/policyHandler.go` | Watches K8s CRDs, converts to internal types |
| Policy conversion | `KloudKnox/core/policyConverter.go` | `KloudKnoxPolicy` → internal `Policy` struct |
| Kubernetes client | `KloudKnox/core/k8sHandler.go` | CRD informers and pod/namespace lookups |
| Containerd integration | `KloudKnox/core/containerdHandler.go` | Container lifecycle events |
| gRPC export | `KloudKnox/exporter/` | Streams events, alerts, and logs to clients |
| Shared types | `KloudKnox/types/` | All cross-package data structures |

**Regenerating BPF Go bindings** (after editing `.bpf.c` files):

```bash
cd KloudKnox
make bpf        # delegates to KloudKnox/BPF/Makefile
# equivalent to:
#   cd KloudKnox/BPF && make
# which runs clang -> *.bpf.o and bpf2go -> *_bpfel.go for
# system_events, net_enforcer, and bpf_enforcer.
```

`make clean` at the `KloudKnox/` level removes the BPF object files and generated Go bindings; the next `make` regenerates them.

## Code Contribution Process

### 1. Select an Issue

Browse open issues at [GitHub Issues](https://github.com/boanlab/KloudKnox/issues).

Label reference:

| Label | Description |
|---|---|
| `good-first-issue` | Suitable for first-time contributors |
| `help-wanted` | Tasks open to external contributors |
| `bug` | Confirmed bug reports |
| `enhancement` | New feature requests |

Comment on the issue you intend to work on before starting.

### 2. Fork and Create a Branch

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/your-username/KloudKnox.git
cd KloudKnox

# Add the upstream remote
git remote add upstream https://github.com/boanlab/KloudKnox.git

# Create a feature or fix branch
git checkout -b feature/your-feature-name
git checkout -b fix/your-bug-fix-name
```

### 3. Implement and Test

Follow existing code style. Run linters and tests before submitting (from the `KloudKnox/` directory):

```bash
make gofmt          # gofmt -w -s
make golangci-lint  # golangci-lint run (auto-installs the binary)
make gosec          # gosec -exclude=G402 ./...
make test           # go test ./... -v -count=1
```

`make` (the default `build` target) already chains `gofmt`, `golangci-lint`, and `gosec` before compiling, so a plain `make` is enough for local verification — run `make test` separately.

### 4. Submit a Pull Request

```bash
git add <files>
git commit -m "feat(monitor): brief description of change"
git push origin feature/your-feature-name
```

Open a pull request on GitHub against the `main` branch. Include the related issue number in the description.

## Commit Message Convention

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:

| Type | Description |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style or formatting changes |
| `refactor` | Refactoring without behavior change |
| `test` | Adding or updating tests |
| `chore` | Build process or tooling changes |

Example:

```
feat(monitor): add syscall filtering by name

- Add filter interface to the system monitor
- Implement allowlist and denylist matching

Closes #123
```

## Issue and Pull Request Guidelines

### Bug Report Template

```markdown
## Description
A clear description of the bug.

## Steps to Reproduce
1. Run '...'
2. Observe '...'

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- OS: Ubuntu 22.04
- Kernel: 5.15.0-91-generic
- KloudKnox version: (output of `kkctl version`)
- `kkctl sysdump -o bundle.tar.gz` output attached (recommended)

## Additional Context
Logs, screenshots, or other relevant information.
```

### Feature Request Template

```markdown
## Description
A clear description of the requested feature.

## Use Case
Why this feature is needed and how it will be used.

## Proposed Solution
A specific implementation approach or design.

## Alternatives Considered
Other approaches that were evaluated.
```

### Pull Request Requirements

- PR title must be concise and descriptive
- Link all related issues
- Include a summary of changes and the reasoning
- All linter checks and tests must pass
- At least two approvals are required before merging

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
