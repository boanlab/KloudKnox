# Contributing to KloudKnox

Thank you for your interest in contributing to KloudKnox.

This document is a quick entry point. The full guide — including environment setup, build instructions, commit conventions, and PR requirements — lives in **[contribution/README.md](contribution/README.md)**.

## Quick Start

```bash
# 1. Fork and clone
git clone https://github.com/your-username/KloudKnox.git
cd KloudKnox

git remote add upstream https://github.com/boanlab/KloudKnox.git

# 2. Set up the dev environment
cd contribution/golang   && ./install-golang.sh
cd ../bpf                && ./install-deps.sh
cd ../containerd         && ./install-containerd.sh
cd ../k8s                && ./install-kubeadm.sh && ./initialize-kubeadm.sh && CNI=flannel ./deploy-cni.sh

# 3. Build
cd ../../KloudKnox
make

# 4. Create a branch and work
git checkout -b fix/your-bug   # or feature/your-feature
```

Install Docker (`contribution/docker/install-docker.sh`) additionally if you need to build container images. See the [full guide](contribution/README.md) for details.

## Before Submitting a PR

From the `KloudKnox/` directory, make sure linters and tests pass:

```bash
make gofmt
make golangci-lint
make gosec
make test
```

Commit messages follow the `<type>(<scope>): <subject>` convention (e.g. `feat(monitor): add syscall filtering`). PRs require linked issues and at least two approvals. See the [full guide](contribution/README.md#commit-message-convention) for the complete rules.

## Where to Start

| What | Where |
|---|---|
| Open issues | [GitHub Issues](https://github.com/boanlab/KloudKnox/issues) |
| Good first issues | [`good-first-issue` label](https://github.com/boanlab/KloudKnox/issues?q=label%3Agood-first-issue) |
| Full contribution guide | [contribution/README.md](contribution/README.md) |
| Security vulnerabilities | [SECURITY.md](SECURITY.md) |

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University
