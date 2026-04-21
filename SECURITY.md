# Security Policy

## Supported Versions

KloudKnox is under active development and has not yet cut a tagged release.
Only the latest commit on the `main` branch receives security fixes.

| Version | Supported |
|---|---|
| Latest `main` | Yes |
| Forks / older commits | No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by email to **namjh@dankook.ac.kr** with the subject line `[KloudKnox Security]`.

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Your environment (OS, kernel version, Kubernetes version, commit SHA of KloudKnox)
- Affected component (agent, operator, webhook, relay, CLI)
- Any suggested mitigations if you have them

We aim to acknowledge reports within 5 business days.

## Disclosure Policy

We follow a coordinated disclosure model. Please allow us reasonable time to address the vulnerability before any public disclosure. We will credit reporters in the release notes unless you prefer to remain anonymous.

## Scope

The following are in scope (report here):

- The KloudKnox agent (`KloudKnox/`), including its eBPF programs (`KloudKnox/BPF/`)
- Policy enforcement and monitoring logic (`KloudKnox/enforcer/`, `KloudKnox/monitor/`)
- The operator controller (`operator-controller/`) and its CRDs (`operator-controller/api/`)
- The gRPC API (`protobuf/`)
- Deployment manifests and Helm-style YAML under `deployments/`

For components that live in their own repositories, report vulnerabilities there (same email address applies):

- Relay server: https://github.com/boanlab/kloudknox-relay-server
- `kkctl` CLI: https://github.com/boanlab/kloudknox-cli

The following are out of scope:

- Third-party dependencies (report to the upstream project)
- The Linux kernel, eBPF verifier, BPF-LSM, or AppArmor itself
- Misconfigurations in user-supplied policies or cluster RBAC
- Issues that require root on the host the agent is already running on
