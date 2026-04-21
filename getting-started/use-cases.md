# Policy Recipes

A collection of complete, copy-paste `KloudKnoxPolicy` recipes for common security scenarios. Each recipe includes the policy, the minimum selector assumptions, and a verification step.

For the full spec, see [policy-authoring.md](policy-authoring.md). For the deployment walkthrough, see [README.md](README.md).

---

## Table of Contents

- [Observability First: Audit-Only Baseline](#observability-first-audit-only-baseline)
- [Block Shell Access in Production](#block-shell-access-in-production)
- [Protect Sensitive Files](#protect-sensitive-files)
- [Enforce Read-Only Configuration](#enforce-read-only-configuration)
- [Block Package Managers at Runtime](#block-package-managers-at-runtime)
- [Prevent Crypto Mining](#prevent-crypto-mining)
- [Restrict Egress to an Allowlist](#restrict-egress-to-an-allowlist)
- [Block Connections to Internal CIDRs](#block-connections-to-internal-cidrs)
- [Allow One Binary to Write, Deny the Rest](#allow-one-binary-to-write-deny-the-rest)
- [Ingress Allowlist by Pod Label](#ingress-allowlist-by-pod-label)
- [Defense-in-Depth: Combine Rules](#defense-in-depth-combine-rules)

---

## Observability First: Audit-Only Baseline

Before turning on enforcement, record what a workload actually does. An `Audit`-only policy generates alerts for every matched operation without blocking anything, so you can tune the rules against real traffic.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: audit-baseline
  namespace: default
spec:
  selector:
    app: web
  process:
    - dir: /bin/
      recursive: true
      action: Audit
    - dir: /usr/bin/
      recursive: true
      action: Audit
  file:
    - dir: /etc/
      recursive: true
      action: Audit
  network:
    - direction: egress
      ipBlock:
        cidr: 0.0.0.0/0
      action: Audit
  action: Audit
```

Run the workload under normal load, then stream alerts:

```bash
kkctl stream alerts --podName <pod> --policyName audit-baseline
```

Use the observed activity to shape the `Block` rules in the next iteration.

---

## Block Shell Access in Production

Production containers rarely need an interactive shell. Block the common shells and audit any attempt.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: no-shell
  namespace: default
spec:
  selector:
    app: web
  process:
    - path: /bin/bash
      action: Block
    - path: /bin/sh
      action: Block
    - path: /bin/dash
      action: Block
    - path: /usr/bin/zsh
      action: Block
  action: Block
```

Verify:

```bash
kubectl exec -it <pod> -- /bin/bash
# exec failed: permission denied
```

An alert appears with `policyAction: Block` and `resource: /bin/bash`.

---

## Protect Sensitive Files

Deny read access to credentials and secrets that the workload never legitimately touches.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: protect-secrets
  namespace: default
spec:
  selector:
    app: web
  file:
    - path: /etc/shadow
      action: Block
    - path: /etc/gshadow
      action: Block
    - dir: /root/.ssh/
      recursive: true
      action: Block
    - dir: /home/
      recursive: true
      action: Block
    - dir: /var/run/secrets/kubernetes.io/serviceaccount/
      recursive: true
      action: Block
  action: Block
```

Pair with read-only file-system mounts in the workload spec for defense-in-depth.

---

## Enforce Read-Only Configuration

Allow the workload to read its config but block any modification.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: read-only-config
  namespace: default
spec:
  selector:
    app: nginx
  file:
    - dir: /etc/nginx/
      recursive: true
      readOnly: true
      action: Allow
  action: Block
```

Any write attempt to `/etc/nginx/**` returns `EACCES` and emits a `Block` alert; reads succeed silently.

---

## Block Package Managers at Runtime

A running container should not be installing software. Block every package manager binary.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: no-package-managers
  namespace: default
spec:
  selector:
    app: web
  process:
    - path: /usr/bin/apt
      action: Block
    - path: /usr/bin/apt-get
      action: Block
    - path: /usr/bin/dpkg
      action: Block
    - path: /sbin/apk
      action: Block
    - path: /usr/bin/yum
      action: Block
    - path: /usr/bin/dnf
      action: Block
    - path: /usr/bin/pip
      action: Block
    - path: /usr/bin/pip3
      action: Block
    - path: /usr/bin/npm
      action: Block
  action: Block
```

---

## Prevent Crypto Mining

Miners are usually dropped into writable temp directories and executed there. Block execution from those directories and deny outbound pool traffic on common ports.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: no-mining
  namespace: default
spec:
  selector:
    app: web
  process:
    - dir: /tmp/
      recursive: true
      action: Block
    - dir: /var/tmp/
      recursive: true
      action: Block
    - dir: /dev/shm/
      recursive: true
      action: Block
  network:
    - direction: egress
      ports:
        - port: 3333
          protocol: TCP
        - port: 4444
          protocol: TCP
        - port: 5555
          protocol: TCP
        - port: 7777
          protocol: TCP
        - port: 14444
          protocol: TCP
      action: Block
  action: Audit
```

The process rules cover dropper patterns; the network rules cover typical Stratum pool ports. Add FQDN rules for known pools that reach your workloads:

```yaml
  network:
    - direction: egress
      fqdn: pool.minexmr.com
      action: Block
```

---

## Restrict Egress to an Allowlist

Default-deny egress with a narrow set of permitted destinations.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: egress-allowlist
  namespace: default
spec:
  selector:
    app: payment-service
  network:
    # Allow DNS
    - direction: egress
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
      ipBlock:
        cidr: 0.0.0.0/0
      action: Allow

    # Allow the payment API
    - direction: egress
      fqdn: api.stripe.com
      ports:
        - port: 443
          protocol: TCP
      action: Allow

    # Allow internal metrics endpoint
    - direction: egress
      ipBlock:
        cidr: 10.0.10.0/24
      ports:
        - port: 9090
          protocol: TCP
      action: Allow
  action: Block
```

The top-level `Block` closes everything else. The three `Allow` rules carve the permitted paths. Swap `Block` to `Audit` during rollout to observe what would be denied.

---

## Block Connections to Internal CIDRs

Stop a compromised workload from pivoting into internal networks.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: no-internal-pivot
  namespace: default
spec:
  selector:
    app: public-api
  network:
    - direction: egress
      ipBlock:
        cidr: 10.0.0.0/8
        except:
          - 10.0.10.0/24
      action: Block
    - direction: egress
      ipBlock:
        cidr: 172.16.0.0/12
      action: Block
    - direction: egress
      ipBlock:
        cidr: 192.168.0.0/16
      action: Block
  action: Audit
```

The `except` field carves a hole for the one internal subnet the workload legitimately needs.

---

## Allow One Binary to Write, Deny the Rest

Use `fromSource` to tie a file rule to a specific calling binary — for example, only the application process may write to its log file.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: log-writer
  namespace: default
spec:
  selector:
    app: web
  file:
    # The app itself may write
    - path: /var/log/app.log
      fromSource:
        - path: /usr/bin/app
      action: Allow

    # Everyone else is blocked
    - path: /var/log/app.log
      action: Block
  action: Block
```

Rule order within a file is preserved; the `Allow` rule qualified by `fromSource` takes effect for matching processes, and the generic `Block` rule catches everything else.

---

## Ingress Allowlist by Pod Label

In Kubernetes mode, restrict who can connect to a service by matching remote pod labels.

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: db-ingress-allowlist
  namespace: default
spec:
  selector:
    app: database
  network:
    - direction: ingress
      selector:
        app: api
      ports:
        - port: 5432
          protocol: TCP
      action: Allow
    - direction: ingress
      selector:
        app: migrations
      ports:
        - port: 5432
          protocol: TCP
      action: Allow
  action: Block
```

Only pods labeled `app=api` or `app=migrations` can reach port 5432 on pods labeled `app=database`.

---

## Defense-in-Depth: Combine Rules

Real workloads need multiple rule types layered at once — process, file, network, capability, and IPC. This recipe hardens a stateless web service:

```yaml
apiVersion: security.boanlab.com/v1
kind: KloudKnoxPolicy
metadata:
  name: web-hardening
  namespace: default
spec:
  selector:
    app: web

  process:
    - path: /bin/bash
      action: Block
    - path: /bin/sh
      action: Block
    - dir: /tmp/
      recursive: true
      action: Block

  file:
    - path: /etc/shadow
      action: Block
    - dir: /root/.ssh/
      recursive: true
      action: Block
    - dir: /etc/nginx/
      recursive: true
      readOnly: true
      action: Allow
    - dir: /var/log/nginx/
      recursive: true
      action: Allow

  network:
    - direction: egress
      ports:
        - port: 53
          protocol: UDP
      ipBlock:
        cidr: 0.0.0.0/0
      action: Allow
    - direction: ingress
      ports:
        - port: 80
          protocol: TCP
        - port: 443
          protocol: TCP
      ipBlock:
        cidr: 0.0.0.0/0
      action: Allow

  capability:
    - name: CAP_NET_RAW
      action: Block
    - name: CAP_SYS_PTRACE
      action: Block

  ipc:
    signal:
      - permission: send
        signals: [SIGKILL]
        action: Block
    ptrace:
      - permission: trace
        action: Block

  action: Block
```

- Process: no shells, no execution from `/tmp`.
- File: protected secrets, read-only config, writable logs.
- Network: DNS out, HTTP/HTTPS in, everything else denied.
- Capability: no raw sockets, no ptrace capability.
- IPC: no arbitrary `SIGKILL` delivery and no process tracing.

Stage the rollout by deploying first with `action: Audit` at the top, tuning the rules with `kkctl stream alerts`, then switching the default to `action: Block`.

---

## See also

- [policy-authoring.md](policy-authoring.md) — full `KloudKnoxPolicy` reference
- [README.md](README.md) — 15-minute Kubernetes quickstart
- [docker-mode.md](docker-mode.md) — Docker and hybrid-mode deployment
- [kloudknox-cli](https://github.com/boanlab/kloudknox-cli) — full `kkctl` reference
