# Containerd Installation

Installs `containerd.io` from the official Docker repository and configures it for use with Kubernetes (systemd cgroup driver).

## What it does

1. Adds the Docker APT repository and GPG key
2. Installs `containerd.io`
3. Generates `/etc/containerd/config.toml` via `containerd config default`
4. Sets `SystemdCgroup = true` (required for Kubernetes with systemd)
5. Restarts the containerd service

## Usage

```bash
cd contribution/containerd
./install-containerd.sh
```

## Requirements

- Ubuntu 22.04 or later
- `sudo` privileges
- Internet access

## After Installation

```bash
systemctl status containerd   # should be active (running)
```

## Note

This installs containerd as a standalone container runtime. If you need the full Docker CLI as well, use `../docker/install-docker.sh` instead — it installs both `docker-ce` and containerd.
