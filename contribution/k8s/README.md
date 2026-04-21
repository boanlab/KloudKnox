# Kubernetes Setup

Scripts for setting up a Kubernetes cluster with kubeadm.

## Scripts

| Script | When to Run |
|---|---|
| `install-kubeadm.sh` | Every node (master + workers) |
| `initialize-kubeadm.sh` | Master node only, once |
| `deploy-cni.sh` | Master node only, after initialization |
| `enable-bridge-nf-call-iptables.sh` | Any node where `bridge-nf-call-iptables` is off |

---

### 1. Install kubeadm, kubelet, kubectl

Run on **every node**:

```bash
./install-kubeadm.sh
```

This installs Kubernetes v1.29, enables IP forwarding, loads `br_netfilter`, and mounts BPFfs (required for Cilium).

---

### 2. Initialize the master node

Run on the **master node only**:

```bash
# Single-node cluster (removes control-plane taint so workloads can schedule)
./initialize-kubeadm.sh

# Multi-node cluster (keeps the taint; workers join separately)
MULTI=true ./initialize-kubeadm.sh
```

The join command for worker nodes is printed at the end of the kubeadm output and also saved in `~/k8s_init.log`.

---

### 3. Deploy a CNI

Run on the **master node** after initialization:

```bash
CNI=flannel ./deploy-cni.sh   # default
CNI=calico  ./deploy-cni.sh
CNI=cilium  ./deploy-cni.sh
```

KloudKnox is tested with Flannel and Calico. Cilium is supported but requires the BPFfs mount added by `install-kubeadm.sh`.

---

### enable-bridge-nf-call-iptables.sh

Utility script that sets `net.bridge.bridge-nf-call-iptables=1` and persists it via `sysctl.conf`. Run this if you see CNI connectivity issues caused by the flag being reset.

## Requirements

- Ubuntu 22.04 or later
- `sudo` privileges
- Containerd installed (`../containerd/install-containerd.sh`)
- Internet access
