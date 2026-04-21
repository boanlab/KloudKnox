#!/bin/bash

set -euo pipefail

# update repo
sudo apt-get update

# install base build dependencies
sudo apt-get install -y build-essential libbpf-dev linux-tools-common linux-tools-generic curl gnupg lsb-release

# install clang/llvm 19 from apt.llvm.org (Ubuntu 22.04 ships clang 14 only)
if ! command -v clang-19 >/dev/null 2>&1; then
    curl -fsSL https://apt.llvm.org/llvm.sh | sudo bash -s -- 19
fi

sudo apt-get install -y clang-format-19

sudo update-alternatives --install /usr/bin/clang        clang        /usr/bin/clang-19        190
sudo update-alternatives --install /usr/bin/clang++      clang++      /usr/bin/clang++-19      190
sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-19 190
sudo update-alternatives --install /usr/bin/llvm-strip   llvm-strip   /usr/bin/llvm-strip-19   190
sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-19 190
sudo update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-19 190

# install bpf2go
go install github.com/cilium/ebpf/cmd/bpf2go@latest
