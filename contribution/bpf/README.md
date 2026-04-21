# BPF Development Dependencies

Installs the tools required to compile KloudKnox's eBPF programs.

## What it installs

| Package | Purpose |
|---|---|
| `build-essential` | C compiler and standard build tools |
| `libbpf-dev` | libbpf headers for BPF program development |
| `linux-tools-generic` | `bpftool` for inspecting loaded programs and maps |
| `clang-19` + `llvm-19` | eBPF bytecode compiler and LLVM toolchain (installed from `apt.llvm.org`) |
| `clang-format-19` | Source formatter used by `KloudKnox/BPF/Makefile` |
| `bpf2go` | Cilium's Go code generator for embedding BPF objects |

Clang 19 and LLVM 19 are set as the default alternatives so `make` can find them
without extra configuration. `KloudKnox/BPF/Makefile` defaults to `CLANG=clang-19`,
so any other clang on the path is not used unless explicitly overridden.

## Usage

```bash
cd contribution/bpf
./install-deps.sh
```

## Requirements

- Ubuntu 22.04 or later (apt-based; `clang-19` is pulled from `apt.llvm.org`)
- Go must already be installed (needed for `bpf2go`)
- `sudo` privileges

## After Installation

Verify the toolchain:

```bash
clang --version    # should print clang version 19.x
llvm-strip --version
bpftool version
```

Then build the BPF programs:

```bash
cd KloudKnox
make
```
