# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

CLANG        ?= clang-19
STRIP        ?= llvm-strip
OBJCOPY      ?= llvm-objcopy
CLANG_FORMAT ?= clang-format
CFLAGS       := -O2 -g -target bpf -Wall

BPF_SOURCES := $(wildcard monitor/*.bpf.c enforcer/*.bpf.c) \
               $(wildcard monitor/*.bpf.h enforcer/*.bpf.h common/*.h)

OUT_DIR := ..

# ===================== #
# ==  Build targets  == #
# ===================== #

.PHONY: build
build: format \
       generate-vmlinux-header \
       generate-system-monitor \
       generate-network-enforcer \
       generate-bpf-enforcer

.PHONY: format
format:
	@if ! command -v $(CLANG_FORMAT) >/dev/null 2>&1; then \
		echo "clang-format not found, skipping format"; \
	else \
		echo "Formatting BPF sources..."; \
		$(CLANG_FORMAT) -i --style=file $(BPF_SOURCES); \
	fi

# compile-bpf(src, obj, go_src)
# Compiles a BPF C source to an object file and runs bpf2go if not already built.
define compile-bpf
@if [ ! -f $(2) ]; then \
	echo "Compiling $(1) -> $(2)"; \
	$(CLANG) $(CFLAGS) -o $(2) -c $(1); \
	go get github.com/cilium/ebpf/cmd/bpf2go; \
	go generate $(3); \
fi
endef

.PHONY: generate-vmlinux-header
generate-vmlinux-header:
	@for dir in common monitor enforcer; do \
		if [ ! -f $$dir/vmlinux.h ]; then \
			echo "Generating $$dir/vmlinux.h ..."; \
			bpftool btf dump file /sys/kernel/btf/vmlinux format c > $$dir/vmlinux.h; \
		fi; \
	done

.PHONY: generate-system-monitor
generate-system-monitor:
	$(call compile-bpf, \
		monitor/system_events.bpf.c, \
		$(OUT_DIR)/monitor/system_events.bpf.o, \
		$(OUT_DIR)/monitor/system_events.bpf.go)

.PHONY: generate-network-enforcer
generate-network-enforcer:
	$(call compile-bpf, \
		enforcer/net_enforcer.bpf.c, \
		$(OUT_DIR)/enforcer/net_enforcer.bpf.o, \
		$(OUT_DIR)/enforcer/net_enforcer.bpf.go)

.PHONY: generate-bpf-enforcer
generate-bpf-enforcer:
	$(call compile-bpf, \
		enforcer/bpf_enforcer.bpf.c, \
		$(OUT_DIR)/enforcer/bpf_enforcer.bpf.o, \
		$(OUT_DIR)/enforcer/bpf_enforcer.bpf.go)

# ===================== #
# ==  Clean targets  == #
# ===================== #

.PHONY: clean
clean: clean-system-monitor clean-network-enforcer clean-bpf-enforcer

.PHONY: clean-system-monitor
clean-system-monitor:
	rm -f $(OUT_DIR)/monitor/*.o $(OUT_DIR)/monitor/*_bpfel.go
	rm -f monitor/vmlinux.h

.PHONY: clean-network-enforcer
clean-network-enforcer:
	rm -f $(OUT_DIR)/enforcer/net_*.o $(OUT_DIR)/enforcer/net_*_bpfel.go
	rm -f enforcer/vmlinux.h

.PHONY: clean-bpf-enforcer
clean-bpf-enforcer:
	rm -f $(OUT_DIR)/enforcer/bpf_*.o $(OUT_DIR)/enforcer/bpf_*_bpfel.go
	rm -f enforcer/vmlinux.h

# ========================= #
# ==  Tool installation  == #
# ========================= #

.PHONY: install-tools
install-tools:
	@if ! command -v clang-19 >/dev/null 2>&1; then \
		echo "Installing clang-19 from apt.llvm.org..."; \
		sudo apt-get update; \
		sudo apt-get install -y curl gnupg lsb-release; \
		curl -fsSL https://apt.llvm.org/llvm.sh | sudo bash -s -- 19; \
		sudo update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-19   190; \
		sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 190; \
	else echo "clang-19: already installed"; fi
	@if ! command -v clang-format-19 >/dev/null 2>&1; then \
		echo "Installing clang-format-19..."; \
		sudo apt-get install -y clang-format-19; \
		sudo update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-19 190; \
	else echo "clang-format-19: already installed"; fi
	@if ! command -v llvm-strip-19 >/dev/null 2>&1; then \
		echo "Installing LLVM-19 utilities..."; \
		sudo update-alternatives --install /usr/bin/llvm-strip   llvm-strip   /usr/bin/llvm-strip-19   190; \
		sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-19 190; \
		sudo update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-19 190; \
	else echo "LLVM-19: already installed"; fi
	@if ! dpkg -l | grep -q libbpf-dev; then \
		echo "Installing BPF development tools..."; \
		sudo apt-get install -y libbpf-dev linux-tools-common linux-tools-generic; \
	else echo "libbpf-dev: already installed"; fi
	@if ! command -v bpf2go >/dev/null 2>&1; then \
		echo "Installing bpf2go..."; \
		go install github.com/cilium/ebpf/cmd/bpf2go@latest; \
	else echo "bpf2go: already installed"; fi
