# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

.PHONY: up down status list logs-kloudknox logs-alerts run run-all clean \
        ensure-up ensure-k8s-up

# ----------------------------------------------------------------------
# Local e2e suite (docker compose via e2e.sh)
# ----------------------------------------------------------------------

ART_DIR            := $(CURDIR)/artifacts
KLOUDKNOX_PID_FILE := $(ART_DIR)/kloudknox.pid
KKCTL_PID_FILE     := $(ART_DIR)/kkctl.pid

up:
	./e2e.sh up

down:
	./e2e.sh down

status:
	./e2e.sh status

list:
	./e2e.sh list

logs-kloudknox:
	./e2e.sh logs kloudknox

logs-alerts:
	./e2e.sh logs alerts

# ensure-up: if KloudKnox/kkctl daemons aren't running, run 'up' first.
# Matches bootstrap_check_daemons_running (lib/bootstrap.sh) semantics.
ensure-up:
	@if ! { [ -s "$(KLOUDKNOX_PID_FILE)" ] && kill -0 "$$(cat $(KLOUDKNOX_PID_FILE))" 2>/dev/null; } \
	   || ! { [ -s "$(KKCTL_PID_FILE)" ]     && kill -0 "$$(cat $(KKCTL_PID_FILE))"     2>/dev/null; }; then \
	    echo "[make] e2e daemons not running — bootstrapping via './e2e.sh up'"; \
	    ./e2e.sh up; \
	fi

# make run CASE=test-07
run:
	@test -n "$(CASE)" || { echo "usage: make run CASE=<id>"; exit 2; }
	@$(MAKE) --no-print-directory ensure-up
	./e2e.sh run $(CASE)

run-all: ensure-up
	./e2e.sh run-all

clean: PURGE_CM := 1
clean: down k8s-down
	rm -rf artifacts

# ----------------------------------------------------------------------
# K8s live integration (cluster with KloudKnox installed from deployments/*.yaml)
# Overridable: KL_NS, KL_WEBHOOK_TEST_NS, KL_RELAY_LOCAL_PORT
# ----------------------------------------------------------------------

REPO_ROOT := $(realpath $(CURDIR)/../..)

# component-dir : image name
COMPONENT_IMAGES := \
  kloudknox-apparmor-webhook/apparmor-webhook:boanlab/kloudknox-apparmor-webhook \
  KloudKnox/operator-controller:boanlab/kloudknox-operator \
  kloudknox-relay-server/relay-server:boanlab/kloudknox-relay-server \
  kloudknox-cli/kloudknox-cli:boanlab/kloudknox-cli \
  KloudKnox/KloudKnox:boanlab/kloudknox

# build-images: build each component image and import into containerd k8s.io
# namespace so IfNotPresent pulls resolve locally without a registry push.
.PHONY: build-images
build-images:
	@for entry in $(COMPONENT_IMAGES); do \
	  comp=$${entry%%:*}; \
	  image=$${entry##*:}; \
	  echo "==> $$comp: make build-image TAG=v0.1.0"; \
	  make -C "$(REPO_ROOT)/$$comp" build-image TAG=v0.1.0; \
	  echo "==> importing $$image:v0.1.0 into containerd k8s.io"; \
	  docker save "$$image:v0.1.0" | sudo ctr -n k8s.io images import -; \
	done

.PHONY: k8s-up k8s-down k8s-live k8s-live-components k8s-live-webhook \
        k8s-live-operator k8s-live-relay k8s-live-kkctl

KL_NS ?= kloudknox

# k8s-up: install cert-manager (if missing) + apply deployments/ + wait rollout
k8s-up:
	./k8s-live.sh up

# k8s-down: remove KloudKnox deployments. Pass PURGE_CM=1 to also remove
# cert-manager (cluster-wide — skip if other workloads rely on it).
#   make k8s-down
#   make k8s-down PURGE_CM=1
k8s-down:
	./k8s-live.sh down $(if $(PURGE_CM),--purge-cert-manager)

# ensure-k8s-up: if KloudKnox isn't installed in the cluster (namespace or
# daemonset missing), run 'k8s-up' first. Mirrors kl_preflight
# (lib/k8s_live.sh) so checks stay cheap.
ensure-k8s-up:
	@if ! kubectl cluster-info >/dev/null 2>&1; then \
	    echo "[make] kubectl cluster-info failed — is the cluster reachable?" >&2; \
	    exit 1; \
	fi; \
	if ! kubectl get namespace "$(KL_NS)" >/dev/null 2>&1 \
	   || ! kubectl -n "$(KL_NS)" get daemonset kloudknox >/dev/null 2>&1; then \
	    echo "[make] KloudKnox not installed in cluster — bootstrapping via './k8s-live.sh up'"; \
	    ./k8s-live.sh up; \
	fi

k8s-live: ensure-k8s-up
	./k8s-live.sh check

k8s-live-components: ensure-k8s-up
	./k8s-live.sh check-components

k8s-live-webhook: ensure-k8s-up
	./k8s-live.sh check-webhook

k8s-live-operator: ensure-k8s-up
	./k8s-live.sh check-operator

k8s-live-relay: ensure-k8s-up
	./k8s-live.sh check-relay

k8s-live-kkctl: ensure-k8s-up
	./k8s-live.sh check-kkctl
