#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University
#
# Docker-only e2e suite (features.md §30).
#
# Prereqs on the host:
#   - docker + docker compose v2
#   - jq
#   - kkctl on PATH (or export KKCTL=/path/to/kkctl)
#   - KloudKnox running in docker mode with alerts streaming to
#     $ALERTS_FILE (default /var/log/kloudknox/alerts.jsonl).
#     Start it with e.g.
#       kkctl stream alerts --server localhost:36890 \
#         > /var/log/kloudknox/alerts.jsonl &
#
# The suite does NOT manage the KloudKnox daemon itself — keeping
# enforcement out of the test orchestration keeps each scenario
# debuggable in isolation.

set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="${E2E_ROOT}/policies"
COMPOSE_FILE="${E2E_ROOT}/compose.test.yaml"

: "${KKCTL:=kkctl}"
: "${ALERTS_FILE:=/var/log/kloudknox/alerts.jsonl}"
: "${ALERT_WINDOW_SEC:=5}"
: "${SETTLE_SEC:=2}"

# shellcheck source=./assert.sh
source "${E2E_ROOT}/assert.sh"

pass=0
fail=0
failures=()

log()  { printf '\033[36m[e2e]\033[0m %s\n' "$*"; }
pass() { pass=$((pass + 1)); printf '\033[32m  PASS\033[0m %s\n' "$*"; }
oops() { fail=$((fail + 1)); failures+=("$*"); printf '\033[31m  FAIL\033[0m %s\n' "$*"; }

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required tool: $1" >&2
        exit 2
    }
}

precheck() {
    need docker
    need jq
    need "${KKCTL}"
    if ! docker version >/dev/null 2>&1; then
        echo "docker daemon unreachable" >&2
        exit 2
    fi
    if [[ ! -f "${ALERTS_FILE}" ]]; then
        log "alerts file ${ALERTS_FILE} does not exist yet — will be created on first alert"
    fi
}

compose() { docker compose -f "${COMPOSE_FILE}" "$@"; }

# Stub AppArmor profiles must exist in /etc/apparmor.d BEFORE compose up —
# Docker fails container creation if `security_opt: apparmor=<name>` points
# at an unknown profile, and KloudKnox only rewrites profiles that are
# already registered. The stubs are deliberately permissive (plain `file,`,
# `network,`, `capability,`, `unix,`, `signal,`, `ptrace,`) so containers
# boot with behaviour equivalent to docker-default until a policy lands and
# the daemon swaps the body.
ensure_stub_profiles() {
    for name in kloudknox-docker-e2e-alpine kloudknox-docker-e2e-nginx kloudknox-docker-e2e-ubuntu kloudknox-docker-e2e-attacker; do
        if sudo aa-status 2>/dev/null | grep -q "^   ${name}\$"; then
            continue
        fi
        log "creating stub AppArmor profile ${name}"
        sudo tee "/etc/apparmor.d/${name}" >/dev/null <<EOF
## == Managed by KloudKnox == ##

#include <tunables/global>

profile ${name} flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  file,
  network,
  capability,
  unix,
  signal,
  ptrace,
}
EOF
        sudo apparmor_parser -r "/etc/apparmor.d/${name}"
    done
}

setup() {
    # Order matters: first tear down any stale containers from a previous run
    # so the daemon has a chance to unregister their profiles, THEN re-register
    # the stubs, THEN bring the containers up. Using `compose up --force-recreate`
    # as the entry point races against the daemon: the container-removed event
    # triggers `apparmor_parser -R`, and the new container is created with a
    # `security_opt` that points at a profile that has just been unloaded —
    # runc then fails with "write .../attr/apparmor/exec: no such file or
    # directory".
    log "removing stale containers (if any)"
    compose down --remove-orphans >/dev/null 2>&1 || true
    sleep 1
    ensure_stub_profiles
    log "bringing up test containers"
    compose up -d
    # Wait until nginx is actually serving before applying policies — otherwise
    # selector matching can race with the start event.
    sleep "${SETTLE_SEC}"
}

teardown() {
    log "tearing down test containers and policies"
    for p in "${POLICY_DIR}"/*.yaml; do
        "${KKCTL}" --env docker delete -f "${p}" >/dev/null 2>&1 || true
    done
    compose down --remove-orphans >/dev/null 2>&1 || true
}

apply_policy() {
    local path="$1"
    "${KKCTL}" --env docker apply -f "${path}" >/dev/null
    sleep "${SETTLE_SEC}"
}

# Each scenario: apply policy, snapshot offset, trigger, assert alert.
#
# The trigger commands ignore their own exit status (|| true) because whether
# the LSM returns EPERM, the syscall errors out, or the block is silently
# enforced depends on the enforcer type — what we assert on is the alert.

scenario_nginx_hardening() {
    local name="e2e-nginx-hardening"
    log "scenario 1: nginx hardening (${name})"
    apply_policy "${POLICY_DIR}/01-nginx-hardening.yaml"
    local off; off="$(assert_offset)"
    docker exec e2e-nginx cat /etc/nginx/nginx.conf >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

scenario_docker_sock_block() {
    local name="e2e-docker-sock-block"
    log "scenario 2: docker.sock block (${name})"
    apply_policy "${POLICY_DIR}/02-docker-sock-block.yaml"
    local off; off="$(assert_offset)"
    docker exec e2e-alpine cat /var/run/docker.sock >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

scenario_file_fromsource() {
    local name="e2e-shadow-fromsource-block"
    log "scenario 3: file + fromSource block (${name})"
    apply_policy "${POLICY_DIR}/03-file-fromsource-block.yaml"
    local off; off="$(assert_offset)"
    # Double-exec via `sh -c`: KloudKnox maps fromSource rules onto an AppArmor
    # `cx` child profile transition (see policyConverter/apparmor_profile.go).
    # The transition only fires when the exec happens FROM WITHIN the parent
    # profile — `docker exec /usr/bin/cat` enters the parent profile *as part
    # of* the exec itself and lands in the parent's `file,` allow rule before
    # the child profile has a chance to evaluate. `sh -c '...'` splits this
    # into two execs: sh enters the parent profile, then execs /usr/bin/cat,
    # which hits `/usr/bin/cat cx,` and transitions into the child profile
    # where `deny /etc/shadow rw,` applies.
    docker exec e2e-ubuntu sh -c '/usr/bin/cat /etc/shadow' >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

scenario_network_egress() {
    local name="e2e-egress-cloudflare-block"
    log "scenario 4: network egress block (${name})"
    apply_policy "${POLICY_DIR}/04-network-egress-block.yaml"
    local off; off="$(assert_offset)"
    docker exec e2e-alpine wget -q -T 2 -O /dev/null http://1.1.1.1/ >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

scenario_applyToAll() {
    local name="e2e-applyToAll-mount"
    log "scenario 5: applyToAll file block (${name})"
    apply_policy "${POLICY_DIR}/05-applyToAll-sys-admin.yaml"
    local off; off="$(assert_offset)"
    docker exec e2e-ubuntu cat /etc/hostname >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

scenario_capability() {
    local name="e2e-cap-netraw-block"
    log "scenario 6: capability block (${name})"
    apply_policy "${POLICY_DIR}/06-capability-block.yaml"
    local off; off="$(assert_offset)"
    docker exec e2e-alpine ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

# e2e-attacker shares e2e-alpine's PID ns but runs under a distinct
# AppArmor profile, which disables abstractions/base's implicit
# `signal peer=@{profile_name}` same-profile grant and lets the
# allow-list policy actually mediate cross-profile signals.
scenario_ipc_signal() {
    local name="e2e-ipc-signal-allow-list"
    log "scenario 7: ipc signal allow-list (${name})"
    apply_policy "${POLICY_DIR}/07-ipc-signal-allow-list.yaml"
    local off; off="$(assert_offset)"
    docker exec e2e-attacker sh -c 'kill -KILL 1' >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

# scenario_ipc_unix — gated on ENABLE_IPC_SCENARIO=1. The trigger needs
# a client that can open AF_UNIX stream sockets; alpine:3.19 ships busybox
# nc which does not support -U, so we install socat on-demand (alpine has
# outbound network on the default bridge).
scenario_ipc_unix() {
    local name="e2e-ipc-unix-docker-sock-block"
    if [[ "${ENABLE_IPC_SCENARIO:-0}" != "1" ]]; then
        log "scenario 8: ipc unix-connect block (${name}) — SKIP (set ENABLE_IPC_SCENARIO=1 to run)"
        return
    fi
    log "scenario 8: ipc unix-connect block (${name})"
    if ! docker exec e2e-alpine sh -c 'command -v socat' >/dev/null 2>&1; then
        docker exec e2e-alpine apk add --no-cache socat >/dev/null 2>&1 || {
            oops "${name} (socat install failed)"
            return
        }
    fi
    apply_policy "${POLICY_DIR}/08-ipc-unix-docker-sock-block.yaml"
    local off; off="$(assert_offset)"
    docker exec e2e-alpine sh -c 'echo | socat - UNIX-CONNECT:/var/run/docker.sock' >/dev/null 2>&1 || true
    if assert_has_alert "${off}" "${name}" >/dev/null; then
        pass "${name}"
    else
        oops "${name}"
    fi
}

main() {
    precheck
    trap teardown EXIT
    setup
    scenario_nginx_hardening
    scenario_docker_sock_block
    scenario_file_fromsource
    scenario_network_egress
    scenario_applyToAll
    scenario_capability
    scenario_ipc_signal
    scenario_ipc_unix

    echo
    log "results: ${pass} passed, ${fail} failed"
    if (( fail > 0 )); then
        for f in "${failures[@]}"; do
            echo "  - ${f}" >&2
        done
        exit 1
    fi
}

main "$@"
