#!/usr/bin/env bash
# Daemon lifecycle: build, start, stop, status.
# Sourced by e2e.sh — relies on globals E2E_ROOT / REPO_ROOT / ART_DIR /
# KLOUDKNOX_DIR / KKCTL_DIR / E2E_WORKLOADS_YAML / POLICIES_DIR.

KLOUDKNOX_PID_FILE="${ART_DIR}/kloudknox.pid"
KLOUDKNOX_CRD_FILE="${KLOUDKNOX_DEPLOY_DIR}/01_kloudknoxpolicy.yaml"
KKCTL_PID_FILE="${ART_DIR}/kkctl.pid"
KLOUDKNOX_LOG="${ART_DIR}/kloudknox.log"
KKCTL_LOG="${ART_DIR}/kkctl.stderr"
ALERTS_FILE="${ART_DIR}/alerts.jsonl"
KLOUDKNOX_GRPC_PORT="${KLOUDKNOX_GRPC_PORT:-36890}"

_bootstrap_require() {
    local missing=0
    for bin in "$@"; do
        if ! command -v "${bin}" >/dev/null 2>&1; then
            echo "missing required tool: ${bin}" >&2
            missing=1
        fi
    done
    return "${missing}"
}

_bootstrap_preflight() {
    _bootstrap_require kubectl jq python3 go || return 1
    if ! kubectl cluster-info >/dev/null 2>&1; then
        echo "kubectl cluster-info failed — is the cluster reachable?" >&2
        return 1
    fi
    if [[ ! -d "${KLOUDKNOX_DIR}" ]] || [[ ! -d "${KKCTL_DIR}" ]]; then
        echo "KloudKnox or kloudknox-cli directory missing" >&2
        return 1
    fi
    if [[ ! -f "${E2E_WORKLOADS_YAML}" ]]; then
        echo "missing ${E2E_WORKLOADS_YAML}" >&2
        return 1
    fi
}

_bootstrap_pid_alive() {
    local pid="$1"
    [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1
}

_bootstrap_read_pid() {
    local file="$1"
    [[ -f "${file}" ]] || { echo ""; return; }
    cat "${file}"
}

_bootstrap_wait_file_contains() {
    local file="$1" pattern="$2" timeout="${3:-30}"
    local start=${SECONDS}
    while (( SECONDS - start < timeout )); do
        if [[ -f "${file}" ]] && grep -q -- "${pattern}" "${file}" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

_bootstrap_install_crd() {
    if [[ ! -f "${KLOUDKNOX_CRD_FILE}" ]]; then
        echo "[bootstrap] missing CRD manifest: ${KLOUDKNOX_CRD_FILE}" >&2
        return 1
    fi
    echo "[bootstrap] installing KloudKnoxPolicy CRD ..."
    if ! kubectl apply -f "${KLOUDKNOX_CRD_FILE}" >/dev/null; then
        echo "[bootstrap] kubectl apply CRD failed" >&2
        return 1
    fi
    if ! kubectl wait --for=condition=Established \
            crd/kloudknoxpolicies.security.boanlab.com --timeout=30s >/dev/null 2>&1; then
        echo "[bootstrap] CRD did not reach Established within 30s" >&2
        return 1
    fi
}

_bootstrap_build_kloudknox() {
    echo "[bootstrap] building KloudKnox ..."
    ( cd "${KLOUDKNOX_DIR}" && make build ) >"${ART_DIR}/kloudknox.build.log" 2>&1 || {
        echo "[bootstrap] KloudKnox build failed — see ${ART_DIR}/kloudknox.build.log" >&2
        return 1
    }
}

_bootstrap_build_kkctl() {
    echo "[bootstrap] building kkctl ..."
    ( cd "${KKCTL_DIR}" && make build ) >"${ART_DIR}/kkctl.build.log" 2>&1 || {
        echo "[bootstrap] kkctl build failed — see ${ART_DIR}/kkctl.build.log" >&2
        return 1
    }
}

_bootstrap_start_kloudknox() {
    local pid
    pid="$(_bootstrap_read_pid "${KLOUDKNOX_PID_FILE}")"
    if _bootstrap_pid_alive "${pid}"; then
        echo "[bootstrap] KloudKnox already running (pid=${pid})"
        return 0
    fi
    : >"${KLOUDKNOX_LOG}"
    echo "[bootstrap] starting KloudKnox (sudo -E) ..."
    # `cd && cmd &` would background the *list*, making $! the subshell's pid
    # instead of sudo's. Put cd on its own line so `sudo ... &` is a simple
    # command and $! points at the actual sudo wrapper (which forwards signals
    # to the kloudknox child).
    (
        cd "${KLOUDKNOX_DIR}" || exit 1
        sudo -E nohup ./bin/kloudknox >>"${KLOUDKNOX_LOG}" 2>&1 &
        echo $! >"${KLOUDKNOX_PID_FILE}"
    )
    sleep 1
    pid="$(_bootstrap_read_pid "${KLOUDKNOX_PID_FILE}")"
    if ! _bootstrap_pid_alive "${pid}"; then
        echo "[bootstrap] KloudKnox failed to start — see ${KLOUDKNOX_LOG}" >&2
        return 1
    fi
    echo "[bootstrap] KloudKnox pid=${pid}"
    echo "[bootstrap] waiting for enforcer to be ready ..."
    if ! _bootstrap_wait_file_contains "${KLOUDKNOX_LOG}" "Started.*Enforcer" 30; then
        echo "[bootstrap] KloudKnox enforcer did not start within 30s — see ${KLOUDKNOX_LOG}" >&2
        return 1
    fi
}

_bootstrap_start_kkctl() {
    local pid
    pid="$(_bootstrap_read_pid "${KKCTL_PID_FILE}")"
    if _bootstrap_pid_alive "${pid}"; then
        echo "[bootstrap] kkctl already running (pid=${pid})"
        return 0
    fi
    : >"${ALERTS_FILE}"
    : >"${KKCTL_LOG}"
    echo "[bootstrap] starting kkctl stream alerts -> ${ALERTS_FILE} ..."
    (
        cd "${KKCTL_DIR}" || exit 1
        nohup ./bin/kkctl stream alerts >"${ALERTS_FILE}" 2>"${KKCTL_LOG}" &
        echo $! >"${KKCTL_PID_FILE}"
    )
    if ! _bootstrap_wait_file_contains "${KKCTL_LOG}" "Connected to" 30; then
        echo "[bootstrap] kkctl did not connect within 30s — see ${KKCTL_LOG}" >&2
        return 1
    fi
    pid="$(_bootstrap_read_pid "${KKCTL_PID_FILE}")"
    echo "[bootstrap] kkctl pid=${pid}"
}

_bootstrap_deploy_pods() {
    echo "[bootstrap] deploying e2e workloads (with AppArmor) ..."
    kubectl apply -f "${E2E_WORKLOADS_YAML}" >/dev/null

    # KloudKnox loads AppArmor profiles reactively on Pod ADD events, so the
    # very first create attempt can lose the race to kubelet and fail with
    # `apparmor profile not found`. Kubelet backoff usually wins on its own,
    # but if a pod went phase=Failed before the profile landed the ReplicaSet
    # needs a nudge. Wait briefly; if not converged, rollout restart once and
    # wait for the new ReplicaSets to finish.
    if kubectl wait --for=condition=ready pod \
           -l 'group in (group-1,group-2)' --timeout=60s >/dev/null 2>&1; then
        echo "[bootstrap] pods ready"
        return 0
    fi

    echo "[bootstrap] pods not ready in 60s; rolling out restart ..."
    kubectl rollout restart deploy/ubuntu-1 deploy/ubuntu-2 deploy/ubuntu-3 deploy/ubuntu-4 >/dev/null
    local d
    for d in ubuntu-1 ubuntu-2 ubuntu-3 ubuntu-4; do
        if ! kubectl rollout status "deploy/${d}" --timeout=90s >/dev/null; then
            echo "[bootstrap] ${d} rollout did not complete" >&2
            kubectl get pods -l "container=${d}" -o wide >&2 || true
            return 1
        fi
    done
    echo "[bootstrap] pods ready"
}

bootstrap_up() {
    mkdir -p "${ART_DIR}"
    _bootstrap_preflight || return 1
    _bootstrap_install_crd || return 1
    # Purge leftover KloudKnoxPolicy CRs before the daemon's informer does its
    # initial sync — otherwise a stale block-policy from a prior session stays
    # live in the in-memory cache and conflicts with the first test that
    # re-applies the same selector/CIDR under a different action.
    kubectl delete kloudknoxpolicies.security.boanlab.com --all \
        --ignore-not-found --wait=true >/dev/null 2>&1 || true
    _bootstrap_build_kloudknox || return 1
    _bootstrap_build_kkctl || return 1
    _bootstrap_start_kloudknox || return 1
    _bootstrap_start_kkctl || return 1
    _bootstrap_deploy_pods || return 1
    echo "[bootstrap] up — use 'e2e.sh run <id>' to run a case"
}

_bootstrap_stop_pid() {
    local label="$1" file="$2" pid
    pid="$(_bootstrap_read_pid "${file}")"
    if _bootstrap_pid_alive "${pid}"; then
        echo "[bootstrap] stopping ${label} (pid=${pid}) ..."
        if [[ "${label}" == "KloudKnox" ]]; then
            sudo kill "${pid}" 2>/dev/null || true
        else
            kill "${pid}" 2>/dev/null || true
        fi
        local start=${SECONDS}
        while _bootstrap_pid_alive "${pid}" && (( SECONDS - start < 10 )); do
            sleep 0.5
        done
        if _bootstrap_pid_alive "${pid}"; then
            echo "[bootstrap] ${label} did not exit, sending SIGKILL" >&2
            if [[ "${label}" == "KloudKnox" ]]; then
                sudo kill -9 "${pid}" 2>/dev/null || true
            else
                kill -9 "${pid}" 2>/dev/null || true
            fi
        fi
    fi
    rm -f "${file}"
}

_bootstrap_sweep_proc() {
    # Kill lingering processes by exact comm name (covers cases where the
    # pid-file tracked a sudo wrapper and the actual binary was orphaned, or
    # where the pid file is missing/stale). Safe for this dev-only suite.
    local label="$1" name="$2" use_sudo="$3"
    local pk=(pkill) pg=(pgrep)
    [[ "${use_sudo}" == "1" ]] && pk=(sudo pkill)
    "${pg[@]}" -x "${name}" >/dev/null 2>&1 || return 0
    echo "[bootstrap] sweeping stray ${label} processes ..."
    "${pk[@]}" -TERM -x "${name}" 2>/dev/null || true
    local start=${SECONDS}
    while "${pg[@]}" -x "${name}" >/dev/null 2>&1 && (( SECONDS - start < 5 )); do
        sleep 0.5
    done
    if "${pg[@]}" -x "${name}" >/dev/null 2>&1; then
        echo "[bootstrap] ${label} did not exit, sending SIGKILL" >&2
        "${pk[@]}" -KILL -x "${name}" 2>/dev/null || true
    fi
}

_bootstrap_wait_port_free() {
    local port="$1" timeout="${2:-5}"
    local start=${SECONDS}
    while (( SECONDS - start < timeout )); do
        if ! sudo ss -tlnH "sport = :${port}" 2>/dev/null | grep -q .; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

bootstrap_down() {
    mkdir -p "${ART_DIR}"
    echo "[bootstrap] deleting policies ..."
    kubectl delete -f "${POLICIES_DIR}/" --ignore-not-found >/dev/null 2>&1 || true
    echo "[bootstrap] deleting pods ..."
    kubectl delete -f "${E2E_WORKLOADS_YAML}" --ignore-not-found >/dev/null 2>&1 || true
    _bootstrap_stop_pid kkctl "${KKCTL_PID_FILE}"
    _bootstrap_stop_pid KloudKnox "${KLOUDKNOX_PID_FILE}"
    _bootstrap_sweep_proc kkctl kkctl 0
    _bootstrap_sweep_proc KloudKnox  kloudknox  1
    if ! _bootstrap_wait_port_free "${KLOUDKNOX_GRPC_PORT}" 5; then
        echo "[bootstrap] WARNING: port ${KLOUDKNOX_GRPC_PORT} still in use" >&2
    fi
    echo "[bootstrap] down"
}

bootstrap_status() {
    local kpid gpid
    kpid="$(_bootstrap_read_pid "${KLOUDKNOX_PID_FILE}")"
    gpid="$(_bootstrap_read_pid "${KKCTL_PID_FILE}")"
    if _bootstrap_pid_alive "${kpid}"; then
        echo "KloudKnox : running (pid=${kpid})"
    else
        echo "KloudKnox : not running"
    fi
    if _bootstrap_pid_alive "${gpid}"; then
        echo "kkctl     : running (pid=${gpid})"
    else
        echo "kkctl     : not running"
    fi
    if [[ -f "${ALERTS_FILE}" ]]; then
        local n
        n="$(wc -l <"${ALERTS_FILE}" || echo 0)"
        echo "alerts.jsonl: ${n} line(s)"
        if [[ "${n}" -gt 0 ]]; then
            echo "last alert:"
            tail -n 1 "${ALERTS_FILE}" | jq -c '{podName, policyName, policyAction, resource}' 2>/dev/null || tail -n 1 "${ALERTS_FILE}"
        fi
    fi
}

bootstrap_check_daemons_running() {
    local kpid gpid
    kpid="$(_bootstrap_read_pid "${KLOUDKNOX_PID_FILE}")"
    gpid="$(_bootstrap_read_pid "${KKCTL_PID_FILE}")"
    if ! _bootstrap_pid_alive "${kpid}" || ! _bootstrap_pid_alive "${gpid}"; then
        echo "[bootstrap] daemons are not running — run 'e2e.sh up' first" >&2
        exit 1
    fi
}
