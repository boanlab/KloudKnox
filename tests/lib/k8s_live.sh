#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# K8s live integration checks: apparmor-webhook, operator-controller,
# relay-server, and kkctl.
# Sourced by k8s-live.sh — relies on globals set there.

KL_NS="${KL_NS:-kloudknox}"
KL_RELAY_LOCAL_PORT="${KL_RELAY_LOCAL_PORT:-33900}"
KL_RELAY_PF_PID_FILE="${ART_DIR}/relay-pf.pid"
KL_RELAY_PF_LOG="${ART_DIR}/relay-pf.log"
KL_LIVE_REPORT="${ART_DIR}/k8s-live-report.md"
KL_RESULTS_TSV="${ART_DIR}/k8s-live-results.tsv"

_kl_pass=0
_kl_fail=0

# result tracking

_kl_ok() {
    local name="$1" detail="${2:-}"
    echo "  [PASS] ${name}${detail:+ — ${detail}}"
    printf '%s\tPASS\t%s\n' "${name}" "${detail}" >>"${KL_RESULTS_TSV}"
    _kl_pass=$((_kl_pass + 1))
    printf '| %s | PASS | %s |\n' "${name}" "${detail}" >>"${KL_LIVE_REPORT}"
}

_kl_fail() {
    local name="$1" detail="${2:-}"
    echo "  [FAIL] ${name}${detail:+ — ${detail}}" >&2
    printf '%s\tFAIL\t%s\n' "${name}" "${detail}" >>"${KL_RESULTS_TSV}"
    _kl_fail=$((_kl_fail + 1))
    printf '| %s | FAIL | %s |\n' "${name}" "${detail}" >>"${KL_LIVE_REPORT}"
}

_kl_section() {
    echo ""
    echo "[$*]"
    printf '\n## %s\n\n| check | result | detail |\n|---|---|---|\n' "$*" >>"${KL_LIVE_REPORT}"
}

kl_report_init() {
    mkdir -p "${ART_DIR}"
    : >"${KL_RESULTS_TSV}"
    {
        echo "# KloudKnox K8s Live Integration Report"
        echo ""
        echo "Run at: $(date -Iseconds)"
        echo ""
    } >"${KL_LIVE_REPORT}"
    _kl_pass=0
    _kl_fail=0
}

kl_report_summary() {
    {
        echo ""
        echo "## Summary"
        echo ""
        echo "- passed: ${_kl_pass}"
        echo "- failed: ${_kl_fail}"
    } >>"${KL_LIVE_REPORT}"
    echo ""
    echo "[summary]"
    echo "  passed: ${_kl_pass}  failed: ${_kl_fail}"
    echo "  report: ${KL_LIVE_REPORT}"
    [[ "${_kl_fail}" -eq 0 ]]
}

# preflight

kl_preflight() {
    local missing=0
    for bin in kubectl jq python3; do
        if ! command -v "${bin}" >/dev/null 2>&1; then
            echo "missing required tool: ${bin}" >&2
            missing=1
        fi
    done
    [[ "${missing}" -eq 0 ]] || return 1

    if ! kubectl cluster-info >/dev/null 2>&1; then
        echo "kubectl cluster-info failed — is the cluster reachable?" >&2
        return 1
    fi

    if ! kubectl get namespace "${KL_NS}" >/dev/null 2>&1; then
        echo "namespace '${KL_NS}' not found — deploy KloudKnox first" >&2
        return 1
    fi
}

# component health

# Wait for a rollout to reach ready state within a timeout (default 120s).
_kl_rollout_ready() {
    local kind="$1" name="$2" timeout="${3:-120}"
    kubectl rollout status "${kind}/${name}" -n "${KL_NS}" --timeout="${timeout}s" \
        >/dev/null 2>&1
}

kl_check_components() {
    _kl_section "component health"

    local ds_ready
    ds_ready="$(kubectl get daemonset kloudknox -n "${KL_NS}" \
        -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)"
    local ds_desired
    ds_desired="$(kubectl get daemonset kloudknox -n "${KL_NS}" \
        -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 0)"
    if [[ "${ds_desired}" -gt 0 && "${ds_ready}" -eq "${ds_desired}" ]]; then
        _kl_ok "kloudknox daemonset" "${ds_ready}/${ds_desired} ready"
    else
        _kl_fail "kloudknox daemonset" "${ds_ready}/${ds_desired} ready"
    fi

    for dep in kloudknox-operator kloudknox-relay-server kloudknox-apparmor-webhook; do
        if _kl_rollout_ready deployment "${dep}" 30; then
            _kl_ok "${dep} deployment" "rollout complete"
        else
            _kl_fail "${dep} deployment" "not ready within 30s"
        fi
    done
}

# apparmor webhook

kl_check_webhook() {
    _kl_section "apparmor-webhook"

    # TLS cert + caBundle injection is handled by cert-manager (Issuer +
    # Certificate + cainjector inject-ca-from annotation on the MWC), so the
    # test does not need to sync the caBundle manually.

    # The MutatingWebhookConfiguration fires only for namespaces labelled
    # kloudknox-inject=enabled.  Label the test namespace so the webhook sees
    # the e2e workload pods.
    local test_ns="${KL_WEBHOOK_TEST_NS:-default}"
    echo "  labelling namespace '${test_ns}' kloudknox-inject=enabled ..."
    if ! kubectl label namespace "${test_ns}" kloudknox-inject=enabled \
            --overwrite >/dev/null 2>&1; then
        _kl_fail "namespace label" "kubectl label failed"
        return
    fi
    _kl_ok "namespace label" "${test_ns}: kloudknox-inject=enabled"

    # Deploy the plain e2e-workloads manifest (no pre-injected AppArmor).
    echo "  deploying ${E2E_WORKLOADS_PLAIN_YAML} ..."
    if ! kubectl apply -f "${E2E_WORKLOADS_PLAIN_YAML}" >/dev/null 2>&1; then
        _kl_fail "e2e-workloads deploy" "kubectl apply failed"
        return
    fi

    echo "  waiting for pods to be ready ..."
    if ! kubectl wait --for=condition=ready pod -l group=group-1 \
            --timeout=120s >/dev/null 2>&1 || \
       ! kubectl wait --for=condition=ready pod -l group=group-2 \
            --timeout=120s >/dev/null 2>&1; then
        _kl_fail "e2e-workloads pods ready" "timed out after 120s"
        kubectl delete -f "${E2E_WORKLOADS_PLAIN_YAML}" --ignore-not-found >/dev/null 2>&1 || true
        return
    fi
    _kl_ok "e2e-workloads pods ready" ""

    # Verify that at least one pod received an AppArmor injection from the
    # webhook (annotation or SecurityContext.AppArmorProfile).
    local injected=0
    local pods
    mapfile -t pods < <(kubectl get pods \
        -l 'group in (group-1,group-2)' \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)

    for pod in "${pods[@]}"; do
        # K8s < 1.30: annotation per container
        local ann
        ann="$(kubectl get pod "${pod}" \
            -o jsonpath='{.metadata.annotations}' 2>/dev/null || echo "")"
        if echo "${ann}" | grep -q 'apparmor'; then
            injected=$((injected + 1))
            continue
        fi
        # K8s >= 1.30: SecurityContext.AppArmorProfile
        local sc
        sc="$(kubectl get pod "${pod}" \
            -o jsonpath='{.spec.containers[*].securityContext.appArmorProfile}' \
            2>/dev/null || echo "")"
        if [[ -n "${sc}" ]]; then
            injected=$((injected + 1))
        fi
    done

    if [[ "${injected}" -gt 0 ]]; then
        _kl_ok "apparmor injected" "${injected}/${#pods[@]} pods"
    else
        _kl_fail "apparmor injected" "no pods received AppArmor annotation"
    fi

    # Cleanup test pods; leave label (non-destructive).
    kubectl delete -f "${E2E_WORKLOADS_PLAIN_YAML}" --ignore-not-found >/dev/null 2>&1 || true
}

# operator-controller

_kl_wait_policy_status() {
    local name="$1" expected="$2" timeout="${3:-20}"
    local start=${SECONDS}
    while (( SECONDS - start < timeout )); do
        local got
        got="$(kubectl get kloudknoxpolicies.security.boanlab.com "${name}" \
            -o jsonpath='{.status.status}' 2>/dev/null || echo "")"
        if [[ "${got}" == "${expected}" || "${got}" == "${expected}:"* ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

kl_check_operator() {
    _kl_section "operator-controller"

    # 1. offline validation via kkctl
    if command -v "${KKCTL_BIN}" >/dev/null 2>&1; then
        if "${KKCTL_BIN}" policy validate \
                -f "${POLICIES_LIVE_DIR}/valid-policy.yaml" >/dev/null 2>&1; then
            _kl_ok "kkctl policy validate (valid)" ""
        else
            _kl_fail "kkctl policy validate (valid)" "expected success"
        fi

        if ! "${KKCTL_BIN}" policy validate \
                -f "${POLICIES_LIVE_DIR}/invalid-no-selector.yaml" >/dev/null 2>&1; then
            _kl_ok "kkctl policy validate (invalid)" "correctly rejected"
        else
            _kl_fail "kkctl policy validate (invalid)" "expected failure but passed"
        fi
    else
        _kl_fail "kkctl binary" "not found at ${KKCTL_BIN}"
    fi

    # 2. valid process policy → operator sets status=Active
    local valid_name="k8slive-valid-test"
    kubectl delete kloudknoxpolicies.security.boanlab.com "${valid_name}" \
        --ignore-not-found >/dev/null 2>&1 || true

    if kubectl apply -f "${POLICIES_LIVE_DIR}/valid-policy.yaml" >/dev/null 2>&1; then
        if _kl_wait_policy_status "${valid_name}" "Active" 20; then
            _kl_ok "operator: valid policy → Active" ""
        else
            local got
            got="$(kubectl get kloudknoxpolicies.security.boanlab.com \
                "${valid_name}" -o jsonpath='{.status.status}' 2>/dev/null || echo '?')"
            _kl_fail "operator: valid policy → Active" "status=${got}"
        fi
    else
        _kl_fail "operator: apply valid policy" "kubectl apply failed"
    fi
    kubectl delete kloudknoxpolicies.security.boanlab.com "${valid_name}" \
        --ignore-not-found >/dev/null 2>&1 || true

    # 3. valid file policy → operator sets status=Active
    local file_name="k8slive-valid-file-test"
    kubectl delete kloudknoxpolicies.security.boanlab.com "${file_name}" \
        --ignore-not-found >/dev/null 2>&1 || true

    if kubectl apply -f "${POLICIES_LIVE_DIR}/valid-file-policy.yaml" >/dev/null 2>&1; then
        if _kl_wait_policy_status "${file_name}" "Active" 20; then
            _kl_ok "operator: file policy → Active" ""
        else
            local got2
            got2="$(kubectl get kloudknoxpolicies.security.boanlab.com \
                "${file_name}" -o jsonpath='{.status.status}' 2>/dev/null || echo '?')"
            _kl_fail "operator: file policy → Active" "status=${got2}"
        fi
    else
        _kl_fail "operator: apply file policy" "kubectl apply failed"
    fi
    kubectl delete kloudknoxpolicies.security.boanlab.com "${file_name}" \
        --ignore-not-found >/dev/null 2>&1 || true

    # 4. invalid policy → webhook rejects at admission
    # The CRD schema (minProperties: 1 on selector) or the validating webhook
    # should reject this.  If neither is active, the reconciler marks it Invalid.
    local reject_out
    if reject_out="$(kubectl apply \
            -f "${POLICIES_LIVE_DIR}/invalid-no-selector.yaml" 2>&1)"; then
        if _kl_wait_policy_status "k8slive-invalid-test" "Invalid" 20; then
            _kl_ok "operator: invalid policy → Invalid status" \
                "webhook not blocking; operator reconciler rejected"
        else
            _kl_fail "operator: invalid policy rejected" \
                "policy admitted and not marked Invalid"
        fi
        kubectl delete kloudknoxpolicies.security.boanlab.com k8slive-invalid-test \
            --ignore-not-found >/dev/null 2>&1 || true
    else
        _kl_ok "operator: invalid policy → webhook rejected" \
            "$(echo "${reject_out}" | grep -oE 'denied.*|BadRequest.*' | head -1)"
    fi
}

# relay-server

_kl_start_relay_portforward() {
    local local_port="${KL_RELAY_LOCAL_PORT}"
    : >"${KL_RELAY_PF_LOG}"
    kubectl port-forward svc/kloudknox-relay-server \
        "${local_port}:33900" -n "${KL_NS}" \
        >"${KL_RELAY_PF_LOG}" 2>&1 &
    echo $! >"${KL_RELAY_PF_PID_FILE}"
    # Wait for port-forward to be ready (kubectl prints "Forwarding from ...")
    local start=${SECONDS}
    while (( SECONDS - start < 15 )); do
        if grep -q "Forwarding from" "${KL_RELAY_PF_LOG}" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

_kl_stop_relay_portforward() {
    local pid
    pid="$(cat "${KL_RELAY_PF_PID_FILE}" 2>/dev/null || echo "")"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
    fi
    rm -f "${KL_RELAY_PF_PID_FILE}"
}

kl_check_relay() {
    _kl_section "relay-server"

    # Verify the relay-server pod is running before attempting a port-forward.
    local relay_ready
    relay_ready="$(kubectl get deployment kloudknox-relay-server -n "${KL_NS}" \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
    if [[ "${relay_ready:-0}" -lt 1 ]]; then
        _kl_fail "relay-server pod ready" "readyReplicas=${relay_ready:-0}"
        return
    fi
    _kl_ok "relay-server pod ready" "readyReplicas=${relay_ready}"

    # Open a port-forward so kkctl can reach the relay gRPC endpoint.
    echo "  starting port-forward svc/kloudknox-relay-server → localhost:${KL_RELAY_LOCAL_PORT} ..."
    if ! _kl_start_relay_portforward; then
        _kl_fail "relay port-forward" "kubectl port-forward did not become ready within 15s"
        _kl_stop_relay_portforward
        return
    fi
    _kl_ok "relay port-forward" "localhost:${KL_RELAY_LOCAL_PORT}"

    # Connect kkctl to the relay and stream for a few seconds; success means
    # the gRPC handshake completed without an immediate connection error.
    if command -v "${KKCTL_BIN}" >/dev/null 2>&1; then
        local stream_log="${ART_DIR}/relay-stream.log"
        : >"${stream_log}"
        # Run in background, kill after KL_RELAY_STREAM_SEC seconds.
        local stream_sec="${KL_RELAY_STREAM_SEC:-5}"
        "${KKCTL_BIN}" --server "localhost:${KL_RELAY_LOCAL_PORT}" \
            stream alerts >"${stream_log}" 2>&1 &
        local stream_pid=$!
        sleep "${stream_sec}"

        # If the process already exited with a non-zero code it could not connect.
        if ! kill -0 "${stream_pid}" 2>/dev/null; then
            wait "${stream_pid}" 2>/dev/null || true
            _kl_fail "kkctl → relay stream" \
                "process exited early — see ${stream_log}"
        else
            kill "${stream_pid}" 2>/dev/null || true
            wait "${stream_pid}" 2>/dev/null || true
            _kl_ok "kkctl → relay stream" \
                "connected for ${stream_sec}s without error"
        fi
    else
        _kl_fail "kkctl binary" "not found at ${KKCTL_BIN} — skipping relay stream test"
    fi

    _kl_stop_relay_portforward
}

# kkctl

# Expand KL_KKCTL_MODE into a list of modes to run.
_kl_kkctl_modes() {
    case "${KL_KKCTL_MODE:-both}" in
        local) echo "local" ;;
        pod)   echo "pod" ;;
        both)  echo "local pod" ;;
        *)     echo "local" ;;
    esac
}

# Probe whether a given kkctl mode is usable right now.
_kl_kkctl_available() {
    local mode="$1"
    case "${mode}" in
        local)
            command -v "${KKCTL_BIN}" >/dev/null 2>&1
            ;;
        pod)
            local ready
            ready="$(kubectl -n "${KL_NS}" get deployment "${KL_KKCTL_POD_DEPLOY}" \
                -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
            [[ "${ready:-0}" -ge 1 ]]
            ;;
        *) return 1 ;;
    esac
}

# Run kkctl in the requested mode. For "pod" mode, file args (-f <path>) are
# turned into stdin via "-f -" so the caller does not need to copy files into
# the pod; kkctl's readPolicyInput already supports "-".
_kl_kkctl() {
    local mode="$1"; shift
    case "${mode}" in
        local)
            "${KKCTL_BIN}" "$@"
            ;;
        pod)
            # Detect "-f <path>" and replace with stdin.
            local args=() file=""
            while (( $# )); do
                if [[ "$1" == "-f" && -n "${2:-}" && "$2" != "-" ]]; then
                    file="$2"
                    args+=("-f" "-")
                    shift 2
                else
                    args+=("$1")
                    shift
                fi
            done
            if [[ -n "${file}" ]]; then
                kubectl -n "${KL_NS}" exec -i \
                    "deployment/${KL_KKCTL_POD_DEPLOY}" -- \
                    kkctl "${args[@]}" <"${file}"
            else
                kubectl -n "${KL_NS}" exec \
                    "deployment/${KL_KKCTL_POD_DEPLOY}" -- \
                    kkctl "${args[@]}"
            fi
            ;;
    esac
}

# Per-mode subset of the kkctl checks (version / status / policy validate).
_kl_check_kkctl_mode() {
    local mode="$1" tag="[${1}]"

    # version
    local ver_out
    if ver_out="$(_kl_kkctl "${mode}" version 2>&1)"; then
        _kl_ok "kkctl ${tag} version" "${ver_out}"
    else
        _kl_fail "kkctl ${tag} version" "${ver_out}"
    fi

    # status (k8s env) — both modes can reach the API server
    # (pod uses in-cluster ServiceAccount kubeconfig).
    local status_out
    if status_out="$(_kl_kkctl "${mode}" --env k8s \
            --namespace "${KL_NS}" status 2>&1)"; then
        _kl_ok "kkctl ${tag} status" \
            "$(echo "${status_out}" | grep -i 'daemonset\|ready' | head -1)"
    else
        _kl_fail "kkctl ${tag} status" "$(echo "${status_out}" | head -1)"
    fi

    # offline policy validate — valid
    if _kl_kkctl "${mode}" policy validate \
            -f "${POLICIES_LIVE_DIR}/valid-policy.yaml" >/dev/null 2>&1; then
        _kl_ok "kkctl ${tag} policy validate (valid)" ""
    else
        _kl_fail "kkctl ${tag} policy validate (valid)" "unexpectedly failed"
    fi

    # offline policy validate — invalid (must fail)
    if ! _kl_kkctl "${mode}" policy validate \
            -f "${POLICIES_LIVE_DIR}/invalid-no-selector.yaml" >/dev/null 2>&1; then
        _kl_ok "kkctl ${tag} policy validate (invalid)" "correctly rejected"
    else
        _kl_fail "kkctl ${tag} policy validate (invalid)" "expected error but exited 0"
    fi
}

kl_check_kkctl() {
    _kl_section "kkctl"

    local any_ran=0
    for mode in $(_kl_kkctl_modes); do
        if ! _kl_kkctl_available "${mode}"; then
            case "${mode}" in
                local) _kl_fail "kkctl [local] binary" "not found at ${KKCTL_BIN}" ;;
                pod)   _kl_fail "kkctl [pod] deployment" \
                           "${KL_KKCTL_POD_DEPLOY} not ready in ns ${KL_NS}" ;;
            esac
            continue
        fi
        any_ran=1
        _kl_check_kkctl_mode "${mode}"
    done

    # Skipped in every mode (requires the local KloudKnox REST socket).
    _kl_ok "kkctl get policies" "skipped (requires local KloudKnox REST socket)"

    # Apply + operator reconcile is mode-independent: we use kubectl apply
    # directly because kkctl apply --also-k8s additionally needs the local
    # REST socket which the test env doesn't provide.  Run once.
    if (( any_ran )); then
        local apply_name="k8slive-kkctl-apply-test"
        kubectl delete kloudknoxpolicies.security.boanlab.com "${apply_name}" \
            --ignore-not-found >/dev/null 2>&1 || true

        local tmp_policy
        tmp_policy="$(mktemp --suffix=.yaml)"
        sed "s/k8slive-valid-test/${apply_name}/" \
            "${POLICIES_LIVE_DIR}/valid-policy.yaml" >"${tmp_policy}"

        if kubectl apply -f "${tmp_policy}" >/dev/null 2>&1; then
            if _kl_wait_policy_status "${apply_name}" "Active" 20; then
                _kl_ok "kkctl apply (via kubectl) → operator Active" ""
            else
                local got
                got="$(kubectl get kloudknoxpolicies.security.boanlab.com \
                    "${apply_name}" -o jsonpath='{.status.status}' 2>/dev/null || echo '?')"
                _kl_fail "kkctl apply (via kubectl) → operator Active" "status=${got}"
            fi
        else
            _kl_fail "kkctl apply (via kubectl)" "kubectl apply failed"
        fi

        rm -f "${tmp_policy}"
        kubectl delete kloudknoxpolicies.security.boanlab.com "${apply_name}" \
            --ignore-not-found >/dev/null 2>&1 || true
    fi
}
