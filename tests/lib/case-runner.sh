#!/usr/bin/env bash
# Run a single case from cases/test-cases.yaml.
# Delegates YAML parsing to a Python helper (no yq dependency).

CASES_PY="${E2E_ROOT}/lib/cases.py"
_LAST_POLICY_PATH=""
_CASE_INGRESS_CIDR=""

cases_get_json() {
    local id="$1"
    python3 "${CASES_PY}" get "${CASES_FILE}" "${id}"
}

cases_ids() {
    python3 "${CASES_PY}" ids "${CASES_FILE}"
}

cases_list() {
    python3 "${CASES_PY}" list "${CASES_FILE}"
}

_case_pod_name() {
    local label="$1"
    kubectl get pods -l "container=${label}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

_case_detect_ingress_cidr() {
    if [[ -n "${_CASE_INGRESS_CIDR}" ]]; then
        printf '%s' "${_CASE_INGRESS_CIDR}"
        return
    fi
    local node_cidr oct1 oct2
    node_cidr="$(kubectl get nodes -o jsonpath='{.items[0].spec.podCIDR}' 2>/dev/null || true)"
    if [[ -z "${node_cidr}" ]]; then
        _CASE_INGRESS_CIDR="10.0.0.0/8"
    else
        oct1="$(printf '%s' "${node_cidr}" | cut -d. -f1)"
        oct2="$(printf '%s' "${node_cidr}" | cut -d. -f2)"
        _CASE_INGRESS_CIDR="${oct1}.${oct2}.0.0/16"
    fi
    printf '%s' "${_CASE_INGRESS_CIDR}"
}

_apply_policy() {
    local path="$1"
    local cidr
    cidr="$(_case_detect_ingress_cidr)"
    sed "s|10\\.0\\.0\\.0/8|${cidr}|g" "${path}" | kubectl apply -f - >/dev/null
}

# Snapshot the log size *before* kubectl apply fires. Network policies commit
# in sub-ms: Added + Updated-to-pod can both land before a post-apply stat(2)
# runs, causing tail -c +offset+1 to skip past the confirmation lines.
_case_snapshot_log_offset() {
    _CASE_LOG_OFFSET="$(stat -c%s "${KLOUDKNOX_LOG}" 2>/dev/null || echo 0)"
}

# Poll KLOUDKNOX_LOG for the final policy-to-pod commit message. Waiting for
# "Updated security policies for profile:" alone is racy because the kernel
# AppArmor profile is loaded before pod.FileRules (the user-space matcher
# cache) is refreshed, causing the first deny event after a policy apply to
# miss policy metadata. Network-only policies never touch AppArmor, so allow
# either the "to pod" commit message or the namespaced "Added/Updated
# KloudKnoxPolicy" log as confirmation.
_case_wait_policy_applied() {
    local policy_name="$1"
    local log_offset="${_CASE_LOG_OFFSET:-0}" timeout="${POLICY_WAIT_TIMEOUT:-10}"
    local start=${SECONDS}
    while (( SECONDS - start < timeout )); do
        if tail -c "+$((log_offset + 1))" "${KLOUDKNOX_LOG}" 2>/dev/null \
                | grep -qE "Updated a KloudKnoxPolicy \(${policy_name}\) to pod|(Added|Updated) a KloudKnoxPolicy \(default/${policy_name}\)"; then
            sleep 0.2   # allow matcher cache to settle before first step runs
            return 0
        fi
        sleep 0.5
    done
    echo "[warn] policy '${policy_name}' apply not confirmed within ${timeout}s, proceeding anyway" >&2
}

_case_step_prompt_pause() {
    [[ "${E2E_OPT_STEP:-0}" -eq 1 ]] || return 0
    read -r -p "  [step] press ENTER to continue... " _ </dev/tty
}

case_runner_run() {
    local case_id="$1"
    local case_json name policy step_count
    if ! case_json="$(cases_get_json "${case_id}")"; then
        echo "[${case_id}] not found in ${CASES_FILE}" >&2
        return 1
    fi
    name="$(echo "${case_json}" | jq -r '.name')"
    policy="$(echo "${case_json}" | jq -r '.policy')"
    step_count="$(echo "${case_json}" | jq '.steps | length')"

    echo "[${case_id}] ${name}"
    if [[ "${E2E_OPT_DRY_RUN:-0}" -eq 1 ]]; then
        echo "${case_json}" | jq .
        return 0
    fi

    local policy_path="${E2E_ROOT}/${policy}"
    if [[ ! -f "${policy_path}" ]]; then
        echo "[${case_id}] policy file missing: ${policy_path}" >&2
        return 1
    fi

    if [[ -n "${_LAST_POLICY_PATH}" && -f "${_LAST_POLICY_PATH}" ]]; then
        kubectl delete -f "${_LAST_POLICY_PATH}" --ignore-not-found >/dev/null 2>&1 || true
    fi

    echo "[${case_id}] apply ${policy}"
    _case_snapshot_log_offset
    if ! _apply_policy "${policy_path}"; then
        echo "[${case_id}] kubectl apply failed" >&2
        return 1
    fi
    _LAST_POLICY_PATH="${policy_path}"
    local policy_name
    policy_name="$(basename "${policy_path}" .yaml)"
    _case_wait_policy_applied "${policy_name}"

    report_begin_case "${case_id}" "${name}" "${step_count}"
    local step_pass=0 step_fail=0 i=0
    while [[ "${i}" -lt "${step_count}" ]]; do
        local step pod_label exec_cmd expect step_timeout pod
        step="$(echo "${case_json}" | jq -c ".steps[${i}]")"
        pod_label="$(echo "${step}" | jq -r '.pod')"
        exec_cmd="$(echo "${step}" | jq -r '.exec')"
        expect="$(echo "${step}" | jq -r '.expect')"
        step_timeout="$(echo "${step}" | jq -r '.timeout // 15')"

        pod="$(_case_pod_name "${pod_label}")"
        if [[ -z "${pod}" ]]; then
            echo "  step $((i+1))/${step_count}: no pod found for label=${pod_label}"
            report_step "${case_id}" "$((i+1))" "${pod_label}" "${exec_cmd}" "${expect}" "FAIL" "pod missing"
            step_fail=$((step_fail + 1))
            i=$((i + 1))
            continue
        fi

        echo "  step $((i+1))/${step_count}: ${exec_cmd} [pod=${pod_label} expect=${expect}]"
        _case_step_prompt_pause

        local offset rc=0 tmp_out tmp_err
        offset="$(assert_alert_offset)"
        tmp_out="$(mktemp)"; tmp_err="$(mktemp)"
        timeout "${step_timeout}" kubectl exec "${pod}" -- bash --norc --noprofile -c "${exec_cmd}" \
            >"${tmp_out}" 2>"${tmp_err}" || rc=$?

        if [[ "${E2E_OPT_VERBOSE:-0}" -eq 1 ]]; then
            echo "    exit=${rc}"
            [[ -s "${tmp_out}" ]] && { echo "    stdout:"; sed 's/^/      /' "${tmp_out}"; }
            [[ -s "${tmp_err}" ]] && { echo "    stderr:"; sed 's/^/      /' "${tmp_err}"; }
        fi

        if [[ "${E2E_OPT_NO_ASSERT:-0}" -eq 1 ]]; then
            echo "    (no-assert) exit=${rc}"
            report_step "${case_id}" "$((i+1))" "${pod_label}" "${exec_cmd}" "${expect}" "SKIP" "no-assert"
        else
            ASSERT_VERDICT=""; ASSERT_REASON=""
            if assert_step "${rc}" "${expect}" "${policy_name}" "${pod_label}" \
                           "${offset}" "${E2E_ALERT_WINDOW:-3}"; then
                echo "    PASS — ${ASSERT_REASON}"
                step_pass=$((step_pass + 1))
                report_step "${case_id}" "$((i+1))" "${pod_label}" "${exec_cmd}" "${expect}" "PASS" "${ASSERT_REASON}"
            else
                echo "    FAIL — ${ASSERT_REASON}"
                step_fail=$((step_fail + 1))
                report_step "${case_id}" "$((i+1))" "${pod_label}" "${exec_cmd}" "${expect}" "FAIL" "${ASSERT_REASON}"
            fi
        fi
        rm -f "${tmp_out}" "${tmp_err}"
        i=$((i + 1))
    done

    kubectl delete -f "${policy_path}" --ignore-not-found >/dev/null 2>&1 || true
    _LAST_POLICY_PATH=""

    local case_rc=0
    if [[ "${step_fail}" -eq 0 ]]; then
        echo "[${case_id}] RESULT: PASS (${step_pass}/${step_count})"
    else
        echo "[${case_id}] RESULT: FAIL (${step_pass}/${step_count} passed, ${step_fail} failed)"
        case_rc=1
    fi
    report_end_case "${case_id}" "${step_pass}" "${step_fail}" "${step_count}"
    return "${case_rc}"
}
