#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${E2E_ROOT}/../.." && pwd)"
ART_DIR="${E2E_ROOT}/artifacts"
CASES_FILE="${E2E_ROOT}/cases/test-cases.yaml"

KLOUDKNOX_DIR="${REPO_ROOT}/KloudKnox/KloudKnox"
KLOUDKNOX_DEPLOY_DIR="${REPO_ROOT}/KloudKnox/deployments"
KKCTL_DIR="${REPO_ROOT}/kloudknox-cli/kloudknox-cli"
E2E_WORKLOADS_YAML="${E2E_ROOT}/e2e-workloads_with_apparmor.yaml"
POLICIES_DIR="${E2E_ROOT}/policies"

# shellcheck source=lib/bootstrap.sh
source "${E2E_ROOT}/lib/bootstrap.sh"
# shellcheck source=lib/assert.sh
source "${E2E_ROOT}/lib/assert.sh"
# shellcheck source=lib/case-runner.sh
source "${E2E_ROOT}/lib/case-runner.sh"
# shellcheck source=lib/report.sh
source "${E2E_ROOT}/lib/report.sh"

usage() {
    cat <<'EOF'
Usage: e2e.sh <command> [args]

Commands:
  up                         build and start KloudKnox + kkctl stream alerts, deploy pods
  down                       stop daemons, delete policies & pods
  status                     show daemon PIDs and last alert summary
  run <id> [<id> ...] [opts] run one or more cases (daemons must be up)
  run-all [opts]             run every case in cases/test-cases.yaml
  list                       list registered cases
  logs kloudknox|alerts      tail a log file

run options:
  --step                 pause between steps (manual checkpoint)
  --no-assert            execute commands but skip PASS/FAIL judgment
  --alert-window <sec>   window to wait for alerts (default 3)
  --verbose              print full exec stdout/stderr
  --dry-run              print plan, do not execute

run-all options:
  --skip-tags <tag>      skip cases with this tag (e.g. --skip-tags external-network)

Artifacts written under tests/artifacts/.
EOF
}

cmd_up() {
    bootstrap_up
}

cmd_down() {
    bootstrap_down
}

cmd_status() {
    bootstrap_status
}

cmd_logs() {
    local which="${1:-}"
    case "${which}" in
        kloudknox) tail -F "${ART_DIR}/kloudknox.log" ;;
        alerts)    tail -F "${ART_DIR}/alerts.jsonl" ;;
        *) echo "usage: e2e.sh logs kloudknox|alerts" >&2; return 2 ;;
    esac
}

cmd_list() {
    cases_list
}

cmd_run() {
    local -a ids=()
    local opt_step=0 opt_no_assert=0 opt_verbose=0 opt_dry=0
    local alert_window=3
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --step)          opt_step=1 ;;
            --no-assert)     opt_no_assert=1 ;;
            --verbose)       opt_verbose=1 ;;
            --dry-run)       opt_dry=1 ;;
            --alert-window)  alert_window="$2"; shift ;;
            -h|--help)       usage; return 0 ;;
            --) shift; while [[ $# -gt 0 ]]; do ids+=("$1"); shift; done ;;
            -*) echo "unknown option: $1" >&2; return 2 ;;
            *)  ids+=("$1") ;;
        esac
        shift
    done
    if [[ ${#ids[@]} -eq 0 ]]; then
        echo "run: need at least one case id" >&2
        return 2
    fi

    export E2E_OPT_STEP="${opt_step}"
    export E2E_OPT_NO_ASSERT="${opt_no_assert}"
    export E2E_OPT_VERBOSE="${opt_verbose}"
    export E2E_OPT_DRY_RUN="${opt_dry}"
    export E2E_ALERT_WINDOW="${alert_window}"

    bootstrap_check_daemons_running

    report_reset
    local pass=0 fail=0 case_id rc
    for case_id in "${ids[@]}"; do
        if case_runner_run "${case_id}"; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
        fi
    done
    report_summary "${pass}" "${fail}"
    [[ ${fail} -eq 0 ]]
}

cmd_run_all() {
    local skip_tags=""
    local -a pass_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-tags) skip_tags="$2"; shift 2 ;;
            *) pass_args+=("$1"); shift ;;
        esac
    done

    local -a ids=()
    if [[ -n "${skip_tags}" ]]; then
        mapfile -t ids < <(python3 "${CASES_PY}" ids-excluding "${CASES_FILE}" "${skip_tags}")
    else
        mapfile -t ids < <(cases_ids)
    fi
    if [[ ${#ids[@]} -eq 0 ]]; then
        echo "no cases registered in ${CASES_FILE}" >&2
        return 2
    fi
    cmd_run "${ids[@]}" "${pass_args[@]+"${pass_args[@]}"}"
}

main() {
    local cmd="${1:-}"
    shift || true
    case "${cmd}" in
        up)      cmd_up "$@" ;;
        down)    cmd_down "$@" ;;
        status)  cmd_status "$@" ;;
        run)     cmd_run "$@" ;;
        run-all) cmd_run_all "$@" ;;
        list)    cmd_list "$@" ;;
        logs)    cmd_logs "$@" ;;
        ""|-h|--help|help) usage ;;
        *) echo "unknown command: ${cmd}" >&2; usage >&2; return 2 ;;
    esac
}

main "$@"
