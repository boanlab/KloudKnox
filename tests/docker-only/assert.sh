#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University
#
# Tail-based alert matcher for the docker-only e2e suite.
#
# Callers pass an offset (captured before the triggering exec) plus a
# policy name. assert_has_alert scans bytes after the offset for a
# record whose .policyName matches, returning 0 on first match.

set -euo pipefail

: "${ALERTS_FILE:=/var/log/kloudknox/alerts.jsonl}"
: "${ALERT_WINDOW_SEC:=5}"

# snapshot the current size of ALERTS_FILE. Use before triggering so the
# assertion below only looks at new bytes.
assert_offset() {
    if [[ -f "${ALERTS_FILE}" ]]; then
        stat -c%s "${ALERTS_FILE}"
    else
        echo 0
    fi
}

# assert_has_alert <offset> <policy> [<window_sec>]
# Returns 0 if at least one alert with the given policyName appears in the
# window after offset. Prints the matching JSON to stdout on success and
# the tail of alerts.jsonl to stderr on failure for debugging.
assert_has_alert() {
    local offset="$1" policy="$2" window="${3:-${ALERT_WINDOW_SEC}}"
    local deadline=$((SECONDS + window))
    local record=""
    while (( SECONDS < deadline )); do
        if [[ -f "${ALERTS_FILE}" ]]; then
            record="$(tail -c "+$((offset + 1))" "${ALERTS_FILE}" 2>/dev/null \
                | jq -c --arg p "${policy}" \
                    'select((.policyName // "") | split(",") | index($p))' \
                2>/dev/null | head -n1)"
            if [[ -n "${record}" ]]; then
                printf '%s\n' "${record}"
                return 0
            fi
        fi
        sleep 0.25
    done
    echo "no alert matching policy=${policy} within ${window}s" >&2
    if [[ -f "${ALERTS_FILE}" ]]; then
        echo "--- last 10 alerts in ${ALERTS_FILE} ---" >&2
        tail -n 10 "${ALERTS_FILE}" >&2 || true
    fi
    return 1
}

# If invoked directly, expose a one-shot check against the whole file.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 1 ]]; then
        echo "usage: $0 <policyName> [window_sec]" >&2
        exit 2
    fi
    assert_has_alert 0 "$@"
fi
