#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# K8s live integration test driver.
# Verifies apparmor-webhook, operator-controller, relay-server, and kkctl
# against a running Kubernetes cluster with KloudKnox installed.
#
# Prerequisites: KloudKnox deployed via deployments/*.yaml, cluster reachable.
# Does NOT start/stop the KloudKnox daemon — use the regular e2e.sh for
# local (non-K8s) testing.

set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${E2E_ROOT}/../.." && pwd)"
ART_DIR="${E2E_ROOT}/artifacts"

KLOUDKNOX_DIR="${REPO_ROOT}/KloudKnox/KloudKnox"
KLOUDKNOX_DEPLOY_DIR="${REPO_ROOT}/KloudKnox/deployments"
KKCTL_DIR="${REPO_ROOT}/kloudknox-cli/kloudknox-cli"
KKCTL_BIN="${KKCTL_DIR}/bin/kkctl"

E2E_WORKLOADS_PLAIN_YAML="${E2E_ROOT}/e2e-workloads.yaml"
POLICIES_LIVE_DIR="${E2E_ROOT}/policies/k8s-live"

KL_NS="${KL_NS:-kloudknox}"
KL_WEBHOOK_TEST_NS="${KL_WEBHOOK_TEST_NS:-default}"
KL_RELAY_LOCAL_PORT="${KL_RELAY_LOCAL_PORT:-33900}"
KL_RELAY_STREAM_SEC="${KL_RELAY_STREAM_SEC:-5}"
KL_CERT_MANAGER_VERSION="${KL_CERT_MANAGER_VERSION:-v1.16.1}"
KL_DEPLOY_DIR="${KL_DEPLOY_DIR:-${KLOUDKNOX_DEPLOY_DIR}}"
KL_KKCTL_MODE="${KL_KKCTL_MODE:-both}"
KL_KKCTL_POD_DEPLOY="${KL_KKCTL_POD_DEPLOY:-kloudknox-cli}"

export ART_DIR KLOUDKNOX_DIR KKCTL_DIR KKCTL_BIN
export E2E_WORKLOADS_PLAIN_YAML POLICIES_LIVE_DIR
export KL_NS KL_WEBHOOK_TEST_NS KL_RELAY_LOCAL_PORT KL_RELAY_STREAM_SEC
export KL_KKCTL_MODE KL_KKCTL_POD_DEPLOY

# shellcheck source=lib/k8s_live.sh
source "${E2E_ROOT}/lib/k8s_live.sh"

usage() {
    cat <<'EOF'
Usage: k8s-live.sh <command> [args]

Commands:
  up                         install cert-manager (if absent) and apply
                             deployments/, then wait for KloudKnox rollout
  down [--purge-cert-manager]
                             remove KloudKnox deployments; with the flag
                             also remove cert-manager
  check                      run all component checks (default)
  check-components           verify K8s deployments/daemonsets are ready
  check-webhook              verify apparmor-webhook injects profiles into pods
  check-operator             verify operator-controller validates and normalises policies
  check-relay                verify relay-server gRPC streaming via port-forward
  check-kkctl                verify kkctl commands against the live cluster

Environment variables (all optional):
  KL_NS                      KloudKnox namespace          (default: kloudknox)
  KL_WEBHOOK_TEST_NS         namespace for webhook test   (default: default)
  KL_RELAY_LOCAL_PORT        local port for relay pf      (default: 33900)
  KL_RELAY_STREAM_SEC        seconds to hold relay stream (default: 5)
  KL_CERT_MANAGER_VERSION    cert-manager release tag     (default: v1.16.1)
  KL_DEPLOY_DIR              deployments/ path            (default: <repo>/deployments)
  KL_KKCTL_MODE              kkctl test mode: local|pod|both (default: both)
                             local → host binary at kloudknox-cli/kloudknox-cli/bin/kkctl
                             pod   → kubectl exec into kloudknox-cli deployment
  KL_KKCTL_POD_DEPLOY        deployment name for pod-mode  (default: kloudknox-cli)

Artifacts written under tests/artifacts/.
EOF
}

_run_check() {
    local fn="$1" label="$2"
    echo ""
    echo "[k8s-live] ${label}"
    "${fn}"
}

_kl_cert_manager_url() {
    echo "https://github.com/cert-manager/cert-manager/releases/download/${KL_CERT_MANAGER_VERSION}/cert-manager.yaml"
}

_kl_cert_manager_installed() {
    kubectl get crd certificates.cert-manager.io >/dev/null 2>&1
}

# cert-manager's Deployments report "available" before its validating webhook
# endpoints are actually serving. Poll a dry-run Issuer apply — when the
# webhook accepts it, the admission path is ready.
_kl_cert_manager_wait_webhook() {
    local probe
    probe=$(cat <<'EOF'
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: kloudknox-cm-probe
  namespace: kube-system
spec:
  selfSigned: {}
EOF
)
    local deadline=$(( SECONDS + 120 ))
    while (( SECONDS < deadline )); do
        if echo "${probe}" | kubectl apply --dry-run=server -f - >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "  cert-manager webhook did not become ready within 120s" >&2
    return 1
}

cmd_up() {
    for bin in kubectl; do
        command -v "${bin}" >/dev/null 2>&1 || { echo "missing: ${bin}" >&2; exit 1; }
    done
    if ! kubectl cluster-info >/dev/null 2>&1; then
        echo "kubectl cluster-info failed — is the cluster reachable?" >&2
        exit 1
    fi
    [[ -d "${KL_DEPLOY_DIR}" ]] || {
        echo "deploy dir not found: ${KL_DEPLOY_DIR}" >&2; exit 1; }

    echo "[k8s-up] cert-manager (${KL_CERT_MANAGER_VERSION})"
    if _kl_cert_manager_installed; then
        echo "  already installed — skipping"
    else
        echo "  installing from $(_kl_cert_manager_url)"
        kubectl apply -f "$(_kl_cert_manager_url)" >/dev/null
        echo "  waiting for cert-manager deployments ..."
        kubectl -n cert-manager wait --for=condition=available \
            --timeout=180s deployment --all
    fi

    echo "  waiting for cert-manager admission webhook ..."
    _kl_cert_manager_wait_webhook || exit 1

    echo "[k8s-up] applying ${KL_DEPLOY_DIR}/"
    kubectl apply -f "${KL_DEPLOY_DIR}/"

    # relay-server and kloudknox-cli manifests live in sibling split repos.
    # Apply from sibling checkouts when present, otherwise fetch from GitHub.
    # (The apparmor-webhook manifest is bundled under ${KL_DEPLOY_DIR}/ and
    # applied by the blanket `kubectl apply -f ${KL_DEPLOY_DIR}/` above.)
    local relay_src="${REPO_ROOT}/kloudknox-relay-server/deployments/relay-server.yaml"
    local kkctl_src="${REPO_ROOT}/kloudknox-cli/deployments/kloudknox-cli.yaml"
    if [[ -f "${relay_src}" ]]; then
        echo "[k8s-up] applying ${relay_src}"
        kubectl apply -f "${relay_src}"
    else
        echo "[k8s-up] applying relay-server manifest from GitHub (no sibling checkout)"
        kubectl apply -f "https://raw.githubusercontent.com/boanlab/kloudknox-relay-server/main/deployments/relay-server.yaml"
    fi
    if [[ -f "${kkctl_src}" ]]; then
        echo "[k8s-up] applying ${kkctl_src}"
        kubectl apply -f "${kkctl_src}"
    else
        echo "[k8s-up] applying kloudknox-cli manifest from GitHub (no sibling checkout)"
        kubectl apply -f "https://raw.githubusercontent.com/boanlab/kloudknox-cli/main/deployments/kloudknox-cli.yaml"
    fi

    echo "[k8s-up] waiting for KloudKnox rollout ..."
    kubectl -n "${KL_NS}" rollout status daemonset/kloudknox --timeout=180s
    for dep in kloudknox-operator kloudknox-apparmor-webhook kloudknox-relay-server kloudknox-cli; do
        kubectl -n "${KL_NS}" rollout status "deployment/${dep}" --timeout=180s
    done

    echo "[k8s-up] done"
}

cmd_down() {
    local purge_cm=0
    while (( $# )); do
        case "$1" in
            --purge-cert-manager) purge_cm=1 ;;
            -h|--help)
                echo "Usage: k8s-live.sh down [--purge-cert-manager]"
                return 0 ;;
            *) echo "unknown arg: $1" >&2; return 2 ;;
        esac
        shift
    done

    # apparmor-webhook is deleted by the blanket `kubectl delete -f ${KL_DEPLOY_DIR}/`
    # below (the manifest lives in-tree under deployments/).
    local relay_src="${REPO_ROOT}/kloudknox-relay-server/deployments/relay-server.yaml"
    local kkctl_src="${REPO_ROOT}/kloudknox-cli/deployments/kloudknox-cli.yaml"
    if [[ -f "${kkctl_src}" ]]; then
        echo "[k8s-down] deleting ${kkctl_src}"
        kubectl delete -f "${kkctl_src}" --ignore-not-found
    else
        kubectl delete -f "https://raw.githubusercontent.com/boanlab/kloudknox-cli/main/deployments/kloudknox-cli.yaml" --ignore-not-found
    fi
    if [[ -f "${relay_src}" ]]; then
        echo "[k8s-down] deleting ${relay_src}"
        kubectl delete -f "${relay_src}" --ignore-not-found
    else
        kubectl delete -f "https://raw.githubusercontent.com/boanlab/kloudknox-relay-server/main/deployments/relay-server.yaml" --ignore-not-found
    fi

    if [[ -d "${KL_DEPLOY_DIR}" ]]; then
        echo "[k8s-down] deleting ${KL_DEPLOY_DIR}/"
        kubectl delete -f "${KL_DEPLOY_DIR}/" --ignore-not-found
    else
        echo "[k8s-down] deploy dir not found: ${KL_DEPLOY_DIR} (skipping)"
    fi

    if (( purge_cm )); then
        echo "[k8s-down] purging cert-manager (${KL_CERT_MANAGER_VERSION})"
        kubectl delete -f "$(_kl_cert_manager_url)" --ignore-not-found
    else
        echo "[k8s-down] cert-manager left in place (pass --purge-cert-manager to remove)"
    fi

    echo "[k8s-down] done"
}

cmd_check() {
    kl_preflight || exit 1
    kl_report_init
    _run_check kl_check_components   "component health"
    _run_check kl_check_webhook      "apparmor-webhook"
    _run_check kl_check_operator     "operator-controller"
    _run_check kl_check_relay        "relay-server"
    _run_check kl_check_kkctl        "kkctl"
    kl_report_summary
}

cmd_check_components() {
    kl_preflight || exit 1
    kl_report_init
    _run_check kl_check_components "component health"
    kl_report_summary
}

cmd_check_webhook() {
    kl_preflight || exit 1
    kl_report_init
    _run_check kl_check_webhook "apparmor-webhook"
    kl_report_summary
}

cmd_check_operator() {
    kl_preflight || exit 1
    kl_report_init
    _run_check kl_check_operator "operator-controller"
    kl_report_summary
}

cmd_check_relay() {
    kl_preflight || exit 1
    kl_report_init
    _run_check kl_check_relay "relay-server"
    kl_report_summary
}

cmd_check_kkctl() {
    kl_preflight || exit 1
    kl_report_init
    _run_check kl_check_kkctl "kkctl"
    kl_report_summary
}

main() {
    local cmd="${1:-check}"
    shift || true
    case "${cmd}" in
        up)               cmd_up "$@" ;;
        down)             cmd_down "$@" ;;
        check)            cmd_check ;;
        check-components) cmd_check_components ;;
        check-webhook)    cmd_check_webhook ;;
        check-operator)   cmd_check_operator ;;
        check-relay)      cmd_check_relay ;;
        check-kkctl)      cmd_check_kkctl ;;
        ""|-h|--help|help) usage ;;
        *) echo "unknown command: ${cmd}" >&2; usage >&2; exit 2 ;;
    esac
}

main "$@"
