#!/usr/bin/env bash
# Run the Kubernetes [Conformance] suite via hydrophone against the current
# cluster (KUBECONFIG must point at the containerd-rs cluster) and collect the
# results into RESULTS_DIR. A pass = zero failed conformance tests (SC-001).
set -euo pipefail

CONFORMANCE_IMAGE="${CONFORMANCE_IMAGE:-registry.k8s.io/conformance:v1.35.6}"
RESULTS_DIR="${RESULTS_DIR:-conformance-results}"
FOCUS="${FOCUS:-}"
KUBECONFIG="${KUBECONFIG:-${HOME}/.kube/config}"
export KUBECONFIG

log() { echo "[conformance] $*"; }

require_tools() {
  command -v hydrophone >/dev/null 2>&1 || {
    echo "hydrophone not found; install: go install sigs.k8s.io/hydrophone@latest" >&2
    exit 1
  }
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found" >&2; exit 1; }
}

main() {
  require_tools
  mkdir -p "${RESULTS_DIR}"

  local args=(--conformance-image "${CONFORMANCE_IMAGE}" --output-dir "${RESULTS_DIR}")
  if [[ -n "${FOCUS}" ]]; then
    log "focused run: ${FOCUS}"
    args+=(--focus "${FOCUS}")
  else
    log "full [Conformance] run with ${CONFORMANCE_IMAGE}"
    args+=(--conformance)
  fi

  hydrophone "${args[@]}"
  log "results in ${RESULTS_DIR} (e2e.log, junit_01.xml)"
}

main "$@"
