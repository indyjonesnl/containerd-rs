#!/usr/bin/env bash
# CRI-conformance suite (kubernetes-sigs/cri-tools `critest`) against a running
# containerd-rs daemon — the same suite Go containerd / CRI-O gate CRI
# compliance on. Assumes the daemon is up and CNI is configured; needs no
# kubelet or cluster. See ci/critest-docker.sh for a self-contained harness.
#
# Env:
#   CRI_SOCKET       CRI endpoint (default unix:///run/containerd-rs.sock)
#   CRICTL_VERSION   cri-tools release for critest (default v1.35.0)
#   RESULTS_DIR      output dir for the log (default critest-results)
#   PARALLEL         parallel nodes (default 1)
#   FOCUS            ginkgo focus regex (empty = whole suite)
#   SKIP             ginkgo skip regex — known-deferred / by-design behaviors
#   EXTRA_ARGS       extra critest args (advanced)
set -euo pipefail

CRI_SOCKET="${CRI_SOCKET:-unix:///run/containerd-rs.sock}"
CRICTL_VERSION="${CRICTL_VERSION:-v1.35.0}"
RESULTS_DIR="${RESULTS_DIR:-critest-results}"
PARALLEL="${PARALLEL:-1}"
FOCUS="${FOCUS:-}"
# Known-deferred / by-design behaviors, extended as the first run is triaged.
SKIP="${SKIP:-}"

log() { echo "[critest] $*"; }

if ! command -v critest >/dev/null 2>&1; then
  log "installing critest ${CRICTL_VERSION}"
  curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/critest-${CRICTL_VERSION}-linux-amd64.tar.gz" \
    | tar -xz -C /usr/local/bin
fi

mkdir -p "${RESULTS_DIR}"
args=(-runtime-endpoint "${CRI_SOCKET}" -image-endpoint "${CRI_SOCKET}" -parallel "${PARALLEL}")
[[ -n "${FOCUS}" ]] && args+=(-ginkgo.focus "${FOCUS}")
[[ -n "${SKIP}" ]] && args+=(-ginkgo.skip "${SKIP}")
# shellcheck disable=SC2206
[[ -n "${EXTRA_ARGS:-}" ]] && args+=(${EXTRA_ARGS})

log "critest ${args[*]}"
# pipefail (set -o) propagates critest's exit code through tee, so a failing
# suite still fails the script while we keep the full log for triage.
critest "${args[@]}" 2>&1 | tee "${RESULTS_DIR}/critest.log"
