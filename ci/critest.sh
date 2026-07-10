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
# Known-deferred / by-design / environmental behaviors, skipped so the suite is
# a clean gate for everything else (as containerd maintains its own skips). From
# the 2026-07-03 baseline triage:
#   AppArmor            — test BeforeEach can't load a profile on the runner
#                         (environmental) + our AppArmor RuntimeDefault is deferred.
#   OOMKilled reason    — deferred (T025): crun run deletes the cgroup on exit.
#   RunAsUserName       — Windows-style username, N/A on Linux.
# Override SKIP to change. Real gaps (stats/images/streaming/mounts/namespaces)
# are intentionally NOT skipped — they are being fixed.
DEFAULT_SKIP='AppArmor|should output OOMKilled reason|should support RunAsUserName'
# Colon-dash: an unset OR empty SKIP (the workflow input defaults to empty) uses
# the default. To run the full suite with no skips, pass a non-matching regex.
SKIP="${SKIP:-$DEFAULT_SKIP}"

log() { echo "[critest] $*"; }

if ! command -v critest >/dev/null 2>&1; then
  log "installing critest ${CRICTL_VERSION}"
  curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/critest-${CRICTL_VERSION}-linux-amd64.tar.gz" \
    | tar -xz -C /usr/local/bin
fi

mkdir -p "${RESULTS_DIR}"
# NB: critest embeds Ginkgo v2, which rejects go-test's `-parallel` ("use -p /
# -procs"). Run serial by default; only parallelize via the Ginkgo flag when
# asked (PARALLEL>1).
args=(-runtime-endpoint "${CRI_SOCKET}" -image-endpoint "${CRI_SOCKET}")
[[ -n "${PARALLEL}" && "${PARALLEL}" != "1" ]] && args+=(-ginkgo.procs "${PARALLEL}")
[[ -n "${FOCUS}" ]] && args+=(-ginkgo.focus "${FOCUS}")
[[ -n "${SKIP}" ]] && args+=(-ginkgo.skip "${SKIP}")
# shellcheck disable=SC2206
[[ -n "${EXTRA_ARGS:-}" ]] && args+=(${EXTRA_ARGS})

log "critest ${args[*]}"
# pipefail (set -o) propagates critest's exit code through tee, so a failing
# suite still fails the script while we keep the full log for triage.
critest "${args[@]}" 2>&1 | tee "${RESULTS_DIR}/critest.log"
