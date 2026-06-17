#!/usr/bin/env bash
# Fast CRI-contract smoke against a running containerd-rs daemon using crictl.
# Run before every push to catch gross breakage cheaply (no cluster needed).
#
# NOTE: depends on the CRI runtime (tasks T015-T038). Encodes the validation
# procedure; syntax-validated now, functional once CRI serving lands.
set -euo pipefail

CRI_SOCKET="${CRI_SOCKET:-unix:///run/containerd-rs.sock}"
PAUSE_IMAGE="${PAUSE_IMAGE:-registry.k8s.io/pause:3.10}"
TEST_IMAGE="${TEST_IMAGE:-docker.io/library/busybox:latest}"
export CONTAINER_RUNTIME_ENDPOINT="${CRI_SOCKET}"
export IMAGE_SERVICE_ENDPOINT="${CRI_SOCKET}"

log() { echo "[crictl-validate] $*"; }

main() {
  command -v crictl >/dev/null 2>&1 || { echo "crictl not found" >&2; exit 1; }

  log "version handshake"
  crictl version

  log "image pull (tag) + status"
  crictl pull "${PAUSE_IMAGE}"
  crictl pull "${TEST_IMAGE}"
  crictl images

  log "sandbox + container lifecycle"
  POD_ID="$(crictl runp ci/fixtures/sandbox.json)"
  CTR_ID="$(crictl create "${POD_ID}" ci/fixtures/container.json ci/fixtures/sandbox.json)"
  crictl start "${CTR_ID}"
  crictl ps
  crictl logs "${CTR_ID}"
  crictl exec "${CTR_ID}" echo ok

  log "teardown"
  crictl stop "${CTR_ID}"
  crictl rm "${CTR_ID}"
  crictl stopp "${POD_ID}"
  crictl rmp "${POD_ID}"

  log "OK"
}

main "$@"
