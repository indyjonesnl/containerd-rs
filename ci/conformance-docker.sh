#!/usr/bin/env bash
# Run a conformance focus locally inside a privileged container, mirroring CI
# (same ci/ scripts, same pinned tooling via the conformance image, crun).
# No host sudo, no host runc changes, no CI minutes.
#
# Env:
#   FOCUS            ginkgo --focus regex (empty = full [Conformance] suite)
#   K8S_VERSION      kubernetes version (default v1.35.6)
#   CGROUPS_PER_QOS  default false — a nested container cannot create /kubepods
#   RESULTS_DIR      host output dir (default ./conformance-results)
#   IMAGE            conformance image tag (default containerd-rs-conformance:latest)
#   DAEMON_BIN       host path to the built daemon (default: resolve via cargo)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-containerd-rs-conformance:latest}"
K8S_VERSION="${K8S_VERSION:-v1.35.6}"
CGROUPS_PER_QOS="${CGROUPS_PER_QOS:-false}"
FOCUS="${FOCUS:-}"
RESULTS_DIR="${RESULTS_DIR:-${REPO}/conformance-results}"
# Make RESULTS_DIR absolute so docker -v works regardless of CWD.
RESULTS_DIR="$(mkdir -p "$RESULTS_DIR" && cd "$RESULTS_DIR" && pwd)"

# Resolve the daemon binary, honouring CARGO_TARGET_DIR.
if [[ -z "${DAEMON_BIN:-}" ]]; then
  target_dir="$(cd "$REPO" && cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
  DAEMON_BIN="${target_dir}/release/containerd-rs"
fi
[[ -x "$DAEMON_BIN" ]] || { echo "daemon not built at $DAEMON_BIN — run 'make release'" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "image $IMAGE missing — run: docker build -f ci/conformance.Dockerfile -t $IMAGE ." >&2; exit 1; }

# --privileged + cgroup2 + modules so kubelet/CNI/netfilter work nested.
# The daemon is mounted to the path kubeadm-init.sh defaults to inside /work.
#
# Nested-docker notes:
#   /var/lib/containerd-rs is a tmpfs so that the overlayfs snapshotter can
#   create overlay mounts on it — the container root is itself overlayfs, and
#   the kernel does not allow overlay-on-overlay without tmpfs as the backing
#   store.  The CI config uses systemd_cgroup=true (real host); inside docker
#   there is no systemd, so we generate a docker-local config with
#   systemd_cgroup=false before invoking kubeadm-init.sh.
docker run --rm --privileged \
  --cgroupns host \
  --tmpfs /run --tmpfs /var/run \
  --tmpfs /var/lib/containerd-rs \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v /lib/modules:/lib/modules:ro \
  -v "$REPO":/work:ro \
  -v "$DAEMON_BIN":/work/target/release/containerd-rs:ro \
  -v "$RESULTS_DIR":/work/conformance-results:rw \
  -e K8S_VERSION="$K8S_VERSION" \
  -e CGROUPS_PER_QOS="$CGROUPS_PER_QOS" \
  -e FOCUS="$FOCUS" \
  "$IMAGE" bash -euxc '
    # Generate a docker-local config: identical to /work/ci/config.toml except
    # systemd_cgroup=false (no systemd inside docker).  The overlayfs snapshotter
    # works because /var/lib/containerd-rs is mounted as tmpfs (see --tmpfs above).
    DOCKER_CONFIG=/tmp/config-docker.toml
    sed "s/systemd_cgroup = true/systemd_cgroup = false/" /work/ci/config.toml > "$DOCKER_CONFIG"
    grep -q "systemd_cgroup = false" "$DOCKER_CONFIG" || { echo "error: failed to disable systemd_cgroup in $DOCKER_CONFIG — check ci/config.toml formatting" >&2; exit 1; }

    DAEMON_BIN=/work/target/release/containerd-rs CONFIG="$DOCKER_CONFIG" \
    CRI_SOCKET=unix:///run/containerd-rs.sock CGROUPS_PER_QOS="$CGROUPS_PER_QOS" \
    K8S_VERSION="$K8S_VERSION" \
      bash /work/ci/kubeadm-init.sh
    chmod 0644 /etc/kubernetes/admin.conf
    KUBECONFIG=/etc/kubernetes/admin.conf FOCUS="$FOCUS" \
    RESULTS_DIR=/work/conformance-results \
    CONFORMANCE_IMAGE=registry.k8s.io/conformance:'"$K8S_VERSION"' \
      bash /work/ci/run-conformance.sh
  '
echo "[conformance-docker] results in $RESULTS_DIR"
