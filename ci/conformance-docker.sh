#!/usr/bin/env bash
# Run a conformance focus locally inside a privileged container, mirroring CI
# (same ci/ scripts, same pinned tooling via the conformance image, crun).
# No host sudo, no host runc changes, no CI minutes.
#
# Env:
#   FOCUS            ginkgo --focus regex (empty = full [Conformance] suite)
#   K8S_VERSION      kubernetes version (default v1.35.6)
#   CGROUPS_PER_QOS  default true — matches CI. Works nested because we launch
#                    the container with its own delegated cgroup-v2 scope (see
#                    --cgroupns=private + the delegation step below).
#   RESULTS_DIR      host output dir (default ./conformance-results)
#   IMAGE            conformance image tag (default containerd-rs-conformance:latest)
#   DAEMON_BIN       host path to the built daemon (default: resolve via cargo)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-containerd-rs-conformance:latest}"
K8S_VERSION="${K8S_VERSION:-v1.35.6}"
CGROUPS_PER_QOS="${CGROUPS_PER_QOS:-true}"
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

# --privileged + modules so kubelet/CNI/netfilter work nested.
# The daemon is mounted to the path kubeadm-init.sh defaults to inside /work.
#
# Nested-docker notes:
#   - --cgroupns=private (and NO host /sys/fs/cgroup bind mount): docker's
#     systemd cgroup driver gives the container its own delegated cgroup-v2
#     scope, mounted rw as the container's cgroup root. This is the kind-style
#     setup that lets the kubelet create /kubepods with CPU/memory controllers,
#     so CGROUPS_PER_QOS=true works exactly as on CI. All cgroup mutation is
#     confined to the container's scope and is reaped when --rm tears it down —
#     no host cgroup pollution (unlike a host /sys/fs/cgroup bind mount).
#   - /var/lib/containerd-rs is a tmpfs so the overlayfs snapshotter can create
#     overlay mounts on it — the container root is itself overlayfs and the
#     kernel does not allow overlay-on-overlay without tmpfs as the backing
#     store.
#   - The CI config uses systemd_cgroup=true (real host); inside docker there is
#     no systemd, so we generate a docker-local config with systemd_cgroup=false
#     (cgroupfs driver, matching the kubelet's cgroupDriver=cgroupfs) before
#     invoking kubeadm-init.sh.
docker run --rm --privileged \
  --cgroupns=private \
  --tmpfs /run --tmpfs /var/run \
  --tmpfs /var/lib/containerd-rs \
  -v /lib/modules:/lib/modules:ro \
  -v "$REPO":/work:ro \
  -v "$DAEMON_BIN":/work/target/release/containerd-rs:ro \
  -v "$RESULTS_DIR":/work/conformance-results:rw \
  -e K8S_VERSION="$K8S_VERSION" \
  -e CGROUPS_PER_QOS="$CGROUPS_PER_QOS" \
  -e FOCUS="$FOCUS" \
  "$IMAGE" bash -euxc '
    # cgroup-v2 delegation (kind-style): the container owns its cgroup scope as
    # root (--cgroupns=private). Move our own processes into a leaf "init" scope
    # so the scope root has no member processes, then enable controllers in the
    # root subtree_control. This satisfies the cgroup-v2 "no internal processes"
    # rule and lets the kubelet create /kubepods (+ QoS children) with the cpu
    # and memory controllers — i.e. CGROUPS_PER_QOS=true works nested, the same
    # path CI exercises. Confined to the container scope; nothing touches the host.
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
      mkdir -p /sys/fs/cgroup/init.scope
      for p in $(cat /sys/fs/cgroup/cgroup.procs); do
        echo "$p" > /sys/fs/cgroup/init.scope/cgroup.procs 2>/dev/null || true
      done
      echo "+cpu +cpuset +memory +pids +hugetlb" > /sys/fs/cgroup/cgroup.subtree_control
    fi

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
