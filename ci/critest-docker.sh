#!/usr/bin/env bash
# Run `critest` (CRI conformance) locally inside a privileged container against
# containerd-rs — no host sudo, no kubelet, no CI minutes. Reuses the pinned
# conformance image (crun + CNI + crictl baked in via ci/install-tooling.sh);
# critest itself is fetched at runtime by ci/critest.sh.
#
# Env:
#   IMAGE            conformance image (default containerd-rs-conformance:latest)
#   DAEMON_BIN       host path to the built daemon (default: resolve via cargo)
#   RESULTS_DIR      host output dir (default ./critest-results)
#   FOCUS / SKIP     ginkgo focus/skip regexes (forwarded to critest)
#   PARALLEL         parallel nodes (default 1)
#   CRICTL_VERSION   cri-tools release (default v1.35.0)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-containerd-rs-conformance:latest}"
RESULTS_DIR="${RESULTS_DIR:-${REPO}/critest-results}"
RESULTS_DIR="$(mkdir -p "$RESULTS_DIR" && cd "$RESULTS_DIR" && pwd)"
FOCUS="${FOCUS:-}"
SKIP="${SKIP:-}"
PARALLEL="${PARALLEL:-1}"
CRICTL_VERSION="${CRICTL_VERSION:-v1.35.0}"

if [[ -z "${DAEMON_BIN:-}" ]]; then
  target_dir="$(cd "$REPO" && cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
  DAEMON_BIN="${target_dir}/release/containerd-rs"
fi
[[ -x "$DAEMON_BIN" ]] || { echo "daemon not built at $DAEMON_BIN — run 'make release'" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "image $IMAGE missing — run: docker build -f ci/conformance.Dockerfile -t $IMAGE ." >&2; exit 1; }

# --privileged + private cgroup ns so crun/CNI/netfilter and cgroup-v2 resource
# tests work nested (same setup as ci/conformance-docker.sh). No kubelet/kubeadm.
docker run --rm --privileged \
  --cgroupns=private \
  --tmpfs /run --tmpfs /var/run \
  --tmpfs /var/lib/containerd-rs \
  -v /lib/modules:/lib/modules:ro \
  -v "$REPO":/work:ro \
  -v "$DAEMON_BIN":/usr/local/bin/containerd-rs:ro \
  -v "$RESULTS_DIR":/work/critest-results:rw \
  -e FOCUS="$FOCUS" -e SKIP="$SKIP" -e PARALLEL="$PARALLEL" -e CRICTL_VERSION="$CRICTL_VERSION" \
  "$IMAGE" bash -euxc '
    # cgroup-v2 delegation (kind-style): move our procs into a leaf scope and
    # enable controllers in the root subtree so critest cgroup/resource tests
    # can program limits. Confined to this container scope.
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
      mkdir -p /sys/fs/cgroup/init.scope
      for p in $(cat /sys/fs/cgroup/cgroup.procs); do
        echo "$p" > /sys/fs/cgroup/init.scope/cgroup.procs 2>/dev/null || true
      done
      echo "+cpu +cpuset +memory +pids +hugetlb" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
    fi

    EP=unix:///run/containerd-rs.sock
    mkdir -p /etc/containerd-rs /run/containerd-rs /var/lib/containerd-rs /etc/cni/net.d /run/flannel
    cat > /run/flannel/subnet.env <<EOF
FLANNEL_NETWORK=10.244.0.0/16
FLANNEL_SUBNET=10.244.0.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=true
EOF
    cat > /etc/cni/net.d/10-flannel.conflist <<EOF
{"cniVersion":"1.0.0","name":"cbr0","plugins":[{"type":"flannel","delegate":{"hairpinMode":true,"isDefaultGateway":true}},{"type":"portmap","capabilities":{"portMappings":true}}]}
EOF
    # docker has no systemd, so use the cgroupfs driver (systemd_cgroup=false).
    sed "s/systemd_cgroup = true/systemd_cgroup = false/" /work/ci/config.toml > /etc/containerd-rs/config.toml

    containerd-rs --config /etc/containerd-rs/config.toml >/var/log/crs.log 2>&1 &
    for _ in $(seq 1 50); do [ -S /run/containerd-rs.sock ] && break; sleep 0.2; done
    [ -S /run/containerd-rs.sock ] || { echo "daemon socket never appeared"; tail -80 /var/log/crs.log; exit 1; }

    CRI_SOCKET=$EP RESULTS_DIR=/work/critest-results \
    FOCUS="$FOCUS" SKIP="$SKIP" PARALLEL="$PARALLEL" CRICTL_VERSION="$CRICTL_VERSION" \
      bash /work/ci/critest.sh
  '
echo "[critest-docker] results in $RESULTS_DIR"
