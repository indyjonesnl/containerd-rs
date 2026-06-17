#!/usr/bin/env bash
# Stand up a single-node Kubernetes cluster on the host using containerd-rs as
# the SOLE container runtime (no Go containerd in the runtime path).
#
# Requires root. Idempotent-ish: re-running after a failed init may need
# `kubeadm reset -f` first (see `make cluster-down`).
#
# NOTE: depends on the CRI runtime (tasks T015-T038). Until containerd-rs serves
# CRI, kubeadm preflight/init will not succeed — this script encodes the target
# procedure and is validated for syntax, not yet for a green conformance run.
set -euo pipefail

K8S_VERSION="${K8S_VERSION:-v1.36.1}"
PAUSE_IMAGE="${PAUSE_IMAGE:-registry.k8s.io/pause:3.10}"
CRI_SOCKET="${CRI_SOCKET:-unix:///run/containerd-rs.sock}"
POD_CIDR="${POD_CIDR:-10.244.0.0/16}"
DAEMON_BIN="${DAEMON_BIN:-./target/release/containerd-rs}"
CONFIG="${CONFIG:-./ci/config.toml}"
FLANNEL_MANIFEST="${FLANNEL_MANIFEST:-https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml}"

log() { echo "[kubeadm-init] $*"; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
  fi
}

prepare_host() {
  log "configuring kernel networking + disabling swap"
  modprobe br_netfilter || true
  modprobe overlay || true
  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.bridge.bridge-nf-call-iptables=1 || true
  swapoff -a || true
}

start_daemon() {
  log "starting containerd-rs on ${CRI_SOCKET}"
  "${DAEMON_BIN}" --config "${CONFIG}" &
  echo $! > /run/containerd-rs.pid
  # Wait for the CRI socket to appear.
  local sock_path="${CRI_SOCKET#unix://}"
  for _ in $(seq 1 30); do
    [[ -S "${sock_path}" ]] && { log "CRI socket ready"; return 0; }
    sleep 1
  done
  echo "CRI socket ${sock_path} did not appear" >&2
  exit 1
}

kubeadm_up() {
  log "kubeadm init (k8s ${K8S_VERSION})"
  kubeadm init \
    --kubernetes-version="${K8S_VERSION}" \
    --cri-socket="${CRI_SOCKET}" \
    --pod-network-cidr="${POD_CIDR}"

  export KUBECONFIG=/etc/kubernetes/admin.conf
  mkdir -p "${HOME}/.kube"
  cp -f /etc/kubernetes/admin.conf "${HOME}/.kube/config"

  log "applying flannel CNI"
  kubectl apply -f "${FLANNEL_MANIFEST}"

  log "untainting control-plane so conformance pods schedule"
  kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true

  log "waiting for node Ready"
  kubectl wait --for=condition=Ready node --all --timeout=300s
}

main() {
  require_root
  prepare_host
  start_daemon
  kubeadm_up
  log "cluster up on containerd-rs"
}

main "$@"
