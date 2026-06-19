#!/usr/bin/env bash
# Stand up a single-node Kubernetes cluster on the host using containerd-rs as
# the SOLE container runtime (no Go containerd in the runtime path), then wait
# until the node is Ready and all system pods (etcd, apiserver, controller-manager,
# scheduler, kube-proxy, CoreDNS) are Running. Exits non-zero on any failure so
# `make cluster-up` / CI gates on a healthy cluster.
#
# kubeadm is driven phase-by-phase with a manually-started kubelet (no systemd
# dependency), which is what the local Docker harness and the GitHub runner both
# use. Requires root. Re-running after a failed init may need `kubeadm reset -f`
# (see `make cluster-down`).
#
# Env overrides:
#   DAEMON_BIN   containerd-rs binary (default ./target/release/containerd-rs)
#   CONFIG       daemon config.toml (default ./ci/config.toml)
#   CRI_SOCKET   CRI endpoint (default unix:///run/containerd-rs.sock)
#   K8S_VERSION  kubernetes version (default v1.31.1)
#   POD_CIDR     pod network CIDR (default 10.244.0.0/16)
#   NODE_NAME    node name (default crs-node)
#   RUNC_SRC     if set, copy this runc binary to /usr/local/bin/runc (Docker harness)
set -euo pipefail

K8S_VERSION="${K8S_VERSION:-v1.31.1}"
CRI_SOCKET="${CRI_SOCKET:-unix:///run/containerd-rs.sock}"
POD_CIDR="${POD_CIDR:-10.244.0.0/16}"
NODE_NAME="${NODE_NAME:-crs-node}"
DAEMON_BIN="${DAEMON_BIN:-./target/release/containerd-rs}"
CONFIG="${CONFIG:-./ci/config.toml}"
KC="kubectl --kubeconfig=/etc/kubernetes/admin.conf"

log() { echo "[kubeadm-init] $*"; }
fail() { echo "[kubeadm-init] FAIL: $*" >&2; exit 1; }

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "must run as root"
}

prepare_host() {
  log "kernel networking + swap + CNI (flannel, static subnet)"
  # Ensure runtime deps on a minimal host (no-op where already present, e.g. CI).
  if command -v apt-get >/dev/null 2>&1 && ! command -v conntrack >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y -qq ca-certificates iproute2 iptables ethtool socat conntrack kmod procps iputils-ping >/dev/null 2>&1 || true
  fi
  if [[ -n "${RUNC_SRC:-}" && -f "${RUNC_SRC}" ]]; then
    cp "${RUNC_SRC}" /usr/local/bin/runc && chmod +x /usr/local/bin/runc
  fi
  modprobe br_netfilter 2>/dev/null || true
  modprobe overlay 2>/dev/null || true
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null 2>&1 || true
  # Required for CNI portmap hostPort DNAT to localhost-bound services: without it
  # the kernel won't route 127.0.0.0/8 to a remote (pod) destination, so hostPort
  # connections fail with "No route to host" (the HostPort conformance test).
  sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true
  swapoff -a 2>/dev/null || true

  mkdir -p /lib/modules /etc/cni/net.d /run/flannel
  cat > /run/flannel/subnet.env <<EOF
FLANNEL_NETWORK=${POD_CIDR}
FLANNEL_SUBNET=10.244.0.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=true
EOF
  cat > /etc/cni/net.d/10-flannel.conflist <<'EOF'
{"cniVersion":"1.0.0","name":"cbr0","plugins":[{"type":"flannel","delegate":{"hairpinMode":true,"isDefaultGateway":true}},{"type":"portmap","capabilities":{"portMappings":true}}]}
EOF
}

start_daemon() {
  log "starting containerd-rs on ${CRI_SOCKET}"
  "${DAEMON_BIN}" --config "${CONFIG}" >/var/log/crs.log 2>&1 &
  echo $! > /run/containerd-rs.pid
  local sock_path="${CRI_SOCKET#unix://}"
  for _ in $(seq 1 50); do
    [[ -S "${sock_path}" ]] && { log "CRI socket ready"; return 0; }
    sleep 0.2
  done
  fail "CRI socket ${sock_path} did not appear (see /var/log/crs.log)"
}

write_kubeadm_config() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}')
  log "kubeadm config (advertise ${ip}, k8s ${K8S_VERSION})"
  cat > /tmp/kubeadm.yaml <<EOF
apiVersion: kubeadm.k8s.io/v1beta3
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: "${ip}"
nodeRegistration:
  criSocket: "${CRI_SOCKET}"
  name: ${NODE_NAME}
  kubeletExtraArgs:
    fail-swap-on: "false"
---
apiVersion: kubeadm.k8s.io/v1beta3
kind: ClusterConfiguration
kubernetesVersion: ${K8S_VERSION}
networking:
  podSubnet: ${POD_CIDR}
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: cgroupfs
failSwapOn: false
cgroupsPerQOS: false
enforceNodeAllocatable: []
imageGCHighThresholdPercent: 100
EOF
}

kubeadm_up() {
  write_kubeadm_config
  log "phases: preflight/certs/kubeconfig/kubelet-start"
  kubeadm init phase preflight --config=/tmp/kubeadm.yaml --ignore-preflight-errors=all 2>&1 | tail -3
  kubeadm init phase certs all --config=/tmp/kubeadm.yaml >/dev/null || fail "certs phase"
  kubeadm init phase kubeconfig all --config=/tmp/kubeadm.yaml >/dev/null || fail "kubeconfig phase"
  kubeadm init phase kubelet-start --config=/tmp/kubeadm.yaml 2>&1 | tail -2

  log "starting kubelet (manual, no systemd)"
  # shellcheck disable=SC1091
  . /var/lib/kubelet/kubeadm-flags.env 2>/dev/null || true
  kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf \
          --kubeconfig=/etc/kubernetes/kubelet.conf \
          --config=/var/lib/kubelet/config.yaml \
          --hostname-override="${NODE_NAME}" \
          --cgroups-per-qos=false --enforce-node-allocatable="" \
          ${KUBELET_KUBEADM_ARGS:-} >/var/log/kubelet.log 2>&1 &
  echo $! > /run/kubelet.pid
  sleep 3

  log "control-plane + etcd static pods"
  kubeadm init phase control-plane all --config=/tmp/kubeadm.yaml 2>&1 | tail -2
  kubeadm init phase etcd local --config=/tmp/kubeadm.yaml 2>&1 | tail -1

  log "waiting for control-plane containers (via CRI)"
  local ok=0 sock="${CRI_SOCKET}"
  for i in $(seq 1 90); do
    if [[ "$(crictl --runtime-endpoint "${sock}" ps 2>/dev/null | grep -cE 'kube-apiserver|etcd')" -ge 2 ]]; then
      log "control-plane up after ~$((i*2))s"; ok=1; break
    fi
    sleep 2
  done
  [[ "${ok}" == 1 ]] || fail "control-plane containers did not start"

  kubeadm init phase upload-config all --config=/tmp/kubeadm.yaml 2>&1 | tail -1
  kubeadm init phase mark-control-plane --config=/tmp/kubeadm.yaml >/dev/null 2>&1 || true
  kubeadm init phase bootstrap-token --config=/tmp/kubeadm.yaml >/dev/null 2>&1 || true
  kubeadm init phase addon all --config=/tmp/kubeadm.yaml 2>&1 | tail -1 || true

  export KUBECONFIG=/etc/kubernetes/admin.conf
  mkdir -p "${HOME}/.kube"
  cp -f /etc/kubernetes/admin.conf "${HOME}/.kube/config"
}

tune_kube_proxy() {
  # kube-proxy writes /proc/sys/net/netfilter/nf_conntrack_max, which is EACCES
  # from a nested network namespace (the Docker test node). Setting conntrack
  # maxPerCore and min to 0 skips that write. Harmless on a real host node.
  log "kube-proxy: disable conntrack-max management"
  ${KC} -n kube-system get cm kube-proxy -o jsonpath='{.data.config\.conf}' > /tmp/config.conf 2>/dev/null || return 0
  [[ -s /tmp/config.conf ]] || return 0
  ${KC} -n kube-system get cm kube-proxy -o jsonpath='{.data.kubeconfig\.conf}' > /tmp/kubeconfig.conf 2>/dev/null || true
  sed -i -E 's/maxPerCore: (null|[0-9]+)/maxPerCore: 0/; s/min: (null|[0-9]+)/min: 0/' /tmp/config.conf
  ${KC} -n kube-system create cm kube-proxy \
      --from-file=config.conf=/tmp/config.conf \
      --from-file=kubeconfig.conf=/tmp/kubeconfig.conf \
      --dry-run=client -o yaml | ${KC} -n kube-system apply -f - >/dev/null 2>&1 || true
  ${KC} -n kube-system delete pod -l k8s-app=kube-proxy --grace-period=0 --force >/dev/null 2>&1 || true
}

wait_ready() {
  log "untainting control-plane so workloads schedule"
  ${KC} taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true

  log "waiting for node Ready"
  local ok=0
  for i in $(seq 1 90); do
    [[ "$(${KC} get node "${NODE_NAME}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" == "True" ]] \
      && { log "node Ready after ~$((i*2))s"; ok=1; break; }
    sleep 2
  done
  [[ "${ok}" == 1 ]] || { ${KC} get nodes -o wide; fail "node never became Ready"; }

  log "waiting for all system pods Running"
  ok=0; local total run
  for _ in $(seq 1 100); do
    total=$(${KC} get pods -A --no-headers 2>/dev/null | wc -l)
    run=$(${KC} get pods -A --no-headers 2>/dev/null | grep -c " Running " || true)
    [[ "${total:-0}" -ge 7 && "${run:-0}" -ge "${total:-99}" ]] && { ok=1; break; }
    sleep 3
  done
  ${KC} get pods -A -o wide
  ${KC} get nodes -o wide
  [[ "${ok}" == 1 ]] || fail "not all system pods reached Running"
  log "SUCCESS: ${NODE_NAME} Ready, ${run}/${total} pods Running on containerd-rs"
}

main() {
  require_root
  prepare_host
  start_daemon
  kubeadm_up
  tune_kube_proxy
  wait_ready
}

main "$@"
