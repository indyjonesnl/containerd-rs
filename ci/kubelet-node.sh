#!/usr/bin/env bash
# Run a REAL kubelet against containerd-rs and start a host-network pod.
#
# Designed to run INSIDE a privileged container (where we have root) so it can
# stand in for a kind/Docker node without touching the host. Proven working:
# the upstream kubelet pulls the image, creates the sandbox + container, and the
# pod container reaches Running — all driven through the containerd-rs CRI API.
#
# Launch (from the repo root, with a release binary at ./target/release or the
# shared target dir):
#   docker run --rm --privileged \
#     -v <containerd-rs binary>:/usr/local/bin/containerd-rs:ro \
#     -v <kubelet>:/usr/local/bin/kubelet:ro \
#     -v <crictl>:/usr/local/bin/crictl:ro \
#     -v /usr/bin/runc:/hostrunc:ro \
#     -v $PWD/ci/kubelet-node.sh:/node.sh:ro \
#     ubuntu:24.04 bash /node.sh
#
# IMPORTANT: runc must be COPIED to a normal path (not bind-mounted read-only) —
# runc's CVE-2019-5736 memfd self-exec fails to start init from a ro bind mount
# ("fork/exec /proc/self/fd/N: permission denied").
set -u
EP="unix:///run/containerd-rs.sock"
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq ca-certificates >/dev/null 2>&1
cp /hostrunc /usr/local/bin/runc && chmod +x /usr/local/bin/runc

mkdir -p /etc/containerd-rs /run /var/lib/containerd-rs /etc/kubernetes/manifests /var/lib/kubelet
cat > /etc/containerd-rs/config.toml <<EOF
root = "/var/lib/containerd-rs"
state = "/run/containerd-rs"
cri_socket = "/run/containerd-rs.sock"
stream_server_address = "127.0.0.1:10010"
EOF

RUST_LOG=info containerd-rs --config /etc/containerd-rs/config.toml >/var/log/crs.log 2>&1 &
for _ in $(seq 1 50); do [ -S /run/containerd-rs.sock ] && break; sleep 0.2; done

cat > /etc/kubernetes/manifests/smoke.yaml <<EOF
apiVersion: v1
kind: Pod
metadata: { name: smoke, namespace: default }
spec:
  hostNetwork: true
  containers:
  - name: c
    image: docker.io/library/busybox:latest
    command: ["/bin/sh","-c","echo KUBELET_RAN_ME; sleep 3600"]
EOF

kubelet \
  --container-runtime-endpoint="$EP" --image-service-endpoint="$EP" \
  --pod-manifest-path=/etc/kubernetes/manifests \
  --fail-swap-on=false --cgroup-driver=cgroupfs \
  --cgroups-per-qos=false --enforce-node-allocatable="" \
  --hostname-override=crs-node --address=127.0.0.1 --read-only-port=0 \
  --anonymous-auth=true --authorization-mode=AlwaysAllow --v=2 \
  >/var/log/kubelet.log 2>&1 &

C(){ crictl --runtime-endpoint "$EP" --image-endpoint "$EP" "$@"; }
for i in $(seq 1 60); do
  sleep 2
  [ "$(C ps 2>/dev/null | grep -c ' Running ')" -ge 1 ] && {
    echo "[OK] pod container Running via kubelet after ~$((i*2))s"; break; }
done
C pods | head -3
C ps | head -3
