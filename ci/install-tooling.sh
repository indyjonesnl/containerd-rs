#!/usr/bin/env bash
# Install the conformance toolchain into /usr/local/bin + /opt/cni/bin.
# Single source of truth shared by the GitHub conformance workflow
# (.github/workflows/conformance-reusable.yml) and the local docker harness
# (ci/conformance.Dockerfile) so the two never drift. Run as root.
# Versions come from env with the workflow defaults.
set -euxo pipefail

K8S_VERSION="${K8S_VERSION:-v1.35.6}"
CRUN_VERSION="${CRUN_VERSION:-1.28}"
CRICTL_VERSION="${CRICTL_VERSION:-v1.35.0}"
CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.5.1}"

cd /usr/local/bin
for b in kubeadm kubelet kubectl; do
  curl -fsSLo "$b" "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/$b"
  chmod +x "$b"
done
curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz" \
  | tar -xz -C /usr/local/bin
# crun is a drop-in OCI runtime (CLI-compatible with runc) but faster and
# lighter. The daemon execs "runc" from PATH, so install crun under both names.
curl -fsSLo /usr/local/bin/crun \
  "https://github.com/containers/crun/releases/download/${CRUN_VERSION}/crun-${CRUN_VERSION}-linux-amd64"
chmod +x /usr/local/bin/crun
ln -sf /usr/local/bin/crun /usr/local/bin/runc
mkdir -p /opt/cni/bin
curl -fsSL "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz" \
  | tar -xz -C /opt/cni/bin
curl -fsSL "https://github.com/flannel-io/cni-plugin/releases/download/v1.5.1-flannel2/cni-plugin-flannel-linux-amd64-v1.5.1-flannel2.tgz" \
  | tar -xz -C /opt/cni/bin
test -f /opt/cni/bin/flannel || cp /opt/cni/bin/flannel-amd64 /opt/cni/bin/flannel || true
go install sigs.k8s.io/hydrophone@latest
cp "$(go env GOPATH)/bin/hydrophone" /usr/local/bin/hydrophone
