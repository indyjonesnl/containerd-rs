#!/usr/bin/env bash
# Verify CNI pod networking with Flannel: two pod-network sandboxes each get an
# isolated IP from the Flannel subnet and can reach each other over the bridge.
#
# Run INSIDE a privileged container (root) with the CNI plugins mounted at
# /opt/cni/bin (reference plugins + the flannel plugin). Proven working: pods get
# 10.244.0.x IPs in their own netns and ping succeeds pod-to-pod.
#
#   docker run --rm --privileged \
#     -v <containerd-rs>:/usr/local/bin/containerd-rs:ro \
#     -v <crictl>:/usr/local/bin/crictl:ro \
#     -v /usr/bin/crun:/hostcrun:ro \
#     -v <cni-plugins-dir>:/opt/cni/bin:ro \
#     -v $PWD/ci/cni-node.sh:/cni.sh:ro \
#     ubuntu:24.04 bash /cni.sh
#
# A single-node Flannel setup needs no flanneld/etcd: the flannel CNI plugin
# reads a static /run/flannel/subnet.env and delegates to the bridge plugin.
set -u
EP="unix:///run/containerd-rs.sock"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq ca-certificates iproute2 iptables iputils-ping >/dev/null 2>&1
cp /hostcrun /usr/local/bin/crun && chmod +x /usr/local/bin/crun

mkdir -p /etc/containerd-rs /run/containerd-rs /var/lib/containerd-rs /etc/cni/net.d /run/flannel
cat > /run/flannel/subnet.env <<EOF
FLANNEL_NETWORK=10.244.0.0/16
FLANNEL_SUBNET=10.244.0.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=true
EOF
cat > /etc/cni/net.d/10-flannel.conflist <<EOF
{"cniVersion":"1.0.0","name":"cbr0","plugins":[
 {"type":"flannel","delegate":{"hairpinMode":true,"isDefaultGateway":true}},
 {"type":"portmap","capabilities":{"portMappings":true}}]}
EOF
cat > /etc/containerd-rs/config.toml <<EOF
root="/var/lib/containerd-rs"
state="/run/containerd-rs"
cri_socket="/run/containerd-rs.sock"
stream_server_address="127.0.0.1:10010"
EOF

containerd-rs --config /etc/containerd-rs/config.toml >/var/log/crs.log 2>&1 &
for _ in $(seq 1 50); do [ -S /run/containerd-rs.sock ] && break; sleep 0.2; done
C(){ crictl --runtime-endpoint "$EP" --image-endpoint "$EP" "$@"; }

# pod-network sandbox (namespaceOptions.network = 0 = POD)
mksb(){ printf '{"metadata":{"name":"%s","uid":"%s","namespace":"default","attempt":1},"linux":{"securityContext":{"namespaceOptions":{"network":0}}}}' "$1" "$1" > /tmp/$1.json; }
mksb a; mksb b
PODA=$(C runp /tmp/a.json); PODB=$(C runp /tmp/b.json)
IPA=$(C inspectp "$PODA" | grep -oE '"ip": "[0-9.]+"' | head -1 | grep -oE '[0-9.]+')
IPB=$(C inspectp "$PODB" | grep -oE '"ip": "[0-9.]+"' | head -1 | grep -oE '[0-9.]+')
echo "pod A IP=$IPA   pod B IP=$IPB"
ip netns exec "$PODA" ping -c2 -W2 "$IPB"
