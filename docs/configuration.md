# Configuration reference

containerd-rs reads a single TOML file, by default `/etc/containerd-rs/config.toml`
(override with `--config <path>`). Every field has a default, so an empty file is
valid; the defaults below match a typical node layout.

```toml
# Persistent store root: content blobs, snapshot layers, and the redb metadata db.
root = "/var/lib/containerd-rs"

# Ephemeral state: the runc state root and per-container OCI bundles. Put this on
# a tmpfs (e.g. /run) so it clears on reboot.
state = "/run/containerd-rs"

# Unix socket the kubelet/crictl connect to. Use this as the kubelet's
# --container-runtime-endpoint (prefix with unix://).
cri_socket = "/run/containerd-rs.sock"

# Address of the exec/attach/port-forward streaming HTTP server. The URLs
# returned to the kubelet from Exec/Attach/PortForward point here.
stream_server_address = "127.0.0.1:10010"

[cri]
# Pause image for pod sandboxes (also reported in Status info).
sandbox_image = "registry.k8s.io/pause:3.10"

# Default runtime name / type. The direct-runc model uses runc; these mirror
# containerd's config keys for compatibility.
default_runtime_name = "runc"
runtime_type = "io.containerd.runc.v2"

# Snapshotter. overlayfs is the implemented snapshotter.
snapshotter = "overlayfs"

# Whether the runtime uses the systemd cgroup driver. The default (false) means
# cgroupfs; match this to the kubelet's --cgroup-driver.
systemd_cgroup = false

# Directory of registry host configs (TLS/auth per registry), containerd-style.
registry_config_path = "/etc/containerd-rs/certs.d"

# CNI plugin config dir and binary dir for pod networking.
cni_conf_dir = "/etc/cni/net.d"
cni_bin_dir  = "/opt/cni/bin"
```

## Field summary

### Top level

| Field | Default | Purpose |
|-------|---------|---------|
| `root` | `/var/lib/containerd-rs` | Persistent store (content, snapshots, metadata) |
| `state` | `/run/containerd-rs` | Ephemeral state (runc root, OCI bundles) |
| `cri_socket` | `/run/containerd-rs.sock` | CRI gRPC Unix socket |
| `stream_server_address` | `127.0.0.1:10010` | Streaming server listen address |

### `[cri]`

| Field | Default | Purpose |
|-------|---------|---------|
| `sandbox_image` | `registry.k8s.io/pause:3.10` | Pod sandbox (pause) image |
| `default_runtime_name` | `runc` | Default OCI runtime |
| `runtime_type` | `io.containerd.runc.v2` | Runtime type (compatibility) |
| `snapshotter` | `overlayfs` | Snapshotter implementation |
| `systemd_cgroup` | `false` | Use systemd cgroup driver (else cgroupfs) |
| `registry_config_path` | `/etc/containerd-rs/certs.d` | Per-registry host config dir |
| `cni_conf_dir` | `/etc/cni/net.d` | CNI network config dir |
| `cni_bin_dir` | `/opt/cni/bin` | CNI plugin binary dir |

## Notes

- **cgroup driver must match the kubelet.** On a host without systemd (e.g. the
  CI/Docker harness), use `systemd_cgroup = false` (cgroupfs) and pass
  `cgroupDriver: cgroupfs` to the kubelet.
- **kube-proxy in a nested netns** (e.g. inside a Docker "node") cannot write
  `nf_conntrack_max`; set the kube-proxy ConfigMap `conntrack.maxPerCore: 0` and
  `min: 0`. On a real host node this is unnecessary. `ci/kubeadm-init.sh` applies
  this workaround automatically.
- **Registry credentials** are supplied per-pull via the CRI `PullImageRequest.Auth`
  (kubelet image pull secrets), not in this file.
