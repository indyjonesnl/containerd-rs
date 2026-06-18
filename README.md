# containerd-rs

[![conformance-sig-node](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-node.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-node.yml)
[![conformance-sig-storage](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-storage.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-storage.yml)
[![conformance-sig-network](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-network.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-network.yml)

A Rust reimplementation of [containerd](https://containerd.io)'s kubelet-facing
surface: a daemon that serves the **Kubernetes CRI v1** API (`RuntimeService` +
`ImageService`) over a Unix socket and runs containers via `runc`. The goal
(SC-001) is to be a drop-in replacement for containerd as the node container
runtime and pass the **Kubernetes Conformance** suite.

Status: a single-node cluster brought up with `kubeadm` runs entirely on
containerd-rs — control plane converges, the node reaches `Ready`, the system
pods (etcd, apiserver, controller-manager, scheduler, kube-proxy, CoreDNS) run,
and `kubectl exec`/`attach`/`port-forward` work over SPDY. A `[Conformance]` test
passes end-to-end; the `[Conformance]` suite runs in CI, split into per-sig
workflows (see below).

## Architecture at a glance

containerd-rs uses a **direct-runc** model: the daemon shells out to `runc` and
supervises the container process in-process (no TTRPC shim). The CRI plugin,
content store, snapshotter, and image puller are all built in.

```
kubelet ──CRI v1 gRPC (unix socket)──▶ containerd-rs daemon
                                        │
   Exec/Attach/PortForward ── URL ─────▶ streaming server (SPDY/3.1 + WS)
                                        │
   images ──▶ content store (verify-on-commit) + overlayfs snapshots
   metadata ──▶ redb                    │
   pods ──▶ CNI (Flannel) / host-net    ▼
                                       runc  (one process per container)
```

| Crate | Responsibility |
|-------|----------------|
| `core-types` | Shared types: content digests, OCI descriptors, namespaces |
| `content` | Content-addressable blob store (digest/size verified on commit, dedup) |
| `metadata` | Persistent metadata store backed by [redb](https://www.redb.org) |
| `snapshots` | Overlayfs snapshotter: layer diff apply, OCI whiteouts, chainIDs |
| `images` | Image pull pipeline (oci-client), registry auth, chainID identity, GC |
| `runtime` | OCI bundle generation + `runc` supervision (run/exec/kill/stats) |
| `sandbox` | Pod sandbox model: network namespace + CNI plugin chain |
| `cri` | CRI v1 gRPC server + the exec/attach/port-forward streaming server |
| `containerd-rs` | The daemon binary (config, store bring-up, serve, reconcile) |

See [`docs/architecture.md`](docs/architecture.md) for the request flow and design
notes, and [`docs/configuration.md`](docs/configuration.md) for the full config
reference.

## Build

```sh
make build          # debug build of the workspace
make release        # release build (produces target/release/containerd-rs)
make check          # fmt-check + clippy (-D warnings) + tests — the local gate
```

`make check` mirrors CI exactly; run it before pushing.

## Run the daemon

```sh
sudo containerd-rs --config /etc/containerd-rs/config.toml
```

A minimal config (all fields have defaults — see the config reference):

```toml
root  = "/var/lib/containerd-rs"      # persistent store (content, snapshots, metadata)
state = "/run/containerd-rs"          # ephemeral state (runc root, OCI bundles)
cri_socket = "/run/containerd-rs.sock"
stream_server_address = "127.0.0.1:10010"

[cri]
sandbox_image = "registry.k8s.io/pause:3.10"
snapshotter   = "overlayfs"
cni_conf_dir  = "/etc/cni/net.d"
cni_bin_dir   = "/opt/cni/bin"
```

Point the kubelet at it with `--container-runtime-endpoint=unix:///run/containerd-rs.sock`.

Smoke-test with `crictl`:

```sh
crictl --runtime-endpoint unix:///run/containerd-rs.sock version
crictl --runtime-endpoint unix:///run/containerd-rs.sock images
```

## Bring up a single-node cluster

`ci/kubeadm-init.sh` (via `make cluster-up`) stands up a kubeadm control plane on
containerd-rs as the sole runtime. Requires root + `runc`, `kubeadm`/`kubelet`/
`kubectl`, `crictl`, and CNI plugins on the host.

```sh
make release
make cluster-up     # phase-by-phase kubeadm + manual kubelet; waits for Ready + 7/7 pods
make cluster-down   # kubeadm reset + stop kubelet/daemon
```

## Conformance (SC-001)

The Kubernetes `[Conformance]` suite is the acceptance gate. It runs via
[hydrophone](https://github.com/kubernetes-sigs/hydrophone):

```sh
make conformance-smoke   # one Conformance test (fast pipeline check)
make conformance         # full [Conformance] suite -> conformance-results/
```

In CI the suite is split into three manual (`workflow_dispatch`) per-sig
workflows, each building the daemon, installing the Kubernetes toolchain,
bringing up the cluster on a real runner, and running its slice via hydrophone
(they share `conformance-reusable.yml`):

| Workflow | Focus | Asserts |
|----------|-------|---------|
| `conformance-sig-node.yml` | `[sig-node]` | runtime/CRI on the node: lifecycle, exec/attach, probes, security context, env, sysctls, ephemeral containers |
| `conformance-sig-storage.yml` | `[sig-storage]` | volume/mount path: emptyDir, configMap/secret/projected/downwardAPI volumes, subpaths |
| `conformance-sig-network.yml` | `[sig-network]` | pod networking, Services/ClusterIP, DNS, hostPort |

They run only on demand (conformance is expensive; CI minutes are limited). The
status badges at the top of this README reflect each workflow's latest run.

## Testing

- Unit + contract + integration tests: `make test` (or `cargo test --workspace`).
- Tests that need `runc`/network are `#[ignore]`d; run them with
  `cargo test -p <crate> -- --ignored`.
- CRI contract tests: `crates/cri/tests/contract_*.rs`.
- End-to-end pod lifecycle + image management: `crates/cri/tests/integration_*.rs`.

## License

MIT — see [LICENSE](LICENSE).
