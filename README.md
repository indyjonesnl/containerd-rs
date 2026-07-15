# containerd-rs

[![conformance-sig-node](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-node.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-node.yml)
[![conformance-sig-api-machinery](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-api-machinery.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-api-machinery.yml)
[![conformance-sig-storage](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-storage.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-storage.yml)
[![conformance-sig-apps](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-apps.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-apps.yml)
[![conformance-sig-network](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-network.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-network.yml)
[![conformance-sig-cli](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-cli.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-cli.yml)
[![conformance-sig-scheduling](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-scheduling.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-scheduling.yml)
[![conformance-sig-auth](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-auth.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-auth.yml)
[![conformance-sig-instrumentation](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-instrumentation.yml/badge.svg)](https://github.com/indyjonesnl/containerd-rs/actions/workflows/conformance-sig-instrumentation.yml)

A Rust reimplementation of [containerd](https://containerd.io)'s kubelet-facing
surface: a daemon that serves the **Kubernetes CRI v1** API (`RuntimeService` +
`ImageService`) over a Unix socket and runs containers via `crun` (a fast,
runc-compatible OCI runtime). The goal (SC-001) is to be a drop-in replacement
for containerd as the node container runtime and pass the **Kubernetes
Conformance** suite.

Status: a single-node cluster brought up with `kubeadm` runs entirely on
containerd-rs — control plane converges, the node reaches `Ready`, the system
pods (etcd, apiserver, controller-manager, scheduler, kube-proxy, CoreDNS) run,
and `kubectl exec`/`attach`/`port-forward` work over SPDY. A `[Conformance]` test
passes end-to-end; the `[Conformance]` suite runs in CI, split into per-sig
workflows (see below).

## Architecture at a glance

containerd-rs uses a **direct-crun** model: the daemon shells out to `crun` and
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
                                       crun  (one process per container)
```

| Crate | Responsibility |
|-------|----------------|
| `core-types` | Shared types: content digests, OCI descriptors, namespaces |
| `content` | Content-addressable blob store (digest/size verified on commit, dedup) |
| `metadata` | Persistent metadata store backed by [redb](https://www.redb.org) |
| `snapshots` | Overlayfs snapshotter: layer diff apply, OCI whiteouts, chainIDs |
| `images` | Image pull pipeline (oci-client), registry auth, chainID identity, GC; also imports local OCI/docker-save archives (no registry) |
| `runtime` | OCI bundle generation + `crun` supervision (run/exec/kill/stats) |
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
state = "/run/containerd-rs"          # ephemeral state (crun root, OCI bundles)
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

### Importing a local image (no registry)

Load an image built on this node straight into the store:

```sh
containerd-rs import ./myapp.tar --ref myapp:dev
```

Accepts OCI image-layout and `docker save` archives (auto-detected). The daemon
must be running; the CLI talks to it over the root-only admin unix socket
(`/run/containerd-rs/admin.sock` by default, `--socket` to override), and the
daemon reads the archive path directly (single-node). For multi-node clusters,
use a registry — that is how image distribution works in containerd too.

## Bring up a single-node cluster

`ci/kubeadm-init.sh` (via `make cluster-up`) stands up a kubeadm control plane on
containerd-rs as the sole runtime. Requires root + `crun`, `kubeadm`/`kubelet`/
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

In CI the suite is split into manual (`workflow_dispatch`) per-sig workflows,
each building the daemon, installing the Kubernetes toolchain, bringing up the
cluster on a real runner, and running its slice via hydrophone (they share
`conformance-reusable.yml`). The split covers **441** of the `[Conformance]`
specs across nine SIGs (`registry.k8s.io/conformance:v1.35.6`):

| Workflow | Focus | Specs | Asserts |
|----------|-------|------:|---------|
| `conformance-sig-node.yml` | `[sig-node]` | 105 | runtime/CRI on the node: lifecycle, exec/attach, probes, security context, env, sysctls, ephemeral containers |
| `conformance-sig-api-machinery.yml` | `[sig-api-machinery]` | 95 | apiserver contract: CRDs, admission webhooks, watch, namespaces, garbage collection, resource quota, server-side apply |
| `conformance-sig-storage.yml` | `[sig-storage]` | 91 | volume/mount path: emptyDir, configMap/secret/projected/downwardAPI volumes, subpaths |
| `conformance-sig-apps.yml` | `[sig-apps]` | 60 | workload controllers: Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob (rolling updates, scale, ordered bring-up) |
| `conformance-sig-network.yml` | `[sig-network]` | 47 | pod networking, Services/ClusterIP, DNS, hostPort |
| `conformance-sig-cli.yml` | `[sig-cli]` | 17 | kubectl behaviours: create/apply/run/expose/patch/label |
| `conformance-sig-scheduling.yml` | `[sig-scheduling]` | 11 | predicates and basic scheduling: node selectors, taints/tolerations, resource fit |
| `conformance-sig-auth.yml` | `[sig-auth]` | 10 | ServiceAccount tokens, projected SA volumes, related authn/authz |
| `conformance-sig-instrumentation.yml` | `[sig-instrumentation]` | 4 | Events API lifecycle: create/patch/delete/list |

A few `[Conformance]` specs structurally require a **multi-node** cluster (they
fail with "needs a cluster with at least 2 nodes") and so cannot pass on this
single-node setup — `[sig-architecture] … should have at least two untainted
nodes` (no workflow) and `[sig-apps] Daemon set [Serial] should rollback without
unnecessary restarts`. `ci/run-conformance.sh` skips these by default (`SKIP`
regex, overridable); they are environmental, not runtime, limitations.

They run only on demand (conformance is expensive; CI minutes are limited), and
each can be validated locally first with the docker harness, e.g.
`make conformance-docker FOCUS='\[sig-apps\].*\[Conformance\]'`. The status
badges at the top of this README reflect each workflow's latest run.

## Testing

- Unit + contract + integration tests: `make test` (or `cargo test --workspace`).
- Tests that need `crun`/network are `#[ignore]`d; run them with
  `cargo test -p <crate> -- --ignored`.
- CRI contract tests: `crates/cri/tests/contract_*.rs`.
- End-to-end pod lifecycle + image management: `crates/cri/tests/integration_*.rs`.

## License

MIT — see [LICENSE](LICENSE).
