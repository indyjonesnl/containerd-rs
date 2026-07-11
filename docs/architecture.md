# Architecture

containerd-rs replaces containerd as the node container runtime behind the
kubelet. It implements the **CRI v1** contract (`RuntimeService` +
`ImageService`) and everything beneath it — image pull, content storage,
snapshots, container execution, pod networking, and streaming — in one daemon.

## Direct-crun model

Upstream containerd launches a per-pod `containerd-shim-crun-v2` and talks to it
over TTRPC. containerd-rs instead **shells out to `crun` directly** and
supervises the container process inside the daemon (`crates/runtime`):

- `CreateContainer` writes an OCI bundle (merged rootfs + generated
  `config.json`).
- `StartContainer` spawns `crun run` with piped stdio; a supervision task pumps
  stdout/stderr to the container log file and a live broadcast bus, and records
  the exit code.
- `ExecSync`/`Exec` shell out to `crun exec`; `StopContainer`/`RemoveContainer`
  use `crun kill`/`crun delete`.

This trades the shim's out-of-process isolation for simplicity. The TTRPC shim
client (tasks T015/T016) is therefore not implemented.

## CRI surface (`crates/cri`)

The daemon serves CRI v1 gRPC over a Unix socket (tonic + a vendored
`runtime/v1/api.proto`). `RuntimeService` covers sandbox and container lifecycle,
status, stats, logs, and `UpdateRuntimeConfig`/`Status`/`RuntimeConfig`.
`ImageService` covers pull/list/status/remove/fs-info.

Objects live in the `k8s.io` runtime namespace. State enums are reported exactly
(`PodSandboxState{READY,NOTREADY}`, `ContainerState{CREATED,RUNNING,EXITED,
UNKNOWN}`) with accurate exit codes and timestamps — the kubelet's
`podSandboxChanged` logic depends on this, including the sandbox network-namespace
mode in `PodSandboxStatus.linux` (NODE for host-network pods).

## Streaming: exec / attach / port-forward

`Exec`/`Attach`/`PortForward` return a one-time **URL** into a separate streaming
HTTP server (axum), not inline gRPC streams. The kubelet upgrades that connection
using **SPDY/3.1** — the kubelet↔runtime leg stays on SPDY permanently
(Kubernetes KEP-4006 only moved kubectl↔apiserver↔kubelet to WebSockets). So
`crates/cri/src/spdy.rs` implements the SPDY/3 subset the kubelet's
`moby/spdystream` client uses: the HTTP/1.1 upgrade, frame codec, the zlib NV
header (de)compressor with the fixed SPDY dictionary, and a stream multiplexer
mapping the remotecommand `streamType` streams (stdin/stdout/stderr/error/resize)
to a streaming `crun exec`. WebSocket (`v4.channel.k8s.io`) handlers remain as a
fallback for clients (e.g. crictl) that connect that way.

## Content store (`crates/content`)

A content-addressable blob store mirroring containerd's `blobs/sha256/<hex>`
layout with an `ingest/` staging area. The critical invariant: a blob's digest
and size are verified at **commit** time, then moved into place with an atomic
rename. A partial/interrupted write is never committed (so the store can't be
corrupted and a pull is always retryable), staging files are unique per writer
and cleaned up on drop, and committing an already-present digest is a successful
no-op (dedup).

## Snapshots (`crates/snapshots`)

Layer diffs are applied onto per-layer directories keyed by **chainID**
(`crates/images/identity.rs`, matching the OCI image-spec algorithm so snapshot
keys interoperate with containerd). Diff application (`diff.rs`) decompresses the
layer (gzip/zstd/none), extracts the tar, and honors OCI whiteouts (`.wh.<name>`
removes a sibling; `.wh..wh..opq` clears a directory) — with a guard so a
malicious whiteout path can't escape the rootfs. The merged rootfs for a
container is an overlay of its layers' chainID directories.

## Images (`crates/images`)

The pull pipeline uses `oci-client`: resolve the reference, select the
node-platform manifest, fetch the config + layers into the content store, assert
each layer's diffID against the config, compute chainIDs, and unpack. Registry
credentials come from the CRI `AuthConfig` (bearer identity/registry tokens,
username/password, or base64 `auth`); oci-client performs the docker bearer-token
handshake. Concurrent duplicate pulls of the same reference are serialized.
`RemoveImage` reclaims unreferenced blobs and snapshots (`gc.rs`).

## Pod networking (`crates/sandbox`)

`RunPodSandbox` either shares the host network namespace (NODE network mode) or
creates a network namespace and runs the CNI plugin chain (Flannel, via a static
`/run/flannel/subnet.env` bridge) to assign the pod IP. Containers in the sandbox
join its netns. The pod's `/etc/resolv.conf` is generated from the CRI DNS config
and bind-mounted in.

## Persistence + restart (`crates/metadata`, daemon)

Sandbox/container/image records are stored in [redb](https://www.redb.org). On
startup the daemon reconciles persisted state (containers whose processes are
gone are marked appropriately) so a restart doesn't leave orphans or duplicates.

## Request flow: `kubectl run` → running container

1. kubelet `PullImage` → resolve, fetch config + layers into the content store,
   verify diffIDs, unpack each layer into its chainID snapshot dir.
2. `RunPodSandbox` → set up the netns (CNI or host), generate `resolv.conf`,
   record the sandbox `READY`.
3. `CreateContainer` → overlay the image's chainID dirs into a rootfs, generate
   the OCI `config.json` (honoring `privileged`, `run_as_user`, mounts, env),
   write the bundle, record `CREATED`.
4. `StartContainer` → `crun run`, supervise stdio → log file + live bus, record
   `RUNNING`; on exit record `EXITED` with the code.
5. `Exec`/`Attach`/`PortForward` → mint a streaming URL; the kubelet connects over
   SPDY and is wired to a live `crun exec` / the container's output bus / a
   localhost TCP proxy.

## Conformance & equivalence

Two independent gates:

- **Kubernetes `[Conformance]`** (via hydrophone) — the end-to-end acceptance
  gate (SC-001), split into nine per-sig CI workflows (see the README).
- **critest** (`kubernetes-sigs/cri-tools`) — the CRI-conformance suite upstream
  containerd/CRI-O gate on. It drives the CRI contract directly (no kubelet), so
  it pins the runtime surface. **Equivalence with containerd is defined as
  critest green minus a ratified, documented skip list** — currently 85 Passed /
  0 Failed / 28 Skipped, i.e. every runnable spec passes. `ci/critest.sh` owns
  the skip regex with an inline rationale for each entry; `make critest-docker`
  runs the whole thing in a self-contained privileged container (no CI minutes).

Notable runtime-surface behaviours the critest burn-down pinned down:

- **Seccomp `RuntimeDefault`** — emits the real upstream (moby/containerd)
  default profile, resolved per-container against its effective capabilities and
  host arch (mirrors Docker/containerd `setupSeccomp`); see `crates/runtime/src/seccomp.rs`.
  Never a hand-rolled allowlist.
- **Attach over SPDY** — `StdinOnce` closes the container's stdin on stdin-stream
  close (EOF to the process), matching containerd's `ContainerIO.Attach`, so a
  client that waits for the streams to close doesn't hang.
- **AppArmor `RuntimeDefault`** — host-guarded like containerd (`HostSupports()`):
  a no-op where AppArmor is unsupported (e.g. in-container, or a kernel without
  the LSM). The critest AppArmor specs are therefore an environmental skip, not a
  runtime gap.
