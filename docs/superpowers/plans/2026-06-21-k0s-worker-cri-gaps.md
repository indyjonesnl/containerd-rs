# Plan — containerd-rs v0.1.1: k0s-worker CRI gaps

**Date:** 2026-06-21
**Spec:** `docs/superpowers/specs/2026-06-21-k0s-worker-cri-gaps-design.md` (Approved)
**Branch / worktree:** `fix/k0s-worker-cri-gaps` at `/home/jones/PhpstormProjects/containerd-rs-k0sfix` (off `origin/main`)

## Goal

Make containerd-rs host a full k0s worker node (kubelet with per-QoS cgroups
enabled; CNI installed asynchronously by a kube-router DaemonSet after the daemon
is already serving). Close four CRI gaps and ship **v0.1.1**, unblocking the
mikronetes worker1 canary (containerd-rs + crun under a k0s worker at 512 MB).

## Architecture

The CRI surface lives in `crates/cri/src/server.rs` (`RuntimeSvc` + `ImageSvc`,
both holding `Arc<Context>`). Image metadata is `metadata::ImageRecord`
(`crates/metadata/src/records.rs`), written at pull time in
`crates/images/src/pull.rs` and surfaced to the kubelet by `record_to_image`.
Pod networking is `sandbox::cni::Cni` (`crates/sandbox/src/cni.rs`); the runtime
spec/bundle is `crates/runtime/src/bundle.rs`. Container cgroups today are only
OCI-spec path *strings* handed to runc/crun (`cgroups_path`, server.rs:1658) —
there is **no** Rust code that touches `/sys/fs/cgroup`, so gap 3 introduces the
first real cgroupfs write.

## Tech Stack

Rust workspace, `edition = "2021"`, `rust-version = "1.85"`, `version = "0.1.0"`
(`Cargo.toml [workspace.package]`). gRPC via `tonic` 0.14 (`#[tonic::async_trait]`).
Tests: `tokio::test`, `tempfile`, in-process gRPC harness over a unix socket.

## Global Constraints

- Workspace `edition = "2021"`, `rust-version = "1.85"` — do not bump either.
- `make check` (= `fmt-check` + `lint` (`clippy --workspace --all-targets -- -D warnings`) + `test` (`cargo test --workspace`)) MUST pass before each commit.
- **cgroup-v2 only**; **cgroupfs driver** (matches the kubelet — server.rs:426/1336 report `cgroupfs`). No systemd-slice handling for the pod cgroup.
- Do not break existing conformance/tests. The in-process harness uses host networking and empty stores; gap 1's test must not depend on CNI binaries being present.
- Every commit ends with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Pod-level cgroup **limit enforcement is out of scope** (gap 3 creates the cgroup so reads succeed; it sets no `memory.max`/`cpu.max` values).
- Never collapse a username to UID 0 on the CRI surface (do not reuse `bundle.rs::parse_user`).

## Task ordering (ascending difficulty)

1. Gap 4 — `UpdateRuntimeConfig` (warm-up).
2. Gap 2 — image `User` surfaced for `runAsNonRoot`.
3. Gap 1 — CNI failure must fail `RunPodSandbox` (no host fallback).
4. Gap 3 — pod-level cgroup creation (hardest; touches `/sys/fs/cgroup`).
5. Version bump to `0.1.1` + release-readiness check (no tag push).

---

## Task 1 — Gap 4: `UpdateRuntimeConfig` returns Ok

### 1a. Write the failing test

The existing `pod_sandbox_stats` assertion in server.rs:2049 keeps the
"still-unimplemented" coverage, so we only add a positive assertion. Add to the
`#[cfg(test)] mod tests` in `crates/cri/src/server.rs` (after
`version_and_status_over_unix_socket`, reusing its connection pattern). Simplest:
extend that test with the call below right after the `pod_sandbox_stats` block
(client `client` is already a `RuntimeServiceClient`):

```rust
        // Gap 4: UpdateRuntimeConfig is implemented and returns Ok, accepting a
        // pod CIDR without erroring (the kubelet calls this at startup).
        client
            .update_runtime_config(v1::UpdateRuntimeConfigRequest {
                runtime_config: Some(v1::RuntimeConfig {
                    network_config: Some(v1::NetworkConfig {
                        pod_cidr: "10.244.0.0/16".into(),
                    }),
                }),
            })
            .await
            .expect("update_runtime_config returns Ok");
```

### 1b. Run it — expect FAIL

```
cargo test -p cri version_and_status_over_unix_socket
```

Expected: `update_runtime_config returns Ok` panics — the call returns
`Code::Unimplemented` (method is still in `unary_unimpl!`).

### 1c. Implement

In `crates/cri/src/server.rs`, remove the `update_runtime_config` line from the
`unary_unimpl!` block (server.rs:1399):

```rust
    unary_unimpl! {
        pod_sandbox_stats => PodSandboxStatsRequest / PodSandboxStatsResponse,
        list_pod_sandbox_stats => ListPodSandboxStatsRequest / ListPodSandboxStatsResponse,
        checkpoint_container => CheckpointContainerRequest / CheckpointContainerResponse,
        list_metric_descriptors => ListMetricDescriptorsRequest / ListMetricDescriptorsResponse,
        list_pod_sandbox_metrics => ListPodSandboxMetricsRequest / ListPodSandboxMetricsResponse,
        update_pod_sandbox_resources => UpdatePodSandboxResourcesRequest / UpdatePodSandboxResourcesResponse,
    }
```

Add a real async handler inside `impl RuntimeService for RuntimeSvc` (place it
next to `update_container_resources`, before the `unary_unimpl!` block):

```rust
    async fn update_runtime_config(
        &self,
        request: Request<v1::UpdateRuntimeConfigRequest>,
    ) -> Result<Response<v1::UpdateRuntimeConfigResponse>, Status> {
        // The kubelet calls this once at startup to hand the runtime the pod
        // CIDR. We have no per-CIDR CNI behavior yet (kube-router/flannel own
        // IPAM), so we log it and accept. Returning Ok (not Unimplemented) is
        // what the kubelet requires to finish node setup.
        let pod_cidr = request
            .into_inner()
            .runtime_config
            .and_then(|c| c.network_config)
            .map(|n| n.pod_cidr)
            .unwrap_or_default();
        tracing::info!(%pod_cidr, "UpdateRuntimeConfig");
        Ok(Response::new(v1::UpdateRuntimeConfigResponse {}))
    }
```

Note: the spec mentions "optionally stash on `Context`". `Context` fields are
`pub` but shared `Arc` (no interior mutability), so stashing would need an
`ArcSwap`/`Mutex` field — out of proportion for a value nothing reads yet. We log
it and do not stash; the spec marks stashing optional. If a reviewer wants it
stashed, add `pub pod_cidr: std::sync::Mutex<String>` to `Context`, init `""` in
`Context::new`, and set it here — but that is not required for the fix.

### 1d. Run it — expect PASS

```
cargo test -p cri version_and_status_over_unix_socket
```

### 1e. Gate + commit

```
make check
git commit -am "feat(cri): implement UpdateRuntimeConfig (gap 4)

Remove update_runtime_config from the unary_unimpl! list and add a handler
that accepts runtime_config.network_config.pod_cidr, logs it, and returns Ok
so the kubelet finishes node setup instead of seeing Unimplemented.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2 — Gap 2: image `User` surfaced (`runAsNonRoot`)

### 2a. Write the failing test

This needs a stored `ImageRecord` with a populated `user` and the real
`record_to_image` mapping. `record_to_image` is a private fn in
`crates/cri/src/server.rs`, so add a **unit test** in `#[cfg(test)] mod tests`
(it can call `super::record_to_image` and construct `ImageRecord` directly —
`ImageRecord` is imported in that module via `use super::*`). Covering numeric,
`uid:gid`, and non-numeric users:

```rust
    fn image_rec_with_user(user: &str) -> metadata::ImageRecord {
        metadata::ImageRecord {
            name: "img".into(),
            target_digest: String::new(),
            image_id: "sha256:abc".into(),
            repo_tags: vec!["img:latest".into()],
            repo_digests: vec![],
            size: 0,
            layer_digests: vec![],
            chain_ids: vec![],
            user: user.into(),
        }
    }

    #[test]
    fn record_to_image_maps_numeric_user_to_uid() {
        let img = record_to_image(&image_rec_with_user("65532"));
        assert_eq!(img.uid.map(|u| u.value), Some(65532));
        assert!(img.username.is_empty());
    }

    #[test]
    fn record_to_image_maps_uid_gid_to_uid() {
        let img = record_to_image(&image_rec_with_user("65532:65532"));
        assert_eq!(img.uid.map(|u| u.value), Some(65532));
        assert!(img.username.is_empty());
    }

    #[test]
    fn record_to_image_maps_named_user_to_username_not_zero() {
        let img = record_to_image(&image_rec_with_user("nonroot"));
        // MUST NOT collapse to uid 0 (that is what the kubelet reads as root).
        assert!(img.uid.is_none(), "named user must not become a uid");
        assert_eq!(img.username, "nonroot");
    }

    #[test]
    fn record_to_image_empty_user_is_root_unset() {
        let img = record_to_image(&image_rec_with_user(""));
        assert!(img.uid.is_none());
        assert!(img.username.is_empty());
    }
```

Also extend the network-gated contract test
`crates/cri/tests/contract_image_service.rs::pull_then_status_and_list` (still
`#[ignore]`, requires network) to assert pause:3.10 surfaces *some* identity —
pause runs as uid 0 so this only checks the field round-trips without panicking;
leave it informational:

```rust
    // pause:3.10 has no `User` set -> root -> no uid/username surfaced.
    let im = st.image.expect("status has image");
    assert!(im.uid.is_none() && im.username.is_empty());
```

### 2b. Run it — expect FAIL

```
cargo test -p cri record_to_image
```

Expected: compile error — `ImageRecord` has no field `user`, and
`record_to_image` hardcodes `uid: None, username: String::new()`.

### 2c. Implement

**1. Add the field to `ImageRecord`** (`crates/metadata/src/records.rs`, after
`chain_ids`):

```rust
    /// Snapshot chainIDs this image references (for GC).
    #[serde(default)]
    pub chain_ids: Vec<String>,
    /// OCI image config `User` (e.g. "65532", "65532:65532", "nonroot"); empty
    /// means root. Surfaced to the kubelet for runAsNonRoot admission.
    #[serde(default)]
    pub user: String,
```

`#[serde(default)]` keeps old on-disk records (no `user` key) deserializable.

**2. Capture `User` at pull time** (`crates/images/src/pull.rs`). Extend
`ImageConfigJson` to parse the `config.User` field (the config blob is already
read into `config_bytes` and parsed into `ImageConfigJson` at pull.rs:170):

```rust
#[derive(Deserialize)]
struct ImageConfigJson {
    rootfs: RootFs,
    #[serde(default)]
    config: OciConfig,
}

#[derive(Deserialize, Default)]
struct OciConfig {
    #[serde(default, rename = "User")]
    user: String,
}
```

Add `user` to `PulledImage` (struct at pull.rs:~90, fields end at `layer_digests`):

```rust
    /// Compressed layer blob digests, in order.
    pub layer_digests: Vec<Digest>,
    /// OCI image config `User` (empty == root).
    pub user: String,
```

Populate it in the `Ok(PulledImage { .. })` returned near pull.rs:237 (capture
`parsed_config.config.user` before the per-layer loop consumes nothing of it —
it is owned by `parsed_config`, still in scope):

```rust
    Ok(PulledImage {
        reference: reference.to_string(),
        image_id,
        manifest_digest,
        size: total,
        diff_ids,
        chain_ids,
        layer_digests,
        user: parsed_config.config.user,
    })
```

**3. Persist it** in `ImageSvc::pull_image` (`crates/cri/src/server.rs`, the
`ImageRecord { .. }` literal at server.rs:1494):

```rust
            chain_ids: pulled.chain_ids.iter().map(|d| d.to_string()).collect(),
            user: pulled.user.clone(),
        };
```

**4. Map it in `record_to_image`** (`crates/cri/src/server.rs:122`). Numeric
(`"65532"` or `"65532:65532"`) → `uid: Some(Int64Value{ value })`; non-numeric →
`username`. Never produce uid 0 from a name:

```rust
fn record_to_image(rec: &ImageRecord) -> v1::Image {
    // Map the stored OCI `User` to CRI fields. The uid part is everything before
    // an optional ":gid". A purely-numeric uid -> Int64Value; a name (needs
    // /etc/passwd to resolve) -> username. NEVER collapse a name to uid 0 — the
    // kubelet reads uid 0 as "image runs as root" and rejects runAsNonRoot pods.
    let (uid, username) = match rec.user.split(':').next().unwrap_or("") {
        "" => (None, String::new()),
        u => match u.parse::<i64>() {
            Ok(n) => (Some(v1::Int64Value { value: n }), String::new()),
            Err(_) => (None, u.to_string()),
        },
    };
    v1::Image {
        id: rec.image_id.clone(),
        repo_tags: rec.repo_tags.clone(),
        repo_digests: rec.repo_digests.clone(),
        size: rec.size,
        uid,
        username,
        spec: None,
        pinned: false,
    }
}
```

Note any other `ImageRecord { .. }` literals must gain `user` — there are tests
in this plan that build the struct, and the pull path above; grep for
`ImageRecord {` before committing to catch compile errors.

### 2d. Run it — expect PASS

```
cargo test -p cri record_to_image
cargo test -p images          # PulledImage/ImageConfigJson changes compile
```

### 2e. Gate + commit

```
make check
git commit -am "feat: surface image User for runAsNonRoot (gap 2)

Add user: String (serde default) to ImageRecord; capture config.User at pull
(ImageConfigJson + PulledImage.user); map it in record_to_image — numeric ->
uid Int64Value, name -> username, never collapsing a name to uid 0.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3 — Gap 1: CNI failure must fail `RunPodSandbox` (no host fallback)

### 3a. Write the failing test

Use the real in-process harness (`crates/cri/tests/common/mod.rs::start()`),
whose `Context` points `cni_conf_dir` at a non-existent `cni/net.d` — so
`load_conflist()` fails with `Io(ENOENT)`, reproducing the async-CNI race. Add a
new integration test file `crates/cri/tests/contract_run_pod_sandbox.rs`:

```rust
//! Gap 1 — RunPodSandbox must FAIL (not silently host-network) when CNI is
//! unavailable for a non-hostNetwork pod, so the kubelet retries once
//! kube-router installs the conflist + binaries.

mod common;

use cri::v1;

fn sandbox_config(host_network: bool) -> v1::PodSandboxConfig {
    let ns = v1::NamespaceOption {
        // Node == host network; Pod (0) == needs CNI.
        network: if host_network {
            v1::NamespaceMode::Node as i32
        } else {
            v1::NamespaceMode::Pod as i32
        },
        ..Default::default()
    };
    v1::PodSandboxConfig {
        metadata: Some(v1::PodSandboxMetadata {
            name: "p".into(),
            uid: "u".into(),
            namespace: "default".into(),
            attempt: 0,
        }),
        linux: Some(v1::LinuxPodSandboxConfig {
            security_context: Some(v1::LinuxSandboxSecurityContext {
                namespace_options: Some(ns),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn run_pod_sandbox_fails_when_cni_unavailable() {
    let mut h = common::start().await;
    let res = h
        .rt
        .run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(sandbox_config(false)),
            runtime_handler: String::new(),
        })
        .await;
    let err = res.expect_err("non-hostNetwork pod must fail when CNI is absent");
    assert!(
        matches!(err.code(), tonic::Code::Unavailable | tonic::Code::Internal),
        "got {:?}",
        err.code()
    );
    // It must not have silently created a Ready sandbox.
    let list = h
        .rt
        .list_pod_sandbox(v1::ListPodSandboxRequest { filter: None })
        .await
        .unwrap()
        .into_inner();
    assert!(
        list.items.iter().all(|s| s.state != v1::PodSandboxState::SandboxReady as i32),
        "no Ready sandbox may exist after a CNI failure"
    );
}

#[tokio::test]
async fn run_pod_sandbox_host_network_still_succeeds() {
    // The explicit-hostNetwork branch is unchanged: it never touches CNI.
    let mut h = common::start().await;
    let resp = h
        .rt
        .run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(sandbox_config(true)),
            runtime_handler: String::new(),
        })
        .await
        .expect("hostNetwork pod succeeds without CNI")
        .into_inner();
    assert!(!resp.pod_sandbox_id.is_empty());
}
```

Host requirement: none beyond the existing harness — both tests run with no runc
and no CNI binaries. (The hostNetwork test exercises the `("host", host_ip())`
arm only.)

### 3b. Run it — expect FAIL

```
cargo test -p cri --test contract_run_pod_sandbox
```

Expected: `run_pod_sandbox_fails_when_cni_unavailable` panics at `expect_err`
(today the `Err(e)` arm falls back to host network and returns Ok with a Ready
sandbox). The hostNetwork test passes already.

### 3c. Implement

In `crates/cri/src/server.rs::run_pod_sandbox`, change only the CNI-failure arm
(server.rs:571-575) so a non-hostNetwork CNI failure returns an error after
best-effort teardown. Replace the `Err(e)` arm:

```rust
        let (netns_path, ip) = if host_network {
            ("host".to_string(), sandbox::net::host_ip())
        } else {
            match self
                .ctx
                .cni
                .create_netns(&id)
                .and_then(|_| self.ctx.cni.setup(&id, &id, &port_mappings))
            {
                Ok(ip) => {
                    tracing::info!(sandbox = %id, %ip, "RunPodSandbox (CNI)");
                    (self.ctx.cni.netns_path(&id).display().to_string(), ip)
                }
                Err(e) => {
                    // A non-hostNetwork pod MUST get real CNI networking. If CNI
                    // is unavailable (e.g. kube-router hasn't installed the
                    // conflist + binaries yet) we tear down best-effort and FAIL
                    // the sandbox so the kubelet retries — silently falling back
                    // to host networking gives every pod the node's network and
                    // breaks NetworkPolicy/Service routing.
                    let _ = self.ctx.cni.teardown(&id, &id);
                    tracing::warn!(sandbox = %id, error = %e, "CNI setup failed; failing RunPodSandbox for kubelet retry");
                    return Err(Status::unavailable(format!(
                        "CNI network setup failed for sandbox {id}: {e}"
                    )));
                }
            }
        };
```

The `if netns_path == "host"` log block below stays. Nothing is persisted on the
failure path (we return before building `SandboxRecord`), so no NotReady record
leaks. The explicit-hostNetwork branch (server.rs:558-559) is untouched.

### 3d. Run it — expect PASS

```
cargo test -p cri --test contract_run_pod_sandbox
```

### 3e. Gate + commit

```
make check
git commit -am "fix(cri): fail RunPodSandbox when CNI is unavailable (gap 1)

A non-hostNetwork pod whose CNI setup fails now tears down best-effort and
returns Status::unavailable so the kubelet retries, instead of silently
falling back to host networking. The explicit-hostNetwork branch is unchanged.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4 — Gap 3: pod-level cgroup creation

### 4a. Write the failing test

The kubelet (cgroupfs driver, `cgroupsPerQOS=true`) reads `memory.max`/`cpu.max`
at the pod-level cgroup `/sys/fs/cgroup/<cgroup_parent>/`. Nothing creates it
today. We add a free function `ensure_pod_cgroup(cgroup_parent: &str) ->
std::io::Result<()>` in `crates/cri/src/server.rs` (next to `cgroups_path`,
server.rs:1658) and unit-test it against a writable temp root.

Because the helper must be testable without root and without a real
`/sys/fs/cgroup`, split it: a pure `ensure_pod_cgroup_at(root: &Path,
cgroup_parent: &str)` that does the filesystem work under an arbitrary root, and
a thin `ensure_pod_cgroup` that calls it with `/sys/fs/cgroup`. Test the `_at`
form against a `tempfile::tempdir()`:

```rust
    #[test]
    fn ensure_pod_cgroup_creates_dir_and_enables_controllers() {
        let root = tempfile::tempdir().unwrap();
        // Simulate the cgroup-v2 root: parent's available controllers.
        let parent = root.path().join("kubepods").join("besteffort");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(parent.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        std::fs::write(parent.join("cgroup.subtree_control"), "").unwrap();

        ensure_pod_cgroup_at(root.path(), "/kubepods/besteffort/podABC").unwrap();

        let pod = parent.join("podABC");
        assert!(pod.is_dir(), "pod-level cgroup dir created");
        // Controllers the children will need are delegated via the parent's
        // subtree_control (cgroup-v2 no-internal-processes: enable on the parent,
        // not the leaf).
        let sc = std::fs::read_to_string(parent.join("cgroup.subtree_control")).unwrap();
        assert!(sc.contains("+cpu"), "cpu delegated: {sc:?}");
        assert!(sc.contains("+memory"), "memory delegated: {sc:?}");
    }

    #[test]
    fn ensure_pod_cgroup_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("kubepods");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(parent.join("cgroup.controllers"), "cpu memory\n").unwrap();
        std::fs::write(parent.join("cgroup.subtree_control"), "").unwrap();
        ensure_pod_cgroup_at(root.path(), "/kubepods/pod1").unwrap();
        // Second call must not error on the already-present dir.
        ensure_pod_cgroup_at(root.path(), "/kubepods/pod1").unwrap();
    }
```

Note on the live `/sys/fs/cgroup` integration: there is no test that writes the
real cgroup root, because `make check`/CI is not guaranteed a writable delegated
cgroup. The `_at` unit tests prove the logic; the real-root path is exercised by
the conformance-docker harness (`CGROUPS_PER_QOS=true`, delegated scope) and the
mikronetes canary smoke test (the spec's real gate). If a maintainer wants a live
smoke test, gate it: `if std::fs::metadata("/sys/fs/cgroup/cgroup.subtree_control").is_err() { return; }`
at the top and mark it `#[ignore]`.

### 4b. Run it — expect FAIL

```
cargo test -p cri ensure_pod_cgroup
```

Expected: compile error — `ensure_pod_cgroup_at`/`ensure_pod_cgroup` do not exist.

### 4c. Implement

**1. Add the helpers** in `crates/cri/src/server.rs` (next to `cgroups_path`):

```rust
/// cgroup-v2 root the kubelet (cgroupfs driver) reads pod limits under.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Create the pod-level cgroup-v2 directory for `cgroup_parent` and delegate the
/// controllers the kubelet expects (so `memory.max`/`cpu.max` exist for it to
/// read). Pod-level *enforcement* is out of scope — we only ensure the limit
/// files exist (they default to "max").
///
/// cgroup-v2 "no internal processes": controllers are enabled by writing
/// `+ctrl` to the *parent's* `cgroup.subtree_control`, never the leaf's. The pod
/// cgroup is an intermediate node; container leaves live in its children.
fn ensure_pod_cgroup(cgroup_parent: &str) -> std::io::Result<()> {
    ensure_pod_cgroup_at(std::path::Path::new(CGROUP_ROOT), cgroup_parent)
}

fn ensure_pod_cgroup_at(root: &Path, cgroup_parent: &str) -> std::io::Result<()> {
    let pod_dir = root.join(cgroup_parent.trim_start_matches('/'));
    // The parent cgroup must already exist (kubelet creates the QoS tier); the
    // pod dir is the new leaf-of-parent we own.
    let parent = pod_dir
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "cgroup_parent has no parent dir"))?;

    // Delegate cpu+memory from the parent so the pod cgroup gets cpu.max/memory.max.
    // Read what the parent actually has available; only delegate the intersection
    // of {cpu, memory} with the parent's cgroup.controllers.
    let available = std::fs::read_to_string(parent.join("cgroup.controllers")).unwrap_or_default();
    let want = ["cpu", "memory"];
    let to_enable: Vec<&str> = want
        .iter()
        .copied()
        .filter(|c| available.split_whitespace().any(|a| a == *c))
        .collect();
    if !to_enable.is_empty() {
        let line: String = to_enable.iter().map(|c| format!("+{c} ")).collect();
        // Best-effort: subtree_control may already list them (idempotent write).
        let _ = std::fs::write(parent.join("cgroup.subtree_control"), line.trim_end());
    }

    // Create the pod cgroup dir (idempotent).
    match std::fs::create_dir(&pod_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    Ok(())
}
```

(`create_dir` not `create_dir_all`: the parent QoS cgroup must pre-exist; we own
only the pod leaf. In the unit test we pre-create the parent, matching the
kubelet's real behavior.)

**2. Call it from `run_pod_sandbox`** (`crates/cri/src/server.rs`). After the
`cgroup_parent` is computed (server.rs:527, right after the
`tracing::info!(%cgroup_parent, ...)` line) and before the network block:

```rust
        tracing::info!(%cgroup_parent, "RunPodSandbox cgroup_parent");

        // Driver is cgroupfs (we report cgroupfs to the kubelet). When the
        // kubelet runs with cgroupsPerQOS it reads memory.max/cpu.max at the
        // pod-level cgroup; create that cgroup (+ delegate controllers) so the
        // reads succeed. Best-effort: a missing/RO /sys/fs/cgroup (e.g. the
        // host-network/contract harness) must not fail sandbox creation.
        if !cgroup_parent.is_empty() {
            if let Err(e) = ensure_pod_cgroup(&cgroup_parent) {
                tracing::warn!(%cgroup_parent, error = %e, "could not create pod cgroup (continuing)");
            }
        }
```

Rationale for best-effort (warn, not fail): the driver is always cgroupfs here
(server.rs:1336), so no driver guard is needed; and the in-process contract
harness has no writable `/sys/fs/cgroup`. Failing would break gap 1's new test
and the existing harness tests. The kubelet only reads these files when
`cgroupsPerQOS=true` on a real node, where `/sys/fs/cgroup` is writable.

**3. Flip CI to exercise it.** Per the spec's regression guard, default the
conformance harness to `CGROUPS_PER_QOS=true`. In `ci/kubeadm-init.sh:29`:

```sh
CGROUPS_PER_QOS="${CGROUPS_PER_QOS:-true}"
```

(`ci/conformance-docker.sh` already defaults `true`; `ci/kubelet-node.sh:56`
hardcodes `--cgroups-per-qos=false` for the secondary node-join path — leave it,
it is a separate harness, but note it in the PR so the maintainer decides whether
to flip it too. Do not change `kubelet-node.sh` blindly — out of plan scope.)

### 4d. Run it — expect PASS

```
cargo test -p cri ensure_pod_cgroup
cargo test -p cri --test contract_run_pod_sandbox   # gap 1 still green (cgroup is best-effort)
```

### 4e. Gate + commit

```
make check
git commit -am "feat(cri): create pod-level cgroup for kubelet QoS reads (gap 3)

run_pod_sandbox now creates the pod-level cgroup-v2 dir and delegates cpu+memory
via the parent's cgroup.subtree_control so memory.max/cpu.max exist for the
kubelet (cgroupfs, cgroupsPerQOS) to read. Best-effort: no /sys/fs/cgroup write
does not fail the sandbox. No pod-level limit enforcement. CI now defaults
CGROUPS_PER_QOS=true.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5 — Version bump to 0.1.1 + release-readiness

NOT the tag push — the human/controller cuts `v0.1.1`.

### 5a. Bump the workspace version

In `Cargo.toml [workspace.package]`:

```toml
version = "0.1.1"
```

Regenerate the lockfile so it tracks the new version:

```
cargo update -p containerd-rs --precise 0.1.1 2>/dev/null || cargo build --workspace
```

(Simplest: run `cargo build --workspace`, which rewrites `Cargo.lock` for the
bumped workspace members.)

### 5b. Release-readiness check

```
make check                       # fmt + clippy + full test suite green
cargo build --workspace --release
ls -la target/release/containerd-rs   # the daemon binary exists
```

Expected: `make check` green; the release binary builds. Confirm version:

```
./target/release/containerd-rs --version   # or `grep version Cargo.toml` if no flag
```

### 5c. Commit (no tag)

```
git commit -am "chore: bump workspace version to 0.1.1

All four k0s-worker CRI gaps fixed (UpdateRuntimeConfig, image User,
CNI-fail-not-fallback, pod cgroup). Release tag cut separately.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

Do **not** run `git tag` / `git push --tags`. Hand off to the controller.

---

## Self-Review

### Spec coverage
- **Gap 4** (Task 1): removed from `unary_unimpl!`, real handler reads
  `runtime_config.network_config.pod_cidr`, returns `Ok(UpdateRuntimeConfigResponse{})`. Stashing on `Context` correctly noted as optional (no reader yet; `Arc<Context>` lacks interior mutability).
- **Gap 2** (Task 2): `user: String` (`#[serde(default)]`) on `ImageRecord`; captured at pull via `ImageConfigJson.config.User` -> `PulledImage.user`; `record_to_image` maps numeric->uid, name->username, never name->0; empty->root. Covers `"65532"`, `"65532:65532"`, `"nonroot"`, `""`.
- **Gap 1** (Task 3): non-hostNetwork CNI failure -> best-effort `teardown` -> `Status::unavailable`, no Ready record persisted. Explicit-hostNetwork branch untouched (separate passing test asserts this).
- **Gap 3** (Task 4): pod cgroup dir created + cpu/memory delegated via parent `cgroup.subtree_control` (no-internal-processes respected — parent, not leaf); no limit enforcement; cgroupfs assumed (matches reported driver); CI `CGROUPS_PER_QOS` flipped to `true`.
- **Task 5**: version 0.1.1, `make check` + release build, no tag.

### Placeholder scan
No `TODO`/`unimplemented!`/"add error handling" hand-waving. Every edit shows the
actual function body. Cgroup helper handles `AlreadyExists` explicitly (idempotent).

### Type consistency (verified against the worktree)
- `v1::Int64Value { value: i64 }` — `record_to_image` uses `.value` (matches the test's `img.uid.map(|u| u.value)`).
- `ImageRecord` fields exactly: `name, target_digest, image_id, repo_tags, repo_digests, size, layer_digests, chain_ids` + new `user`.
- `PulledImage` fields end at `layer_digests: Vec<Digest>`; add `user: String`.
- `OciConfigInner` (server.rs:376) already renames `User`; the new `OciConfig` in pull.rs mirrors that rename — kept separate because pull.rs cannot import the cri crate (no dep), and `ImageConfigJson` only needs `rootfs` + `config.User`.
- `RunPodSandboxRequest { config, runtime_handler }`, `PodSandboxConfig.linux.security_context.namespace_options.network` (== `NamespaceMode::Node as i32` for host net) — matches server.rs:531-537.
- `Context::new` signature unchanged (gap 4 stashing declined), so `common/mod.rs` and the in-server test harness compile unmodified.

### Watch-outs flagged for the implementer
- Grep `ImageRecord {` before committing Task 2 — every literal needs `user`.
- `cargo test -p images` after Task 2 (PulledImage changed).
- `ensure_pod_cgroup` is best-effort on purpose; if a reviewer wants hard failure on a real node, that is a follow-up (would break the in-process harness as written).
