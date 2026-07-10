//! CRI v1 service implementations.
//!
//! `Version` and `Status` are real (enough for the kubelet handshake and
//! `crictl version`/`crictl info`). Every other RPC returns `unimplemented`
//! until its task (T024–T038) lands. Serving over a unix socket is provided by
//! [`serve`].

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use metadata::records::{
    ContainerRecord, ContainerState, ImageRecord, MountRecord, ResourcesRecord, SandboxRecord,
    SandboxState,
};
use metadata::Kind;
use tonic::{Request, Response, Status};

use crate::v1::image_service_server::{ImageService, ImageServiceServer};
use crate::v1::runtime_service_server::{RuntimeService, RuntimeServiceServer};
use crate::v1::{self};

/// CRI runtime API version string the kubelet checks (containerd reports this).
const CRI_RUNTIME_API_VERSION: &str = "0.1.0";
/// The CRI proto API version (the `runtime.v1` package).
const CRI_API_VERSION: &str = "v1";
/// Runtime name reported to the kubelet.
const RUNTIME_NAME: &str = "containerd-rs";

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// Shared daemon state handed to the CRI services.
pub struct Context {
    pub content: content::Store,
    pub metadata: metadata::Store,
    pub snapshots_root: PathBuf,
    /// Ephemeral state dir; holds per-container OCI bundles + the crun state.
    pub state_dir: PathBuf,
    pub namespace: String,
    /// Streaming-session registry shared with the streaming HTTP server.
    pub streaming: Arc<crate::streaming::Sessions>,
    /// Base URL the kubelet uses to reach the streaming server.
    pub stream_base_url: String,
    /// CNI runtime for pod networking.
    pub cni: sandbox::cni::Cni,
    /// Per-image-reference locks serializing concurrent duplicate pulls.
    pub pull_locks: crate::locks::KeyedLocks,
    /// Image pull behavior supplied by daemon configuration.
    pub pull_options: images::pull::PullOptions,
    /// Pass `--no-pivot` to crun (MS_MOVE + chroot instead of pivot_root).
    /// Default false (pivot_root, like containerd) — required for mount
    /// propagation (rshared/rslave). Set true ONLY on a ramdisk/initramfs root
    /// (M2a) where pivot_root(2) fails (new root + put-old on the same ramfs).
    pub no_pivot_root: bool,
    /// Broadcast bus for container lifecycle events (feature 002 US3 / T026),
    /// consumed by the CRI `GetContainerEvents` stream (kubelet evented PLEG).
    /// `send` is a no-op when there are no subscribers.
    pub container_events: tokio::sync::broadcast::Sender<v1::ContainerEventResponse>,
}

impl Context {
    /// Build a context using the CRI runtime namespace (`k8s.io`). `stream_addr`
    /// is the streaming server's listen address (e.g. `127.0.0.1:10010`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        content: content::Store,
        metadata: metadata::Store,
        snapshots_root: PathBuf,
        state_dir: PathBuf,
        stream_addr: &str,
        cni_conf_dir: PathBuf,
        cni_bin_dir: PathBuf,
        pull_options: images::pull::PullOptions,
        no_pivot_root: bool,
    ) -> Self {
        let streaming = Arc::new(crate::streaming::Sessions::new(state_dir.join("crun")));
        let (container_events, _) = tokio::sync::broadcast::channel(512);
        Self {
            content,
            metadata,
            snapshots_root,
            state_dir,
            namespace: core_types::Namespace::CRI.to_string(),
            streaming,
            stream_base_url: format!("http://{stream_addr}"),
            cni: sandbox::cni::Cni::new(cni_conf_dir, cni_bin_dir),
            pull_locks: crate::locks::KeyedLocks::default(),
            pull_options,
            no_pivot_root,
            container_events,
        }
    }

    /// Emit a container lifecycle event to `GetContainerEvents` subscribers
    /// (feature 002 US3 / T026). No-op when there are no subscribers.
    pub fn emit_container_event(&self, container_id: &str, event: v1::ContainerEventType) {
        let _ = self.container_events.send(v1::ContainerEventResponse {
            container_id: container_id.to_string(),
            container_event_type: event as i32,
            created_at: unix_nanos(),
            pod_sandbox_status: None,
            containers_statuses: Vec::new(),
        });
    }
}

/// Strip an optional `:tag` from a reference's final path segment, yielding the
/// repository name (e.g. `registry.k8s.io/pause:3.10` -> `registry.k8s.io/pause`).
fn repo_name(reference: &str) -> &str {
    let seg_start = reference.rfind('/').map(|i| i + 1).unwrap_or(0);
    match reference[seg_start..].rfind(':') {
        Some(rel) => &reference[..seg_start + rel],
        None => reference,
    }
}

/// Whether `reference` is a digest reference (`name@sha256:...`).
fn is_digest_ref(reference: &str) -> bool {
    reference.contains('@')
}

/// Normalize an image reference for storage/lookup: a bare name with no tag and
/// no digest gets an implicit `:latest` (as containerd/docker do), so a pull of
/// `busybox` and a status query for `busybox` both resolve to `busybox:latest`.
/// Digest refs and already-tagged refs are returned unchanged. `repo_name`
/// stripping nothing (and no `@`) means there is no tag → append `:latest`.
fn normalize_image_ref(reference: &str) -> String {
    if is_digest_ref(reference) || repo_name(reference) != reference {
        reference.to_string()
    } else {
        format!("{reference}:latest")
    }
}

/// Build pull credentials from the CRI `AuthConfig`, in priority order: a bearer
/// identity/registry token, explicit username/password, or a base64-encoded
/// `auth` (`"username:password"`, as found in docker config / pull secrets);
/// otherwise anonymous. oci-client performs the docker bearer-token handshake
/// (401 → realm/scope → token) under all of these.
fn auth_from_config(a: v1::AuthConfig) -> images::pull::Auth {
    use base64::Engine as _;
    if !a.identity_token.is_empty() {
        return images::pull::Auth::Bearer(a.identity_token);
    }
    if !a.registry_token.is_empty() {
        return images::pull::Auth::Bearer(a.registry_token);
    }
    if !a.username.is_empty() {
        return images::pull::Auth::Basic {
            username: a.username,
            password: a.password,
        };
    }
    if !a.auth.is_empty() {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(a.auth.trim()) {
            if let Ok(s) = String::from_utf8(decoded) {
                if let Some((u, p)) = s.split_once(':') {
                    return images::pull::Auth::Basic {
                        username: u.to_string(),
                        password: p.to_string(),
                    };
                }
            }
        }
    }
    images::pull::Auth::Anonymous
}

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

/// Emit unary RPC methods that return `unimplemented`.
///
/// `#[async_trait]` on the impl runs before this declarative macro expands, so
/// it can't desugar `async fn`s we generate here. We therefore emit the boxed
/// future form async_trait itself produces, matching the trait method exactly.
macro_rules! unary_unimpl {
    ($($method:ident => $req:ident / $resp:ident),* $(,)?) => {
        $(
            fn $method<'s, 'async_trait>(
                &'s self,
                _request: Request<v1::$req>,
            ) -> ::core::pin::Pin<Box<
                dyn ::core::future::Future<Output = Result<Response<v1::$resp>, Status>>
                    + ::core::marker::Send + 'async_trait,
            >>
            where
                's: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move {
                    Err(Status::unimplemented(concat!(
                        stringify!($method),
                        " not yet implemented (see specs/001-rust-containerd/tasks.md)"
                    )))
                })
            }
        )*
    };
}

/// RuntimeService implementation.
#[derive(Clone)]
pub struct RuntimeSvc {
    ctx: Arc<Context>,
}

impl RuntimeSvc {
    fn ns(&self) -> &str {
        &self.ctx.namespace
    }

    /// Generate an opaque 64-hex id seeded by `seed` plus the current time.
    fn gen_id(&self, seed: &str) -> String {
        let input = format!("{seed}/{}", unix_nanos());
        core_types::Digest::sha256(input.as_bytes())
            .hex()
            .to_string()
    }

    fn get_container(&self, id: &str) -> Result<Option<ContainerRecord>, Status> {
        self.ctx
            .metadata
            .get(Kind::Container, self.ns(), id)
            .map_err(|e| Status::internal(e.to_string()))
    }

    /// Write a `resolv.conf` for a sandbox into its state dir and return the path.
    ///
    /// Mirrors containerd's CRI DNS handling: render `nameserver`/`search`/`options`
    /// from the CRI `DNSConfig`. When the kubelet supplies no DNS config (e.g.
    /// `dnsPolicy: Default` is resolved host-side and may arrive empty), copy the
    /// node's `/etc/resolv.conf` so containers still get working resolution. Returns
    /// `None` only if nothing could be written.
    fn write_sandbox_resolv_conf(
        &self,
        sandbox_id: &str,
        dns: Option<&v1::DnsConfig>,
    ) -> Option<String> {
        let dir = self.ctx.state_dir.join(self.ns()).join(sandbox_id);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!(sandbox = %sandbox_id, error = %e, "resolv.conf: mkdir failed");
            return None;
        }
        let path = dir.join("resolv.conf");

        let has_dns = dns.is_some_and(|d| {
            !d.servers.is_empty() || !d.searches.is_empty() || !d.options.is_empty()
        });
        let content = if has_dns {
            let d = dns.unwrap();
            let mut s = String::new();
            if !d.searches.is_empty() {
                s.push_str(&format!("search {}\n", d.searches.join(" ")));
            }
            for ns in &d.servers {
                s.push_str(&format!("nameserver {ns}\n"));
            }
            if !d.options.is_empty() {
                s.push_str(&format!("options {}\n", d.options.join(" ")));
            }
            s
        } else {
            // Fall back to the node's resolver configuration.
            std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default()
        };

        match std::fs::write(&path, content) {
            Ok(()) => Some(path.display().to_string()),
            Err(e) => {
                tracing::warn!(sandbox = %sandbox_id, error = %e, "resolv.conf: write failed");
                None
            }
        }
    }

    /// Best-effort CPU/memory sample for a container via `crun events --stats`.
    /// Returns `(cpu_total_nanos, mem_working_set_bytes)`, zeros if the sample is
    /// unavailable (crun error / non-JSON / missing fields). A failed sample MUST
    /// NOT drop the whole stats entry — see [`container_stats_for`].
    async fn sample_usage(&self, id: &str) -> (u64, u64) {
        let crun_root = self.ctx.state_dir.join("crun");
        let id = id.to_string();
        let out = match tokio::task::spawn_blocking(move || {
            runtime::crun::stats(runtime::crun::DEFAULT_BIN, &crun_root, &id)
        })
        .await
        {
            Ok(Ok(o)) if o.status.success() => o,
            _ => return (0, 0),
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
            return (0, 0);
        };
        let data = &v["data"];
        (
            data["cpu"]["usage"]["total"].as_u64().unwrap_or(0),
            data["memory"]["usage"]["usage"].as_u64().unwrap_or(0),
        )
    }

    /// Build CRI `ContainerStats` for a container. Returns `None` only for a
    /// non-running container (no live cgroup). Usage is best-effort (a failed
    /// sample yields zeros, never a nil entry), so the returned stats ALWAYS
    /// carry the container id + labels/annotations — which `ListContainerStats`
    /// enumeration and label filtering depend on (critest container.go:187+).
    async fn container_stats_for(&self, rec: &ContainerRecord) -> Option<v1::ContainerStats> {
        if rec.state != ContainerState::Running {
            return None;
        }
        let (cpu_total, mem_usage) = self.sample_usage(&rec.id).await;
        let ts = unix_nanos();
        Some(v1::ContainerStats {
            attributes: Some(v1::ContainerAttributes {
                id: rec.id.clone(),
                metadata: Some(v1::ContainerMetadata {
                    name: rec.name.clone(),
                    attempt: rec.attempt,
                }),
                labels: rec.labels.clone(),
                annotations: rec.annotations.clone(),
            }),
            cpu: Some(v1::CpuUsage {
                timestamp: ts,
                usage_core_nano_seconds: Some(v1::UInt64Value { value: cpu_total }),
                usage_nano_cores: None,
                psi: None,
            }),
            memory: Some(v1::MemoryUsage {
                timestamp: ts,
                working_set_bytes: Some(v1::UInt64Value { value: mem_usage }),
                available_bytes: None,
                usage_bytes: Some(v1::UInt64Value { value: mem_usage }),
                rss_bytes: None,
                page_faults: None,
                major_page_faults: None,
                psi: None,
            }),
            writable_layer: None,
            swap: None,
            io: None,
        })
    }

    /// Build CRI `PodSandboxStats` for a sandbox (feature 002 US3 / T023):
    /// pod-level CPU/memory read from the pod cgroup (v2) via `runtime::cgroup`,
    /// plus per-container stats for the sandbox's running containers. Network and
    /// process usage are left unset (follow-up); missing cgroup files read as 0.
    async fn pod_sandbox_stats_for(&self, sb: &SandboxRecord) -> v1::PodSandboxStats {
        let ts = unix_nanos();
        // Pod-level usage from the kubelet-delegated pod cgroup, when present.
        let cg = if sb.cgroup_parent.is_empty() {
            runtime::cgroup::CgroupStats::default()
        } else {
            let dir = std::path::Path::new("/sys/fs/cgroup")
                .join(sb.cgroup_parent.trim_start_matches('/'));
            runtime::cgroup::read_stats(&dir)
        };

        // Per-container stats for this sandbox's running containers.
        let mut containers = Vec::new();
        if let Ok(recs) = self
            .ctx
            .metadata
            .list::<ContainerRecord>(Kind::Container, self.ns())
        {
            for rec in recs.iter().filter(|r| r.sandbox_id == sb.id) {
                if let Some(s) = self.container_stats_for(rec).await {
                    containers.push(s);
                }
            }
        }

        v1::PodSandboxStats {
            attributes: Some(v1::PodSandboxAttributes {
                id: sb.id.clone(),
                metadata: Some(v1::PodSandboxMetadata {
                    name: sb.name.clone(),
                    uid: sb.uid.clone(),
                    namespace: sb.k8s_namespace.clone(),
                    attempt: sb.attempt,
                }),
                labels: sb.labels.clone(),
                annotations: sb.annotations.clone(),
            }),
            linux: Some(v1::LinuxPodSandboxStats {
                cpu: Some(v1::CpuUsage {
                    timestamp: ts,
                    usage_core_nano_seconds: Some(v1::UInt64Value {
                        value: cg.cpu_usage_nanos,
                    }),
                    usage_nano_cores: None,
                    psi: None,
                }),
                memory: Some(v1::MemoryUsage {
                    timestamp: ts,
                    working_set_bytes: Some(v1::UInt64Value {
                        value: cg.memory_current_bytes,
                    }),
                    available_bytes: None,
                    usage_bytes: Some(v1::UInt64Value {
                        value: cg.memory_current_bytes,
                    }),
                    rss_bytes: Some(v1::UInt64Value {
                        value: cg.memory_anon_bytes,
                    }),
                    page_faults: None,
                    major_page_faults: None,
                    psi: None,
                }),
                network: None,
                process: None,
                containers,
                io: None,
            }),
            windows: None,
        }
    }

    /// Find an image record by reference, image id, repo tag, repo digest, or
    /// name. Matches the raw ref AND its `:latest`-normalized form, so a bare
    /// `repo/img` (no tag) resolves the stored `repo/img:latest` repoTag — the
    /// kubelet/critest create containers from untagged image refs (e.g. the
    /// host-net web-server image). Mirrors ImageSvc::find_image.
    fn find_image(&self, image_ref: &str) -> Result<Option<ImageRecord>, Status> {
        let all = self
            .ctx
            .metadata
            .list::<ImageRecord>(Kind::Image, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        let nref = normalize_image_ref(image_ref);
        Ok(all.into_iter().find(|r| {
            r.image_id == image_ref
                || r.repo_tags.iter().any(|t| t == image_ref || t == &nref)
                || r.repo_digests.iter().any(|d| d == image_ref)
                || r.name == image_ref
        }))
    }

    /// Read + parse the stored image config blob into bundle `ImageConfig`
    /// (defaults if the blob is absent/unreadable).
    fn parse_image_config(&self, image_id: &str) -> runtime::bundle::ImageConfig {
        image_id
            .parse::<core_types::Digest>()
            .ok()
            .and_then(|d| self.ctx.content.read(&d).ok())
            .and_then(|bytes| serde_json::from_slice::<OciImageConfig>(&bytes).ok())
            .map(|oci| runtime::bundle::ImageConfig {
                env: oci.config.env,
                entrypoint: oci.config.entrypoint,
                cmd: oci.config.cmd,
                working_dir: (!oci.config.working_dir.is_empty()).then_some(oci.config.working_dir),
                user: (!oci.config.user.is_empty()).then_some(oci.config.user),
            })
            .unwrap_or_default()
    }

    /// Materialize a merged rootfs by applying each image layer (in order) into
    /// `rootfs`. Compression is auto-detected from each blob.
    fn unpack_rootfs(&self, layer_digests: &[String], rootfs: &Path) -> Result<(), Status> {
        for ld in layer_digests {
            let digest = ld
                .parse::<core_types::Digest>()
                .map_err(|e| Status::internal(format!("bad layer digest {ld}: {e}")))?;
            let bytes = self
                .ctx
                .content
                .read(&digest)
                .map_err(|e| Status::internal(format!("read layer {ld}: {e}")))?;
            let comp = snapshots::diff::Compression::detect(&bytes);
            snapshots::diff::apply_layer(rootfs, Box::new(std::io::Cursor::new(bytes)), comp)
                .map_err(|e| Status::internal(format!("unpack layer {ld}: {e}")))?;
        }
        Ok(())
    }
}

fn sandbox_metadata(rec: &SandboxRecord) -> v1::PodSandboxMetadata {
    v1::PodSandboxMetadata {
        name: rec.name.clone(),
        uid: rec.uid.clone(),
        namespace: rec.k8s_namespace.clone(),
        attempt: rec.attempt,
    }
}

fn sandbox_state_i32(state: SandboxState) -> i32 {
    match state {
        SandboxState::Ready => v1::PodSandboxState::SandboxReady as i32,
        SandboxState::NotReady => v1::PodSandboxState::SandboxNotready as i32,
    }
}

fn container_state_i32(state: ContainerState) -> i32 {
    match state {
        ContainerState::Created => v1::ContainerState::ContainerCreated as i32,
        ContainerState::Running => v1::ContainerState::ContainerRunning as i32,
        ContainerState::Exited => v1::ContainerState::ContainerExited as i32,
        ContainerState::Unknown => v1::ContainerState::ContainerUnknown as i32,
    }
}

/// OCI image config (the `config` object) — the fields bundle generation needs.
#[derive(serde::Deserialize, Default)]
struct OciImageConfig {
    #[serde(default)]
    config: OciConfigInner,
}

#[derive(serde::Deserialize, Default)]
struct OciConfigInner {
    #[serde(default, rename = "Env")]
    env: Vec<String>,
    #[serde(default, rename = "Entrypoint")]
    entrypoint: Vec<String>,
    #[serde(default, rename = "Cmd")]
    cmd: Vec<String>,
    #[serde(default, rename = "WorkingDir")]
    working_dir: String,
    #[serde(default, rename = "User")]
    user: String,
}

#[tonic::async_trait]
impl RuntimeService for RuntimeSvc {
    async fn version(
        &self,
        _request: Request<v1::VersionRequest>,
    ) -> Result<Response<v1::VersionResponse>, Status> {
        Ok(Response::new(v1::VersionResponse {
            // `version` is the CRI runtime API version the kubelet validates
            // (must be "0.1.0"); `runtime_api_version` is the proto package.
            version: CRI_RUNTIME_API_VERSION.to_string(),
            runtime_name: RUNTIME_NAME.to_string(),
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
            runtime_api_version: CRI_API_VERSION.to_string(),
        }))
    }

    async fn status(
        &self,
        request: Request<v1::StatusRequest>,
    ) -> Result<Response<v1::StatusResponse>, Status> {
        let condition = |t: &str| v1::RuntimeCondition {
            r#type: t.to_string(),
            status: true,
            reason: String::new(),
            message: String::new(),
        };
        let status = v1::RuntimeStatus {
            conditions: vec![condition("RuntimeReady"), condition("NetworkReady")],
        };
        // When `verbose`, surface the runtime configuration under `info["config"]`,
        // mirroring containerd's CRI. Tools (crictl, kubeadm) parse this for the
        // sandbox image / cgroup driver; an empty `info` makes kubeadm log
        // `no 'config' field in CRI info`.
        let mut info = std::collections::HashMap::new();
        if request.into_inner().verbose {
            let config = serde_json::json!({
                "sandboxImage": "registry.k8s.io/pause:3.10",
                "cgroupDriver": "cgroupfs",
                "snapshotter": "overlayfs",
                "defaultRuntimeName": "crun",
                "rootDir": self.ctx.snapshots_root.display().to_string(),
                "stateDir": self.ctx.state_dir.display().to_string(),
            });
            info.insert("config".to_string(), config.to_string());
            info.insert(
                "runtime".to_string(),
                serde_json::json!({
                    "name": "containerd-rs",
                    "version": env!("CARGO_PKG_VERSION"),
                })
                .to_string(),
            );
        }
        Ok(Response::new(v1::StatusResponse {
            status: Some(status),
            info,
            runtime_handlers: Vec::new(),
            features: None,
        }))
    }

    // Streaming RPCs (unimplemented): named concrete stream types are required
    // by the trait even though we never construct them.
    type StreamPodSandboxesStream = BoxStream<v1::StreamPodSandboxesResponse>;
    async fn stream_pod_sandboxes(
        &self,
        _request: Request<v1::StreamPodSandboxesRequest>,
    ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
        Err(Status::unimplemented(
            "stream_pod_sandboxes not yet implemented",
        ))
    }

    type StreamContainersStream = BoxStream<v1::StreamContainersResponse>;
    async fn stream_containers(
        &self,
        _request: Request<v1::StreamContainersRequest>,
    ) -> Result<Response<Self::StreamContainersStream>, Status> {
        Err(Status::unimplemented(
            "stream_containers not yet implemented",
        ))
    }

    type StreamContainerStatsStream = BoxStream<v1::StreamContainerStatsResponse>;
    async fn stream_container_stats(
        &self,
        _request: Request<v1::StreamContainerStatsRequest>,
    ) -> Result<Response<Self::StreamContainerStatsStream>, Status> {
        Err(Status::unimplemented(
            "stream_container_stats not yet implemented",
        ))
    }

    type StreamPodSandboxStatsStream = BoxStream<v1::StreamPodSandboxStatsResponse>;
    async fn stream_pod_sandbox_stats(
        &self,
        _request: Request<v1::StreamPodSandboxStatsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxStatsStream>, Status> {
        Err(Status::unimplemented(
            "stream_pod_sandbox_stats not yet implemented",
        ))
    }

    type GetContainerEventsStream = BoxStream<v1::ContainerEventResponse>;
    async fn get_container_events(
        &self,
        _request: Request<v1::GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        // Subscribe to the lifecycle bus and stream events until the client
        // disconnects. Lagged subscribers skip missed events rather than error;
        // a closed sender ends the stream (feature 002 US3 / T026).
        let rx = self.ctx.container_events.subscribe();
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => return Some((Ok(ev), rx)),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
        Ok(Response::new(Box::pin(stream)))
    }

    type StreamPodSandboxMetricsStream = BoxStream<v1::StreamPodSandboxMetricsResponse>;
    async fn stream_pod_sandbox_metrics(
        &self,
        _request: Request<v1::StreamPodSandboxMetricsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxMetricsStream>, Status> {
        Err(Status::unimplemented(
            "stream_pod_sandbox_metrics not yet implemented",
        ))
    }

    async fn run_pod_sandbox(
        &self,
        request: Request<v1::RunPodSandboxRequest>,
    ) -> Result<Response<v1::RunPodSandboxResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("pod sandbox config required"))?;
        let meta = config.metadata.clone().unwrap_or_default();
        let id = self.gen_id(&format!("{}/{}/{}", meta.namespace, meta.name, meta.uid));

        let cgroup_parent = config
            .linux
            .as_ref()
            .map(|l| l.cgroup_parent.clone())
            .unwrap_or_default();
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

        // Namespace modes from the pod sandbox (NODE == share host). Network
        // drives CNI vs host-net; pid/ipc are applied per-container (HostPID/HostIPC).
        let ns_opts = config
            .linux
            .as_ref()
            .and_then(|l| l.security_context.as_ref())
            .and_then(|sc| sc.namespace_options.as_ref());
        let node = v1::NamespaceMode::Node as i32;
        let pod = v1::NamespaceMode::Pod as i32;
        let host_network = ns_opts.map(|ns| ns.network == node).unwrap_or(false);
        let host_pid = ns_opts.map(|ns| ns.pid == node).unwrap_or(false);
        let host_ipc = ns_opts.map(|ns| ns.ipc == node).unwrap_or(false);
        // Pod-level PID/IPC sharing (shareProcessNamespace): containers join a
        // shared namespace owned by a holder process (we run no pause container).
        // Only when namespace_options is explicitly present — a pod with no
        // options keeps per-container namespaces. Not when sharing the host's.
        let shared_pid = !host_pid && ns_opts.map(|ns| ns.pid == pod).unwrap_or(false);
        let shared_ipc = !host_ipc && ns_opts.map(|ns| ns.ipc == pod).unwrap_or(false);

        // Returns (netns_path, pod_ip). For a CNI pod we create a netns + run the
        // plugin chain; if CNI is unavailable/fails we tear down best-effort and
        // return Status::unavailable so the kubelet retries once CNI is ready.
        // Pod hostPort declarations -> CNI portmap capability arg.
        let port_mappings: Vec<sandbox::cni::PortMapping> = config
            .port_mappings
            .iter()
            .map(|pm| sandbox::cni::PortMapping {
                host_port: pm.host_port,
                container_port: pm.container_port,
                protocol: match pm.protocol {
                    1 => "udp",
                    2 => "sctp",
                    _ => "tcp",
                }
                .to_string(),
                host_ip: pm.host_ip.clone(),
            })
            .collect();
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
        if netns_path == "host" {
            tracing::info!(sandbox = %id, %ip, "RunPodSandbox (host network)");
        }

        // Generate the pod's resolv.conf from the CRI DNSConfig and stash it in the
        // sandbox state dir; each container bind-mounts it at /etc/resolv.conf.
        // Falls back to the node's /etc/resolv.conf when no DNS config is supplied.
        let resolv_conf_path = self.write_sandbox_resolv_conf(&id, config.dns_config.as_ref());

        // Pod-shared PID/IPC namespace holder (shareProcessNamespace): a PID-1
        // process owning the shared namespace that workload containers join.
        let pid_holder_pid = if shared_pid || shared_ipc {
            match sandbox::pid_holder::spawn_holder(&self.ctx.state_dir, &id) {
                Ok(h) => {
                    tracing::info!(sandbox = %id, holder = h.pid, shared_pid, shared_ipc, "spawned pod PID/IPC namespace holder");
                    Some(h.pid)
                }
                Err(e) => {
                    tracing::warn!(sandbox = %id, error = %e, "failed to spawn pod PID/IPC namespace holder; containers will not share it");
                    None
                }
            }
        } else {
            None
        };

        let rec = SandboxRecord {
            id: id.clone(),
            name: meta.name,
            k8s_namespace: meta.namespace,
            uid: meta.uid,
            attempt: meta.attempt,
            state: SandboxState::Ready,
            netns_path: Some(netns_path),
            ip: Some(ip),
            runtime_handler: req.runtime_handler,
            pause_container_id: None,
            snapshot_key: None,
            created_at: unix_nanos() as u64,
            labels: config.labels,
            annotations: config.annotations,
            log_directory: config.log_directory,
            host_network,
            host_pid,
            host_ipc,
            shared_pid,
            shared_ipc,
            pid_holder_pid,
            resolv_conf_path,
            sysctls: config
                .linux
                .as_ref()
                .map(|l| l.sysctls.clone())
                .unwrap_or_default(),
            cgroup_parent,
            hostname: config.hostname.clone(),
        };
        // Demote any prior sandbox for the same pod (namespace/name/uid) to
        // NotReady. `gen_id` salts with a timestamp, so each call mints a fresh
        // id; without this the old Ready records linger and the kubelet sees
        // `readySandboxCount > 1`, which also forces sandbox recreation.
        if let Ok(existing) = self
            .ctx
            .metadata
            .list::<SandboxRecord>(Kind::Sandbox, self.ns())
        {
            for mut other in existing {
                if other.id != id
                    && other.state == SandboxState::Ready
                    && other.name == rec.name
                    && other.k8s_namespace == rec.k8s_namespace
                    && other.uid == rec.uid
                {
                    other.state = SandboxState::NotReady;
                    let oid = other.id.clone();
                    let _ = self
                        .ctx
                        .metadata
                        .put(Kind::Sandbox, self.ns(), &oid, &other);
                }
            }
        }
        self.ctx
            .metadata
            .put(Kind::Sandbox, self.ns(), &id, &rec)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(v1::RunPodSandboxResponse {
            pod_sandbox_id: id,
        }))
    }

    async fn pod_sandbox_status(
        &self,
        request: Request<v1::PodSandboxStatusRequest>,
    ) -> Result<Response<v1::PodSandboxStatusResponse>, Status> {
        let id = request.into_inner().pod_sandbox_id;
        let rec: SandboxRecord = self
            .ctx
            .metadata
            .get(Kind::Sandbox, self.ns(), &id)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("sandbox {id} not found")))?;
        let status = v1::PodSandboxStatus {
            id: rec.id.clone(),
            metadata: Some(sandbox_metadata(&rec)),
            state: sandbox_state_i32(rec.state),
            created_at: rec.created_at as i64,
            network: rec.ip.as_ref().map(|ip| v1::PodSandboxNetworkStatus {
                ip: ip.clone(),
                additional_ips: Vec::new(),
            }),
            // Report the network namespace mode so the kubelet's
            // `podSandboxChanged` check (which compares this against the pod's
            // desired mode) matches; otherwise it recreates the sandbox forever.
            linux: Some(v1::LinuxPodSandboxStatus {
                namespaces: Some(v1::Namespace {
                    options: Some(v1::NamespaceOption {
                        network: if rec.host_network {
                            v1::NamespaceMode::Node as i32
                        } else {
                            v1::NamespaceMode::Pod as i32
                        },
                        pid: if rec.host_pid {
                            v1::NamespaceMode::Node as i32
                        } else {
                            v1::NamespaceMode::Container as i32
                        },
                        ipc: if rec.host_ipc {
                            v1::NamespaceMode::Node as i32
                        } else {
                            v1::NamespaceMode::Pod as i32
                        },
                        target_id: String::new(),
                        userns_options: None,
                    }),
                }),
            }),
            labels: rec.labels,
            annotations: rec.annotations,
            runtime_handler: rec.runtime_handler,
        };
        Ok(Response::new(v1::PodSandboxStatusResponse {
            status: Some(status),
            info: std::collections::HashMap::new(),
            containers_statuses: Vec::new(),
            timestamp: unix_nanos(),
        }))
    }

    async fn list_pod_sandbox(
        &self,
        request: Request<v1::ListPodSandboxRequest>,
    ) -> Result<Response<v1::ListPodSandboxResponse>, Status> {
        let filter = request.into_inner().filter;
        let records: Vec<SandboxRecord> = self
            .ctx
            .metadata
            .list(Kind::Sandbox, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        let items = records
            .into_iter()
            .filter(|r| {
                filter.as_ref().is_none_or(|f| {
                    (f.id.is_empty() || f.id == r.id)
                        && f.state
                            .as_ref()
                            .is_none_or(|s| s.state == sandbox_state_i32(r.state))
                        && f.label_selector
                            .iter()
                            .all(|(k, v)| r.labels.get(k).is_some_and(|rv| rv == v))
                })
            })
            .map(|r| v1::PodSandbox {
                id: r.id.clone(),
                metadata: Some(sandbox_metadata(&r)),
                state: sandbox_state_i32(r.state),
                created_at: r.created_at as i64,
                labels: r.labels,
                annotations: r.annotations,
                runtime_handler: r.runtime_handler,
            })
            .collect();
        Ok(Response::new(v1::ListPodSandboxResponse { items }))
    }

    async fn stop_pod_sandbox(
        &self,
        request: Request<v1::StopPodSandboxRequest>,
    ) -> Result<Response<v1::StopPodSandboxResponse>, Status> {
        let id = request.into_inner().pod_sandbox_id;
        if let Some(mut rec) = self
            .ctx
            .metadata
            .get::<SandboxRecord>(Kind::Sandbox, self.ns(), &id)
            .map_err(|e| Status::internal(e.to_string()))?
        {
            rec.state = SandboxState::NotReady;
            // The pod's containers are stopping; tear down the shared PID/IPC
            // namespace holder (its PID 1 exiting frees the namespace).
            if let Some(holder) = rec.pid_holder_pid.take() {
                sandbox::pid_holder::kill_holder(holder);
            }
            self.ctx
                .metadata
                .put(Kind::Sandbox, self.ns(), &id, &rec)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(v1::StopPodSandboxResponse {}))
    }

    async fn remove_pod_sandbox(
        &self,
        request: Request<v1::RemovePodSandboxRequest>,
    ) -> Result<Response<v1::RemovePodSandboxResponse>, Status> {
        let id = request.into_inner().pod_sandbox_id;
        // Tear down CNI networking for a real per-pod netns (no-op for host net).
        if let Ok(Some(rec)) = self
            .ctx
            .metadata
            .get::<SandboxRecord>(Kind::Sandbox, self.ns(), &id)
        {
            if rec.netns_path.as_deref().is_some_and(|p| p != "host") {
                let _ = self.ctx.cni.teardown(&id, &id);
            }
            // Belt-and-suspenders: reap the ns holder if StopPodSandbox didn't.
            if let Some(holder) = rec.pid_holder_pid {
                sandbox::pid_holder::kill_holder(holder);
            }
        }
        self.ctx
            .metadata
            .delete(Kind::Sandbox, self.ns(), &id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(v1::RemovePodSandboxResponse {}))
    }

    async fn create_container(
        &self,
        request: Request<v1::CreateContainerRequest>,
    ) -> Result<Response<v1::CreateContainerResponse>, Status> {
        let req = request.into_inner();
        let sandbox_id = req.pod_sandbox_id;
        // The sandbox must exist; the container joins its network namespace.
        let sandbox: SandboxRecord = self
            .ctx
            .metadata
            .get(Kind::Sandbox, self.ns(), &sandbox_id)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("sandbox {sandbox_id} not found")))?;

        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("container config required"))?;
        let meta = config.metadata.clone().unwrap_or_default();
        let image_ref = config.image.clone().map(|s| s.image).unwrap_or_default();
        let id = self.gen_id(&format!("{sandbox_id}/{}/{}", meta.name, meta.attempt));

        // Resolve the image (best-effort: a missing image yields an empty base
        // config + no layers rather than failing the bookkeeping).
        let image_rec = self.find_image(&image_ref)?;
        let image_id = image_rec
            .as_ref()
            .map(|r| r.image_id.clone())
            .unwrap_or_default();
        let image_cfg = self.parse_image_config(&image_id);
        let layers = image_rec.map(|r| r.layer_digests).unwrap_or_default();

        // Use a rootless spec (user namespace + uid/gid mapping) only when the
        // daemon itself is non-root. As root (e.g. inside a privileged
        // kind/Docker node), a rootless spec's userns + dropped caps make crun's
        // init exec fail ("fork/exec /proc/self/fd/N: permission denied"), so use
        // a full root spec instead.
        let uid = rustix::process::getuid().as_raw();
        let host_ids = if uid == 0 {
            None
        } else {
            Some((uid, rustix::process::getgid().as_raw()))
        };
        let sec_ctx = config
            .linux
            .as_ref()
            .and_then(|l| l.security_context.as_ref());
        let privileged = sec_ctx.map(|sc| sc.privileged).unwrap_or(false);
        let run_as_user = sec_ctx
            .and_then(|sc| sc.run_as_user.as_ref())
            .map(|v| v.value as u32);
        let run_as_group = sec_ctx
            .and_then(|sc| sc.run_as_group.as_ref())
            .map(|v| v.value as u32);
        // CRI: RunAsGroup set without a user (RunAsUser or RunAsUsername) must be
        // rejected at CreateContainer — the runtime has no uid to pair with the
        // requested gid. Mirrors containerd's validation; cri-tools asserts it.
        let has_run_as_user = run_as_user.is_some()
            || sec_ctx
                .map(|sc| !sc.run_as_username.is_empty())
                .unwrap_or(false);
        if run_as_group.is_some() && !has_run_as_user {
            return Err(Status::invalid_argument(
                "RunAsGroup is specified without RunAsUser",
            ));
        }
        let container_req = runtime::bundle::ContainerRequest {
            command: config.command.clone(),
            args: config.args.clone(),
            envs: config
                .envs
                .iter()
                .map(|kv| {
                    (
                        kv.key.clone(),
                        String::from_utf8_lossy(&kv.value).into_owned(),
                    )
                })
                .collect(),
            working_dir: (!config.working_dir.is_empty()).then(|| config.working_dir.clone()),
            // Apply the pod's hostname in the container's (private) UTS namespace.
            // Host-network pods share the host UTS ns, so leave it to the node's.
            hostname: (!sandbox.host_network && !sandbox.hostname.is_empty())
                .then(|| sandbox.hostname.clone()),
            terminal: config.tty,
            readonly_rootfs: sec_ctx.map(|sc| sc.readonly_rootfs).unwrap_or(false),
            rootless_host_ids: host_ids,
            netns_path: sandbox.netns_path.clone(),
            // Join the sandbox's shared PID/IPC namespace holder when the pod
            // requested shareProcessNamespace (pod-level PID/IPC).
            pid_ns_path: sandbox
                .shared_pid
                .then_some(sandbox.pid_holder_pid)
                .flatten()
                .map(|p| format!("/proc/{p}/ns/pid")),
            ipc_ns_path: sandbox
                .shared_ipc
                .then_some(sandbox.pid_holder_pid)
                .flatten()
                .map(|p| format!("/proc/{p}/ns/ipc")),
            mounts: {
                let mut mounts: Vec<runtime::bundle::MountSpec> = config
                    .mounts
                    .iter()
                    .map(|m| runtime::bundle::MountSpec {
                        source: m.host_path.clone(),
                        destination: m.container_path.clone(),
                        readonly: m.readonly,
                        propagation: match m.propagation {
                            x if x == v1::MountPropagation::PropagationHostToContainer as i32 => {
                                runtime::bundle::Propagation::HostToContainer
                            }
                            x if x == v1::MountPropagation::PropagationBidirectional as i32 => {
                                runtime::bundle::Propagation::Bidirectional
                            }
                            _ => runtime::bundle::Propagation::Private,
                        },
                        recursive_read_only: m.recursive_read_only,
                    })
                    .collect();
                // Bind the pod's generated resolv.conf at /etc/resolv.conf unless the
                // container already mounts there (kubelet sometimes manages it).
                if let Some(rc) = &sandbox.resolv_conf_path {
                    let has_resolv = mounts.iter().any(|m| m.destination == "/etc/resolv.conf");
                    if !has_resolv && std::path::Path::new(rc).is_file() {
                        mounts.push(runtime::bundle::MountSpec {
                            source: rc.clone(),
                            destination: "/etc/resolv.conf".to_string(),
                            readonly: true,
                            propagation: runtime::bundle::Propagation::Private,
                            recursive_read_only: false,
                        });
                    }
                }
                mounts
            },
            privileged,
            run_as_user,
            run_as_group,
            supplemental_groups: sec_ctx
                .map(|sc| sc.supplemental_groups.iter().map(|&g| g as u32).collect())
                .unwrap_or_default(),
            sysctls: sandbox.sysctls.clone(),
            resources: config
                .linux
                .as_ref()
                .and_then(|l| l.resources.as_ref())
                .map(cri_resources)
                .unwrap_or_default(),
            cgroup_path: (!sandbox.cgroup_parent.is_empty())
                .then(|| cgroups_path(&sandbox.cgroup_parent, &id)),
            add_capabilities: sec_ctx
                .and_then(|sc| sc.capabilities.as_ref())
                .map(|c| c.add_capabilities.clone())
                .unwrap_or_default(),
            drop_capabilities: sec_ctx
                .and_then(|sc| sc.capabilities.as_ref())
                .map(|c| c.drop_capabilities.clone())
                .unwrap_or_default(),
            no_new_privileges: sec_ctx.map(|sc| sc.no_new_privs).unwrap_or(false),
            apparmor_profile: map_apparmor(sec_ctx.and_then(|sc| sc.apparmor.as_ref())),
            // Only emit a SELinux label when the host actually has SELinux
            // enabled; otherwise the runtime's write to /proc/self/attr/* fails
            // with EINVAL and crashes the container (see host_selinux_enabled).
            selinux_label: host_selinux_enabled()
                .then(|| map_selinux(sec_ctx.and_then(|sc| sc.selinux_options.as_ref())))
                .flatten(),
            masked_paths: sec_ctx
                .map(|sc| sc.masked_paths.clone())
                .unwrap_or_default(),
            readonly_paths: sec_ctx
                .map(|sc| sc.readonly_paths.clone())
                .unwrap_or_default(),
            seccomp: map_seccomp(sec_ctx.and_then(|sc| sc.seccomp.as_ref())),
            // HostPID/HostIPC come from the pod sandbox's namespace options.
            host_pid: sandbox.host_pid,
            host_ipc: sandbox.host_ipc,
        };

        // Build the bundle: merge image layers into a single rootfs, then write
        // a rootless config.json over it.
        let bundle = runtime::shim::Bundle::new(&self.ctx.state_dir, self.ns(), &id);
        bundle
            .create()
            .map_err(|e| Status::internal(e.to_string()))?;
        self.unpack_rootfs(&layers, &bundle.rootfs())?;
        let spec = runtime::bundle::generate_spec(&image_cfg, &container_req, &bundle.rootfs())
            .map_err(|e| Status::internal(e.to_string()))?;
        runtime::bundle::write_bundle(bundle.dir(), &spec)
            .map_err(|e| Status::internal(e.to_string()))?;

        let rec = ContainerRecord {
            id: id.clone(),
            sandbox_id,
            name: meta.name,
            attempt: meta.attempt,
            image_ref,
            image_id,
            state: ContainerState::Created,
            snapshot_key: String::new(),
            // CRI log_path is relative to the sandbox log_directory; resolve to
            // an absolute path so kubelet/crictl find the log where they expect.
            log_path: {
                let lp = std::path::Path::new(&config.log_path);
                if lp.is_absolute() || sandbox.log_directory.is_empty() {
                    config.log_path.clone()
                } else {
                    std::path::Path::new(&sandbox.log_directory)
                        .join(&config.log_path)
                        .display()
                        .to_string()
                }
            },
            created_at: unix_nanos() as u64,
            started_at: None,
            finished_at: None,
            exit_code: None,
            reason: None,
            labels: config.labels.clone(),
            annotations: config.annotations.clone(),
            // Echo only the CRI-requested mounts in ContainerStatus.Mounts — NOT
            // the internally-injected ones (e.g. the pod's resolv.conf bind). The
            // kubelet/critest assert this list matches exactly what they asked for
            // (critest non-recursive-readonly expects len == requested).
            mounts: config
                .mounts
                .iter()
                .map(|m| MountRecord {
                    host_path: m.host_path.clone(),
                    container_path: m.container_path.clone(),
                    readonly: m.readonly,
                    propagation: m.propagation,
                    recursive_read_only: m.recursive_read_only,
                })
                .collect(),
            resources: config
                .linux
                .as_ref()
                .and_then(|l| l.resources.as_ref())
                .map(resources_record),
            // Re-adoption fields are populated when the container is started
            // (see restart-survival wiring, feature 002 US1). Unset at creation.
            crun_root: None,
            bundle_dir: None,
            pid: None,
            restart_count: 0,
            stdin: config.stdin,
            stdin_once: config.stdin_once,
        };

        // Touch the CRI LogPath synchronously so the kubelet / crictl can
        // stat/open it as soon as the container is in the Created state.
        // supervise_container will later re-open it for append, so we only
        // need an empty placeholder here.  Errors are non-fatal — if the
        // directory doesn't exist yet we still record the container.
        if !rec.log_path.is_empty() {
            let lp = std::path::Path::new(&rec.log_path);
            if lp.is_absolute() {
                if let Some(parent) = lp.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(lp);
            }
        }

        self.ctx
            .metadata
            .put(Kind::Container, self.ns(), &id, &rec)
            .map_err(|e| Status::internal(e.to_string()))?;
        tracing::info!(container = %id, "CreateContainer wrote OCI bundle + record");
        self.ctx
            .emit_container_event(&id, v1::ContainerEventType::ContainerCreatedEvent);
        Ok(Response::new(v1::CreateContainerResponse {
            container_id: id,
        }))
    }

    async fn container_status(
        &self,
        request: Request<v1::ContainerStatusRequest>,
    ) -> Result<Response<v1::ContainerStatusResponse>, Status> {
        let id = request.into_inner().container_id;
        let rec = self
            .get_container(&id)?
            .ok_or_else(|| Status::not_found(format!("container {id} not found")))?;
        let status = v1::ContainerStatus {
            id: rec.id.clone(),
            metadata: Some(v1::ContainerMetadata {
                name: rec.name.clone(),
                attempt: rec.attempt,
            }),
            state: container_state_i32(rec.state),
            created_at: rec.created_at as i64,
            started_at: rec.started_at.unwrap_or(0) as i64,
            finished_at: rec.finished_at.unwrap_or(0) as i64,
            exit_code: rec.exit_code.unwrap_or(0),
            image: Some(v1::ImageSpec {
                image: rec.image_ref.clone(),
                ..Default::default()
            }),
            image_ref: rec.image_id.clone(),
            reason: rec.reason.clone().unwrap_or_default(),
            message: String::new(),
            labels: rec.labels.clone(),
            annotations: rec.annotations.clone(),
            mounts: rec
                .mounts
                .iter()
                .map(|m| v1::Mount {
                    host_path: m.host_path.clone(),
                    container_path: m.container_path.clone(),
                    readonly: m.readonly,
                    propagation: m.propagation,
                    recursive_read_only: m.recursive_read_only,
                    ..Default::default()
                })
                .collect(),
            log_path: rec.log_path.clone(),
            resources: rec.resources.as_ref().map(record_to_cri_resources),
            image_id: rec.image_id.clone(),
            user: None,
            stop_signal: 0,
        };
        Ok(Response::new(v1::ContainerStatusResponse {
            status: Some(status),
            info: std::collections::HashMap::new(),
        }))
    }

    async fn list_containers(
        &self,
        request: Request<v1::ListContainersRequest>,
    ) -> Result<Response<v1::ListContainersResponse>, Status> {
        let filter = request.into_inner().filter;
        let records: Vec<ContainerRecord> = self
            .ctx
            .metadata
            .list(Kind::Container, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        let containers = records
            .into_iter()
            .filter(|r| {
                filter.as_ref().is_none_or(|f| {
                    (f.id.is_empty() || f.id == r.id)
                        && (f.pod_sandbox_id.is_empty() || f.pod_sandbox_id == r.sandbox_id)
                        && f.state
                            .as_ref()
                            .is_none_or(|s| s.state == container_state_i32(r.state))
                        && f.label_selector
                            .iter()
                            .all(|(k, v)| r.labels.get(k).is_some_and(|rv| rv == v))
                })
            })
            .map(|r| v1::Container {
                id: r.id.clone(),
                pod_sandbox_id: r.sandbox_id.clone(),
                metadata: Some(v1::ContainerMetadata {
                    name: r.name.clone(),
                    attempt: r.attempt,
                }),
                image: Some(v1::ImageSpec {
                    image: r.image_ref.clone(),
                    ..Default::default()
                }),
                image_ref: r.image_id.clone(),
                state: container_state_i32(r.state),
                created_at: r.created_at as i64,
                labels: r.labels.clone(),
                annotations: r.annotations.clone(),
                image_id: r.image_id.clone(),
            })
            .collect();
        Ok(Response::new(v1::ListContainersResponse { containers }))
    }

    async fn stop_container(
        &self,
        request: Request<v1::StopContainerRequest>,
    ) -> Result<Response<v1::StopContainerResponse>, Status> {
        let req = request.into_inner();
        let id = req.container_id;
        let timeout_secs = req.timeout; // 0 = force-kill immediately

        if let Some(rec) = self.get_container(&id)? {
            if rec.state != ContainerState::Exited {
                let crun_root = self.ctx.state_dir.join("crun");
                let ctx = self.ctx.clone();
                let ns = self.ns().to_string();

                // Step 1: Send SIGTERM (best-effort; crun may not know the
                // container if it was never started).
                {
                    let crun_root2 = crun_root.clone();
                    let id2 = id.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        runtime::crun::kill(
                            runtime::crun::DEFAULT_BIN,
                            &crun_root2,
                            &id2,
                            "SIGTERM",
                        )
                    })
                    .await;
                }

                // Step 2: If timeout > 0, poll the metadata store until the
                // supervise task flips the state to Exited (it calls child.wait()
                // after crun run returns, which SIGTERM triggers).
                let exited_gracefully = if timeout_secs > 0 {
                    let deadline = std::time::Instant::now()
                        + std::time::Duration::from_secs(timeout_secs as u64);
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        match ctx
                            .metadata
                            .get::<ContainerRecord>(Kind::Container, &ns, &id)
                        {
                            Ok(Some(r)) if r.state == ContainerState::Exited => break true,
                            _ => {}
                        }
                        if std::time::Instant::now() >= deadline {
                            break false;
                        }
                    }
                } else {
                    // timeout=0: caller wants immediate force-kill.
                    false
                };

                // Step 3: If still not exited, escalate to SIGKILL then
                // force-delete the crun container to reap any process tree.
                if !exited_gracefully {
                    let crun_root2 = crun_root.clone();
                    let id2 = id.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = runtime::crun::kill(
                            runtime::crun::DEFAULT_BIN,
                            &crun_root2,
                            &id2,
                            "KILL",
                        );
                        // Force-delete sweeps any surviving process tree even if
                        // crun kill above raced or the init ignored the signal.
                        let _ =
                            runtime::crun::delete(runtime::crun::DEFAULT_BIN, &crun_root2, &id2);
                    })
                    .await;
                }

                // Step 4: Re-read the record — the supervise task may have already
                // written the real exit code; only overwrite if still not Exited.
                if let Ok(Some(mut updated)) =
                    ctx.metadata
                        .get::<ContainerRecord>(Kind::Container, &ns, &id)
                {
                    if updated.state != ContainerState::Exited {
                        // Supervise task didn't update yet (or container was
                        // Created, never Running). Record a forced exit.
                        updated.state = ContainerState::Exited;
                        updated.finished_at = Some(unix_nanos() as u64);
                        // -1 signals a forced/unclean exit (not a graceful 0).
                        updated.exit_code = Some(-1);
                        updated.reason = Some("Error".to_string());
                        ctx.metadata
                            .put(Kind::Container, &ns, &id, &updated)
                            .map_err(|e| Status::internal(e.to_string()))?;
                    }
                }
            }
        }
        self.ctx
            .emit_container_event(&id, v1::ContainerEventType::ContainerStoppedEvent);
        Ok(Response::new(v1::StopContainerResponse {}))
    }

    async fn remove_container(
        &self,
        request: Request<v1::RemoveContainerRequest>,
    ) -> Result<Response<v1::RemoveContainerResponse>, Status> {
        let id = request.into_inner().container_id;
        // Force-delete any leftover crun state, then drop record + bundle.
        let crun_root = self.ctx.state_dir.join("crun");
        let id2 = id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            runtime::crun::delete(runtime::crun::DEFAULT_BIN, &crun_root, &id2)
        })
        .await;
        self.ctx
            .metadata
            .delete(Kind::Container, self.ns(), &id)
            .map_err(|e| Status::internal(e.to_string()))?;
        let _ = runtime::shim::Bundle::new(&self.ctx.state_dir, self.ns(), &id).remove();
        self.ctx
            .emit_container_event(&id, v1::ContainerEventType::ContainerDeletedEvent);
        Ok(Response::new(v1::RemoveContainerResponse {}))
    }

    async fn start_container(
        &self,
        request: Request<v1::StartContainerRequest>,
    ) -> Result<Response<v1::StartContainerResponse>, Status> {
        let id = request.into_inner().container_id;
        let mut rec = self
            .get_container(&id)?
            .ok_or_else(|| Status::not_found(format!("container {id} not found")))?;
        if rec.state != ContainerState::Created {
            return Err(Status::failed_precondition(format!(
                "container {id} is not in Created state"
            )));
        }

        let bundle = runtime::shim::Bundle::new(&self.ctx.state_dir, self.ns(), &id);
        if !bundle.config_json().is_file() {
            return Err(Status::internal("container bundle config.json missing"));
        }
        let crun_root = self.ctx.state_dir.join("crun");
        std::fs::create_dir_all(&crun_root).map_err(|e| Status::internal(e.to_string()))?;

        let log_path = container_log_path(&bundle, &rec.log_path);

        // A `terminal: true` container needs PTY supervision (console socket).
        let terminal = std::fs::read(bundle.config_json())
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["process"]["terminal"].as_bool())
            .unwrap_or(false);

        // Mark Running before launching; supervision flips it to Exited on exit.
        rec.state = ContainerState::Running;
        rec.started_at = Some(unix_nanos() as u64);
        // Persist re-adoption handles (feature 002 US1 / T009) so that after a
        // daemon restart `reconcile()` can probe `crun state <id>` and re-adopt a
        // still-running container instead of tearing it down.
        rec.crun_root = Some(crun_root.display().to_string());
        rec.bundle_dir = Some(bundle.dir().display().to_string());
        self.ctx
            .metadata
            .put(Kind::Container, self.ns(), &id, &rec)
            .map_err(|e| Status::internal(e.to_string()))?;

        // Supervise the container with LIVE stdio: spawn `crun run` with piped
        // stdout/stderr, stream each chunk to the CRI log file *and* a broadcast
        // bus (for Attach / log-follow), then record the exit code.
        let ctx = self.ctx.clone();
        let ns = self.ns().to_string();
        let cid = id.clone();
        let bundle_dir = bundle.dir().to_path_buf();
        let live = self.ctx.streaming.live_channel(&id);
        let sessions = self.ctx.streaming.clone();
        let stdin_open = rec.stdin;
        let no_pivot = self.ctx.no_pivot_root;
        tokio::spawn(async move {
            let code = supervise_container(
                &crun_root,
                &bundle_dir,
                &cid,
                &log_path,
                live,
                terminal,
                stdin_open,
                no_pivot,
                sessions,
            )
            .await;
            if let Ok(Some(mut r)) = ctx
                .metadata
                .get::<ContainerRecord>(Kind::Container, &ns, &cid)
            {
                r.state = ContainerState::Exited;
                r.exit_code = Some(code);
                r.finished_at = Some(unix_nanos() as u64);
                // CRI terminated-state reason: kubelet maps this to the pod's
                // container `state.terminated.reason` ("Completed"/"Error").
                r.reason = Some(if code == 0 { "Completed" } else { "Error" }.to_string());
                let _ = ctx.metadata.put(Kind::Container, &ns, &cid, &r);
            }
            ctx.emit_container_event(&cid, v1::ContainerEventType::ContainerStoppedEvent);
            ctx.streaming.close_live(&cid);
            ctx.streaming.close_log(&cid);
            ctx.streaming.close_stdin(&cid);
            tracing::info!(container = %cid, exit_code = code, "container exited");
        });

        // `crun run` is spawned asynchronously above, but the kubelet may issue an
        // exec immediately (a container postStart hook is an ExecSync the instant
        // StartContainer returns). Wait until crun has actually registered the
        // container so that exec doesn't fail with "container does not exist".
        let crun_root_wait = self.ctx.state_dir.join("crun");
        let wait_id = id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            for _ in 0..100 {
                if let Ok(o) =
                    runtime::crun::state(runtime::crun::DEFAULT_BIN, &crun_root_wait, &wait_id)
                {
                    if o.status.success() {
                        return;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        })
        .await;

        self.ctx
            .emit_container_event(&id, v1::ContainerEventType::ContainerStartedEvent);
        Ok(Response::new(v1::StartContainerResponse {}))
    }

    async fn exec_sync(
        &self,
        request: Request<v1::ExecSyncRequest>,
    ) -> Result<Response<v1::ExecSyncResponse>, Status> {
        let req = request.into_inner();
        if req.cmd.is_empty() {
            return Err(Status::invalid_argument("exec cmd required"));
        }
        self.get_container(&req.container_id)?.ok_or_else(|| {
            Status::not_found(format!("container {} not found", req.container_id))
        })?;

        let crun_root = self.ctx.state_dir.join("crun");
        let id = req.container_id.clone();
        let cmd = req.cmd.clone();
        // Have crun write the exec'd process's host-visible PID here. On timeout
        // we must SIGKILL *that* process: killing our `crun exec` host process is
        // not enough, because crun puts the exec'd process in its own session, so
        // it survives (and the container's `pgrep` still finds it).
        let pid_file = self
            .ctx
            .state_dir
            .join(format!("exec-{id}-{}.pid", unix_nanos()));

        let mut command = tokio::process::Command::new(runtime::crun::DEFAULT_BIN);
        command
            .arg("--root")
            .arg(&crun_root)
            .arg("exec")
            .arg("--pid-file")
            .arg(&pid_file)
            .arg(&id)
            .args(&cmd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0);
        let child = command
            .spawn()
            .map_err(|e| Status::internal(format!("crun exec: {e}")))?;
        // With process_group(0), the child is its own group leader, so pgid == pid.
        let pgid = child.id();
        let waiter = tokio::spawn(async move { child.wait_with_output().await });

        let out = if req.timeout > 0 {
            let dur = std::time::Duration::from_secs(req.timeout as u64);
            match tokio::time::timeout(dur, waiter).await {
                Ok(joined) => {
                    let _ = std::fs::remove_file(&pid_file);
                    joined
                        .map_err(|e| Status::internal(e.to_string()))?
                        .map_err(|e| Status::internal(format!("crun exec: {e}")))?
                }
                Err(_) => {
                    // Timed out: SIGKILL the exec'd process by its host PID (from
                    // the pid-file), then the crun-exec process group as a backstop.
                    if let Some(pid) = std::fs::read_to_string(&pid_file)
                        .ok()
                        .and_then(|t| t.trim().parse::<i32>().ok())
                        .and_then(rustix::process::Pid::from_raw)
                    {
                        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                    }
                    if let Some(p) = pgid.and_then(|g| rustix::process::Pid::from_raw(g as i32)) {
                        let _ =
                            rustix::process::kill_process_group(p, rustix::process::Signal::KILL);
                    }
                    let _ = std::fs::remove_file(&pid_file);
                    return Err(Status::deadline_exceeded(format!(
                        "exec timed out after {}s",
                        req.timeout
                    )));
                }
            }
        } else {
            let out = waiter
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .map_err(|e| Status::internal(format!("crun exec: {e}")))?;
            let _ = std::fs::remove_file(&pid_file);
            out
        };

        Ok(Response::new(v1::ExecSyncResponse {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.status.code().unwrap_or(-1),
        }))
    }

    async fn exec(
        &self,
        request: Request<v1::ExecRequest>,
    ) -> Result<Response<v1::ExecResponse>, Status> {
        let req = request.into_inner();
        if req.cmd.is_empty() {
            return Err(Status::invalid_argument("exec cmd required"));
        }
        self.get_container(&req.container_id)?.ok_or_else(|| {
            Status::not_found(format!("container {} not found", req.container_id))
        })?;

        // Return a one-time URL into the streaming server (kubelet connects there).
        let token = self
            .ctx
            .streaming
            .register_exec(crate::streaming::ExecSession {
                container_id: req.container_id,
                cmd: req.cmd,
                tty: req.tty,
                stdin: req.stdin,
                stdout: req.stdout,
                stderr: req.stderr,
            });
        Ok(Response::new(v1::ExecResponse {
            url: format!("{}/exec/{}", self.ctx.stream_base_url, token),
        }))
    }

    async fn container_stats(
        &self,
        request: Request<v1::ContainerStatsRequest>,
    ) -> Result<Response<v1::ContainerStatsResponse>, Status> {
        let id = request.into_inner().container_id;
        let rec = self
            .get_container(&id)?
            .ok_or_else(|| Status::not_found(format!("container {id} not found")))?;
        let stats = self.container_stats_for(&rec).await;
        Ok(Response::new(v1::ContainerStatsResponse { stats }))
    }

    async fn pod_sandbox_stats(
        &self,
        request: Request<v1::PodSandboxStatsRequest>,
    ) -> Result<Response<v1::PodSandboxStatsResponse>, Status> {
        let id = request.into_inner().pod_sandbox_id;
        let sb = self
            .ctx
            .metadata
            .get::<SandboxRecord>(Kind::Sandbox, self.ns(), &id)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("sandbox {id} not found")))?;
        let stats = self.pod_sandbox_stats_for(&sb).await;
        Ok(Response::new(v1::PodSandboxStatsResponse {
            stats: Some(stats),
        }))
    }

    async fn list_pod_sandbox_stats(
        &self,
        request: Request<v1::ListPodSandboxStatsRequest>,
    ) -> Result<Response<v1::ListPodSandboxStatsResponse>, Status> {
        let filter = request.into_inner().filter;
        let sandboxes: Vec<SandboxRecord> = self
            .ctx
            .metadata
            .list(Kind::Sandbox, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        let mut stats = Vec::new();
        for sb in sandboxes {
            let keep = filter
                .as_ref()
                .is_none_or(|f| f.id.is_empty() || f.id == sb.id);
            if keep {
                stats.push(self.pod_sandbox_stats_for(&sb).await);
            }
        }
        Ok(Response::new(v1::ListPodSandboxStatsResponse { stats }))
    }

    async fn list_metric_descriptors(
        &self,
        _request: Request<v1::ListMetricDescriptorsRequest>,
    ) -> Result<Response<v1::ListMetricDescriptorsResponse>, Status> {
        Ok(Response::new(v1::ListMetricDescriptorsResponse {
            descriptors: metric_descriptors(),
        }))
    }

    async fn list_pod_sandbox_metrics(
        &self,
        _request: Request<v1::ListPodSandboxMetricsRequest>,
    ) -> Result<Response<v1::ListPodSandboxMetricsResponse>, Status> {
        let sandboxes: Vec<SandboxRecord> = self
            .ctx
            .metadata
            .list(Kind::Sandbox, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        let pod_metrics = sandboxes
            .iter()
            .map(pod_sandbox_metrics_for)
            .collect::<Vec<_>>();
        Ok(Response::new(v1::ListPodSandboxMetricsResponse {
            pod_metrics,
        }))
    }

    async fn list_container_stats(
        &self,
        request: Request<v1::ListContainerStatsRequest>,
    ) -> Result<Response<v1::ListContainerStatsResponse>, Status> {
        let filter = request.into_inner().filter;
        let records: Vec<ContainerRecord> = self
            .ctx
            .metadata
            .list(Kind::Container, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        let mut stats = Vec::new();
        for rec in records {
            let keep = filter.as_ref().is_none_or(|f| {
                (f.id.is_empty() || f.id == rec.id)
                    && (f.pod_sandbox_id.is_empty() || f.pod_sandbox_id == rec.sandbox_id)
                    // label_selector: keep only containers whose labels are a
                    // superset of every selector entry (critest filter-by-labels).
                    && f.label_selector
                        .iter()
                        .all(|(k, v)| rec.labels.get(k).is_some_and(|rv| rv == v))
            });
            if !keep {
                continue;
            }
            if let Some(s) = self.container_stats_for(&rec).await {
                stats.push(s);
            }
        }
        Ok(Response::new(v1::ListContainerStatsResponse { stats }))
    }

    async fn attach(
        &self,
        request: Request<v1::AttachRequest>,
    ) -> Result<Response<v1::AttachResponse>, Status> {
        let req = request.into_inner();
        let rec = self.get_container(&req.container_id)?.ok_or_else(|| {
            Status::not_found(format!("container {} not found", req.container_id))
        })?;
        let token = self
            .ctx
            .streaming
            .register_attach(crate::streaming::AttachSession {
                container_id: req.container_id,
                stdin: req.stdin,
                stdout: req.stdout,
                stderr: req.stderr,
                tty: req.tty,
                stdin_once: rec.stdin_once,
            });
        Ok(Response::new(v1::AttachResponse {
            url: format!("{}/attach/{}", self.ctx.stream_base_url, token),
        }))
    }

    async fn port_forward(
        &self,
        request: Request<v1::PortForwardRequest>,
    ) -> Result<Response<v1::PortForwardResponse>, Status> {
        let req = request.into_inner();
        // Sandbox must exist; ports are carried over the stream by the client.
        let sandbox = self
            .ctx
            .metadata
            .get::<SandboxRecord>(Kind::Sandbox, self.ns(), &req.pod_sandbox_id)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!("sandbox {} not found", req.pod_sandbox_id))
            })?;
        // Where to dial the forwarded port:
        // * host-network pod: its ports live in the (shared) host netns, reachable
        //   at localhost from the daemon — NOT necessarily at the node's external
        //   IP (the server may bind 127.0.0.1). Dial 127.0.0.1.
        // * pod-network pod: dial the pod IP (routable from the host via the CNI
        //   bridge); the port is NOT at the host's 127.0.0.1.
        let host = if sandbox.host_network {
            "127.0.0.1".to_string()
        } else {
            sandbox
                .ip
                .filter(|ip| !ip.is_empty())
                .unwrap_or_else(|| "127.0.0.1".to_string())
        };
        let token = self
            .ctx
            .streaming
            .register_portforward(crate::streaming::PortForwardSession {
                pod_sandbox_id: req.pod_sandbox_id,
                host,
            });
        Ok(Response::new(v1::PortForwardResponse {
            url: format!("{}/portforward/{}", self.ctx.stream_base_url, token),
        }))
    }

    async fn runtime_config(
        &self,
        _request: Request<v1::RuntimeConfigRequest>,
    ) -> Result<Response<v1::RuntimeConfigResponse>, Status> {
        // Report the cgroup driver to the kubelet (cgroupfs; rootless/no systemd).
        Ok(Response::new(v1::RuntimeConfigResponse {
            linux: Some(v1::LinuxRuntimeConfiguration {
                cgroup_driver: v1::CgroupDriver::Cgroupfs as i32,
            }),
        }))
    }

    async fn reopen_container_log(
        &self,
        request: Request<v1::ReopenContainerLogRequest>,
    ) -> Result<Response<v1::ReopenContainerLogResponse>, Status> {
        let id = request.into_inner().container_id;
        let rec = self
            .get_container(&id)?
            .ok_or_else(|| Status::not_found(format!("container {id} not found")))?;
        // Match containerd: reopen is only valid for a running container.
        if rec.state != ContainerState::Running {
            return Err(Status::failed_precondition("container is not running"));
        }
        let bundle = runtime::shim::Bundle::new(&self.ctx.state_dir, self.ns(), &id);
        let log_path = container_log_path(&bundle, &rec.log_path);
        // Open a fresh file at the ORIGINAL path (the kubelet has just renamed the
        // old one away for rotation).
        let new_file = tokio::fs::File::create(&log_path)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        // Swap it into the running supervisor's shared log handle so the
        // stdout/stderr pumps write here from now on — the moved (old) file stops
        // growing. Mirrors containerd's ContainerIO.AddOutput log-writer swap.
        if let Some(handle) = self.ctx.streaming.log_handle(&id) {
            *handle.lock().await = Some(new_file);
        }
        Ok(Response::new(v1::ReopenContainerLogResponse {}))
    }

    /// Live in-place resize: apply the new CPU/memory limits to the running
    /// container's cgroup via `crun update` (cgroup v2 `memory.max`/`cpu.max`/
    /// `cpu.weight`), no restart. Backs Kubernetes in-place pod resize.
    async fn update_container_resources(
        &self,
        request: Request<v1::UpdateContainerResourcesRequest>,
    ) -> Result<Response<v1::UpdateContainerResourcesResponse>, Status> {
        let req = request.into_inner();
        let id = req.container_id;
        let mut rec = self
            .get_container(&id)?
            .ok_or_else(|| Status::not_found(format!("container {id} not found")))?;
        let res = req.linux.as_ref().map(cri_resources).unwrap_or_default();
        let crun_root = self.ctx.state_dir.join("crun");
        let id2 = id.clone();
        let out = tokio::task::spawn_blocking(move || {
            runtime::crun::update(runtime::crun::DEFAULT_BIN, &crun_root, &id2, &res)
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| Status::internal(format!("crun update: {e}")))?;
        if !out.status.success() {
            return Err(Status::internal(format!(
                "crun update failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        // Persist the new limits so ContainerStatus.resources reflects the resize
        // (the kubelet reads it back to confirm the in-place resize took effect).
        if let Some(linux) = req.linux.as_ref() {
            rec.resources = Some(resources_record(linux));
            self.ctx
                .metadata
                .put(Kind::Container, self.ns(), &id, &rec)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        tracing::info!(container = %id, "UpdateContainerResources applied");
        Ok(Response::new(v1::UpdateContainerResourcesResponse {}))
    }

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

    unary_unimpl! {
        checkpoint_container => CheckpointContainerRequest / CheckpointContainerResponse,
        update_pod_sandbox_resources => UpdatePodSandboxResourcesRequest / UpdatePodSandboxResourcesResponse,
    }
}

/// ImageService implementation.
#[derive(Clone)]
pub struct ImageSvc {
    ctx: Arc<Context>,
}

impl ImageSvc {
    fn ns(&self) -> &str {
        &self.ctx.namespace
    }

    /// Find a stored image by reference, image id, repo tag, or repo digest.
    fn find_image(&self, key: &str) -> Result<Option<ImageRecord>, Status> {
        if let Some(rec) = self
            .ctx
            .metadata
            .get::<ImageRecord>(Kind::Image, self.ns(), key)
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Ok(Some(rec));
        }
        let nkey = normalize_image_ref(key);
        let all = self
            .ctx
            .metadata
            .list::<ImageRecord>(Kind::Image, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(all.into_iter().find(|r| {
            r.image_id == key
                // match the raw key AND its :latest-normalized form, so a bare
                // `busybox` query resolves the stored `busybox:latest` repoTag.
                || r.repo_tags.iter().any(|t| t == key || t == &nkey)
                || r.repo_digests.iter().any(|d| d == key)
        }))
    }

    /// Find an image record by its content id (digest). Used by pull to dedup +
    /// aggregate repoTags/repoDigests for the same image across tag/digest pulls.
    fn find_image_by_id(&self, image_id: &str) -> Result<Option<ImageRecord>, Status> {
        // Records are keyed by image_id, so a direct get suffices.
        self.ctx
            .metadata
            .get::<ImageRecord>(Kind::Image, self.ns(), image_id)
            .map_err(|e| Status::internal(e.to_string()))
    }
}

#[tonic::async_trait]
impl ImageService for ImageSvc {
    type StreamImagesStream = BoxStream<v1::StreamImagesResponse>;
    async fn stream_images(
        &self,
        _request: Request<v1::StreamImagesRequest>,
    ) -> Result<Response<Self::StreamImagesStream>, Status> {
        Err(Status::unimplemented("stream_images not yet implemented"))
    }

    async fn pull_image(
        &self,
        request: Request<v1::PullImageRequest>,
    ) -> Result<Response<v1::PullImageResponse>, Status> {
        let req = request.into_inner();
        let reference = req
            .image
            .map(|s| s.image)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Status::invalid_argument("image reference required"))?;

        // Serialize concurrent duplicate pulls of the same reference so they
        // don't race unpacking into the same chainID snapshot dir (the pull
        // itself is idempotent: content is deduped, unpack skips populated dirs).
        let _pull_guard = self.ctx.pull_locks.guard(&reference).await;

        let auth = req
            .auth
            .map(auth_from_config)
            .unwrap_or(images::pull::Auth::Anonymous);
        // Fall back to the node's docker config (config.json / cred helpers) when
        // the kubelet provided no credential (feature 002 US4).
        let auth = images::pull::resolve_auth(&reference, auth);

        let pulled = images::pull::pull_with_options(
            &reference,
            &self.ctx.content,
            &self.ctx.snapshots_root,
            &auth,
            &self.ctx.pull_options,
        )
        .await
        .map_err(|e| {
            // Surface registry auth/authorization failures clearly to the kubelet.
            if e.is_auth_error() {
                Status::unauthenticated(format!(
                    "pull {reference}: registry authentication failed: {e}"
                ))
            } else {
                Status::internal(format!("pull {reference} failed: {e}"))
            }
        })?;

        let image_id = pulled.image_id.to_string();
        // A digest ref (name@sha256:..) is a repoDigest; a tag ref is a repoTag
        // (normalized so a bare name carries an implicit :latest). NB: `repo_name`
        // strips at the last ':' after the final '/', which corrupts a digest ref
        // (it would cut inside `sha256:...`) — so a digest ref is stored as-is;
        // only a tag ref derives its repoDigest as `name@<manifest_digest>`.
        let digest_ref = if is_digest_ref(&reference) {
            Some(reference.clone())
        } else {
            pulled
                .manifest_digest
                .as_ref()
                .map(|d| format!("{}@{}", repo_name(&reference), d))
        };
        let tag_ref = (!is_digest_ref(&reference)).then(|| normalize_image_ref(&reference));

        // Dedup + aggregate by image_id: multiple tags/digests of the SAME image
        // collapse to one record carrying all repoTags/repoDigests (critest
        // "3 repoTags in single image"). Keyed by image_id, not the reference.
        let mut record = self
            .find_image_by_id(&image_id)?
            .unwrap_or_else(|| ImageRecord {
                name: tag_ref.clone().unwrap_or_else(|| reference.clone()),
                target_digest: pulled
                    .manifest_digest
                    .as_ref()
                    .map(|d| d.to_string())
                    .unwrap_or_default(),
                image_id: image_id.clone(),
                repo_tags: Vec::new(),
                repo_digests: Vec::new(),
                size: pulled.size,
                layer_digests: pulled.layer_digests.iter().map(|d| d.to_string()).collect(),
                chain_ids: pulled.chain_ids.iter().map(|d| d.to_string()).collect(),
                user: pulled.user.clone(),
            });
        if let Some(t) = &tag_ref {
            if !record.repo_tags.contains(t) {
                record.repo_tags.push(t.clone());
            }
        }
        if let Some(d) = &digest_ref {
            if !record.repo_digests.contains(d) {
                record.repo_digests.push(d.clone());
            }
        }
        self.ctx
            .metadata
            .put(Kind::Image, self.ns(), &image_id, &record)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(v1::PullImageResponse {
            image_ref: pulled.image_id.to_string(),
        }))
    }

    async fn list_images(
        &self,
        _request: Request<v1::ListImagesRequest>,
    ) -> Result<Response<v1::ListImagesResponse>, Status> {
        let records = self
            .ctx
            .metadata
            .list::<ImageRecord>(Kind::Image, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(v1::ListImagesResponse {
            images: records.iter().map(record_to_image).collect(),
        }))
    }

    async fn image_status(
        &self,
        request: Request<v1::ImageStatusRequest>,
    ) -> Result<Response<v1::ImageStatusResponse>, Status> {
        let key = request
            .into_inner()
            .image
            .map(|s| s.image)
            .unwrap_or_default();
        let image = self.find_image(&key)?.map(|r| record_to_image(&r));
        Ok(Response::new(v1::ImageStatusResponse {
            image,
            info: std::collections::HashMap::new(),
        }))
    }

    async fn remove_image(
        &self,
        request: Request<v1::RemoveImageRequest>,
    ) -> Result<Response<v1::RemoveImageResponse>, Status> {
        let key = request
            .into_inner()
            .image
            .map(|s| s.image)
            .unwrap_or_default();
        if let Some(rec) = self.find_image(&key)? {
            // Records are keyed by image_id (see pull_image dedup/aggregate).
            self.ctx
                .metadata
                .delete(Kind::Image, self.ns(), &rec.image_id)
                .map_err(|e| Status::internal(e.to_string()))?;
            // Reclaim blobs/snapshots no longer referenced by any remaining image.
            let live = self
                .ctx
                .metadata
                .list::<ImageRecord>(Kind::Image, self.ns())
                .map_err(|e| Status::internal(e.to_string()))?;
            let report =
                images::gc::reclaim(&self.ctx.content, &self.ctx.snapshots_root, &rec, &live);
            tracing::info!(
                image = %rec.name,
                blobs = report.blobs_removed,
                snapshots = report.snapshots_removed,
                "removed image and reclaimed storage"
            );
        }
        Ok(Response::new(v1::RemoveImageResponse {}))
    }

    async fn image_fs_info(
        &self,
        _request: Request<v1::ImageFsInfoRequest>,
    ) -> Result<Response<v1::ImageFsInfoResponse>, Status> {
        let used = self
            .ctx
            .content
            .total_size()
            .map_err(|e| Status::internal(e.to_string()))?
            + dir_size(&self.ctx.snapshots_root);
        let usage = v1::FilesystemUsage {
            timestamp: unix_nanos(),
            fs_id: Some(v1::FilesystemIdentifier {
                mountpoint: self.ctx.snapshots_root.display().to_string(),
            }),
            used_bytes: Some(v1::UInt64Value { value: used }),
            inodes_used: None,
        };
        Ok(Response::new(v1::ImageFsInfoResponse {
            image_filesystems: vec![usage],
            container_filesystems: Vec::new(),
        }))
    }
}

/// Current wall-clock time in nanoseconds since the Unix epoch (0 if unavailable).
fn unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Snapshot CRI `LinuxContainerResources` into the persisted record (for
/// `ContainerStatus.resources`, used by the kubelet to verify in-place resizes).
fn resources_record(r: &v1::LinuxContainerResources) -> ResourcesRecord {
    ResourcesRecord {
        cpu_period: r.cpu_period,
        cpu_quota: r.cpu_quota,
        cpu_shares: r.cpu_shares,
        memory_limit_in_bytes: r.memory_limit_in_bytes,
        cpuset_cpus: r.cpuset_cpus.clone(),
        cpuset_mems: r.cpuset_mems.clone(),
    }
}

/// Rebuild the CRI `ContainerResources` for `ContainerStatus` from a record.
fn record_to_cri_resources(rec: &ResourcesRecord) -> v1::ContainerResources {
    v1::ContainerResources {
        linux: Some(v1::LinuxContainerResources {
            cpu_period: rec.cpu_period,
            cpu_quota: rec.cpu_quota,
            cpu_shares: rec.cpu_shares,
            memory_limit_in_bytes: rec.memory_limit_in_bytes,
            cpuset_cpus: rec.cpuset_cpus.clone(),
            cpuset_mems: rec.cpuset_mems.clone(),
            ..Default::default()
        }),
        windows: None,
    }
}

/// Map CRI `LinuxContainerResources` to the runtime's `Resources` (used by both
/// CreateContainer's initial limits and UpdateContainerResources' live resize).
/// Map a CRI seccomp `SecurityProfile` to the bundle's `SeccompProfile`
/// (feature 002 US2). RuntimeDefault is carried through but its profile content
/// is not yet emitted (T002); Localhost carries the node-local profile path.
fn map_seccomp(sp: Option<&v1::SecurityProfile>) -> runtime::bundle::SeccompProfile {
    use runtime::bundle::SeccompProfile;
    use v1::security_profile::ProfileType;
    match sp {
        None => SeccompProfile::Unconfined,
        Some(p) => match ProfileType::try_from(p.profile_type) {
            Ok(ProfileType::RuntimeDefault) => SeccompProfile::RuntimeDefault,
            Ok(ProfileType::Localhost) => SeccompProfile::Localhost(p.localhost_ref.clone()),
            _ => SeccompProfile::Unconfined,
        },
    }
}

/// Map a CRI AppArmor `SecurityProfile` to an OCI apparmor profile name. Only an
/// explicit Localhost (named) profile — or Unconfined — is emitted; RuntimeDefault
/// apparmor is deferred (feature 002 T016) since naming an unloaded profile would
/// fail the container. `None` leaves the host default.
fn map_apparmor(sp: Option<&v1::SecurityProfile>) -> Option<String> {
    use v1::security_profile::ProfileType;
    let p = sp?;
    match ProfileType::try_from(p.profile_type) {
        Ok(ProfileType::Localhost) if !p.localhost_ref.is_empty() => Some(p.localhost_ref.clone()),
        Ok(ProfileType::Unconfined) => Some("unconfined".to_string()),
        _ => None,
    }
}

/// Compose an OCI SELinux process label from CRI `SeLinuxOption` (feature 002
/// US2). `None` when unset (the common case on non-SELinux hosts).
fn map_selinux(opt: Option<&v1::SeLinuxOption>) -> Option<String> {
    let o = opt?;
    if o.user.is_empty() && o.role.is_empty() && o.r#type.is_empty() && o.level.is_empty() {
        return None;
    }
    Some(format!("{}:{}:{}:{}", o.user, o.role, o.r#type, o.level))
}

/// Whether SELinux is enabled on the host (selinuxfs mounted at
/// `/sys/fs/selinux`). Emitting an OCI `process.selinuxLabel` on a host WITHOUT
/// SELinux makes the runtime write to `/proc/self/attr/*`, which fails with
/// `EINVAL` and crashes the container — so labels are only emitted when SELinux
/// is actually enabled (matching containerd). Regression guard: the sig-storage
/// EmptyDir/Subpath conformance tests pass `seLinuxOptions`, and emitting the
/// label unconditionally broke them on the (non-SELinux) CI runner.
fn host_selinux_enabled() -> bool {
    std::path::Path::new("/sys/fs/selinux/enforce").exists()
}

/// The metric families containerd-rs exports via `ListMetricDescriptors` /
/// `ListPodSandboxMetrics` (feature 002 US3 / T024). A minimal cadvisor-style
/// set — pod-level CPU and memory read from the pod cgroup. (Full metric-family
/// parity with containerd needs the reference set; see feature 002 SC-004.)
fn metric_descriptors() -> Vec<v1::MetricDescriptor> {
    vec![
        v1::MetricDescriptor {
            name: "container_cpu_usage_seconds_total".to_string(),
            help: "Cumulative CPU time consumed, in nanoseconds.".to_string(),
            label_keys: Vec::new(),
        },
        v1::MetricDescriptor {
            name: "container_memory_working_set_bytes".to_string(),
            help: "Current memory working set, in bytes.".to_string(),
            label_keys: Vec::new(),
        },
    ]
}

fn metric(name: &str, ty: v1::MetricType, value: u64, ts: i64) -> v1::Metric {
    v1::Metric {
        name: name.to_string(),
        timestamp: ts,
        metric_type: ty as i32,
        label_values: Vec::new(),
        value: Some(v1::UInt64Value { value }),
    }
}

/// Build `PodSandboxMetrics` for a sandbox from its pod cgroup (feature 002 T024).
fn pod_sandbox_metrics_for(sb: &SandboxRecord) -> v1::PodSandboxMetrics {
    let ts = unix_nanos();
    let cg = if sb.cgroup_parent.is_empty() {
        runtime::cgroup::CgroupStats::default()
    } else {
        let dir =
            std::path::Path::new("/sys/fs/cgroup").join(sb.cgroup_parent.trim_start_matches('/'));
        runtime::cgroup::read_stats(&dir)
    };
    v1::PodSandboxMetrics {
        pod_sandbox_id: sb.id.clone(),
        metrics: vec![
            metric(
                "container_cpu_usage_seconds_total",
                v1::MetricType::Counter,
                cg.cpu_usage_nanos,
                ts,
            ),
            metric(
                "container_memory_working_set_bytes",
                v1::MetricType::Gauge,
                cg.memory_current_bytes,
                ts,
            ),
        ],
        container_metrics: Vec::new(),
    }
}

fn cri_resources(r: &v1::LinuxContainerResources) -> runtime::bundle::Resources {
    runtime::bundle::Resources {
        cpu_shares: (r.cpu_shares > 0).then_some(r.cpu_shares as u64),
        cpu_quota: (r.cpu_quota != 0).then_some(r.cpu_quota),
        cpu_period: (r.cpu_period > 0).then_some(r.cpu_period as u64),
        memory_limit: (r.memory_limit_in_bytes > 0).then_some(r.memory_limit_in_bytes),
        cpuset_cpus: (!r.cpuset_cpus.is_empty()).then(|| r.cpuset_cpus.clone()),
        cpuset_mems: (!r.cpuset_mems.is_empty()).then(|| r.cpuset_mems.clone()),
        // HugeTLB limits + cgroup-v2 unified passthrough (pids/blkio) — feature 002 US5.
        hugepage_limits: r
            .hugepage_limits
            .iter()
            .filter(|h| h.limit > 0 && !h.page_size.is_empty())
            .map(|h| (h.page_size.clone(), h.limit))
            .collect(),
        unified: r.unified.clone(),
    }
}

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
    let parent = pod_dir.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cgroup_parent has no parent dir",
        )
    })?;

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

/// Derive a container's cgroup path from the pod's `cgroup_parent`, mirroring
/// containerd's `getCgroupsPath`: a systemd slice parent (`*.slice`) →
/// `slice:cri-containerd:id`; otherwise the cgroupfs path `parent/id`.
fn cgroups_path(cgroup_parent: &str, id: &str) -> String {
    let base = std::path::Path::new(cgroup_parent)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if base.ends_with(".slice") {
        format!("{base}:cri-containerd:{id}")
    } else {
        format!("{}/{}", cgroup_parent.trim_end_matches('/'), id)
    }
}

/// Format one stream's chunk into CRI log lines: `<RFC3339Nano> <stream> <P|F> <line>`.
/// A segment terminated by `\n` is tagged `F` (full); a trailing segment with no
/// newline is tagged `P` (partial). This matters because the kubelet re-appends a
/// newline only for `F` lines when reconstructing logs (e.g. the
/// `terminationMessagePolicy: FallbackToLogsOnError` reader): mis-tagging an
/// unterminated `DONE` as `F` yields `DONE\n` and fails the comparison.
fn cri_log_line(stream: &str, data: &[u8]) -> Vec<u8> {
    let ts = humantime::format_rfc3339_nanos(std::time::SystemTime::now()).to_string();
    let mut out = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let (line, tag, next) = match data[start..].iter().position(|&b| b == b'\n') {
            Some(pos) => (&data[start..start + pos], b"F", start + pos + 1),
            None => (&data[start..], b"P", data.len()),
        };
        start = next;
        // Skip truly-empty full lines (a lone `\n`); keep partials.
        if line.is_empty() && tag == b"F" {
            continue;
        }
        out.extend_from_slice(ts.as_bytes());
        out.push(b' ');
        out.extend_from_slice(stream.as_bytes());
        out.push(b' ');
        out.extend_from_slice(tag);
        out.push(b' ');
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Pump one crun output stream to both the CRI log file and the live bus.
async fn pump_stream<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    channel: u8,
    stream_name: &'static str,
    log: Arc<tokio::sync::Mutex<Option<tokio::fs::File>>>,
    live: tokio::sync::broadcast::Sender<crate::streaming::LiveFrame>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let chunk = &buf[..n];
                let line = cri_log_line(stream_name, chunk);
                if let Some(f) = log.lock().await.as_mut() {
                    let _ = f.write_all(&line).await;
                }
                let _ = live.send((channel, chunk.to_vec()));
            }
        }
    }
}

/// Run `crun run` with piped stdio, streaming output live; returns the exit code.
/// A `terminal` container is supervised over a PTY instead (see [`supervise_tty`]).
#[allow(clippy::too_many_arguments)]
async fn supervise_container(
    crun_root: &Path,
    bundle_dir: &Path,
    cid: &str,
    log_path: &Path,
    live: tokio::sync::broadcast::Sender<crate::streaming::LiveFrame>,
    terminal: bool,
    stdin_open: bool,
    no_pivot: bool,
    sessions: Arc<crate::streaming::Sessions>,
) -> i32 {
    if terminal {
        return supervise_tty(crun_root, bundle_dir, cid, log_path, live, no_pivot).await;
    }
    let mut cmd = tokio::process::Command::new(runtime::crun::DEFAULT_BIN);
    cmd.arg("--root").arg(crun_root).arg("run");
    // Default: pivot_root (like containerd) — required for mount propagation
    // (rshared/rslave). `--no-pivot` (MS_MOVE + chroot) is the opt-in for a
    // ramdisk/initramfs root (M2a), where pivot_root(2) fails because the new
    // root and put-old are on the same ramfs mount; it cannot preserve shared
    // mount peer groups, so propagation does not work under it.
    if no_pivot {
        cmd.arg("--no-pivot");
    }
    cmd.arg("--bundle")
        .arg(bundle_dir)
        .arg(cid)
        // An interactive container (CRI stdin=true) keeps an open stdin pipe so
        // its process (e.g. a shell) blocks for input instead of reading EOF and
        // exiting; Attach forwards the client's stdin through it.
        .stdin(if stdin_open {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Place crun and the container init in their own process group so that
        // `crun delete --force` (sent by stop_container) can sweep any stray
        // children that were reparented to init inside the group, and so that
        // signals sent to the daemon do not accidentally reach the container.
        // Stdio is already fully piped (not a terminal), so this is safe.
        .process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::write(
                log_path,
                cri_log_line("stderr", format!("crun spawn: {e}").as_bytes()),
            );
            return -1;
        }
    };
    if let Some(parent) = log_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let log = Arc::new(tokio::sync::Mutex::new(
        tokio::fs::File::create(log_path).await.ok(),
    ));
    // Publish the log handle so ReopenContainerLog can swap the file in place
    // when the kubelet rotates it (mirrors containerd's ContainerIO.AddOutput).
    sessions.register_log(cid, log.clone());
    // Publish the stdin pipe so Attach can forward the client's input. Held open
    // for the container's lifetime (closed in the exit handler via close_stdin).
    if stdin_open {
        if let Some(stdin) = child.stdin.take() {
            sessions.register_stdin(cid, Arc::new(tokio::sync::Mutex::new(Some(stdin))));
        }
    }
    let so = child.stdout.take();
    let se = child.stderr.take();
    let mut tasks = Vec::new();
    if let Some(so) = so {
        tasks.push(tokio::spawn(pump_stream(
            so,
            1,
            "stdout",
            log.clone(),
            live.clone(),
        )));
    }
    if let Some(se) = se {
        tasks.push(tokio::spawn(pump_stream(
            se,
            2,
            "stderr",
            log.clone(),
            live.clone(),
        )));
    }
    for t in tasks {
        let _ = t.await;
    }
    let status = child.wait().await;
    if let Ok(s) = &status {
        use std::os::unix::process::ExitStatusExt;
        tracing::info!(container = %cid, code = ?s.code(), signal = ?s.signal(), "crun run returned");
        // M2a debug: on non-zero exit, tee the CRI log (crun's stderr) to the
        // tracing output so it surfaces on the serial console. Remove once the
        // systemic crun exit-1 root cause is identified.
        if s.code() != Some(0) {
            if let Ok(bytes) = tokio::fs::read(log_path).await {
                let snippet = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]);
                tracing::error!(container = %cid, log = %snippet, "crun stderr (debug)");
            }
        }
    }
    status.ok().and_then(|s| s.code()).unwrap_or(-1)
}

/// Supervise a `terminal: true` container over a PTY. crun can't share its
/// foreground stdio with a tty container, so [`runtime::crun::run_tty`] runs it
/// detached with a console socket and hands back the pty master; we pump the
/// master to the CRI log + live bus (stdout channel) until the process exits
/// (master EOF), then clean up. The detached console path can't surface an exit
/// code, so we report 0 (tty workloads are typically long-running/interactive).
async fn supervise_tty(
    crun_root: &Path,
    bundle_dir: &Path,
    cid: &str,
    log_path: &Path,
    live: tokio::sync::broadcast::Sender<crate::streaming::LiveFrame>,
    no_pivot: bool,
) -> i32 {
    if let Some(parent) = log_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let crun_root = crun_root.to_path_buf();
    let bundle_dir = bundle_dir.to_path_buf();
    let cid = cid.to_string();
    let log_path = log_path.to_path_buf();
    let console_sock = bundle_dir.join("console.sock");
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let master = match runtime::crun::run_tty(
            runtime::crun::DEFAULT_BIN,
            &crun_root,
            &bundle_dir,
            &cid,
            &console_sock,
            no_pivot,
        ) {
            Ok(m) => m,
            Err(e) => {
                let _ = std::fs::write(
                    &log_path,
                    cri_log_line("stderr", format!("crun run --tty: {e}").as_bytes()),
                );
                return -1;
            }
        };
        let mut log = std::fs::File::create(&log_path).ok();
        let mut master = std::fs::File::from(master);
        let mut buf = [0u8; 8192];
        loop {
            // A pty master read returns 0 (or EIO) once the slave side closes,
            // i.e. the container process has exited.
            match master.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = &buf[..n];
                    if let Some(f) = log.as_mut() {
                        let _ = f.write_all(&cri_log_line("stdout", chunk));
                    }
                    let _ = live.send((1, chunk.to_vec()));
                }
            }
        }
        let _ = runtime::crun::delete(runtime::crun::DEFAULT_BIN, &crun_root, &cid);
        0
    })
    .await
    .unwrap_or(-1)
}

/// Resolve a container's log file path: absolute as-is, else under the bundle.
fn container_log_path(bundle: &runtime::shim::Bundle, log_path: &str) -> PathBuf {
    if log_path.is_empty() {
        bundle.dir().join("container.log")
    } else {
        let p = PathBuf::from(log_path);
        if p.is_absolute() {
            p
        } else {
            bundle.dir().join(log_path)
        }
    }
}

/// Recursively sum the byte size of regular files under `path`.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => total += dir_size(&entry.path()),
            Ok(ft) if ft.is_file() => {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            }
            _ => {}
        }
    }
    total
}

/// Outcome of a restart-recovery reconcile pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub sandboxes: usize,
    pub containers: usize,
    /// Previously-`Running` containers still alive under crun — re-adopted
    /// (kept `Running`, not torn down). These are the pods that survive a
    /// daemon restart (feature 002 US1 / FR-001).
    pub readopted: usize,
    /// Previously-`Running` containers found already exited/created under crun
    /// while the daemon was down — reaped and recorded as `Exited`.
    pub reaped: usize,
    /// Previously-`Running` containers crun no longer knows about — marked
    /// `Unknown` for the kubelet to reconcile.
    pub marked_unknown: usize,
}

/// Reconcile persisted state after a daemon restart.
///
/// The metadata DB survives restarts, so sandboxes and containers are
/// re-discovered. For each previously-`Running` container we probe
/// `crun state <id>` (feature 002 US1):
///  - **running** → **re-adopt**: keep it `Running` and refresh its re-adoption
///    handles. Crucially we do NOT `crun delete --force` it (the old behavior,
///    which killed every running container's process tree on restart and churned
///    every pod on the node).
///  - **created/stopped** → it exited or never fully started while we were down:
///    reap it (`crun delete --force`) and record `Exited` (exit code unknown for
///    a container whose init we did not parent — this generation's exit fidelity
///    is degraded; see feature 002 US1 notes / deferred T008/T012).
///  - **unknown to crun** → mark `Unknown` for the kubelet to reconcile.
///
/// Idempotent and crash-safe (T013): re-running it converges; a container that
/// exits between probe and write is caught on the next status query or pass.
pub fn reconcile(ctx: &Context) -> Result<ReconcileReport, metadata::Error> {
    let ns = &ctx.namespace;
    let mut report = ReconcileReport::default();

    let sandboxes: Vec<SandboxRecord> = ctx.metadata.list(Kind::Sandbox, ns)?;
    report.sandboxes = sandboxes.len();

    let containers: Vec<ContainerRecord> = ctx.metadata.list(Kind::Container, ns)?;
    report.containers = containers.len();
    let crun_root = ctx.state_dir.join("crun");
    for mut c in containers {
        if c.state != ContainerState::Running {
            continue;
        }
        match runtime::crun::probe(runtime::crun::DEFAULT_BIN, &crun_root, &c.id) {
            Ok(Some(st)) if st.is_running() => {
                // Still alive — re-adopt. Refresh handles; leave state Running.
                c.crun_root = Some(crun_root.display().to_string());
                if st.pid.is_some() {
                    c.pid = st.pid;
                }
                ctx.metadata.put(Kind::Container, ns, &c.id, &c)?;
                report.readopted += 1;
            }
            Ok(Some(_)) => {
                // created/stopped while we were down: reap and record exit.
                let _ = runtime::crun::delete(runtime::crun::DEFAULT_BIN, &crun_root, &c.id);
                c.state = ContainerState::Exited;
                if c.finished_at.is_none() {
                    c.finished_at = Some(unix_nanos() as u64);
                }
                if c.exit_code.is_none() {
                    c.exit_code = Some(-1);
                    c.reason = Some("Unknown".to_string());
                }
                ctx.metadata.put(Kind::Container, ns, &c.id, &c)?;
                report.reaped += 1;
            }
            Ok(None) | Err(_) => {
                // crun has no record — idempotent cleanup, then mark Unknown.
                let _ = runtime::crun::delete(runtime::crun::DEFAULT_BIN, &crun_root, &c.id);
                c.state = ContainerState::Unknown;
                ctx.metadata.put(Kind::Container, ns, &c.id, &c)?;
                report.marked_unknown += 1;
            }
        }
    }
    Ok(report)
}

/// Serve the CRI gRPC API on a unix socket until `shutdown` resolves.
///
/// Removes any stale socket file first. The parent directory must exist.
pub async fn serve(
    socket_path: impl AsRef<Path>,
    ctx: Arc<Context>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = socket_path.as_ref();
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    tracing::info!(?socket_path, "serving CRI v1 over unix socket");
    tonic::transport::Server::builder()
        .add_service(RuntimeServiceServer::new(RuntimeSvc { ctx: ctx.clone() }))
        .add_service(ImageServiceServer::new(ImageSvc { ctx }))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    use crate::v1::image_service_client::ImageServiceClient;
    use crate::v1::runtime_service_client::RuntimeServiceClient;
    use tokio::net::UnixStream;
    use tonic::transport::{Endpoint, Uri};

    fn test_context(dir: &std::path::Path) -> Arc<Context> {
        let content = content::Store::open(dir.join("content")).unwrap();
        let metadata = metadata::Store::open(dir.join("meta.db")).unwrap();
        Arc::new(Context::new(
            content,
            metadata,
            dir.join("snapshots"),
            dir.join("state"),
            "127.0.0.1:10010",
            dir.join("cni/net.d"),
            dir.join("cni/bin"),
            images::pull::PullOptions::default(),
            false,
        ))
    }

    // Feature 002 US3 / T024: the exported metric descriptors are stable and the
    // per-metric builder tags type/value correctly.
    #[test]
    fn metric_descriptors_and_builder() {
        let d = metric_descriptors();
        let names: Vec<&str> = d.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"container_cpu_usage_seconds_total"));
        assert!(names.contains(&"container_memory_working_set_bytes"));
        let m = metric(
            "container_memory_working_set_bytes",
            v1::MetricType::Gauge,
            4096,
            1,
        );
        assert_eq!(m.metric_type, v1::MetricType::Gauge as i32);
        assert_eq!(m.value.unwrap().value, 4096);
    }

    // Feature 002 US3 / T026: the container-event bus delivers lifecycle events
    // to subscribers (GetContainerEvents streams from this bus).
    #[tokio::test]
    async fn container_event_bus_delivers_to_subscribers() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_context(dir.path());
        let mut rx = ctx.container_events.subscribe();
        ctx.emit_container_event("c1", v1::ContainerEventType::ContainerStartedEvent);
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.container_id, "c1");
        assert_eq!(
            ev.container_event_type,
            v1::ContainerEventType::ContainerStartedEvent as i32
        );
        // No subscriber-less panic: emit with the receiver dropped is a no-op.
        drop(rx);
        ctx.emit_container_event("c2", v1::ContainerEventType::ContainerDeletedEvent);
    }

    #[tokio::test]
    async fn version_and_status_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("cri.sock");
        let sock_for_server = sock.clone();
        let ctx = test_context(dir.path());

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            serve(sock_for_server, ctx, async {
                let _ = rx.await;
            })
            .await
            .unwrap();
        });

        // Wait for the socket to appear.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Connect a client over the unix socket (the URI is ignored by the
        // custom connector).
        let sock_for_client = sock.clone();
        let channel = Endpoint::try_from("http://[::]:50051")
            .unwrap()
            .connect_with_connector(tower_service_fn(move |_: Uri| {
                let p = sock_for_client.clone();
                async move {
                    let stream = UnixStream::connect(p).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .unwrap();

        let mut client = RuntimeServiceClient::new(channel.clone());

        let v = client
            .version(v1::VersionRequest {
                version: "v1".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(v.runtime_name, "containerd-rs");
        assert_eq!(v.runtime_api_version, "v1");

        let s = client
            .status(v1::StatusRequest { verbose: false })
            .await
            .unwrap()
            .into_inner();
        let conds = s.status.unwrap().conditions;
        assert!(conds.iter().any(|c| c.r#type == "RuntimeReady" && c.status));
        assert!(conds.iter().any(|c| c.r#type == "NetworkReady" && c.status));
        // verbose=false => no info; consumers only parse it when they ask for it.
        assert!(s.info.is_empty());

        // verbose=true must surface info["config"] (kubeadm/crictl parse it; an
        // empty map makes kubeadm warn `no 'config' field in CRI info`).
        let sv = client
            .status(v1::StatusRequest { verbose: true })
            .await
            .unwrap()
            .into_inner();
        let cfg = sv.info.get("config").expect("verbose status has config");
        let parsed: serde_json::Value = serde_json::from_str(cfg).unwrap();
        assert_eq!(parsed["sandboxImage"], "registry.k8s.io/pause:3.10");
        assert_eq!(parsed["cgroupDriver"], "cgroupfs");

        // A still-unimplemented RPC returns the right gRPC code.
        let err = client
            .checkpoint_container(v1::CheckpointContainerRequest {
                container_id: "nope".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        // PodSandboxStats is now implemented: an unknown sandbox is NotFound
        // (not Unimplemented), and ListPodSandboxStats returns an (empty) list.
        let err = client
            .pod_sandbox_stats(v1::PodSandboxStatsRequest {
                pod_sandbox_id: "nope".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        let lst = client
            .list_pod_sandbox_stats(v1::ListPodSandboxStatsRequest { filter: None })
            .await
            .unwrap()
            .into_inner();
        assert!(lst.stats.is_empty());

        // ImageService is wired to the metadata store: empty list + missing
        // image status are real (no network needed).
        let mut images = ImageServiceClient::new(channel);
        let list = images
            .list_images(v1::ListImagesRequest { filter: None })
            .await
            .unwrap()
            .into_inner();
        assert!(list.images.is_empty());

        let st = images
            .image_status(v1::ImageStatusRequest {
                image: Some(v1::ImageSpec {
                    image: "registry.k8s.io/pause:3.10".into(),
                    ..Default::default()
                }),
                verbose: false,
            })
            .await
            .unwrap()
            .into_inner();
        assert!(st.image.is_none());

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

        let _ = tx.send(());
        let _ = server.await;
    }

    // Minimal tower service fn shim so the test doesn't need the `tower` dep
    // surface directly.
    fn tower_service_fn<F>(f: F) -> tower::util::ServiceFn<F> {
        tower::service_fn(f)
    }

    fn image_spec(reference: &str) -> Option<v1::ImageSpec> {
        Some(v1::ImageSpec {
            image: reference.into(),
            ..Default::default()
        })
    }

    #[test]
    fn reconcile_recovers_records_across_restart() {
        let dir = tempfile::tempdir().unwrap();

        fn ctr(id: &str, state: ContainerState) -> ContainerRecord {
            ContainerRecord {
                id: id.into(),
                sandbox_id: "sb".into(),
                name: id.into(),
                attempt: 0,
                image_ref: String::new(),
                image_id: String::new(),
                state,
                snapshot_key: String::new(),
                log_path: String::new(),
                created_at: 0,
                started_at: None,
                finished_at: None,
                exit_code: None,
                reason: None,
                labels: Default::default(),
                annotations: Default::default(),
                mounts: Vec::new(),
                resources: None,
                crun_root: None,
                bundle_dir: None,
                pid: None,
                restart_count: 0,
                stdin: false,
                stdin_once: false,
            }
        }

        // First daemon lifetime: persist a sandbox + two containers.
        {
            let ctx = test_context(dir.path());
            let ns = ctx.namespace.clone();
            ctx.metadata
                .put(
                    Kind::Sandbox,
                    &ns,
                    "sb",
                    &SandboxRecord {
                        id: "sb".into(),
                        name: "p".into(),
                        k8s_namespace: "default".into(),
                        uid: "u".into(),
                        attempt: 0,
                        state: SandboxState::Ready,
                        netns_path: None,
                        ip: None,
                        runtime_handler: String::new(),
                        pause_container_id: None,
                        snapshot_key: None,
                        created_at: 0,
                        labels: Default::default(),
                        annotations: Default::default(),
                        log_directory: String::new(),
                        host_network: false,
                        host_pid: false,
                        host_ipc: false,
                        shared_pid: false,
                        shared_ipc: false,
                        pid_holder_pid: None,
                        resolv_conf_path: None,
                        sysctls: Default::default(),
                        cgroup_parent: String::new(),
                        hostname: String::new(),
                    },
                )
                .unwrap();
            ctx.metadata
                .put(
                    Kind::Container,
                    &ns,
                    "running",
                    &ctr("running", ContainerState::Running),
                )
                .unwrap();
            ctx.metadata
                .put(
                    Kind::Container,
                    &ns,
                    "created",
                    &ctr("created", ContainerState::Created),
                )
                .unwrap();
        }

        // Restart: reopen the same on-disk stores and reconcile.
        let ctx = test_context(dir.path());
        let report = reconcile(&ctx).unwrap();
        assert_eq!(report.sandboxes, 1);
        assert_eq!(report.containers, 2);
        assert_eq!(report.marked_unknown, 1);

        let running: ContainerRecord = ctx
            .metadata
            .get(Kind::Container, &ctx.namespace, "running")
            .unwrap()
            .unwrap();
        assert_eq!(running.state, ContainerState::Unknown);
        let created: ContainerRecord = ctx
            .metadata
            .get(Kind::Container, &ctx.namespace, "created")
            .unwrap()
            .unwrap();
        assert_eq!(created.state, ContainerState::Created);
    }

    #[test]
    fn auth_config_maps_all_credential_forms() {
        use base64::Engine as _;
        use images::pull::Auth;

        // identity_token / registry_token -> Bearer (identity wins).
        let a = auth_from_config(v1::AuthConfig {
            identity_token: "idtok".into(),
            registry_token: "regtok".into(),
            ..Default::default()
        });
        assert!(matches!(a, Auth::Bearer(t) if t == "idtok"));
        let a = auth_from_config(v1::AuthConfig {
            registry_token: "regtok".into(),
            ..Default::default()
        });
        assert!(matches!(a, Auth::Bearer(t) if t == "regtok"));

        // username/password -> Basic.
        let a = auth_from_config(v1::AuthConfig {
            username: "u".into(),
            password: "p".into(),
            ..Default::default()
        });
        assert!(
            matches!(a, Auth::Basic { username, password } if username == "u" && password == "p")
        );

        // base64 "user:pass" `auth` field -> Basic.
        let enc = base64::engine::general_purpose::STANDARD.encode("alice:s3cret");
        let a = auth_from_config(v1::AuthConfig {
            auth: enc,
            ..Default::default()
        });
        assert!(
            matches!(a, Auth::Basic { username, password } if username == "alice" && password == "s3cret")
        );

        // empty -> Anonymous.
        assert!(matches!(
            auth_from_config(v1::AuthConfig::default()),
            Auth::Anonymous
        ));
    }

    // Regression for in-place resize reporting: CRI LinuxContainerResources must
    // round-trip through the persisted record back into ContainerStatus.resources
    // unchanged, so the kubelet sees the limits it requested via UpdateContainerResources.
    #[test]
    fn resources_round_trip_through_record() {
        let cri = v1::LinuxContainerResources {
            cpu_period: 100_000,
            cpu_quota: 2_000,
            cpu_shares: 204,
            memory_limit_in_bytes: 33_554_432,
            cpuset_cpus: "0-1".into(),
            cpuset_mems: "0".into(),
            ..Default::default()
        };
        let rec = resources_record(&cri);
        let out = record_to_cri_resources(&rec);
        let linux = out.linux.expect("linux resources present");
        assert_eq!(linux.cpu_period, 100_000);
        assert_eq!(linux.cpu_quota, 2_000);
        assert_eq!(linux.cpu_shares, 204);
        assert_eq!(linux.memory_limit_in_bytes, 33_554_432);
        assert_eq!(linux.cpuset_cpus, "0-1");
        assert_eq!(linux.cpuset_mems, "0");
    }

    #[tokio::test]
    async fn port_forward_proxies_to_localhost() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let ctx = test_context(dir.path());

        // A localhost TCP echo server stands in for a host-network pod's port.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await; // echo back
                }
            }
        });

        // Streaming server.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::streaming::router(ctx.streaming.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let token = ctx
            .streaming
            .register_portforward(crate::streaming::PortForwardSession {
                pod_sandbox_id: "p".into(),
                host: "127.0.0.1".into(),
            });

        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/portforward/{token}"))
                .await
                .unwrap();
        use tokio_tungstenite::tungstenite::Message as TMsg;
        let lo = (port & 0xff) as u8;
        let hi = (port >> 8) as u8;
        // Port headers on data (0) + error (1) channels, then payload on data.
        ws.send(TMsg::Binary(vec![0, lo, hi])).await.unwrap();
        ws.send(TMsg::Binary(vec![1, lo, hi])).await.unwrap();
        ws.send(TMsg::Binary([&[0u8][..], b"PF_PING"].concat()))
            .await
            .unwrap();

        let mut echoed = false;
        for _ in 0..20 {
            match tokio::time::timeout(std::time::Duration::from_secs(3), ws.next()).await {
                Ok(Some(Ok(TMsg::Binary(d)))) if d.first() == Some(&0) => {
                    if String::from_utf8_lossy(&d[1..]).contains("PF_PING") {
                        echoed = true;
                        break;
                    }
                }
                Ok(Some(Ok(_))) => continue,
                _ => break,
            }
        }
        assert!(
            echoed,
            "port-forward did not echo payload back over the data channel"
        );
    }

    #[tokio::test]
    async fn pod_sandbox_run_status_list_stop_remove() {
        let dir = tempfile::tempdir().unwrap();
        let svc = RuntimeSvc {
            ctx: test_context(dir.path()),
        };
        let cfg = v1::PodSandboxConfig {
            metadata: Some(v1::PodSandboxMetadata {
                name: "nginx".into(),
                uid: "uid-1".into(),
                namespace: "default".into(),
                attempt: 0,
            }),
            // Use host networking so this unit test works without CNI binaries
            // or network namespace privileges (the test exercises sandbox
            // lifecycle, not CNI).
            linux: Some(v1::LinuxPodSandboxConfig {
                security_context: Some(v1::LinuxSandboxSecurityContext {
                    namespace_options: Some(v1::NamespaceOption {
                        network: v1::NamespaceMode::Node as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let id = svc
            .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
                config: Some(cfg),
                runtime_handler: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        assert_eq!(id.len(), 64);

        // Status: Ready, metadata round-trips.
        let st = svc
            .pod_sandbox_status(Request::new(v1::PodSandboxStatusRequest {
                pod_sandbox_id: id.clone(),
                verbose: false,
            }))
            .await
            .unwrap()
            .into_inner();
        let status = st.status.unwrap();
        assert_eq!(status.state, v1::PodSandboxState::SandboxReady as i32);
        assert_eq!(status.metadata.unwrap().name, "nginx");

        // List + Ready-state filter find it.
        let list = svc
            .list_pod_sandbox(Request::new(v1::ListPodSandboxRequest {
                filter: Some(v1::PodSandboxFilter {
                    id: String::new(),
                    state: Some(v1::PodSandboxStateValue {
                        state: v1::PodSandboxState::SandboxReady as i32,
                    }),
                    label_selector: std::collections::HashMap::new(),
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].id, id);

        // Stop -> NotReady.
        svc.stop_pod_sandbox(Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: id.clone(),
        }))
        .await
        .unwrap();
        let st = svc
            .pod_sandbox_status(Request::new(v1::PodSandboxStatusRequest {
                pod_sandbox_id: id.clone(),
                verbose: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            st.status.unwrap().state,
            v1::PodSandboxState::SandboxNotready as i32
        );

        // Remove -> gone (status now NotFound).
        svc.remove_pod_sandbox(Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: id.clone(),
        }))
        .await
        .unwrap();
        let err = svc
            .pod_sandbox_status(Request::new(v1::PodSandboxStatusRequest {
                pod_sandbox_id: id,
                verbose: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn container_create_status_list_stop_remove() {
        use core_types::Digest;

        let dir = tempfile::tempdir().unwrap();
        let ctx = test_context(dir.path());
        let svc = RuntimeSvc { ctx: ctx.clone() };

        // Seed an image: config blob + record (so bundle gen sees entrypoint/cmd).
        let cfg_json =
            br#"{"config":{"Env":["A=B"],"Entrypoint":["/app"],"Cmd":["--flag"],"WorkingDir":"/w","User":"0"}}"#;
        let image_id = Digest::sha256(cfg_json);
        ctx.content.write_blob("cfg", cfg_json, &image_id).unwrap();
        ctx.metadata
            .put(
                Kind::Image,
                ctx.namespace.as_str(),
                "img:latest",
                &ImageRecord {
                    name: "img:latest".into(),
                    target_digest: String::new(),
                    image_id: image_id.to_string(),
                    repo_tags: vec!["img:latest".into()],
                    repo_digests: vec![],
                    size: cfg_json.len() as u64,
                    layer_digests: vec![],
                    chain_ids: vec![],
                    user: String::new(),
                },
            )
            .unwrap();

        // A sandbox to host the container. Use host networking so this unit
        // test works without CNI binaries or network namespace privileges (the
        // test exercises container lifecycle, not CNI).
        let pod = svc
            .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
                config: Some(v1::PodSandboxConfig {
                    metadata: Some(v1::PodSandboxMetadata {
                        name: "pod".into(),
                        uid: "u".into(),
                        namespace: "default".into(),
                        attempt: 0,
                    }),
                    linux: Some(v1::LinuxPodSandboxConfig {
                        security_context: Some(v1::LinuxSandboxSecurityContext {
                            namespace_options: Some(v1::NamespaceOption {
                                network: v1::NamespaceMode::Node as i32,
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                runtime_handler: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pod_sandbox_id;

        // Create a container (no command override -> image entrypoint+cmd).
        let cid = svc
            .create_container(Request::new(v1::CreateContainerRequest {
                pod_sandbox_id: pod.clone(),
                config: Some(v1::ContainerConfig {
                    metadata: Some(v1::ContainerMetadata {
                        name: "c0".into(),
                        attempt: 0,
                    }),
                    image: image_spec("img:latest"),
                    log_path: "c0.log".into(),
                    ..Default::default()
                }),
                sandbox_config: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .container_id;

        // Bundle written with argv = entrypoint ++ cmd from the image config.
        let bundle = runtime::shim::Bundle::new(&ctx.state_dir, ctx.namespace.as_str(), &cid);
        assert!(bundle.config_json().is_file());
        let spec = oci_spec::runtime::Spec::load(bundle.config_json()).unwrap();
        assert_eq!(
            spec.process().as_ref().unwrap().args().as_ref().unwrap(),
            &vec!["/app".to_string(), "--flag".to_string()]
        );

        // Status: Created, image id wired.
        let st = svc
            .container_status(Request::new(v1::ContainerStatusRequest {
                container_id: cid.clone(),
                verbose: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .status
            .unwrap();
        assert_eq!(st.state, v1::ContainerState::ContainerCreated as i32);
        assert_eq!(st.image_id, image_id.to_string());

        // List by sandbox filter.
        let list = svc
            .list_containers(Request::new(v1::ListContainersRequest {
                filter: Some(v1::ContainerFilter {
                    pod_sandbox_id: pod.clone(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(list.containers.len(), 1);

        // Stop -> Exited.
        svc.stop_container(Request::new(v1::StopContainerRequest {
            container_id: cid.clone(),
            timeout: 0,
        }))
        .await
        .unwrap();
        let st = svc
            .container_status(Request::new(v1::ContainerStatusRequest {
                container_id: cid.clone(),
                verbose: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .status
            .unwrap();
        assert_eq!(st.state, v1::ContainerState::ContainerExited as i32);
        // stop_container must NOT hardcode exit_code=0. When the container was
        // never running (Created state here, crun unavailable in unit tests),
        // the force-kill path sets exit_code=-1 (crun spawn failed / not found).
        // Any non-zero code is acceptable; 0 is the old buggy hardcoded value.
        assert_ne!(
            st.exit_code, 0,
            "stop_container must not hardcode exit_code=0 — got 0, expected forced-kill exit"
        );

        // Remove -> gone + bundle deleted.
        svc.remove_container(Request::new(v1::RemoveContainerRequest {
            container_id: cid.clone(),
        }))
        .await
        .unwrap();
        assert!(!bundle.dir().exists());
        let list = svc
            .list_containers(Request::new(v1::ListContainersRequest { filter: None }))
            .await
            .unwrap()
            .into_inner();
        assert!(list.containers.is_empty());
    }

    /// kubectl logs fails with ENOENT when the CRI LogPath file is created lazily
    /// (only when supervise_container starts).  The kubelet stats/opens the log
    /// file as soon as the container is Created, so we must touch it synchronously
    /// inside create_container.
    #[tokio::test]
    async fn log_path_exists_after_create() {
        use core_types::Digest;

        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join("pod-logs");
        std::fs::create_dir_all(&log_dir).unwrap();

        let ctx = test_context(dir.path());
        let svc = RuntimeSvc { ctx: ctx.clone() };

        // Seed image (same minimal config as container_create_status_list_stop_remove).
        let cfg_json =
            br#"{"config":{"Env":[],"Entrypoint":["/app"],"Cmd":[],"WorkingDir":"/","User":"0"}}"#;
        let image_id = Digest::sha256(cfg_json);
        ctx.content.write_blob("cfg", cfg_json, &image_id).unwrap();
        ctx.metadata
            .put(
                Kind::Image,
                ctx.namespace.as_str(),
                "img2:latest",
                &ImageRecord {
                    name: "img2:latest".into(),
                    target_digest: String::new(),
                    image_id: image_id.to_string(),
                    repo_tags: vec!["img2:latest".into()],
                    repo_digests: vec![],
                    size: cfg_json.len() as u64,
                    layer_digests: vec![],
                    chain_ids: vec![],
                    user: String::new(),
                },
            )
            .unwrap();

        // Sandbox with an explicit log_directory so the relative container
        // log_path ("c0.log") gets resolved to an absolute path.
        let pod = svc
            .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
                config: Some(v1::PodSandboxConfig {
                    metadata: Some(v1::PodSandboxMetadata {
                        name: "pod2".into(),
                        uid: "u2".into(),
                        namespace: "default".into(),
                        attempt: 0,
                    }),
                    log_directory: log_dir.to_str().unwrap().to_string(),
                    linux: Some(v1::LinuxPodSandboxConfig {
                        security_context: Some(v1::LinuxSandboxSecurityContext {
                            namespace_options: Some(v1::NamespaceOption {
                                network: v1::NamespaceMode::Node as i32,
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                runtime_handler: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pod_sandbox_id;

        // create_container — the log file must exist on disk IMMEDIATELY after
        // this call returns (before start_container / supervise_container run).
        svc.create_container(Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: pod.clone(),
            config: Some(v1::ContainerConfig {
                metadata: Some(v1::ContainerMetadata {
                    name: "c0".into(),
                    attempt: 0,
                }),
                image: image_spec("img2:latest"),
                log_path: "c0.log".into(),
                ..Default::default()
            }),
            sandbox_config: None,
        }))
        .await
        .unwrap();

        let expected_log = log_dir.join("c0.log");
        assert!(
            expected_log.exists(),
            "CRI LogPath {:?} must exist after create_container (kubectl logs must not ENOENT)",
            expected_log,
        );
    }

    #[tokio::test]
    async fn exec_returns_streaming_url() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_context(dir.path());
        let rt = RuntimeSvc { ctx: ctx.clone() };

        // Seed a container record so the exec target exists.
        ctx.metadata
            .put(
                Kind::Container,
                ctx.namespace.as_str(),
                "c1",
                &ContainerRecord {
                    id: "c1".into(),
                    sandbox_id: "sb".into(),
                    name: "c1".into(),
                    attempt: 0,
                    image_ref: String::new(),
                    image_id: String::new(),
                    state: ContainerState::Running,
                    snapshot_key: String::new(),
                    log_path: String::new(),
                    created_at: 0,
                    started_at: None,
                    finished_at: None,
                    exit_code: None,
                    reason: None,
                    labels: Default::default(),
                    annotations: Default::default(),
                    mounts: Vec::new(),
                    resources: None,
                    crun_root: None,
                    bundle_dir: None,
                    pid: None,
                    restart_count: 0,
                    stdin: false,
                    stdin_once: false,
                },
            )
            .unwrap();

        let resp = rt
            .exec(Request::new(v1::ExecRequest {
                container_id: "c1".into(),
                cmd: vec!["/bin/echo".into(), "hi".into()],
                tty: false,
                stdin: false,
                stdout: true,
                stderr: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.url.starts_with("http://127.0.0.1:10010/exec/"));
        assert_eq!(resp.url.rsplit('/').next().unwrap().len(), 64);
        assert_eq!(ctx.streaming.pending(), 1);

        // Unknown container -> NotFound.
        let err = rt
            .exec(Request::new(v1::ExecRequest {
                container_id: "nope".into(),
                cmd: vec!["x".into()],
                tty: false,
                stdin: false,
                stdout: true,
                stderr: true,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// Pull busybox and start a long-running container; returns (ctx, rt, id).
    async fn running_busybox(
        dir: &std::path::Path,
        command: Vec<String>,
        args: Vec<String>,
    ) -> (Arc<Context>, RuntimeSvc, String) {
        let ctx = test_context(dir);
        let images = ImageSvc { ctx: ctx.clone() };
        let rt = RuntimeSvc { ctx: ctx.clone() };
        let image = "docker.io/library/busybox:latest";
        images
            .pull_image(Request::new(v1::PullImageRequest {
                image: image_spec(image),
                auth: None,
                sandbox_config: None,
            }))
            .await
            .expect("pull busybox");
        let pod = rt
            .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
                config: Some(v1::PodSandboxConfig {
                    metadata: Some(v1::PodSandboxMetadata {
                        name: "p".into(),
                        uid: "u".into(),
                        namespace: "default".into(),
                        attempt: 0,
                    }),
                    ..Default::default()
                }),
                runtime_handler: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        let cid = rt
            .create_container(Request::new(v1::CreateContainerRequest {
                pod_sandbox_id: pod,
                config: Some(v1::ContainerConfig {
                    metadata: Some(v1::ContainerMetadata {
                        name: "c".into(),
                        attempt: 0,
                    }),
                    image: image_spec(image),
                    command,
                    args,
                    log_path: "c.log".into(),
                    ..Default::default()
                }),
                sandbox_config: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .container_id;
        rt.start_container(Request::new(v1::StartContainerRequest {
            container_id: cid.clone(),
        }))
        .await
        .expect("start");
        (ctx, rt, cid)
    }

    /// Wait until `crun exec` works (the container is actually running).
    async fn wait_execable(rt: &RuntimeSvc, cid: &str) {
        for _ in 0..200 {
            if let Ok(resp) = rt
                .exec_sync(Request::new(v1::ExecSyncRequest {
                    container_id: cid.into(),
                    cmd: vec!["/bin/true".into()],
                    timeout: 0,
                }))
                .await
            {
                if resp.into_inner().exit_code == 0 {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("container never became execable");
    }

    #[tokio::test]
    #[ignore = "requires network + crun: ExecSync into a running busybox container"]
    async fn exec_sync_runs_in_container() {
        let dir = tempfile::tempdir().unwrap();
        let (_ctx, rt, cid) =
            running_busybox(dir.path(), vec!["/bin/sleep".into()], vec!["20".into()]).await;
        wait_execable(&rt, &cid).await;

        let resp = rt
            .exec_sync(Request::new(v1::ExecSyncRequest {
                container_id: cid,
                cmd: vec!["/bin/echo".into(), "EXEC_SYNC_MARKER".into()],
                timeout: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.exit_code, 0);
        assert!(String::from_utf8_lossy(&resp.stdout).contains("EXEC_SYNC_MARKER"));
    }

    #[tokio::test]
    #[ignore = "requires network + crun: pod container reaches host localhost (shared netns)"]
    async fn pod_container_has_network() {
        use tokio::io::AsyncReadExt;

        let dir = tempfile::tempdir().unwrap();
        // Host-side TCP listener; the pod container connects to it via localhost.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });

        // Pod sandbox reports a real IP.
        let (ctx, _rt, _cid) = running_busybox(
            dir.path(),
            vec!["/bin/busybox".into()],
            vec![
                "sh".into(),
                "-c".into(),
                format!("echo POD_NET_OK | /bin/busybox nc 127.0.0.1 {port}"),
            ],
        )
        .await;
        // The sandbox of this container reports a routable pod IP.
        let sandboxes: Vec<SandboxRecord> = ctx
            .metadata
            .list(Kind::Sandbox, ctx.namespace.as_str())
            .unwrap();
        assert!(sandboxes[0].ip.as_deref().is_some_and(|ip| !ip.is_empty()));

        let received = tokio::time::timeout(std::time::Duration::from_secs(10), accept)
            .await
            .expect("listener timed out")
            .unwrap();
        assert!(
            received.contains("POD_NET_OK"),
            "pod container could not reach host localhost; got {received:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires network + crun: attach to a running container's live stdout"]
    async fn attach_streams_live_stdout() {
        use futures_util::StreamExt;

        let dir = tempfile::tempdir().unwrap();
        let (ctx, rt, cid) = running_busybox(
            dir.path(),
            vec!["/bin/sh".into()],
            vec![
                "-c".into(),
                "while true; do echo TICK; sleep 1; done".into(),
            ],
        )
        .await;
        wait_execable(&rt, &cid).await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::streaming::router(ctx.streaming.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let token = ctx
            .streaming
            .register_attach(crate::streaming::AttachSession {
                container_id: cid,
                stdin: false,
                stdout: true,
                stderr: true,
                tty: false,
                stdin_once: false,
            });

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/attach/{token}"))
            .await
            .unwrap();
        let mut saw = false;
        for _ in 0..40 {
            match tokio::time::timeout(std::time::Duration::from_secs(3), ws.next()).await {
                Ok(Some(Ok(msg))) if msg.is_binary() => {
                    let d = msg.into_data();
                    if d.first() == Some(&1) && String::from_utf8_lossy(&d[1..]).contains("TICK") {
                        saw = true;
                        break;
                    }
                }
                Ok(Some(Ok(_))) => continue,
                _ => break,
            }
        }
        assert!(saw, "did not receive live stdout over attach");
    }

    #[tokio::test]
    #[ignore = "requires network + crun: reads cgroup stats from a running container"]
    async fn container_stats_from_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let (_ctx, rt, cid) =
            running_busybox(dir.path(), vec!["/bin/sleep".into()], vec!["20".into()]).await;
        wait_execable(&rt, &cid).await;

        let stats = rt
            .container_stats(Request::new(v1::ContainerStatsRequest {
                container_id: cid.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .stats
            .expect("running container has stats");
        let mem = stats.memory.unwrap().working_set_bytes.unwrap().value;
        assert!(mem > 0, "expected non-zero memory usage, got {mem}");

        // ListContainerStats includes it.
        let list = rt
            .list_container_stats(Request::new(v1::ListContainerStatsRequest { filter: None }))
            .await
            .unwrap()
            .into_inner();
        assert!(list
            .stats
            .iter()
            .any(|s| s.attributes.as_ref().is_some_and(|a| a.id == cid)));
    }

    #[tokio::test]
    #[ignore = "requires network + crun: streaming exec over a real WebSocket"]
    async fn streaming_exec_over_websocket() {
        use futures_util::StreamExt;

        let dir = tempfile::tempdir().unwrap();
        let (ctx, rt, cid) =
            running_busybox(dir.path(), vec!["/bin/sleep".into()], vec!["20".into()]).await;
        wait_execable(&rt, &cid).await;

        // Bring up the streaming server on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::streaming::router(ctx.streaming.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let token = ctx.streaming.register_exec(crate::streaming::ExecSession {
            container_id: cid,
            cmd: vec!["/bin/echo".into(), "WS_EXEC_MARKER".into()],
            tty: false,
            stdin: false,
            stdout: true,
            stderr: true,
        });

        let url = format!("ws://{addr}/exec/{token}");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let mut saw_marker = false;
        let mut saw_coded_close = false;
        while let Some(Ok(msg)) = ws.next().await {
            use tokio_tungstenite::tungstenite::Message as TMsg;
            match msg {
                // Channel 1 (stdout) frame carrying the marker.
                TMsg::Binary(data)
                    if data.first() == Some(&1)
                        && String::from_utf8_lossy(&data[1..]).contains("WS_EXEC_MARKER") =>
                {
                    saw_marker = true;
                }
                TMsg::Binary(_) => {}
                TMsg::Close(Some(frame)) => {
                    let code_u16: u16 = frame.code.into();
                    assert_eq!(
                        code_u16, 1000,
                        "exec success path must close with code 1000 (Normal), got {code_u16}"
                    );
                    saw_coded_close = true;
                }
                _ => {}
            }
        }
        assert!(
            saw_marker,
            "did not receive stdout frame with marker over WS"
        );
        assert!(
            saw_coded_close,
            "exec success path must send a Close frame with code 1000 (got bare drop / Close(None))"
        );
    }

    // End-to-end through the CRI services: pull busybox, create + start a
    // container running `echo`, and confirm it actually executed (exit 0 + log
    // marker). Requires network (image pull) + crun + unprivileged userns.
    //   cargo test -p cri -- --ignored --test-threads=1
    #[tokio::test]
    #[ignore = "requires network + crun: pulls busybox and runs a container via CRI"]
    async fn cri_runs_busybox_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_context(dir.path());
        let images = ImageSvc { ctx: ctx.clone() };
        let rt = RuntimeSvc { ctx: ctx.clone() };
        let image = "docker.io/library/busybox:latest";

        images
            .pull_image(Request::new(v1::PullImageRequest {
                image: image_spec(image),
                auth: None,
                sandbox_config: None,
            }))
            .await
            .expect("pull busybox");

        let pod = rt
            .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
                config: Some(v1::PodSandboxConfig {
                    metadata: Some(v1::PodSandboxMetadata {
                        name: "p".into(),
                        uid: "u".into(),
                        namespace: "default".into(),
                        attempt: 0,
                    }),
                    ..Default::default()
                }),
                runtime_handler: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pod_sandbox_id;

        let cid = rt
            .create_container(Request::new(v1::CreateContainerRequest {
                pod_sandbox_id: pod,
                config: Some(v1::ContainerConfig {
                    metadata: Some(v1::ContainerMetadata {
                        name: "c".into(),
                        attempt: 0,
                    }),
                    image: image_spec(image),
                    command: vec!["/bin/echo".into()],
                    args: vec!["CRI_E2E_MARKER".into()],
                    log_path: "c.log".into(),
                    ..Default::default()
                }),
                sandbox_config: None,
            }))
            .await
            .unwrap()
            .into_inner()
            .container_id;

        rt.start_container(Request::new(v1::StartContainerRequest {
            container_id: cid.clone(),
        }))
        .await
        .expect("start");

        // Poll until the (short-lived) container exits.
        let mut exit_code = None;
        for _ in 0..200 {
            let st = rt
                .container_status(Request::new(v1::ContainerStatusRequest {
                    container_id: cid.clone(),
                    verbose: false,
                }))
                .await
                .unwrap()
                .into_inner()
                .status
                .unwrap();
            if st.state == v1::ContainerState::ContainerExited as i32 {
                exit_code = Some(st.exit_code);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(exit_code, Some(0), "container should exit 0");

        let bundle = runtime::shim::Bundle::new(&ctx.state_dir, ctx.namespace.as_str(), &cid);
        let log = std::fs::read_to_string(bundle.dir().join("c.log")).unwrap();
        assert!(log.contains("CRI_E2E_MARKER"), "container log: {log:?}");
    }

    // Feature: image reference normalization (critest Image Manager). A bare
    // name gets an implicit :latest; tagged and digest refs are unchanged; a
    // registry port colon is not mistaken for a tag.
    #[test]
    fn normalize_image_ref_adds_latest() {
        assert_eq!(normalize_image_ref("busybox"), "busybox:latest");
        assert_eq!(
            normalize_image_ref("gcr.io/foo/bar"),
            "gcr.io/foo/bar:latest"
        );
        assert_eq!(normalize_image_ref("busybox:1.29"), "busybox:1.29");
        assert_eq!(normalize_image_ref("host:5000/img"), "host:5000/img:latest");
        assert_eq!(normalize_image_ref("host:5000/img:v2"), "host:5000/img:v2");
        let dg = "img@sha256:9700f9a2f5bf2c45f2f605a0bd3bce7cf37420ec9d3ed50ac2758413308766bf";
        assert_eq!(normalize_image_ref(dg), dg);
        assert!(is_digest_ref(dg));
        assert!(!is_digest_ref("busybox:1.29"));
    }

    #[tokio::test]
    async fn remove_image_reclaims_and_fs_info() {
        use core_types::Digest;

        let dir = tempfile::tempdir().unwrap();
        let ctx = test_context(dir.path());
        let svc = ImageSvc { ctx: ctx.clone() };

        // Seed a config blob, a layer blob, and a snapshot dir, then record them.
        let config = Digest::sha256(b"config");
        let layer = Digest::sha256(b"layer");
        ctx.content.write_blob("c", b"config", &config).unwrap();
        ctx.content.write_blob("l", b"layer", &layer).unwrap();
        let chain = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let (fs, _) = snapshots::snapshot_dirs(&ctx.snapshots_root, chain);
        std::fs::create_dir_all(&fs).unwrap();

        ctx.metadata
            .put(
                Kind::Image,
                ctx.namespace.as_str(),
                // Images are keyed by image_id (see pull_image dedup/aggregate).
                &config.to_string(),
                &ImageRecord {
                    name: "img".into(),
                    target_digest: String::new(),
                    image_id: config.to_string(),
                    repo_tags: vec!["repo:tag".into()],
                    repo_digests: vec![],
                    size: 11,
                    layer_digests: vec![layer.to_string()],
                    chain_ids: vec![chain.to_string()],
                    user: String::new(),
                },
            )
            .unwrap();

        // ImageFsInfo reports non-zero usage (config + layer blobs).
        let fsinfo = svc
            .image_fs_info(Request::new(v1::ImageFsInfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        let used = fsinfo.image_filesystems[0]
            .used_bytes
            .as_ref()
            .unwrap()
            .value;
        assert!(used > 0);

        // Remove by image id -> blobs + snapshot reclaimed, list empty.
        svc.remove_image(Request::new(v1::RemoveImageRequest {
            image: image_spec(&config.to_string()),
        }))
        .await
        .unwrap();

        assert!(!ctx.content.exists(&config));
        assert!(!ctx.content.exists(&layer));
        assert!(!fs.exists());
        let list = svc
            .list_images(Request::new(v1::ListImagesRequest { filter: None }))
            .await
            .unwrap()
            .into_inner();
        assert!(list.images.is_empty());
    }

    // Requires network: exercises the ImageService PullImage -> ListImages ->
    // ImageStatus -> RemoveImage logic against a real registry.
    //   cargo test -p cri -- --ignored
    #[tokio::test]
    #[ignore = "requires network: pulls registry.k8s.io/pause:3.10 via ImageService"]
    async fn image_service_pull_list_status_remove() {
        let dir = tempfile::tempdir().unwrap();
        let svc = ImageSvc {
            ctx: test_context(dir.path()),
        };
        let reference = "registry.k8s.io/pause:3.10";

        let pulled = svc
            .pull_image(Request::new(v1::PullImageRequest {
                image: image_spec(reference),
                auth: None,
                sandbox_config: None,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(pulled.image_ref.starts_with("sha256:"));

        let list = svc
            .list_images(Request::new(v1::ListImagesRequest { filter: None }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(list.images.len(), 1);
        assert_eq!(list.images[0].id, pulled.image_ref);
        assert!(list.images[0].repo_tags.contains(&reference.to_string()));

        // Status resolvable by both the tag and the returned image id.
        for key in [reference, pulled.image_ref.as_str()] {
            let st = svc
                .image_status(Request::new(v1::ImageStatusRequest {
                    image: image_spec(key),
                    verbose: false,
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(st.image.unwrap().id, pulled.image_ref);
        }

        // Remove by tag, then the list is empty and status is None.
        svc.remove_image(Request::new(v1::RemoveImageRequest {
            image: image_spec(reference),
        }))
        .await
        .unwrap();
        let after = svc
            .list_images(Request::new(v1::ListImagesRequest { filter: None }))
            .await
            .unwrap()
            .into_inner();
        assert!(after.images.is_empty());
    }

    fn image_rec_with_user(user: &str) -> ImageRecord {
        ImageRecord {
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
}
