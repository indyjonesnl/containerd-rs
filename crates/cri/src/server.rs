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
    ContainerRecord, ContainerState, ImageRecord, SandboxRecord, SandboxState,
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
    /// Ephemeral state dir; holds per-container OCI bundles + the runc state.
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
}

impl Context {
    /// Build a context using the CRI runtime namespace (`k8s.io`). `stream_addr`
    /// is the streaming server's listen address (e.g. `127.0.0.1:10010`).
    pub fn new(
        content: content::Store,
        metadata: metadata::Store,
        snapshots_root: PathBuf,
        state_dir: PathBuf,
        stream_addr: &str,
        cni_conf_dir: PathBuf,
        cni_bin_dir: PathBuf,
    ) -> Self {
        let streaming = Arc::new(crate::streaming::Sessions::new(state_dir.join("runc")));
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
        }
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

fn record_to_image(rec: &ImageRecord) -> v1::Image {
    v1::Image {
        id: rec.image_id.clone(),
        repo_tags: rec.repo_tags.clone(),
        repo_digests: rec.repo_digests.clone(),
        size: rec.size,
        uid: None,
        username: String::new(),
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

    /// Sample cgroup stats for a Running container via `runc events --stats`.
    /// Returns `None` for non-running containers (no live cgroup).
    async fn container_stats_for(&self, rec: &ContainerRecord) -> Option<v1::ContainerStats> {
        if rec.state != ContainerState::Running {
            return None;
        }
        let runc_root = self.ctx.state_dir.join("runc");
        let id = rec.id.clone();
        let out = tokio::task::spawn_blocking(move || {
            runtime::runc::stats(runtime::runc::DEFAULT_BIN, &runc_root, &id)
        })
        .await
        .ok()?
        .ok()?;
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let data = &v["data"];
        let cpu_total = data["cpu"]["usage"]["total"].as_u64().unwrap_or(0);
        let mem_usage = data["memory"]["usage"]["usage"].as_u64().unwrap_or(0);
        let ts = unix_nanos();
        Some(v1::ContainerStats {
            attributes: Some(v1::ContainerAttributes {
                id: rec.id.clone(),
                metadata: Some(v1::ContainerMetadata {
                    name: rec.name.clone(),
                    attempt: rec.attempt,
                }),
                labels: std::collections::HashMap::new(),
                annotations: std::collections::HashMap::new(),
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

    /// Find an image record by reference, image id, repo tag, or name.
    fn find_image(&self, image_ref: &str) -> Result<Option<ImageRecord>, Status> {
        let all = self
            .ctx
            .metadata
            .list::<ImageRecord>(Kind::Image, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(all.into_iter().find(|r| {
            r.image_id == image_ref
                || r.repo_tags.iter().any(|t| t == image_ref)
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
                "defaultRuntimeName": "runc",
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
        Err(Status::unimplemented(
            "get_container_events not yet implemented",
        ))
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

        // Host network if the pod requests NODE network mode; otherwise try CNI.
        let host_network = config
            .linux
            .as_ref()
            .and_then(|l| l.security_context.as_ref())
            .and_then(|sc| sc.namespace_options.as_ref())
            .map(|ns| ns.network == v1::NamespaceMode::Node as i32)
            .unwrap_or(false);

        // Returns (netns_path, pod_ip). For a CNI pod we create a netns + run the
        // plugin chain; if CNI is unavailable/fails we fall back to host network
        // (rootless containers share the host net namespace).
        let (netns_path, ip) = if host_network {
            ("host".to_string(), sandbox::net::host_ip())
        } else {
            match self
                .ctx
                .cni
                .create_netns(&id)
                .and_then(|_| self.ctx.cni.setup(&id, &id))
            {
                Ok(ip) => {
                    tracing::info!(sandbox = %id, %ip, "RunPodSandbox (CNI)");
                    (self.ctx.cni.netns_path(&id).display().to_string(), ip)
                }
                Err(e) => {
                    let _ = self.ctx.cni.teardown(&id, &id);
                    tracing::warn!(sandbox = %id, error = %e, "CNI setup failed; falling back to host network");
                    ("host".to_string(), sandbox::net::host_ip())
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
            resolv_conf_path,
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
                        pid: v1::NamespaceMode::Container as i32,
                        ipc: v1::NamespaceMode::Pod as i32,
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
        // kind/Docker node), a rootless spec's userns + dropped caps make runc's
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
            hostname: None,
            terminal: config.tty,
            readonly_rootfs: false,
            rootless_host_ids: host_ids,
            netns_path: sandbox.netns_path.clone(),
            mounts: {
                let mut mounts: Vec<runtime::bundle::MountSpec> = config
                    .mounts
                    .iter()
                    .map(|m| runtime::bundle::MountSpec {
                        source: m.host_path.clone(),
                        destination: m.container_path.clone(),
                        readonly: m.readonly,
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
                        });
                    }
                }
                mounts
            },
            privileged,
            run_as_user,
            run_as_group,
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
        };
        self.ctx
            .metadata
            .put(Kind::Container, self.ns(), &id, &rec)
            .map_err(|e| Status::internal(e.to_string()))?;
        tracing::info!(container = %id, "CreateContainer wrote OCI bundle + record");
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
            mounts: Vec::new(),
            log_path: rec.log_path.clone(),
            resources: None,
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
        let id = request.into_inner().container_id;
        if let Some(mut rec) = self.get_container(&id)? {
            if rec.state != ContainerState::Exited {
                // Actually kill the runc container (SIGTERM); the supervision
                // task observes the exit. Without this the process lingers and
                // a kubelet restart hits a port conflict -> CrashLoop.
                let runc_root = self.ctx.state_dir.join("runc");
                let id2 = id.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    runtime::runc::kill(runtime::runc::DEFAULT_BIN, &runc_root, &id2, "SIGTERM")
                })
                .await;
                rec.state = ContainerState::Exited;
                rec.finished_at = Some(unix_nanos() as u64);
                rec.exit_code = Some(0);
                self.ctx
                    .metadata
                    .put(Kind::Container, self.ns(), &id, &rec)
                    .map_err(|e| Status::internal(e.to_string()))?;
            }
        }
        Ok(Response::new(v1::StopContainerResponse {}))
    }

    async fn remove_container(
        &self,
        request: Request<v1::RemoveContainerRequest>,
    ) -> Result<Response<v1::RemoveContainerResponse>, Status> {
        let id = request.into_inner().container_id;
        // Force-delete any leftover runc state, then drop record + bundle.
        let runc_root = self.ctx.state_dir.join("runc");
        let id2 = id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            runtime::runc::delete(runtime::runc::DEFAULT_BIN, &runc_root, &id2)
        })
        .await;
        self.ctx
            .metadata
            .delete(Kind::Container, self.ns(), &id)
            .map_err(|e| Status::internal(e.to_string()))?;
        let _ = runtime::shim::Bundle::new(&self.ctx.state_dir, self.ns(), &id).remove();
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
        let runc_root = self.ctx.state_dir.join("runc");
        std::fs::create_dir_all(&runc_root).map_err(|e| Status::internal(e.to_string()))?;

        let log_path = container_log_path(&bundle, &rec.log_path);

        // Mark Running before launching; supervision flips it to Exited on exit.
        rec.state = ContainerState::Running;
        rec.started_at = Some(unix_nanos() as u64);
        self.ctx
            .metadata
            .put(Kind::Container, self.ns(), &id, &rec)
            .map_err(|e| Status::internal(e.to_string()))?;

        // Supervise the container with LIVE stdio: spawn `runc run` with piped
        // stdout/stderr, stream each chunk to the CRI log file *and* a broadcast
        // bus (for Attach / log-follow), then record the exit code.
        let ctx = self.ctx.clone();
        let ns = self.ns().to_string();
        let cid = id.clone();
        let bundle_dir = bundle.dir().to_path_buf();
        let live = self.ctx.streaming.live_channel(&id);
        tokio::spawn(async move {
            let code = supervise_container(&runc_root, &bundle_dir, &cid, &log_path, live).await;
            if let Ok(Some(mut r)) = ctx
                .metadata
                .get::<ContainerRecord>(Kind::Container, &ns, &cid)
            {
                r.state = ContainerState::Exited;
                r.exit_code = Some(code);
                r.finished_at = Some(unix_nanos() as u64);
                let _ = ctx.metadata.put(Kind::Container, &ns, &cid, &r);
            }
            ctx.streaming.close_live(&cid);
            tracing::info!(container = %cid, exit_code = code, "container exited");
        });

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

        let runc_root = self.ctx.state_dir.join("runc");
        let id = req.container_id.clone();
        let cmd = req.cmd.clone();
        let out = tokio::task::spawn_blocking(move || {
            runtime::runc::exec(runtime::runc::DEFAULT_BIN, &runc_root, &id, &cmd)
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .map_err(|e| Status::internal(format!("runc exec: {e}")))?;

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
        self.get_container(&req.container_id)?.ok_or_else(|| {
            Status::not_found(format!("container {} not found", req.container_id))
        })?;
        let token = self
            .ctx
            .streaming
            .register_attach(crate::streaming::AttachSession {
                container_id: req.container_id,
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
        self.ctx
            .metadata
            .get::<SandboxRecord>(Kind::Sandbox, self.ns(), &req.pod_sandbox_id)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!("sandbox {} not found", req.pod_sandbox_id))
            })?;
        let token = self
            .ctx
            .streaming
            .register_portforward(crate::streaming::PortForwardSession {
                pod_sandbox_id: req.pod_sandbox_id,
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
        let bundle = runtime::shim::Bundle::new(&self.ctx.state_dir, self.ns(), &id);
        let log_path = container_log_path(&bundle, &rec.log_path);
        // Recreate the log file (kubelet calls this after rotating it away).
        std::fs::File::create(&log_path).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(v1::ReopenContainerLogResponse {}))
    }

    unary_unimpl! {
        update_container_resources => UpdateContainerResourcesRequest / UpdateContainerResourcesResponse,
        pod_sandbox_stats => PodSandboxStatsRequest / PodSandboxStatsResponse,
        list_pod_sandbox_stats => ListPodSandboxStatsRequest / ListPodSandboxStatsResponse,
        update_runtime_config => UpdateRuntimeConfigRequest / UpdateRuntimeConfigResponse,
        checkpoint_container => CheckpointContainerRequest / CheckpointContainerResponse,
        list_metric_descriptors => ListMetricDescriptorsRequest / ListMetricDescriptorsResponse,
        list_pod_sandbox_metrics => ListPodSandboxMetricsRequest / ListPodSandboxMetricsResponse,
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
        let all = self
            .ctx
            .metadata
            .list::<ImageRecord>(Kind::Image, self.ns())
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(all.into_iter().find(|r| {
            r.image_id == key
                || r.repo_tags.iter().any(|t| t == key)
                || r.repo_digests.iter().any(|d| d == key)
        }))
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

        let auth = match req.auth {
            Some(a) if !a.username.is_empty() => images::pull::Auth::Basic {
                username: a.username,
                password: a.password,
            },
            _ => images::pull::Auth::Anonymous,
        };

        let pulled = images::pull::pull(
            &reference,
            &self.ctx.content,
            &self.ctx.snapshots_root,
            &auth,
        )
        .await
        .map_err(|e| Status::internal(format!("pull {reference} failed: {e}")))?;

        let repo_digests = match &pulled.manifest_digest {
            Some(d) => vec![format!("{}@{}", repo_name(&reference), d)],
            None => Vec::new(),
        };
        let record = ImageRecord {
            name: reference.clone(),
            target_digest: pulled
                .manifest_digest
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_default(),
            image_id: pulled.image_id.to_string(),
            repo_tags: vec![reference.clone()],
            repo_digests,
            size: pulled.size,
            layer_digests: pulled.layer_digests.iter().map(|d| d.to_string()).collect(),
            chain_ids: pulled.chain_ids.iter().map(|d| d.to_string()).collect(),
        };
        self.ctx
            .metadata
            .put(Kind::Image, self.ns(), &reference, &record)
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
            self.ctx
                .metadata
                .delete(Kind::Image, self.ns(), &rec.name)
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

/// Format one stream's chunk into CRI log lines: `<RFC3339Nano> <stream> F <line>`.
fn cri_log_line(stream: &str, data: &[u8]) -> Vec<u8> {
    let ts = humantime::format_rfc3339_nanos(std::time::SystemTime::now()).to_string();
    let mut out = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        out.extend_from_slice(ts.as_bytes());
        out.push(b' ');
        out.extend_from_slice(stream.as_bytes());
        out.extend_from_slice(b" F ");
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Pump one runc output stream to both the CRI log file and the live bus.
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

/// Run `runc run` with piped stdio, streaming output live; returns the exit code.
async fn supervise_container(
    runc_root: &Path,
    bundle_dir: &Path,
    cid: &str,
    log_path: &Path,
    live: tokio::sync::broadcast::Sender<crate::streaming::LiveFrame>,
) -> i32 {
    let mut cmd = tokio::process::Command::new(runtime::runc::DEFAULT_BIN);
    cmd.arg("--root")
        .arg(runc_root)
        .arg("run")
        .arg("--bundle")
        .arg(bundle_dir)
        .arg(cid)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::write(
                log_path,
                cri_log_line("stderr", format!("runc spawn: {e}").as_bytes()),
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
        tracing::info!(container = %cid, code = ?s.code(), signal = ?s.signal(), "runc run returned");
    }
    status.ok().and_then(|s| s.code()).unwrap_or(-1)
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
    pub marked_unknown: usize,
}

/// Reconcile persisted state after a daemon restart.
///
/// The metadata DB survives restarts, so sandboxes and containers are
/// re-discovered (not orphaned or duplicated). Because task supervision
/// (T015–T016) is not yet wired, there is no live shim to confirm a previously
/// `Running` container is still alive — such containers are conservatively
/// marked `Unknown` so the kubelet reconciles them, rather than being falsely
/// reported as `Running`.
pub fn reconcile(ctx: &Context) -> Result<ReconcileReport, metadata::Error> {
    let ns = &ctx.namespace;
    let mut report = ReconcileReport::default();

    let sandboxes: Vec<SandboxRecord> = ctx.metadata.list(Kind::Sandbox, ns)?;
    report.sandboxes = sandboxes.len();

    let containers: Vec<ContainerRecord> = ctx.metadata.list(Kind::Container, ns)?;
    report.containers = containers.len();
    for mut c in containers {
        if c.state == ContainerState::Running {
            c.state = ContainerState::Unknown;
            ctx.metadata.put(Kind::Container, ns, &c.id, &c)?;
            report.marked_unknown += 1;
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
        ))
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
            .pod_sandbox_stats(v1::PodSandboxStatsRequest {
                pod_sandbox_id: "nope".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

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
                        resolv_conf_path: None,
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
                },
            )
            .unwrap();

        // A sandbox to host the container.
        let pod = svc
            .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
                config: Some(v1::PodSandboxConfig {
                    metadata: Some(v1::PodSandboxMetadata {
                        name: "pod".into(),
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

    /// Wait until `runc exec` works (the container is actually running).
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
    #[ignore = "requires network + runc: ExecSync into a running busybox container"]
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
    #[ignore = "requires network + runc: pod container reaches host localhost (shared netns)"]
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
    #[ignore = "requires network + runc: attach to a running container's live stdout"]
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
            .register_attach(crate::streaming::AttachSession { container_id: cid });

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
    #[ignore = "requires network + runc: reads cgroup stats from a running container"]
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
    #[ignore = "requires network + runc: streaming exec over a real WebSocket"]
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
        });

        let url = format!("ws://{addr}/exec/{token}");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let mut saw_marker = false;
        while let Some(Ok(msg)) = ws.next().await {
            if msg.is_binary() {
                let data = msg.into_data();
                // Channel 1 (stdout) frame carrying the marker.
                if data.first() == Some(&1)
                    && String::from_utf8_lossy(&data[1..]).contains("WS_EXEC_MARKER")
                {
                    saw_marker = true;
                }
            }
        }
        assert!(
            saw_marker,
            "did not receive stdout frame with marker over WS"
        );
    }

    // End-to-end through the CRI services: pull busybox, create + start a
    // container running `echo`, and confirm it actually executed (exit 0 + log
    // marker). Requires network (image pull) + runc + unprivileged userns.
    //   cargo test -p cri -- --ignored --test-threads=1
    #[tokio::test]
    #[ignore = "requires network + runc: pulls busybox and runs a container via CRI"]
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
                "img",
                &ImageRecord {
                    name: "img".into(),
                    target_digest: String::new(),
                    image_id: config.to_string(),
                    repo_tags: vec!["repo:tag".into()],
                    repo_digests: vec![],
                    size: 11,
                    layer_digests: vec![layer.to_string()],
                    chain_ids: vec![chain.to_string()],
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
}
