//! Typed metadata records and their state machines, per
//! `specs/001-rust-containerd/data-model.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Pod sandbox readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxState {
    Ready,
    NotReady,
}

/// CRI container lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerState {
    Created,
    Running,
    Exited,
    Unknown,
}

impl ContainerState {
    /// Whether a transition from `self` to `next` is legal.
    ///
    /// Created → Running → Exited; any state may degrade to Unknown; Unknown may
    /// recover to Running or settle to Exited (e.g. after restart reconcile).
    pub fn can_transition_to(self, next: ContainerState) -> bool {
        use ContainerState::*;
        match (self, next) {
            (Created, Running) => true,
            (Created, Exited) => true, // process exited immediately
            (Running, Exited) => true,
            (_, Unknown) => true,
            (Unknown, Running) => true,
            (Unknown, Exited) => true,
            (a, b) if a == b => true, // idempotent
            _ => false,
        }
    }
}

/// Persisted pod sandbox record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRecord {
    pub id: String,
    pub name: String,
    pub k8s_namespace: String,
    pub uid: String,
    pub attempt: u32,
    pub state: SandboxState,
    pub netns_path: Option<String>,
    pub ip: Option<String>,
    pub runtime_handler: String,
    pub pause_container_id: Option<String>,
    pub snapshot_key: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// CRI pod log directory; container `log_path` is relative to this.
    #[serde(default)]
    pub log_directory: String,
    /// Whether the sandbox shares the host network namespace (NODE network mode).
    /// Reported back in `PodSandboxStatus.linux.namespaces.options.network` so the
    /// kubelet's `podSandboxChanged` namespace-mode comparison matches and it does
    /// not recreate the sandbox every sync.
    #[serde(default)]
    pub host_network: bool,
    /// Whether the sandbox shares the host PID namespace (CRI `namespaceOptions.pid
    /// == NODE`, HostPID). Applied per-container (no pause holder). `#[serde(default)]`
    /// so records written before this field deserialize.
    #[serde(default)]
    pub host_pid: bool,
    /// Whether the sandbox shares the host IPC namespace (HostIPC).
    #[serde(default)]
    pub host_ipc: bool,
    /// Whether containers share a pod-level PID namespace (CRI `namespaceOptions.pid
    /// == POD`, i.e. `shareProcessNamespace`). We run no pause container, so a
    /// dedicated holder process owns the shared namespace; see [[pid_holder]].
    #[serde(default)]
    pub shared_pid: bool,
    /// Whether containers share a pod-level IPC namespace (`namespaceOptions.ipc == POD`).
    #[serde(default)]
    pub shared_ipc: bool,
    /// Host pid of the PID/IPC namespace holder (its PID 1), when `shared_pid` or
    /// `shared_ipc`. Containers join `/proc/<pid>/ns/{pid,ipc}`; killed on sandbox
    /// teardown. `None` when the sandbox shares no pod-level PID/IPC namespace.
    #[serde(default)]
    pub pid_holder_pid: Option<i32>,
    /// Path to the generated `resolv.conf` for this sandbox (from the CRI
    /// `DNSConfig`), bind-mounted at `/etc/resolv.conf` in each container so DNS
    /// works (e.g. CoreDNS's `forward . /etc/resolv.conf`). `None` when no DNS
    /// config was supplied.
    #[serde(default)]
    pub resolv_conf_path: Option<String>,
    /// Namespaced sysctls from the pod's `securityContext.sysctls`
    /// (`LinuxPodSandboxConfig.sysctls`). We run no pause container, so these are
    /// applied to each container's OCI spec (`linux.sysctl`) at create time.
    #[serde(default)]
    pub sysctls: HashMap<String, String>,
    /// CRI `LinuxPodSandboxConfig.cgroup_parent` — the kubelet-managed cgroup the
    /// pod's containers live under. Containers set `linux.cgroupsPath` beneath it
    /// so crun applies resource limits in a delegated cgroup (rather than at the
    /// root, which fails cgroup-v2's "no internal processes" rule).
    #[serde(default)]
    pub cgroup_parent: String,
    /// CRI `PodSandboxConfig.hostname` — the pod's hostname (the kubelet sets it
    /// to the pod name by default). We run no pause container, so it is applied
    /// to each container's OCI `hostname` (in its private UTS namespace) so the
    /// pod reports its own name rather than the node's (e.g. agnhost `/hostname`,
    /// which sig-network's pod-connectivity conformance tests assert against).
    #[serde(default)]
    pub hostname: String,
}

/// Persisted container record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub id: String,
    pub sandbox_id: String,
    pub name: String,
    pub attempt: u32,
    pub image_ref: String,
    pub image_id: String,
    pub state: ContainerState,
    pub snapshot_key: String,
    pub log_path: String,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub reason: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// Container bind mounts (host_path, container_path, readonly), echoed back in
    /// `ContainerStatus.mounts`. The kubelet matches these to read a terminated
    /// container's `terminationMessagePath` file from the host side.
    #[serde(default)]
    pub mounts: Vec<MountRecord>,
    /// Current CRI resource limits, echoed in `ContainerStatus.resources`. Set at
    /// CreateContainer and updated by UpdateContainerResources (in-place resize),
    /// so the kubelet can verify a resize took effect.
    #[serde(default)]
    pub resources: Option<ResourcesRecord>,
    /// Re-adoption handle for surviving a daemon restart (see
    /// `specs/002-containerd-parity/data-model.md`). The OCI runtime `--root`
    /// state dir; with `bundle_dir` and `pid` it lets `reconcile()` probe
    /// `crun state <id>` and re-attach to a still-running container after a
    /// daemon restart instead of marking it `Unknown`. `None` on records written
    /// before restart-survival landed.
    #[serde(default)]
    pub crun_root: Option<String>,
    /// OCI bundle directory for the container (for re-adoption + cleanup).
    #[serde(default)]
    pub bundle_dir: Option<String>,
    /// Host pid of the container init process, used to re-attach an exit waiter
    /// (via pidfd) after a daemon restart.
    #[serde(default)]
    pub pid: Option<i32>,
    /// Kubelet-visible restart count. MUST be preserved across a daemon restart
    /// (a runtime restart is not a container restart).
    #[serde(default)]
    pub restart_count: u32,
    /// CRI `ContainerConfig.stdin` — the container keeps an open stdin (a pipe)
    /// so an interactive process (e.g. a shell) stays alive waiting for input
    /// that `Attach` forwards. Without it the process reads EOF and exits.
    #[serde(default)]
    pub stdin: bool,
    /// CRI `ContainerConfig.stdin_once` — when set (and not a TTY), closing the
    /// attaching client's stdin closes the container's stdin (EOF to the
    /// process), mirroring containerd's `ContainerIO.Attach` (StdinOnce && !Tty).
    /// Keeping stdin open past the attach otherwise hangs a client that waits for
    /// the streams to close (e.g. critest `should support attach`).
    #[serde(default)]
    pub stdin_once: bool,
}

/// A container mount echoed in `ContainerStatus.mounts`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MountRecord {
    pub host_path: String,
    pub container_path: String,
    pub readonly: bool,
    /// CRI `MountPropagation` enum value (0=PRIVATE, 1=HOST_TO_CONTAINER,
    /// 2=BIDIRECTIONAL); echoed in `ContainerStatus.mounts[].propagation`.
    #[serde(default)]
    pub propagation: i32,
    /// CRI `Mount.recursive_read_only`; echoed in `ContainerStatus.mounts`.
    #[serde(default)]
    pub recursive_read_only: bool,
}

/// Current CRI `LinuxContainerResources` values, echoed in `ContainerStatus.resources`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourcesRecord {
    pub cpu_period: i64,
    pub cpu_quota: i64,
    pub cpu_shares: i64,
    pub memory_limit_in_bytes: i64,
    pub cpuset_cpus: String,
    pub cpuset_mems: String,
}

/// Persisted image record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRecord {
    pub name: String,
    pub target_digest: String,
    /// Image config digest (also the CRI image id).
    pub image_id: String,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    pub size: u64,
    /// Compressed layer blob digests this image references (for GC).
    #[serde(default)]
    pub layer_digests: Vec<String>,
    /// Snapshot chainIDs this image references (for GC).
    #[serde(default)]
    pub chain_ids: Vec<String>,
    /// OCI image config `User` (e.g. "65532", "65532:65532", "nonroot"); empty
    /// means root. Surfaced to the kubelet for runAsNonRoot admission.
    #[serde(default)]
    pub user: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_container_transitions() {
        use ContainerState::*;
        assert!(Created.can_transition_to(Running));
        assert!(Running.can_transition_to(Exited));
        assert!(Created.can_transition_to(Exited));
        assert!(Running.can_transition_to(Unknown));
        assert!(Unknown.can_transition_to(Running));
        assert!(Running.can_transition_to(Running)); // idempotent
    }

    #[test]
    fn illegal_container_transitions() {
        use ContainerState::*;
        assert!(!Exited.can_transition_to(Running));
        assert!(!Exited.can_transition_to(Created));
        assert!(!Running.can_transition_to(Created));
    }
}
