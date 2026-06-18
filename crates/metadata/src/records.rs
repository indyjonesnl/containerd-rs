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
