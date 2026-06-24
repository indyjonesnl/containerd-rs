//! Runtime-v2 shim client protocol.
//!
//! This module implements the parts of the shim v2 contract that are pure and
//! testable without a live shim: the shim **binary name** derivation, the
//! per-shim TTRPC **socket address** hashing, and the on-disk **bundle layout**
//! used for launch and restart recovery (see contracts/external-contracts.md §1
//! and §7). The actual process launch + bootstrap handshake + TTRPC Task client
//! require the `containerd-shim-crun-v2` binary and a live node, so they are not
//! implemented here yet (remainder of T015/T016).

use std::path::{Path, PathBuf};

use core_types::Digest;

/// Derive the shim binary name from a runtime id.
///
/// containerd takes the last two dot-separated components of the runtime id,
/// joins them with `-`, and prefixes `containerd-shim-`. So
/// `io.containerd.crun.v2` -> `containerd-shim-crun-v2`.
pub fn shim_binary_name(runtime_id: &str) -> String {
    let parts: Vec<&str> = runtime_id.split('.').collect();
    let n = parts.len();
    if n >= 2 {
        format!("containerd-shim-{}-{}", parts[n - 2], parts[n - 1])
    } else {
        format!("containerd-shim-{runtime_id}")
    }
}

/// Compute the per-shim TTRPC socket address.
///
/// Mirrors containerd: `unix://<stateDir>/s/<sha256(namespace/groupID)>`. The
/// hash is stable so containers sharing a `group_id` (e.g. all containers in one
/// Kubernetes pod, keyed by the sandbox id) reuse a single shim daemon.
pub fn socket_address(state_dir: &Path, namespace: &str, group_id: &str) -> String {
    let input = format!("{namespace}/{group_id}");
    let hash = Digest::sha256(input.as_bytes()).hex().to_string();
    format!("unix://{}/s/{}", state_dir.display(), hash)
}

/// On-disk bundle for one container/sandbox: `<state>/<namespace>/<id>/`.
///
/// Holds the OCI `config.json`, the mounted `rootfs/`, the shim `address` and
/// `bootstrap.json` (for restart reconnection), and runtime `options.json`.
#[derive(Debug, Clone)]
pub struct Bundle {
    dir: PathBuf,
}

impl Bundle {
    /// Bundle path for `id` within `namespace` under the daemon state dir.
    pub fn new(state_dir: &Path, namespace: &str, id: &str) -> Self {
        Self {
            dir: state_dir.join(namespace).join(id),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn rootfs(&self) -> PathBuf {
        self.dir.join("rootfs")
    }
    pub fn config_json(&self) -> PathBuf {
        self.dir.join("config.json")
    }
    /// File holding the shim's TTRPC address (written by the shim on start;
    /// read on daemon restart to reconnect).
    pub fn address_file(&self) -> PathBuf {
        self.dir.join("address")
    }
    /// Protobuf bootstrap params/result persisted for restart recovery.
    pub fn bootstrap_json(&self) -> PathBuf {
        self.dir.join("bootstrap.json")
    }
    pub fn options_json(&self) -> PathBuf {
        self.dir.join("options.json")
    }

    /// Create the bundle directory tree (`dir` + `rootfs/`).
    pub fn create(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.rootfs())
    }

    /// Remove the bundle directory tree.
    pub fn remove(&self) -> std::io::Result<()> {
        if self.dir.exists() {
            std::fs::remove_dir_all(&self.dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_name_from_runtime_id() {
        assert_eq!(
            shim_binary_name("io.containerd.crun.v2"),
            "containerd-shim-crun-v2"
        );
        assert_eq!(
            shim_binary_name("io.containerd.runwasi.v1"),
            "containerd-shim-runwasi-v1"
        );
        assert_eq!(shim_binary_name("custom"), "containerd-shim-custom");
    }

    #[test]
    fn socket_address_is_stable_and_grouped() {
        let state = Path::new("/run/containerd-rs");
        let a = socket_address(state, "k8s.io", "pod-123");
        let b = socket_address(state, "k8s.io", "pod-123");
        let c = socket_address(state, "k8s.io", "pod-456");
        assert_eq!(a, b, "same group -> same socket (shim reuse)");
        assert_ne!(a, c, "different group -> different socket");
        assert!(a.starts_with("unix:///run/containerd-rs/s/"));
        // 64 hex chars of sha256 after the `/s/` prefix.
        let hash = a.rsplit('/').next().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn bundle_layout() {
        let dir = tempfile::tempdir().unwrap();
        let b = Bundle::new(dir.path(), "k8s.io", "ctr-1");
        assert!(b.dir().ends_with("k8s.io/ctr-1"));
        assert!(b.config_json().ends_with("config.json"));
        assert!(b.address_file().ends_with("address"));
        assert!(b.bootstrap_json().ends_with("bootstrap.json"));

        b.create().unwrap();
        assert!(b.rootfs().is_dir());
        b.remove().unwrap();
        assert!(!b.dir().exists());
    }
}
