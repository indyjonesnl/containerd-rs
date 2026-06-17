//! Daemon configuration. Mirrors the load-bearing keys kubeadm/Kubernetes expect
//! from containerd's `config.toml` (see contracts/external-contracts.md §7),
//! adapted to containerd-rs paths.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Persistent root directory (content store, snapshots, metadata).
    pub root: PathBuf,
    /// Ephemeral state directory (sockets, bundles).
    pub state: PathBuf,
    /// CRI gRPC unix socket the kubelet dials.
    pub cri_socket: PathBuf,
    /// Address of the exec/attach/port-forward streaming HTTP server.
    pub stream_server_address: String,
    /// CRI plugin configuration.
    pub cri: CriConfig,
}

/// CRI-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CriConfig {
    /// Pause image anchoring pod sandboxes.
    pub sandbox_image: String,
    /// Default runtime handler name.
    pub default_runtime_name: String,
    /// Runtime type (shim) to launch.
    pub runtime_type: String,
    /// Snapshotter driver.
    pub snapshotter: String,
    /// Use the systemd cgroup driver (true on systemd hosts / Kubernetes).
    pub systemd_cgroup: bool,
    /// Directory of per-registry `hosts.toml` files.
    pub registry_config_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/var/lib/containerd-rs"),
            state: PathBuf::from("/run/containerd-rs"),
            cri_socket: PathBuf::from("/run/containerd-rs.sock"),
            stream_server_address: "127.0.0.1:10010".to_string(),
            cri: CriConfig::default(),
        }
    }
}

impl Default for CriConfig {
    fn default() -> Self {
        Self {
            sandbox_image: "registry.k8s.io/pause:3.10".to_string(),
            default_runtime_name: "runc".to_string(),
            runtime_type: "io.containerd.runc.v2".to_string(),
            snapshotter: "overlayfs".to_string(),
            systemd_cgroup: false,
            registry_config_path: PathBuf::from("/etc/containerd-rs/certs.d"),
        }
    }
}

impl Config {
    /// Parse a TOML config string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Load config from a file path, falling back to defaults if absent.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        if path.exists() {
            let text = std::fs::read_to_string(path)?;
            Ok(Self::from_toml(&text)?)
        } else {
            tracing::warn!(?path, "config file not found; using defaults");
            Ok(Self::default())
        }
    }

    /// Content store root directory.
    pub fn content_dir(&self) -> PathBuf {
        self.root.join("io.containerd.content.v1.content")
    }

    /// Snapshotter root directory.
    pub fn snapshots_dir(&self) -> PathBuf {
        self.root.join("io.containerd.snapshotter.v1.overlayfs")
    }

    /// Metadata database path.
    pub fn metadata_db(&self) -> PathBuf {
        self.root.join("io.containerd.metadata.v1.redb/meta.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_contract_keys() {
        let c = Config::default();
        assert_eq!(c.cri_socket, PathBuf::from("/run/containerd-rs.sock"));
        assert_eq!(c.cri.sandbox_image, "registry.k8s.io/pause:3.10");
        assert_eq!(c.cri.runtime_type, "io.containerd.runc.v2");
        assert_eq!(c.cri.snapshotter, "overlayfs");
    }

    #[test]
    fn toml_overrides_defaults() {
        let toml = r#"
            cri_socket = "/run/custom.sock"
            [cri]
            systemd_cgroup = true
            sandbox_image = "registry.k8s.io/pause:3.9"
        "#;
        let c = Config::from_toml(toml).unwrap();
        assert_eq!(c.cri_socket, PathBuf::from("/run/custom.sock"));
        assert!(c.cri.systemd_cgroup);
        assert_eq!(c.cri.sandbox_image, "registry.k8s.io/pause:3.9");
        // Untouched fields keep defaults.
        assert_eq!(c.cri.runtime_type, "io.containerd.runc.v2");
    }

    #[test]
    fn derived_paths() {
        let c = Config::default();
        assert!(c
            .content_dir()
            .ends_with("io.containerd.content.v1.content"));
        assert!(c.metadata_db().ends_with("meta.db"));
    }
}
