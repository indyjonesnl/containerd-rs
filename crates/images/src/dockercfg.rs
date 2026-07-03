//! Docker `config.json` credential resolution (feature 002 US4 / T027).
//!
//! When the kubelet does not hand the runtime a pull credential (the common
//! case for node-level base images without an `imagePullSecrets`), containerd
//! consults the node's docker config: the `auths` map, `credHelpers`, and
//! `credsStore` (external `docker-credential-*` binaries). This module mirrors
//! that resolution so private/node-credentialed pulls work as under containerd.
//!
//! Cloud credential exchange (ECR/GCR/ACR) is deferred (feature 002 T028) — it
//! needs a live cloud identity + network to implement and validate.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use base64::Engine as _;
use serde::Deserialize;

use crate::pull::Auth;

/// Parsed subset of a docker `config.json`.
#[derive(Debug, Default, Deserialize)]
pub struct DockerConfig {
    #[serde(default)]
    pub auths: HashMap<String, AuthEntry>,
    #[serde(default, rename = "credHelpers")]
    pub cred_helpers: HashMap<String, String>,
    #[serde(default, rename = "credsStore")]
    pub creds_store: Option<String>,
}

/// One `auths` entry.
#[derive(Debug, Default, Deserialize)]
pub struct AuthEntry {
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, rename = "identitytoken")]
    pub identity_token: String,
}

/// Normalize a registry reference/host key to a comparable `host[:port]`,
/// collapsing the Docker Hub aliases to `docker.io`.
fn norm_host(s: &str) -> String {
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let host = s.split('/').next().unwrap_or(s);
    match host {
        "index.docker.io" | "registry-1.docker.io" | "docker.io" => "docker.io".to_string(),
        h => h.to_string(),
    }
}

impl AuthEntry {
    fn to_auth(&self) -> Option<Auth> {
        if !self.identity_token.is_empty() {
            return Some(Auth::Bearer(self.identity_token.clone()));
        }
        if !self.username.is_empty() {
            return Some(Auth::Basic {
                username: self.username.clone(),
                password: self.password.clone(),
            });
        }
        if !self.auth.is_empty() {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(self.auth.trim())
                .ok()?;
            let s = String::from_utf8(decoded).ok()?;
            let (u, p) = s.split_once(':')?;
            return Some(Auth::Basic {
                username: u.to_string(),
                password: p.to_string(),
            });
        }
        None
    }
}

/// The JSON a `docker-credential-*` helper prints for `get`.
#[derive(Debug, Deserialize)]
struct HelperOutput {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Secret")]
    secret: String,
}

/// Parse a credential helper's `get` output into an `Auth`. A username of
/// `<token>` marks an identity/bearer token (the docker-credential convention).
/// Pure — separated for unit-testing without exec.
pub fn parse_helper_output(bytes: &[u8]) -> Option<Auth> {
    let out: HelperOutput = serde_json::from_slice(bytes).ok()?;
    if out.secret.is_empty() {
        return None;
    }
    if out.username == "<token>" {
        Some(Auth::Bearer(out.secret))
    } else {
        Some(Auth::Basic {
            username: out.username,
            password: out.secret,
        })
    }
}

/// Run `docker-credential-<helper> get` with `registry` on stdin.
fn run_helper(helper: &str, registry: &str) -> Option<Auth> {
    use std::io::Write;
    let mut child = Command::new(format!("docker-credential-{helper}"))
        .arg("get")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()?
        .write_all(norm_host(registry).as_bytes())
        .ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_helper_output(&out.stdout)
}

impl DockerConfig {
    /// Resolve credentials for `registry`, in docker's order: a per-registry
    /// `credHelpers` entry, then the global `credsStore`, then a matching
    /// `auths` entry. `None` if nothing matches (caller falls back to anonymous).
    pub fn resolve(&self, registry: &str) -> Option<Auth> {
        let host = norm_host(registry);
        if let Some(helper) = self
            .cred_helpers
            .iter()
            .find(|(k, _)| norm_host(k) == host)
            .map(|(_, v)| v)
        {
            if let Some(a) = run_helper(helper, registry) {
                return Some(a);
            }
        }
        if let Some(store) = &self.creds_store {
            if let Some(a) = run_helper(store, registry) {
                return Some(a);
            }
        }
        self.auths
            .iter()
            .find(|(k, _)| norm_host(k) == host)
            .and_then(|(_, e)| e.to_auth())
    }
}

/// Candidate docker config paths, in precedence order: `$DOCKER_CONFIG`, the
/// kubelet's config, and root's `~/.docker`.
fn config_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        v.push(PathBuf::from(dir).join("config.json"));
    }
    v.push(PathBuf::from("/var/lib/kubelet/config.json"));
    v.push(PathBuf::from("/root/.docker/config.json"));
    v
}

/// Load the first readable docker config from the candidate paths.
pub fn load_default() -> Option<DockerConfig> {
    for p in config_paths() {
        if let Ok(bytes) = std::fs::read(&p) {
            if let Ok(cfg) = serde_json::from_slice::<DockerConfig>(&bytes) {
                return Some(cfg);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_host_collapses_hub_and_strips_scheme() {
        assert_eq!(norm_host("https://index.docker.io/v1/"), "docker.io");
        assert_eq!(norm_host("registry-1.docker.io"), "docker.io");
        assert_eq!(norm_host("https://myreg.example.com/foo"), "myreg.example.com");
        assert_eq!(norm_host("myreg.example.com:5000"), "myreg.example.com:5000");
    }

    #[test]
    fn resolve_from_base64_auth() {
        let json = br#"{"auths":{"myreg.example.com":{"auth":"dXNlcjpwYXNz"}}}"#;
        let cfg: DockerConfig = serde_json::from_slice(json).unwrap();
        match cfg.resolve("myreg.example.com") {
            Some(Auth::Basic { username, password }) => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
            }
            other => panic!("expected Basic user:pass, got {other:?}"),
        }
        assert!(cfg.resolve("other.example.com").is_none());
    }

    #[test]
    fn resolve_from_explicit_username_and_hub_alias() {
        let json = br#"{"auths":{"https://index.docker.io/v1/":{"username":"u","password":"p"}}}"#;
        let cfg: DockerConfig = serde_json::from_slice(json).unwrap();
        // A docker.io image reference matches the index.docker.io key.
        assert!(matches!(
            cfg.resolve("docker.io"),
            Some(Auth::Basic { .. })
        ));
    }

    #[test]
    fn helper_output_token_vs_basic() {
        let tok = br#"{"ServerURL":"r","Username":"<token>","Secret":"abc"}"#;
        assert!(matches!(parse_helper_output(tok), Some(Auth::Bearer(t)) if t == "abc"));
        let basic = br#"{"ServerURL":"r","Username":"u","Secret":"s"}"#;
        assert!(matches!(parse_helper_output(basic), Some(Auth::Basic { .. })));
        assert!(parse_helper_output(br#"{"Username":"u","Secret":""}"#).is_none());
    }
}
