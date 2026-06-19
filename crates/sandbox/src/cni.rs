//! CNI (Container Network Interface) integration for pod networking.
//!
//! Mirrors what containerd's CRI plugin does for a non-host-network pod: create
//! a network namespace, then invoke the configured CNI plugin chain (ADD) to
//! wire a `veth` + assign a pod IP inside that netns; tear it down (DEL) on pod
//! removal. The plugin chain comes from a `*.conflist` in the CNI conf dir
//! (e.g. a Flannel conflist that delegates to the `bridge` plugin).
//!
//! Plugin invocation follows the CNI spec: exec `<bin_dir>/<type>` with the
//! `CNI_*` environment and the per-plugin network config (plus the previous
//! plugin's result as `prevResult`) on stdin; the last result carries the pod IP.
//! This requires root, so the exec paths are exercised on a real node; the pure
//! helpers (conflist selection, netconf assembly, result parsing) are unit-tested.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no CNI conflist found in {0}")]
    NoConfList(String),
    #[error("CNI plugin {plugin} failed: {msg}")]
    Plugin { plugin: String, msg: String },
    #[error("netns command failed: {0}")]
    Netns(String),
    #[error("no IP in CNI result")]
    NoIp,
}

type Result<T> = std::result::Result<T, Error>;

const IFNAME: &str = "eth0";

/// A parsed CNI conflist (`cniVersion` + `name` + ordered `plugins`).
#[derive(Debug, Clone, Deserialize)]
pub struct ConfList {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub name: String,
    pub plugins: Vec<serde_json::Value>,
}

/// A pod host-port mapping, fed to a `portmap`-capable plugin as the
/// `runtimeConfig.portMappings` capability arg (from CRI `PortMapping`).
#[derive(Debug, Clone)]
pub struct PortMapping {
    pub host_port: i32,
    pub container_port: i32,
    /// Lowercase CNI protocol: "tcp" | "udp" | "sctp".
    pub protocol: String,
    pub host_ip: String,
}

/// CNI runtime: knows where conflists and plugin binaries live.
#[derive(Debug, Clone)]
pub struct Cni {
    conf_dir: PathBuf,
    bin_dir: PathBuf,
    netns_dir: PathBuf,
}

impl Cni {
    pub fn new(conf_dir: impl Into<PathBuf>, bin_dir: impl Into<PathBuf>) -> Self {
        Self {
            conf_dir: conf_dir.into(),
            bin_dir: bin_dir.into(),
            netns_dir: PathBuf::from("/run/netns"),
        }
    }

    /// Load the lexicographically-first `*.conflist` in the conf dir. A bare
    /// `*.conf` is wrapped into a single-plugin list.
    pub fn load_conflist(&self) -> Result<ConfList> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.conf_dir)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|s| s.to_str()),
                    Some("conflist") | Some("conf")
                )
            })
            .collect();
        entries.sort();
        let path = entries
            .into_iter()
            .next()
            .ok_or_else(|| Error::NoConfList(self.conf_dir.display().to_string()))?;
        let bytes = std::fs::read(&path)?;
        if path.extension().and_then(|s| s.to_str()) == Some("conflist") {
            Ok(serde_json::from_slice(&bytes)?)
        } else {
            // Wrap a single plugin .conf as a one-element list.
            let plugin: serde_json::Value = serde_json::from_slice(&bytes)?;
            Ok(ConfList {
                cni_version: plugin
                    .get("cniVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1.0.0")
                    .to_string(),
                name: plugin
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("cni")
                    .to_string(),
                plugins: vec![plugin],
            })
        }
    }

    /// Filesystem path of a named network namespace (`/run/netns/<name>`).
    pub fn netns_path(&self, netns: &str) -> PathBuf {
        self.netns_dir.join(netns)
    }

    /// Create a named network namespace (`ip netns add`).
    pub fn create_netns(&self, netns: &str) -> Result<PathBuf> {
        let out = Command::new("ip").args(["netns", "add", netns]).output()?;
        if !out.status.success() {
            return Err(Error::Netns(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        Ok(self.netns_path(netns))
    }

    /// Delete a named network namespace (`ip netns del`); ignores absence.
    pub fn delete_netns(&self, netns: &str) -> Result<()> {
        let _ = Command::new("ip").args(["netns", "del", netns]).output()?;
        Ok(())
    }

    /// Run the ADD chain for `container_id` against `netns`, returning the pod IP.
    /// `port_mappings` are injected as the `runtimeConfig.portMappings` capability
    /// arg for any plugin that declares `capabilities.portMappings` (e.g. portmap),
    /// which is how pod `hostPort`s are programmed.
    pub fn setup(
        &self,
        container_id: &str,
        netns: &str,
        port_mappings: &[PortMapping],
    ) -> Result<String> {
        let conflist = self.load_conflist()?;
        let netns_path = self.netns_path(netns);
        let mut prev_result: Option<serde_json::Value> = None;
        for plugin in &conflist.plugins {
            let mut netconf = assemble_netconf(&conflist, plugin, prev_result.as_ref());
            inject_port_mappings(&mut netconf, plugin, port_mappings);
            let result = self.exec_plugin("ADD", container_id, &netns_path, plugin, &netconf)?;
            prev_result = Some(result);
        }
        extract_ip(prev_result.as_ref().ok_or(Error::NoIp)?)
    }

    /// Run the DEL chain (reverse order) for `container_id`; best-effort.
    pub fn teardown(&self, container_id: &str, netns: &str) -> Result<()> {
        if let Ok(conflist) = self.load_conflist() {
            let netns_path = self.netns_path(netns);
            for plugin in conflist.plugins.iter().rev() {
                let netconf = assemble_netconf(&conflist, plugin, None);
                let _ = self.exec_plugin("DEL", container_id, &netns_path, plugin, &netconf);
            }
        }
        self.delete_netns(netns)
    }

    fn exec_plugin(
        &self,
        command: &str,
        container_id: &str,
        netns_path: &Path,
        plugin: &serde_json::Value,
        netconf: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let plugin_type = plugin
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let mut child = Command::new(self.bin_dir.join(&plugin_type))
            .env("CNI_COMMAND", command)
            .env("CNI_CONTAINERID", container_id)
            .env("CNI_NETNS", netns_path)
            .env("CNI_IFNAME", IFNAME)
            .env("CNI_PATH", &self.bin_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        {
            use std::io::Write;
            let stdin = child.stdin.as_mut().expect("piped stdin");
            stdin.write_all(serde_json::to_string(netconf)?.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(Error::Plugin {
                plugin: plugin_type,
                msg: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        // DEL produces no result; ADD does. Empty stdout -> null.
        if out.stdout.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    }
}

/// Assemble the per-plugin network config the CNI spec feeds on stdin:
/// the plugin object + `cniVersion`/`name` from the list + optional `prevResult`.
fn assemble_netconf(
    conflist: &ConfList,
    plugin: &serde_json::Value,
    prev_result: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut netconf = plugin.clone();
    if let Some(obj) = netconf.as_object_mut() {
        obj.insert("cniVersion".into(), conflist.cni_version.clone().into());
        obj.insert("name".into(), conflist.name.clone().into());
        if let Some(prev) = prev_result {
            obj.insert("prevResult".into(), prev.clone());
        }
    }
    netconf
}

/// If `plugin` declares `capabilities.portMappings`, inject the pod's host-port
/// mappings as `runtimeConfig.portMappings` (the CNI capability-args convention).
fn inject_port_mappings(
    netconf: &mut serde_json::Value,
    plugin: &serde_json::Value,
    port_mappings: &[PortMapping],
) {
    if port_mappings.is_empty() {
        return;
    }
    let capable = plugin
        .get("capabilities")
        .and_then(|c| c.get("portMappings"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    if !capable {
        return;
    }
    let Some(obj) = netconf.as_object_mut() else {
        return;
    };
    let mappings: Vec<serde_json::Value> = port_mappings
        .iter()
        .map(|p| {
            serde_json::json!({
                "hostPort": p.host_port,
                "containerPort": p.container_port,
                "protocol": p.protocol,
                "hostIP": p.host_ip,
            })
        })
        .collect();
    let rc = obj
        .entry("runtimeConfig")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(rc_obj) = rc.as_object_mut() {
        rc_obj.insert("portMappings".into(), serde_json::Value::Array(mappings));
    }
}

/// Extract the first IPv4/IPv6 address (without prefix) from a CNI result.
fn extract_ip(result: &serde_json::Value) -> Result<String> {
    let ips = result
        .get("ips")
        .and_then(|v| v.as_array())
        .ok_or(Error::NoIp)?;
    let addr = ips
        .first()
        .and_then(|ip| ip.get("address"))
        .and_then(|a| a.as_str())
        .ok_or(Error::NoIp)?;
    // "10.244.0.5/24" -> "10.244.0.5"
    Ok(addr.split('/').next().unwrap_or(addr).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flannel_conflist() {
        let dir = tempdir();
        std::fs::write(
            dir.join("10-flannel.conflist"),
            r#"{"cniVersion":"1.0.0","name":"cbr0","plugins":[
                {"type":"flannel","delegate":{"isDefaultGateway":true}},
                {"type":"portmap","capabilities":{"portMappings":true}}]}"#,
        )
        .unwrap();
        let cni = Cni::new(&dir, "/opt/cni/bin");
        let cl = cni.load_conflist().unwrap();
        assert_eq!(cl.name, "cbr0");
        assert_eq!(cl.plugins.len(), 2);
        assert_eq!(cl.plugins[0]["type"], "flannel");
    }

    #[test]
    fn assemble_injects_version_name_and_prev() {
        let cl = ConfList {
            cni_version: "1.0.0".into(),
            name: "cbr0".into(),
            plugins: vec![],
        };
        let plugin = serde_json::json!({"type":"bridge","isGateway":true});
        let prev = serde_json::json!({"ips":[{"address":"10.0.0.1/24"}]});
        let nc = assemble_netconf(&cl, &plugin, Some(&prev));
        assert_eq!(nc["cniVersion"], "1.0.0");
        assert_eq!(nc["name"], "cbr0");
        assert_eq!(nc["type"], "bridge");
        assert_eq!(nc["prevResult"]["ips"][0]["address"], "10.0.0.1/24");
    }

    #[test]
    fn extract_ip_strips_prefix() {
        let r = serde_json::json!({"ips":[{"address":"10.244.1.7/24","gateway":"10.244.1.1"}]});
        assert_eq!(extract_ip(&r).unwrap(), "10.244.1.7");
        assert!(extract_ip(&serde_json::json!({})).is_err());
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("cni-test-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
