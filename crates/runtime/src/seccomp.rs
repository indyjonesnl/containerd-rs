//! The containerd/Docker **RuntimeDefault** seccomp profile.
//!
//! CRI `SecurityProfile::RuntimeDefault` must apply "the runtime's default
//! seccomp profile" (a syscall allowlist). Rather than hand-roll an allowlist
//! (a wrong one is worse than none — it breaks real workloads), we vendor the
//! canonical upstream profile — moby's `profiles/seccomp/default.json`, which
//! containerd's `contrib/seccomp` mirrors — and *resolve* it exactly the way
//! Docker/containerd's `setupSeccomp` does: for the host architecture and the
//! container's effective capability set, keeping only the syscall blocks whose
//! `includes`/`excludes` (caps/arches/minKernel) conditions match.
//!
//! Resolving against the container's caps (rather than emitting a fixed
//! allowlist) is what upstream does and is load-bearing: a container that adds
//! `NET_ADMIN`/`SYS_TIME`/… under RuntimeDefault still gets that capability's
//! syscalls, so RuntimeDefault never breaks an otherwise-valid workload.
//!
//! The resolved profile is returned as an `oci_spec` `LinuxSeccomp`; crun
//! installs it as a classic BPF filter (the container then reports `Seccomp: 2`
//! in `/proc/self/status`).

use std::collections::BTreeSet;

use oci_spec::runtime::LinuxSeccomp;
use serde::Deserialize;
use serde_json::{json, Value};

/// The vendored upstream base profile (Docker seccomp JSON format).
const DEFAULT_PROFILE_JSON: &str = include_str!("seccomp/default_profile.json");

/// Docker-seccomp profile shape (the subset moby's `default.json` uses).
#[derive(Debug, Deserialize)]
struct DockerProfile {
    #[serde(rename = "defaultAction")]
    default_action: String,
    #[serde(rename = "defaultErrnoRet")]
    default_errno_ret: Option<i64>,
    #[serde(rename = "archMap", default)]
    arch_map: Vec<ArchMapEntry>,
    #[serde(default)]
    syscalls: Vec<SyscallBlock>,
}

#[derive(Debug, Deserialize)]
struct ArchMapEntry {
    architecture: String,
    // Upstream writes `null` (not `[]`) for arches with no sub-arches, so accept
    // an explicit null (serde `default` alone only covers a missing field).
    #[serde(rename = "subArchitectures", default)]
    sub_architectures: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SyscallBlock {
    names: Vec<String>,
    action: String,
    #[serde(rename = "errnoRet")]
    errno_ret: Option<i64>,
    #[serde(default)]
    args: Vec<Value>,
    #[serde(default)]
    includes: Filter,
    #[serde(default)]
    excludes: Filter,
}

/// A syscall block's include/exclude conditions.
#[derive(Debug, Default, Deserialize)]
struct Filter {
    #[serde(default)]
    caps: Vec<String>,
    #[serde(default)]
    arches: Vec<String>,
    #[serde(rename = "minKernel")]
    #[serde(default)]
    min_kernel: Option<String>,
}

/// Map the host's Rust target arch to the (Docker GOARCH token, seccomp
/// `SCMP_ARCH_*`) pair the profile keys on. `None` for unsupported arches — the
/// caller then emits no architecture filter (the profile applies regardless,
/// which is what crun assumes when `architectures` is empty).
fn host_arch() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "x86_64" => Some(("amd64", "SCMP_ARCH_X86_64")),
        "aarch64" => Some(("arm64", "SCMP_ARCH_AARCH64")),
        _ => None,
    }
}

/// Build the RuntimeDefault seccomp profile resolved for the given effective
/// capabilities (each a `CAP_*` string). Mirrors Docker/containerd
/// `setupSeccomp`: architecture from the host, syscall blocks filtered by their
/// `includes`/`excludes`.
///
/// `minKernel` gates are treated as satisfied (any realistic host kernel is far
/// newer than the profile's single `4.8` gate) — includes are kept, excludes
/// are not applied on that basis.
pub fn runtime_default(effective_caps: &BTreeSet<String>) -> Result<LinuxSeccomp, String> {
    let profile: DockerProfile = serde_json::from_str(DEFAULT_PROFILE_JSON)
        .map_err(|e| format!("parse bundled default seccomp profile: {e}"))?;

    let host = host_arch();
    let goarch = host.map(|(g, _)| g);

    // Architectures: the host's primary arch plus its sub-architectures, from
    // the profile's archMap.
    let mut architectures: Vec<String> = Vec::new();
    if let Some((_, scmp)) = host {
        if let Some(entry) = profile.arch_map.iter().find(|e| e.architecture == scmp) {
            architectures.push(entry.architecture.clone());
            architectures.extend(entry.sub_architectures.iter().flatten().cloned());
        }
    }

    let cap_matches = |names: &[String]| names.iter().any(|c| effective_caps.contains(c));
    let arch_matches = |names: &[String]| goarch.is_some_and(|a| names.iter().any(|x| x == a));

    let mut syscalls: Vec<Value> = Vec::new();
    for block in &profile.syscalls {
        // Excludes take precedence (Docker order): drop the block if any exclude
        // condition matches.
        if !block.excludes.arches.is_empty() && arch_matches(&block.excludes.arches) {
            continue;
        }
        if !block.excludes.caps.is_empty() && cap_matches(&block.excludes.caps) {
            continue;
        }
        // Includes: keep only if every present include condition matches.
        if !block.includes.arches.is_empty() && !arch_matches(&block.includes.arches) {
            continue;
        }
        if !block.includes.caps.is_empty() && !cap_matches(&block.includes.caps) {
            continue;
        }
        // minKernel: treated as satisfied (see fn docs), so an `includes.minKernel`
        // block is kept and an `excludes.minKernel` block is dropped.
        if block.excludes.min_kernel.is_some() {
            continue;
        }

        let mut entry = json!({ "names": block.names, "action": block.action });
        if let Some(ret) = block.errno_ret {
            entry["errnoRet"] = json!(ret);
        }
        if !block.args.is_empty() {
            entry["args"] = json!(block.args);
        }
        syscalls.push(entry);
    }

    let mut oci = json!({
        "defaultAction": profile.default_action,
        "architectures": architectures,
        "syscalls": syscalls,
    });
    if let Some(ret) = profile.default_errno_ret {
        oci["defaultErrnoRet"] = json!(ret);
    }

    serde_json::from_value(oci).map_err(|e| format!("build OCI seccomp from default profile: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn resolves_to_a_filter_profile() {
        let s = runtime_default(&caps(&[])).expect("resolve");
        // A real filter: ERRNO default action + a non-empty allowlist.
        assert_eq!(
            format!("{:?}", s.default_action()),
            format!("{:?}", oci_spec::runtime::LinuxSeccompAction::ScmpActErrno)
        );
        let n = s.syscalls().as_ref().map(|v| v.len()).unwrap_or(0);
        assert!(n > 5, "expected a populated allowlist, got {n} blocks");
    }

    #[test]
    fn cap_gated_syscalls_follow_capabilities() {
        // `open_by_handle_at` is gated on CAP_DAC_READ_SEARCH in the profile.
        let has = |s: &LinuxSeccomp, name: &str| {
            s.syscalls()
                .as_ref()
                .map(|v| v.iter().any(|c| c.names().iter().any(|n| n == name)))
                .unwrap_or(false)
        };
        let without = runtime_default(&caps(&[])).unwrap();
        assert!(
            !has(&without, "open_by_handle_at"),
            "cap-gated syscall must be absent without its capability"
        );
        let with = runtime_default(&caps(&["CAP_DAC_READ_SEARCH"])).unwrap();
        assert!(
            has(&with, "open_by_handle_at"),
            "cap-gated syscall must be present when the capability is held"
        );
    }
}
