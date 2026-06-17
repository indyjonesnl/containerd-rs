//! OCI runtime bundle generation.
//!
//! Produces a runtime-spec `config.json` from an image config plus a container
//! request, mirroring how containerd's CRI plugin builds the container spec
//! (image Env/Entrypoint/Cmd/User/WorkingDir merged with the CRI request). The
//! base spec (default Linux namespaces, standard mounts, capabilities) comes
//! from `oci_spec::runtime::Spec::default()`; we override process/root/hostname.

use std::path::{Path, PathBuf};

use oci_spec::runtime::{
    LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder, ProcessBuilder, RootBuilder, Spec,
    UserBuilder,
};

/// A bind mount to inject into the container (from a CRI mount).
#[derive(Debug, Clone)]
pub struct MountSpec {
    pub source: String,
    pub destination: String,
    pub readonly: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("oci-spec error: {0}")]
    Spec(#[from] oci_spec::OciSpecError),
    #[error("spec builder error: {0}")]
    Builder(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Subset of the OCI image config relevant to bundle generation.
#[derive(Debug, Default, Clone)]
pub struct ImageConfig {
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub working_dir: Option<String>,
    /// Image `User` field: `uid`, `uid:gid`, `user`, or `user:group`.
    pub user: Option<String>,
}

/// Container-creation request fields (from the CRI `ContainerConfig`).
#[derive(Debug, Default, Clone)]
pub struct ContainerRequest {
    /// Overrides the image ENTRYPOINT.
    pub command: Vec<String>,
    /// Overrides the image CMD.
    pub args: Vec<String>,
    pub envs: Vec<(String, String)>,
    pub working_dir: Option<String>,
    pub hostname: Option<String>,
    pub terminal: bool,
    pub readonly_rootfs: bool,
    /// When set, build a rootless spec mapping container uid/gid 0 to these host
    /// ids (a user namespace + uid/gid mappings + rootless-friendly mounts).
    pub rootless_host_ids: Option<(u32, u32)>,
    /// Network namespace for the container:
    /// * `None` / `Some("host")` -> no network namespace (share host/sandbox-host net)
    /// * `Some(path)` -> join the pod's network namespace at `path` (CNI sandbox)
    pub netns_path: Option<String>,
    /// Host-path bind mounts to inject (from the CRI container config).
    pub mounts: Vec<MountSpec>,
}

/// Resolve the final argv using Kubernetes/CRI override semantics.
///
/// * command + args      -> command ++ args
/// * command only        -> command (image CMD ignored)
/// * args only           -> image ENTRYPOINT ++ args
/// * neither             -> image ENTRYPOINT ++ image CMD
pub fn resolve_argv(image: &ImageConfig, req: &ContainerRequest) -> Vec<String> {
    match (req.command.is_empty(), req.args.is_empty()) {
        (false, false) => [req.command.clone(), req.args.clone()].concat(),
        (false, true) => req.command.clone(),
        (true, false) => [image.entrypoint.clone(), req.args.clone()].concat(),
        (true, true) => [image.entrypoint.clone(), image.cmd.clone()].concat(),
    }
}

/// Merge image env with request env; request entries override by key.
fn merge_env(image: &ImageConfig, req: &ContainerRequest) -> Vec<String> {
    let mut out = image.env.clone();
    for (k, v) in &req.envs {
        let prefix = format!("{k}=");
        out.retain(|e| !e.starts_with(&prefix));
        out.push(format!("{k}={v}"));
    }
    out
}

/// Parse the image `User` field into (uid, gid). Non-numeric names (which need
/// `/etc/passwd` from the rootfs to resolve) fall back to 0.
fn parse_user(user: &Option<String>) -> (u32, u32) {
    match user {
        Some(s) if !s.is_empty() => {
            let mut parts = s.splitn(2, ':');
            let uid = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
            let gid = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
            (uid, gid)
        }
        _ => (0, 0),
    }
}

/// Generate an OCI runtime spec for a container.
pub fn generate_spec(image: &ImageConfig, req: &ContainerRequest, rootfs: &Path) -> Result<Spec> {
    let argv = resolve_argv(image, req);
    let env = merge_env(image, req);
    let cwd = req
        .working_dir
        .clone()
        .or_else(|| image.working_dir.clone())
        .unwrap_or_else(|| "/".to_string());
    let (uid, gid) = parse_user(&image.user);

    let user = UserBuilder::default()
        .uid(uid)
        .gid(gid)
        .build()
        .map_err(|e| Error::Builder(e.to_string()))?;

    let process = ProcessBuilder::default()
        .terminal(req.terminal)
        .args(argv)
        .env(env)
        .cwd(PathBuf::from(cwd))
        .user(user)
        .build()
        .map_err(|e| Error::Builder(e.to_string()))?;

    let root = RootBuilder::default()
        .path(rootfs.to_path_buf())
        .readonly(req.readonly_rootfs)
        .build()
        .map_err(|e| Error::Builder(e.to_string()))?;

    // A rootless base brings the user namespace + uid/gid mappings + rootless
    // mounts; otherwise the standard Linux spec. Process/root/hostname are
    // overridden below either way.
    let mut spec = match req.rootless_host_ids {
        Some((uid, gid)) => Spec::rootless(uid, gid),
        None => Spec::default(),
    };
    spec.set_process(Some(process));
    spec.set_root(Some(root));
    if let Some(h) = &req.hostname {
        spec.set_hostname(Some(h.clone()));
    }
    set_network_namespace(&mut spec, req.netns_path.as_deref());
    add_bind_mounts(&mut spec, &req.mounts);
    Ok(spec)
}

/// Append CRI host-path bind mounts to the spec.
fn add_bind_mounts(spec: &mut Spec, mounts: &[MountSpec]) {
    if mounts.is_empty() {
        return;
    }
    let mut all = spec.mounts().clone().unwrap_or_default();
    for m in mounts {
        let opts = vec![
            "rbind".to_string(),
            "rprivate".to_string(),
            if m.readonly { "ro" } else { "rw" }.to_string(),
        ];
        if let Ok(mount) = MountBuilder::default()
            .destination(PathBuf::from(&m.destination))
            .typ("bind".to_string())
            .source(PathBuf::from(&m.source))
            .options(opts)
            .build()
        {
            all.push(mount);
        }
    }
    spec.set_mounts(Some(all));
}

/// Point the container's network namespace at the pod's (CNI), or drop it for
/// host networking.
fn set_network_namespace(spec: &mut Spec, netns_path: Option<&str>) {
    let Some(mut linux) = spec.linux().clone() else {
        return;
    };
    let mut namespaces = linux.namespaces().clone().unwrap_or_default();
    namespaces.retain(|n| n.typ() != LinuxNamespaceType::Network);
    match netns_path {
        None | Some("host") => {} // no network namespace -> share host net
        Some(path) => {
            if let Ok(ns) = LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Network)
                .path(PathBuf::from(path))
                .build()
            {
                namespaces.push(ns);
            }
        }
    }
    linux.set_namespaces(Some(namespaces));
    spec.set_linux(Some(linux));
}

/// Write a bundle to `bundle_dir`: create `rootfs/` and serialize `config.json`.
/// Returns the path to the written `config.json`.
pub fn write_bundle(bundle_dir: &Path, spec: &Spec) -> Result<PathBuf> {
    std::fs::create_dir_all(bundle_dir.join("rootfs"))?;
    let config = bundle_dir.join("config.json");
    spec.save(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img() -> ImageConfig {
        ImageConfig {
            env: vec!["PATH=/usr/bin".into()],
            entrypoint: vec!["/pause".into()],
            cmd: vec!["--v=2".into()],
            working_dir: Some("/app".into()),
            user: Some("1000:1001".into()),
        }
    }

    #[test]
    fn argv_override_matrix() {
        let i = img();
        // neither -> entrypoint ++ cmd
        assert_eq!(
            resolve_argv(&i, &ContainerRequest::default()),
            vec!["/pause", "--v=2"]
        );
        // args only -> entrypoint ++ args
        let r = ContainerRequest {
            args: vec!["--v=4".into()],
            ..Default::default()
        };
        assert_eq!(resolve_argv(&i, &r), vec!["/pause", "--v=4"]);
        // command only -> command (image cmd dropped)
        let r = ContainerRequest {
            command: vec!["/bin/sh".into()],
            ..Default::default()
        };
        assert_eq!(resolve_argv(&i, &r), vec!["/bin/sh"]);
        // both
        let r = ContainerRequest {
            command: vec!["/bin/sh".into()],
            args: vec!["-c".into(), "echo hi".into()],
            ..Default::default()
        };
        assert_eq!(resolve_argv(&i, &r), vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn env_merge_overrides_by_key() {
        let i = img();
        let r = ContainerRequest {
            envs: vec![
                ("PATH".into(), "/custom".into()),
                ("EXTRA".into(), "1".into()),
            ],
            ..Default::default()
        };
        let env = merge_env(&i, &r);
        assert!(env.contains(&"PATH=/custom".to_string()));
        assert!(!env.contains(&"PATH=/usr/bin".to_string()));
        assert!(env.contains(&"EXTRA=1".to_string()));
    }

    #[test]
    fn parse_user_variants() {
        assert_eq!(parse_user(&Some("1000:1001".into())), (1000, 1001));
        assert_eq!(parse_user(&Some("1000".into())), (1000, 0));
        assert_eq!(parse_user(&Some("root".into())), (0, 0));
        assert_eq!(parse_user(&None), (0, 0));
    }

    #[test]
    fn generates_and_writes_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let i = img();
        let r = ContainerRequest {
            hostname: Some("pod-xyz".into()),
            readonly_rootfs: true,
            ..Default::default()
        };
        let rootfs = dir.path().join("merged");
        let spec = generate_spec(&i, &r, &rootfs).unwrap();

        let proc = spec.process().as_ref().unwrap();
        assert_eq!(proc.args().as_ref().unwrap(), &vec!["/pause", "--v=2"]);
        assert_eq!(proc.cwd(), &PathBuf::from("/app"));
        assert_eq!(proc.user().uid(), 1000);
        assert_eq!(spec.root().as_ref().unwrap().readonly(), Some(true));
        assert_eq!(spec.hostname().as_deref(), Some("pod-xyz"));
        // Default Linux spec brings standard mounts + namespaces.
        assert!(spec
            .mounts()
            .as_ref()
            .map(|m| !m.is_empty())
            .unwrap_or(false));
        assert!(spec.linux().is_some());

        let bundle = dir.path().join("bundle");
        let config = write_bundle(&bundle, &spec).unwrap();
        assert!(config.is_file());
        assert!(bundle.join("rootfs").is_dir());
        // Round-trips back through the parser.
        let reloaded = Spec::load(&config).unwrap();
        assert_eq!(reloaded.hostname().as_deref(), Some("pod-xyz"));
    }
}
