//! OCI runtime bundle generation.
//!
//! Produces a runtime-spec `config.json` from an image config plus a container
//! request, mirroring how containerd's CRI plugin builds the container spec
//! (image Env/Entrypoint/Cmd/User/WorkingDir merged with the CRI request). The
//! base spec (default Linux namespaces, standard mounts, capabilities) comes
//! from `oci_spec::runtime::Spec::default()`; we override process/root/hostname.

use std::path::{Path, PathBuf};

use oci_spec::runtime::{
    Capability, LinuxCapabilitiesBuilder, LinuxCpuBuilder, LinuxDeviceCgroupBuilder,
    LinuxMemoryBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, LinuxResourcesBuilder,
    MountBuilder, ProcessBuilder, RootBuilder, Spec, UserBuilder,
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
    /// Privileged mode (CRI `security_context.privileged`): grant the full
    /// capability set, drop the masked/readonly `/proc` hardening, and allow all
    /// devices. Required by host components like kube-proxy (which writes
    /// `/proc/sys/net/netfilter/*` and programs iptables/nftables).
    pub privileged: bool,
    /// CRI `security_context.run_as_user` — overrides the image `User` uid. When a
    /// pod requests a non-root uid, the kubelet owns its projected serviceaccount
    /// token by that uid (mode 0600); running as the image default (often root)
    /// with caps dropped then can't read it, breaking in-cluster API access.
    pub run_as_user: Option<u32>,
    /// CRI `security_context.run_as_group` — overrides the image `User` gid.
    pub run_as_group: Option<u32>,
    /// CRI `security_context.supplemental_groups` — extra GIDs for the container
    /// process (OCI `process.user.additionalGids`). The kubelet folds the pod's
    /// `fsGroup` into this set, so honoring it is what lets a non-root container
    /// read fsGroup-owned volume files (e.g. group-readable projected secrets).
    pub supplemental_groups: Vec<u32>,
    /// Namespaced sysctls to set in the container's OCI spec (`linux.sysctl`).
    /// Sourced from the pod's `LinuxPodSandboxConfig.sysctls` (we run no pause
    /// container, so they are applied per-container).
    pub sysctls: std::collections::HashMap<String, String>,
    /// CPU/memory limits + requests (from CRI `LinuxContainerResources`), applied
    /// to the OCI `linux.resources` so runc programs the container's cgroup
    /// (cgroup v2: `memory.max`, `cpu.max`, `cpu.weight`). Without these a
    /// container runs unconstrained (`memory.max=max`, `cpu.max=max`).
    pub resources: Resources,
    /// OCI `linux.cgroupsPath` — the kubelet-delegated cgroup the container lives
    /// under (derived from the sandbox's `cgroup_parent`). `Some` only when the
    /// kubelet provides a cgroup parent; resources are applied ONLY when this is
    /// set, so runc never enables controllers on the root cgroup (which fails
    /// cgroup-v2's "no internal processes" rule). Mirrors containerd's
    /// `getCgroupsPath` + "set cgroup only if cgroup_parent != \"\"".
    pub cgroup_path: Option<String>,
}

/// CRI container resource limits/requests mapped to OCI `linux.resources`.
/// `None` fields are left unset (the cgroup default).
#[derive(Debug, Clone, Default)]
pub struct Resources {
    pub cpu_shares: Option<u64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
    pub memory_limit: Option<i64>,
    pub cpuset_cpus: Option<String>,
    pub cpuset_mems: Option<String>,
}

impl Resources {
    fn is_empty(&self) -> bool {
        self.cpu_shares.is_none()
            && self.cpu_quota.is_none()
            && self.cpu_period.is_none()
            && self.memory_limit.is_none()
            && self.cpuset_cpus.is_none()
            && self.cpuset_mems.is_none()
    }
}

/// The full Linux capability set, granted to privileged containers.
fn all_capabilities() -> std::collections::HashSet<Capability> {
    use Capability::*;
    [
        AuditControl,
        AuditRead,
        AuditWrite,
        BlockSuspend,
        Bpf,
        CheckpointRestore,
        Chown,
        DacOverride,
        DacReadSearch,
        Fowner,
        Fsetid,
        IpcLock,
        IpcOwner,
        Kill,
        Lease,
        LinuxImmutable,
        MacAdmin,
        MacOverride,
        Mknod,
        NetAdmin,
        NetBindService,
        NetBroadcast,
        NetRaw,
        Perfmon,
        Setfcap,
        Setgid,
        Setpcap,
        Setuid,
        SysAdmin,
        SysBoot,
        SysChroot,
        SysModule,
        SysNice,
        SysPacct,
        SysPtrace,
        SysRawio,
        SysResource,
        SysTime,
        SysTtyConfig,
        Syslog,
        WakeAlarm,
    ]
    .into_iter()
    .collect()
}

/// Turn `spec` into a privileged container: full caps, no masked/readonly paths,
/// allow-all device cgroup. Mirrors containerd's CRI privileged handling.
fn apply_privileged(spec: &mut Spec) {
    let caps = all_capabilities();
    if let Ok(lc) = LinuxCapabilitiesBuilder::default()
        .bounding(caps.clone())
        .effective(caps.clone())
        .permitted(caps.clone())
        .inheritable(caps.clone())
        .ambient(caps)
        .build()
    {
        if let Some(mut process) = spec.process().clone() {
            process.set_capabilities(Some(lc));
            spec.set_process(Some(process));
        }
    }

    if let Some(mut linux) = spec.linux().clone() {
        // Drop the /proc hardening so privileged workloads can write sysctls.
        linux.set_masked_paths(None);
        linux.set_readonly_paths(None);
        // Allow access to all devices: `a *:* rwm`.
        if let Ok(rule) = LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .access("rwm")
            .build()
        {
            let resources = match linux.resources().clone() {
                Some(mut r) => {
                    r.set_devices(Some(vec![rule]));
                    Some(r)
                }
                None => LinuxResourcesBuilder::default()
                    .devices(vec![rule])
                    .build()
                    .ok(),
            };
            linux.set_resources(resources);
        }
        spec.set_linux(Some(linux));
    }
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
    // CRI run_as_user/run_as_group override the image's User.
    let (img_uid, img_gid) = parse_user(&image.user);
    let uid = req.run_as_user.unwrap_or(img_uid);
    let gid = req.run_as_group.unwrap_or(img_gid);

    let user_builder = UserBuilder::default().uid(uid).gid(gid);
    let user_builder = if req.supplemental_groups.is_empty() {
        user_builder
    } else {
        user_builder.additional_gids(req.supplemental_groups.clone())
    };
    let user = user_builder
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
    // Resource limits require a delegated cgroup (cgroupsPath under the kubelet's
    // cgroup_parent); applying them with runc's default root-level path fails
    // cgroup-v2's "no internal processes" rule. So set cgroupsPath and apply
    // resources together, only when the kubelet gave us a cgroup parent.
    if let Some(cgroup_path) = req.cgroup_path.as_deref().filter(|p| !p.is_empty()) {
        if let Some(mut linux) = spec.linux().clone() {
            linux.set_cgroups_path(Some(PathBuf::from(cgroup_path)));
            spec.set_linux(Some(linux));
        }
        apply_resources(&mut spec, &req.resources);
    }
    if req.privileged {
        apply_privileged(&mut spec);
    }
    apply_sysctls(&mut spec, &req.sysctls);
    Ok(spec)
}

/// Map CRI resource limits/requests onto the OCI `linux.resources` so runc
/// programs the container's cgroup (cgroup v2: `memory.max` from the memory
/// limit, `cpu.max` from quota/period, `cpu.weight` from shares). Unset fields
/// are left at the cgroup default.
fn apply_resources(spec: &mut Spec, res: &Resources) {
    if res.is_empty() {
        return;
    }
    let Some(mut linux) = spec.linux().clone() else {
        return;
    };
    let mut resources = linux.resources().clone().unwrap_or_default();

    let mut cpu = LinuxCpuBuilder::default();
    if let Some(s) = res.cpu_shares {
        cpu = cpu.shares(s);
    }
    if let Some(q) = res.cpu_quota {
        cpu = cpu.quota(q);
    }
    if let Some(p) = res.cpu_period {
        cpu = cpu.period(p);
    }
    if let Some(c) = res.cpuset_cpus.clone().filter(|s| !s.is_empty()) {
        cpu = cpu.cpus(c);
    }
    if let Some(m) = res.cpuset_mems.clone().filter(|s| !s.is_empty()) {
        cpu = cpu.mems(m);
    }
    if let Ok(cpu) = cpu.build() {
        resources.set_cpu(Some(cpu));
    }

    if let Some(limit) = res.memory_limit {
        if let Ok(mem) = LinuxMemoryBuilder::default().limit(limit).build() {
            resources.set_memory(Some(mem));
        }
    }

    linux.set_resources(Some(resources));
    spec.set_linux(Some(linux));
}

/// Set namespaced sysctls in the container's OCI `linux.sysctl`. runc writes
/// these to `/proc/sys/...` inside the container's namespaces during init.
fn apply_sysctls(spec: &mut Spec, sysctls: &std::collections::HashMap<String, String>) {
    if sysctls.is_empty() {
        return;
    }
    let Some(mut linux) = spec.linux().clone() else {
        return;
    };
    let mut merged = linux.sysctl().clone().unwrap_or_default();
    for (k, v) in sysctls {
        merged.insert(k.clone(), v.clone());
    }
    linux.set_sysctl(Some(merged));
    spec.set_linux(Some(linux));
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

    // Regression: a pod with CPU/memory requests+limits must program the
    // container cgroup. Without this the conformance "pod cgroup limits" test
    // sees memory.max=max / cpu.max=max. CRI LinuxContainerResources ->
    // OCI linux.resources (runc converts to cgroup v2 values).
    #[test]
    fn resources_map_to_oci_cgroup_limits() {
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            resources: Resources {
                cpu_shares: Some(2),
                cpu_quota: Some(2000),
                cpu_period: Some(100_000),
                memory_limit: Some(20_971_520),
                ..Default::default()
            },
            // Resources are applied only when a delegated cgroup path is present.
            cgroup_path: Some("/kubepods/pod123/abc".into()),
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, std::path::Path::new("/tmp/rootfs")).unwrap();
        let linux = spec.linux().clone().unwrap();
        assert_eq!(
            linux.cgroups_path().as_ref().map(|p| p.to_string_lossy()),
            Some("/kubepods/pod123/abc".into())
        );
        let res = linux.resources().clone().unwrap();
        let cpu = res.cpu().clone().expect("cpu resources set");
        assert_eq!(cpu.shares(), Some(2));
        assert_eq!(cpu.quota(), Some(2000));
        assert_eq!(cpu.period(), Some(100_000));
        assert_eq!(
            res.memory().as_ref().expect("memory resources set").limit(),
            Some(20_971_520)
        );
    }

    // Safety gate (regression for the bring-up break): with resources requested
    // but NO cgroup_path, we must NOT apply them — otherwise runc enables
    // controllers on the root cgroup and fails ("no internal processes").
    #[test]
    fn resources_skipped_without_cgroup_path() {
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            resources: Resources {
                memory_limit: Some(20_971_520),
                ..Default::default()
            },
            cgroup_path: None,
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, std::path::Path::new("/tmp/rootfs")).unwrap();
        let linux = spec.linux().clone().unwrap();
        assert!(
            linux.cgroups_path().is_none(),
            "no cgroupsPath without parent"
        );
        let no_limits = linux
            .resources()
            .clone()
            .map(|r| r.cpu().is_none() && r.memory().is_none())
            .unwrap_or(true);
        assert!(
            no_limits,
            "resources must NOT be applied without a cgroup_path"
        );
    }

    #[test]
    fn no_resources_leaves_cgroup_unset() {
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            cgroup_path: Some("/kubepods/pod123/abc".into()),
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, std::path::Path::new("/tmp/rootfs")).unwrap();
        let unset = spec
            .linux()
            .clone()
            .unwrap()
            .resources()
            .clone()
            .map(|r| r.cpu().is_none() && r.memory().is_none())
            .unwrap_or(true);
        assert!(unset, "no cpu/memory cgroup limits when none requested");
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
    fn run_as_user_overrides_image_user() {
        let dir = tempfile::tempdir().unwrap();
        let i = img(); // image User is "1000:1001"
                       // No override -> image user.
        let spec = generate_spec(&i, &ContainerRequest::default(), &dir.path().join("a")).unwrap();
        assert_eq!(spec.process().as_ref().unwrap().user().uid(), 1000);
        // CRI run_as_user/group override the image user (e.g. conformance uid 65534).
        let r = ContainerRequest {
            run_as_user: Some(65534),
            run_as_group: Some(65534),
            ..Default::default()
        };
        let spec = generate_spec(&i, &r, &dir.path().join("b")).unwrap();
        let u = spec.process().as_ref().unwrap().user();
        assert_eq!(u.uid(), 65534);
        assert_eq!(u.gid(), 65534);
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
