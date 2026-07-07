//! OCI runtime bundle generation.
//!
//! Produces a runtime-spec `config.json` from an image config plus a container
//! request, mirroring how containerd's CRI plugin builds the container spec
//! (image Env/Entrypoint/Cmd/User/WorkingDir merged with the CRI request). The
//! base spec (default Linux namespaces, standard mounts, capabilities) comes
//! from `oci_spec::runtime::Spec::default()`; we override process/root/hostname.

use std::path::{Path, PathBuf};

use oci_spec::runtime::{
    Capability, LinuxCapabilities, LinuxCapabilitiesBuilder, LinuxCpuBuilder,
    LinuxDeviceCgroupBuilder, LinuxHugepageLimitBuilder, LinuxMemoryBuilder, LinuxNamespaceBuilder,
    LinuxNamespaceType, LinuxResourcesBuilder, MountBuilder, ProcessBuilder, RootBuilder, Spec,
    UserBuilder,
};

/// Mount propagation, mirroring CRI `MountPropagation` → OCI rbind option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Propagation {
    /// `rprivate` — no propagation in either direction (CRI default).
    #[default]
    Private,
    /// `rslave` — host→container propagation only.
    HostToContainer,
    /// `rshared` — bidirectional; also sets the rootfs propagation to `rshared`.
    Bidirectional,
}

/// A bind mount to inject into the container (from a CRI mount).
#[derive(Debug, Clone)]
pub struct MountSpec {
    pub source: String,
    pub destination: String,
    pub readonly: bool,
    /// CRI `Mount.propagation`.
    pub propagation: Propagation,
    /// CRI `Mount.recursive_read_only` — with `readonly`, emit `rro` (recursive)
    /// instead of `ro` (top-level only).
    pub recursive_read_only: bool,
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
    /// Pod-shared PID namespace to join (`/proc/<holder>/ns/pid`), for
    /// `shareProcessNamespace`. `None` keeps the container's private PID ns.
    pub pid_ns_path: Option<String>,
    /// Pod-shared IPC namespace to join (`/proc/<holder>/ns/ipc`). `None` keeps
    /// the container's private IPC ns.
    pub ipc_ns_path: Option<String>,
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
    /// to the OCI `linux.resources` so crun programs the container's cgroup
    /// (cgroup v2: `memory.max`, `cpu.max`, `cpu.weight`). Without these a
    /// container runs unconstrained (`memory.max=max`, `cpu.max=max`).
    pub resources: Resources,
    /// OCI `linux.cgroupsPath` — the kubelet-delegated cgroup the container lives
    /// under (derived from the sandbox's `cgroup_parent`). `Some` only when the
    /// kubelet provides a cgroup parent; resources are applied ONLY when this is
    /// set, so crun never enables controllers on the root cgroup (which fails
    /// cgroup-v2's "no internal processes" rule). Mirrors containerd's
    /// `getCgroupsPath` + "set cgroup only if cgroup_parent != \"\"".
    pub cgroup_path: Option<String>,
    /// CRI `security_context.capabilities.add_capabilities` — capability names to
    /// add to the container's OCI `process.capabilities` sets (bounding/effective/
    /// permitted/inheritable). Names may be given with or without the `CAP_` prefix
    /// (e.g. `"NET_ADMIN"` or `"CAP_NET_ADMIN"`). `"ALL"` expands to every
    /// capability in `all_capabilities()`. Ignored for privileged containers.
    pub add_capabilities: Vec<String>,
    /// CRI `security_context.capabilities.drop_capabilities` — capability names to
    /// remove from the container's OCI `process.capabilities` sets. Applied after
    /// `add_capabilities`. `"ALL"` drops every capability. Ignored for privileged
    /// containers.
    pub drop_capabilities: Vec<String>,
    /// CRI `security_context.no_new_privs` — when true, set OCI
    /// `process.noNewPrivileges` so the process (and its children) cannot gain
    /// privileges via setuid/setgid/file caps on `execve`. Ignored for privileged.
    pub no_new_privileges: bool,
    /// AppArmor profile name to apply (OCI `process.apparmorProfile`), e.g. a
    /// `localhost/<profile>` name. `None` leaves it unset (host default). Ignored
    /// for privileged containers.
    pub apparmor_profile: Option<String>,
    /// SELinux process label to apply (OCI `process.selinuxLabel`), from the CRI
    /// `selinux_options`. `None` leaves it unset. Ignored for privileged.
    pub selinux_label: Option<String>,
    /// CRI `security_context.masked_paths` override. When non-empty, replaces the
    /// base spec's `linux.maskedPaths`. Empty keeps the runtime defaults.
    pub masked_paths: Vec<String>,
    /// CRI `security_context.readonly_paths` override. When non-empty, replaces the
    /// base spec's `linux.readonlyPaths`. Empty keeps the runtime defaults.
    pub readonly_paths: Vec<String>,
    /// Requested seccomp confinement. Ignored for privileged containers.
    pub seccomp: SeccompProfile,
    /// CRI `NamespaceOption.pid == NODE` — share the host PID namespace (HostPID).
    /// Drops the container's private PID namespace so it sees host processes.
    pub host_pid: bool,
    /// CRI `NamespaceOption.ipc == NODE` — share the host IPC namespace (HostIPC).
    pub host_ipc: bool,
}

/// Requested seccomp confinement, mapped from the CRI `SecurityProfile`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SeccompProfile {
    /// No seccomp filter (CRI `Unconfined`). Nothing is emitted.
    #[default]
    Unconfined,
    /// The runtime's default profile (CRI `RuntimeDefault`). Enforcement of the
    /// profile *content* is gated on provisioning the real containerd default
    /// profile (feature 002 T002) — until then this variant is recorded but not
    /// emitted (emitting a wrong allowlist would break workloads).
    RuntimeDefault,
    /// A profile loaded from a node-local JSON file (CRI `Localhost`). The path is
    /// resolved and its OCI seccomp JSON emitted verbatim.
    Localhost(String),
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
    /// HugeTLB limits per page size (CRI `hugepage_limits`) → OCI
    /// `linux.resources.hugepageLimits` (feature 002 US5 / T030).
    pub hugepage_limits: Vec<(String, u64)>,
    /// Raw cgroup-v2 key/values (CRI `unified`) → OCI `linux.resources.unified`.
    /// This is how the kubelet passes controllers OCI has no typed field for,
    /// e.g. `pids.max`, `io.max`, `io.weight`.
    pub unified: std::collections::HashMap<String, String>,
}

impl Resources {
    fn is_empty(&self) -> bool {
        self.cpu_shares.is_none()
            && self.cpu_quota.is_none()
            && self.cpu_period.is_none()
            && self.memory_limit.is_none()
            && self.cpuset_cpus.is_none()
            && self.cpuset_mems.is_none()
            && self.hugepage_limits.is_empty()
            && self.unified.is_empty()
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

/// containerd's default capability set for non-privileged containers — the same
/// 14 caps Docker/Moby grant by default. The bare oci-spec default is only 3
/// (`KILL`/`AUDIT_WRITE`/`NET_BIND_SERVICE`), which breaks images that adjust
/// ownership at startup: e.g. nginx chowns its cache dir and needs `CAP_CHOWN`,
/// without which it crashloops with `chown(...) Operation not permitted`.
fn default_capabilities() -> std::collections::HashSet<Capability> {
    use Capability::*;
    [
        AuditWrite,
        Chown,
        DacOverride,
        Fowner,
        Fsetid,
        Kill,
        Mknod,
        NetBindService,
        NetRaw,
        Setfcap,
        Setgid,
        Setpcap,
        Setuid,
        SysChroot,
    ]
    .into_iter()
    .collect()
}

/// Parse a CRI capability name (e.g. `"NET_ADMIN"` or `"CAP_NET_ADMIN"`) into
/// an `oci_spec::runtime::Capability` variant.  Returns `None` for `"ALL"`
/// (case-insensitive) — the caller expands that to `all_capabilities()` — and
/// also for unknown names.
///
/// `Capability` derives `strum::EnumString` with `SCREAMING_SNAKE_CASE`, so
/// `"NET_ADMIN".parse::<Capability>()` works directly after stripping any
/// leading `CAP_` prefix.
fn parse_cap(name: &str) -> Option<Capability> {
    let upper = name.trim().to_uppercase();
    // Strip any number of leading "CAP_" prefixes (oci-spec does the same in Deserialize).
    let mut key = upper.as_str();
    while let Some(stripped) = key.strip_prefix("CAP_") {
        key = stripped;
    }
    if key == "ALL" {
        return None;
    }
    key.parse::<Capability>().ok()
}

/// Apply `add_capabilities` / `drop_capabilities` to a non-privileged spec.
///
/// Algorithm:
///  1. Start from the default process caps already in `spec` (the containerd
///     default 14-cap set written by [`default_capabilities`]).
///  2. Remove each parsed `drop` capability (or the full set for `"ALL"`).
///  3. Insert each parsed `add` capability (or the full set for `"ALL"`) — adds
///     are applied after drops so an add wins over a `drop: [ALL]`.
///  4. Write the result to bounding/effective/permitted/inheritable **and
///     ambient** — explicitly-requested caps must be ambient so a non-root
///     process keeps them across `execve` (e.g. CoreDNS runs as uid 65532 and
///     adds only `NET_BIND_SERVICE` to bind :53; without ambient, crun drops it
///     on exec and CoreDNS crashloops). This is what containerd's CRI emits.
fn apply_capabilities(spec: &mut Spec, add: &[String], drop: &[String]) {
    if add.is_empty() && drop.is_empty() {
        return;
    }

    // Seed from the default caps already present in the spec's process.
    let mut cap_set: std::collections::HashSet<Capability> = spec
        .process()
        .as_ref()
        .and_then(|p| p.capabilities().as_ref())
        .and_then(|c| c.bounding().clone())
        .unwrap_or_default();

    // Apply drops FIRST, then adds — so adds win when the same cap (or "ALL") is
    // both dropped and added. This is the CRI/containerd semantic and is what the
    // canonical hardening pattern `drop: [ALL], add: [NET_BIND_SERVICE]` (e.g.
    // CoreDNS) relies on: drop ALL clears the set, then the add re-grants the one
    // cap. Applying adds first would let `drop ALL` erase the just-added cap,
    // leaving the container with no capabilities at all.
    for name in drop {
        let upper = name.trim().to_uppercase();
        let mut key = upper.as_str();
        while let Some(s) = key.strip_prefix("CAP_") {
            key = s;
        }
        if key == "ALL" {
            cap_set.clear();
        } else if let Some(cap) = parse_cap(name) {
            cap_set.remove(&cap);
        }
    }

    // Apply adds.  `parse_cap` returns None for "ALL"; we handle that separately.
    for name in add {
        let upper = name.trim().to_uppercase();
        let mut key = upper.as_str();
        while let Some(s) = key.strip_prefix("CAP_") {
            key = s;
        }
        if key == "ALL" {
            cap_set.extend(all_capabilities());
        } else if let Some(cap) = parse_cap(name) {
            cap_set.insert(cap);
        }
    }

    if let Some(lc) = build_caps(cap_set.clone(), cap_set) {
        if let Some(mut process) = spec.process().clone() {
            process.set_capabilities(Some(lc));
            spec.set_process(Some(process));
        }
    }
}

/// Build `LinuxCapabilities` with `caps` in the bounding/effective/permitted/
/// inheritable sets and `ambient` as the ambient set. (Ambient is left empty for
/// the default set — matching containerd — so non-root containers don't silently
/// retain caps across `execve`; privileged passes the full set for ambient too.)
fn build_caps(
    caps: std::collections::HashSet<Capability>,
    ambient: std::collections::HashSet<Capability>,
) -> Option<LinuxCapabilities> {
    LinuxCapabilitiesBuilder::default()
        .bounding(caps.clone())
        .effective(caps.clone())
        .permitted(caps.clone())
        .inheritable(caps)
        .ambient(ambient)
        .build()
        .ok()
}

/// Turn `spec` into a privileged container: full caps, no masked/readonly paths,
/// allow-all device cgroup. Mirrors containerd's CRI privileged handling.
fn apply_privileged(spec: &mut Spec) {
    if let Some(lc) = build_caps(all_capabilities(), all_capabilities()) {
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
/// Apply the pod security context to a non-privileged spec: no-new-privileges,
/// AppArmor profile, SELinux label, masked/readonly-path overrides, and seccomp.
/// Emits OCI-spec fields and lets crun enforce them (matching containerd). Returns
/// an error (fail-closed, feature 002 FR-016) when a requested Localhost seccomp
/// profile cannot be read/parsed — never silently runs the container unconfined.
fn apply_security(spec: &mut Spec, req: &ContainerRequest) -> Result<()> {
    if let Some(mut process) = spec.process().clone() {
        if req.no_new_privileges {
            process.set_no_new_privileges(Some(true));
        }
        if let Some(ap) = &req.apparmor_profile {
            process.set_apparmor_profile(Some(ap.clone()));
        }
        if let Some(label) = &req.selinux_label {
            process.set_selinux_label(Some(label.clone()));
        }
        spec.set_process(Some(process));
    }
    if let Some(mut linux) = spec.linux().clone() {
        if !req.masked_paths.is_empty() {
            linux.set_masked_paths(Some(req.masked_paths.clone()));
        }
        if !req.readonly_paths.is_empty() {
            linux.set_readonly_paths(Some(req.readonly_paths.clone()));
        }
        match &req.seccomp {
            SeccompProfile::Unconfined => {}
            SeccompProfile::RuntimeDefault => {
                // Deferred (feature 002 T002): a hand-rolled default allowlist
                // would risk blocking syscalls real workloads need and breaking
                // conformance. Recorded, not emitted, until the real containerd
                // default profile is provisioned.
                tracing::warn!(
                    container_seccomp = "RuntimeDefault",
                    "seccomp RuntimeDefault requested but the default profile is not \
                     provisioned; running without a seccomp filter (feature 002 T002)"
                );
            }
            SeccompProfile::Localhost(path) => {
                let bytes = std::fs::read(path)
                    .map_err(|e| Error::Builder(format!("read seccomp profile {path}: {e}")))?;
                let seccomp: oci_spec::runtime::LinuxSeccomp = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Builder(format!("parse seccomp profile {path}: {e}")))?;
                linux.set_seccomp(Some(seccomp));
            }
        }
        spec.set_linux(Some(linux));
    }
    Ok(())
}

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

    // Grant containerd's default capability set (privileged is upgraded to the
    // full set later by apply_privileged). Without this the oci-spec default of
    // 3 caps leaves out CAP_CHOWN etc., breaking images like nginx.
    let mut process_builder = ProcessBuilder::default()
        .terminal(req.terminal)
        .args(argv)
        .env(env)
        .cwd(PathBuf::from(cwd))
        .user(user);
    if let Some(caps) = build_caps(default_capabilities(), std::collections::HashSet::new()) {
        process_builder = process_builder.capabilities(caps);
    }
    let mut process = process_builder
        .build()
        .map_err(|e| Error::Builder(e.to_string()))?;
    // oci-spec's Process::default() sets noNewPrivileges=true; containerd leaves
    // it false unless the CRI requests it. Set it explicitly from the request so
    // a container with no_new_privs=false can actually escalate (setuid), rather
    // than inheriting the spec default. apply_security re-affirms true when asked.
    process.set_no_new_privileges(Some(req.no_new_privileges));

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
    // Set the hostname from the request unconditionally — clearing it when the
    // request has none. oci_spec's Spec::default() hardcodes hostname="youki";
    // overriding only on Some would leak that bogus default into hostNetwork
    // pods (and any pod with an empty CRI hostname), which then `inherit` the
    // sandbox/host UTS instead.
    spec.set_hostname(req.hostname.clone());
    set_network_namespace(&mut spec, req.netns_path.as_deref());
    apply_host_namespaces(&mut spec, req.host_pid, req.host_ipc);
    // Pod-shared PID/IPC namespaces (shareProcessNamespace): join the sandbox
    // holder's namespace so the container is not PID 1 and sees its pod peers.
    join_namespace(
        &mut spec,
        LinuxNamespaceType::Pid,
        req.pid_ns_path.as_deref(),
    );
    join_namespace(
        &mut spec,
        LinuxNamespaceType::Ipc,
        req.ipc_ns_path.as_deref(),
    );
    add_bind_mounts(&mut spec, &req.mounts);
    // Resource limits require a delegated cgroup (cgroupsPath under the kubelet's
    // cgroup_parent); applying them with crun's default root-level path fails
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
    } else {
        apply_capabilities(&mut spec, &req.add_capabilities, &req.drop_capabilities);
        apply_security(&mut spec, req)?;
    }
    apply_sysctls(&mut spec, &req.sysctls);
    Ok(spec)
}

/// Map CRI resource limits/requests onto the OCI `linux.resources` so crun
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

    if !res.hugepage_limits.is_empty() {
        let hp: Vec<_> = res
            .hugepage_limits
            .iter()
            .filter_map(|(page, limit)| {
                LinuxHugepageLimitBuilder::default()
                    .page_size(page.clone())
                    .limit(*limit as i64)
                    .build()
                    .ok()
            })
            .collect();
        if !hp.is_empty() {
            resources.set_hugepage_limits(Some(hp));
        }
    }

    // cgroup-v2 passthrough (pids.max, io.max, io.weight, ...).
    if !res.unified.is_empty() {
        let mut u = resources.unified().clone().unwrap_or_default();
        u.extend(res.unified.iter().map(|(k, v)| (k.clone(), v.clone())));
        resources.set_unified(Some(u));
    }

    linux.set_resources(Some(resources));
    spec.set_linux(Some(linux));
}

/// Set namespaced sysctls in the container's OCI `linux.sysctl`. crun writes
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
///
/// **DirectoryOrCreate backstop**: if the source path does not exist it is
/// created with `std::fs::create_dir_all` before the mount is added. This
/// mirrors the Kubernetes `DirectoryOrCreate` host-path volume policy and is
/// required for paths like `/etc/cni/net.d` that the node-local CNI plugin
/// creates lazily. Only *directory* sources are created; file sources are not
/// touched (documented limitation).
fn add_bind_mounts(spec: &mut Spec, mounts: &[MountSpec]) {
    if mounts.is_empty() {
        return;
    }
    let mut all = spec.mounts().clone().unwrap_or_default();
    // The container rootfs propagation must allow the requested mount propagation
    // to flow: `rshared` for a bidirectional mount (also lets container mounts
    // propagate back to the host), `rslave` for host→container so the container
    // receives host mount events. crun/runc otherwise leave the rootfs at a
    // propagation that can block the slave/shared link.
    let mut rootfs_prop: Option<&str> = None;
    for m in mounts {
        let src = Path::new(&m.source);
        if !src.exists() {
            if let Err(e) = std::fs::create_dir_all(src) {
                tracing::warn!(
                    source = %m.source,
                    error = %e,
                    "DirectoryOrCreate: could not create missing bind-mount source dir; continuing"
                );
            }
        }
        // Mirror containerd's withMounts: rbind + a propagation option + ro/rro/rw.
        let mut opts = vec!["rbind".to_string()];
        match m.propagation {
            Propagation::Private => opts.push("rprivate".to_string()),
            Propagation::HostToContainer => {
                opts.push("rslave".to_string());
                if rootfs_prop.is_none() {
                    rootfs_prop = Some("rslave");
                }
            }
            Propagation::Bidirectional => {
                opts.push("rshared".to_string());
                rootfs_prop = Some("rshared"); // bidirectional wins over slave
            }
        }
        if m.readonly {
            // ro = only the top mount is readonly (non-recursive); rro = recursive
            // (submounts readonly too, via mount_setattr AT_RECURSIVE).
            opts.push(if m.recursive_read_only { "rro" } else { "ro" }.to_string());
        } else {
            opts.push("rw".to_string());
        }
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
    if let Some(prop) = rootfs_prop {
        if let Some(mut linux) = spec.linux().clone() {
            linux.set_rootfs_propagation(Some(prop.to_string()));
            spec.set_linux(Some(linux));
        }
    }
}

/// Share the host PID / IPC namespaces when requested (CRI HostPID / HostIPC):
/// drop the corresponding private namespace from the spec so the container joins
/// the host's. `Spec::default()` includes private pid+ipc namespaces, so sharing
/// the host is a removal. (Pod-shared PID/IPC across containers is not supported
/// without a pause/sandbox namespace holder — see GAPS §1.)
fn apply_host_namespaces(spec: &mut Spec, host_pid: bool, host_ipc: bool) {
    if !host_pid && !host_ipc {
        return;
    }
    let Some(mut linux) = spec.linux().clone() else {
        return;
    };
    let mut namespaces = linux.namespaces().clone().unwrap_or_default();
    if host_pid {
        namespaces.retain(|n| n.typ() != LinuxNamespaceType::Pid);
    }
    if host_ipc {
        namespaces.retain(|n| n.typ() != LinuxNamespaceType::Ipc);
    }
    linux.set_namespaces(Some(namespaces));
    spec.set_linux(Some(linux));
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

/// Join an existing namespace of `typ` at `path` (pod-shared PID/IPC). Replaces
/// the container's private namespace of that type with a path reference so crun
/// `setns`es into the sandbox holder's namespace; `None` leaves it private.
fn join_namespace(spec: &mut Spec, typ: LinuxNamespaceType, path: Option<&str>) {
    let Some(path) = path else {
        return;
    };
    let Some(mut linux) = spec.linux().clone() else {
        return;
    };
    let mut namespaces = linux.namespaces().clone().unwrap_or_default();
    namespaces.retain(|n| n.typ() != typ);
    if let Ok(ns) = LinuxNamespaceBuilder::default()
        .typ(typ)
        .path(PathBuf::from(path))
        .build()
    {
        namespaces.push(ns);
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
    // OCI linux.resources (crun converts to cgroup v2 values).
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
    // but NO cgroup_path, we must NOT apply them — otherwise crun enables
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

    // Feature 002 US5 / T030: HugeTLB limits + cgroup-v2 unified passthrough
    // (pids.max, io.max, ...) are emitted into linux.resources.
    #[test]
    fn hugepage_and_unified_resources_emitted() {
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            resources: Resources {
                hugepage_limits: vec![("2MB".into(), 2_097_152)],
                unified: std::collections::HashMap::from([
                    ("pids.max".to_string(), "128".to_string()),
                    ("io.weight".to_string(), "default 200".to_string()),
                ]),
                ..Default::default()
            },
            cgroup_path: Some("/kubepods/pod9/x".into()),
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, std::path::Path::new("/tmp/rootfs")).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            v["linux"]["resources"]["unified"]["pids.max"],
            serde_json::json!("128")
        );
        assert_eq!(
            v["linux"]["resources"]["unified"]["io.weight"],
            serde_json::json!("default 200")
        );
        let hp = &v["linux"]["resources"]["hugepageLimits"];
        assert_eq!(hp[0]["pageSize"], serde_json::json!("2MB"));
        assert_eq!(hp[0]["limit"], serde_json::json!(2_097_152));
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

    #[test]
    fn no_hostname_does_not_leak_oci_spec_default() {
        // oci_spec::runtime::Spec::default() hardcodes hostname="youki"; a
        // request with no hostname (hostNetwork pod, or an empty CRI hostname)
        // must NOT leak that bogus value — the container inherits the
        // sandbox/host UTS instead. Regression guard for the "from-youki" leak.
        let dir = tempfile::tempdir().unwrap();
        let i = img();
        let r = ContainerRequest {
            hostname: None,
            ..Default::default()
        };
        let rootfs = dir.path().join("merged");
        let spec = generate_spec(&i, &r, &rootfs).unwrap();
        assert_eq!(
            spec.hostname().as_deref(),
            None,
            "hostname must be cleared when the request has none (got {:?})",
            spec.hostname()
        );
    }

    // ---------- capabilities tests ----------

    /// Non-privileged container with add_capabilities=["NET_ADMIN"]:
    /// OCI process.capabilities bounding/effective/permitted must contain NetAdmin.
    #[test]
    fn capabilities_add_net_admin() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            add_capabilities: vec!["NET_ADMIN".into()],
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("rootfs")).unwrap();
        let caps = spec
            .process()
            .as_ref()
            .unwrap()
            .capabilities()
            .as_ref()
            .expect("capabilities must be set");
        assert!(
            caps.bounding()
                .as_ref()
                .map(|s| s.contains(&Capability::NetAdmin))
                .unwrap_or(false),
            "bounding must contain NetAdmin"
        );
        assert!(
            caps.effective()
                .as_ref()
                .map(|s| s.contains(&Capability::NetAdmin))
                .unwrap_or(false),
            "effective must contain NetAdmin"
        );
        assert!(
            caps.permitted()
                .as_ref()
                .map(|s| s.contains(&Capability::NetAdmin))
                .unwrap_or(false),
            "permitted must contain NetAdmin"
        );
        // Added caps must also be ambient, or a non-root process loses them on
        // execve (crun does not silently retain them — see apply_capabilities).
        assert!(
            caps.ambient()
                .as_ref()
                .map(|s| s.contains(&Capability::NetAdmin))
                .unwrap_or(false),
            "ambient must contain NetAdmin"
        );
    }

    /// Regression (crun CoreDNS crashloop): a container that drops ALL caps and
    /// adds only NET_BIND_SERVICE — the CoreDNS security context — must carry
    /// NET_BIND_SERVICE in the ambient set so the non-root process can bind :53.
    #[test]
    fn capabilities_drop_all_add_net_bind_is_ambient() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            drop_capabilities: vec!["ALL".into()],
            add_capabilities: vec!["NET_BIND_SERVICE".into()],
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("rootfs")).unwrap();
        let caps = spec
            .process()
            .as_ref()
            .unwrap()
            .capabilities()
            .clone()
            .expect("capabilities must be set");
        let ambient = caps.ambient().clone().expect("ambient set");
        assert_eq!(
            ambient,
            std::collections::HashSet::from([Capability::NetBindService]),
            "ambient must be exactly {{NET_BIND_SERVICE}} after drop ALL + add"
        );
    }

    /// Non-privileged container with drop_capabilities=["NET_ADMIN"]:
    /// OCI process.capabilities bounding/effective/permitted must NOT contain NetAdmin.
    #[test]
    fn capabilities_drop_net_admin() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            drop_capabilities: vec!["NET_ADMIN".into()],
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("rootfs")).unwrap();
        let caps = spec
            .process()
            .as_ref()
            .unwrap()
            .capabilities()
            .as_ref()
            .expect("capabilities must be set");
        assert!(
            !caps
                .bounding()
                .as_ref()
                .map(|s| s.contains(&Capability::NetAdmin))
                .unwrap_or(false),
            "bounding must NOT contain NetAdmin"
        );
        assert!(
            !caps
                .effective()
                .as_ref()
                .map(|s| s.contains(&Capability::NetAdmin))
                .unwrap_or(false),
            "effective must NOT contain NetAdmin"
        );
        assert!(
            !caps
                .permitted()
                .as_ref()
                .map(|s| s.contains(&Capability::NetAdmin))
                .unwrap_or(false),
            "permitted must NOT contain NetAdmin"
        );
    }

    /// Privileged container: add/drop fields are ignored; full all_capabilities() set
    /// is always applied (short-circuit unchanged).
    #[test]
    fn capabilities_privileged_short_circuit() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            privileged: true,
            drop_capabilities: vec!["NET_ADMIN".into()],
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("rootfs")).unwrap();
        let caps = spec
            .process()
            .as_ref()
            .unwrap()
            .capabilities()
            .as_ref()
            .expect("capabilities must be set for privileged");
        let expected = all_capabilities();
        assert!(
            caps.bounding()
                .as_ref()
                .map(|s| *s == expected)
                .unwrap_or(false),
            "privileged bounding must equal full all_capabilities() set"
        );
        assert!(
            caps.effective()
                .as_ref()
                .map(|s| *s == expected)
                .unwrap_or(false),
            "privileged effective must equal full all_capabilities() set"
        );
        assert!(
            caps.permitted()
                .as_ref()
                .map(|s| *s == expected)
                .unwrap_or(false),
            "privileged permitted must equal full all_capabilities() set"
        );
    }

    /// DirectoryOrCreate: a bind-mount whose source dir does not yet exist must
    /// be created automatically before the OCI spec is generated.
    #[test]
    fn add_bind_mounts_creates_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        // This sub-directory intentionally does NOT exist yet.
        let missing_src = tmp.path().join("net.d");
        assert!(!missing_src.exists(), "pre-condition: dir must not exist");

        let req = ContainerRequest {
            mounts: vec![MountSpec {
                source: missing_src.to_string_lossy().into_owned(),
                destination: "/etc/cni/net.d".into(),
                readonly: false,
                propagation: Propagation::Private,
                recursive_read_only: false,
            }],
            ..Default::default()
        };
        let rootfs = tmp.path().join("rootfs");
        let spec = generate_spec(&img(), &req, &rootfs).unwrap();

        // (a) The source directory must have been created.
        assert!(
            missing_src.exists() && missing_src.is_dir(),
            "expected source dir to be created by add_bind_mounts"
        );

        // (b) The spec must contain a bind mount pointing at that source.
        let mounts = spec.mounts().as_ref().expect("spec has mounts");
        let found = mounts.iter().any(|m| {
            m.source()
                .as_ref()
                .map(|s| s == &missing_src)
                .unwrap_or(false)
                && m.destination() == &PathBuf::from("/etc/cni/net.d")
        });
        assert!(
            found,
            "spec must contain the bind mount for the created dir"
        );
    }

    // Regression: with no_new_privs=false the OCI process must have
    // noNewPrivileges=false, NOT oci-spec's default of true — otherwise a setuid
    // binary can never escalate (critest "allow privilege escalation when false").
    #[test]
    fn no_new_privileges_defaults_false_from_request() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            no_new_privileges: false,
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("a")).unwrap();
        assert_eq!(
            spec.process().as_ref().unwrap().no_new_privileges(),
            Some(false),
            "no_new_privs=false must yield noNewPrivileges=false, not the spec default true"
        );

        let req_true = ContainerRequest {
            command: vec!["/bin/true".into()],
            no_new_privileges: true,
            ..Default::default()
        };
        let spec_true = generate_spec(&img(), &req_true, &dir.path().join("b")).unwrap();
        assert_eq!(
            spec_true.process().as_ref().unwrap().no_new_privileges(),
            Some(true)
        );
    }

    // Mirror containerd's withMounts option mapping: propagation → rprivate /
    // rslave / rshared, and readonly → ro (non-recursive) vs rro (recursive).
    // A bidirectional mount also sets rootfsPropagation=rshared.
    #[test]
    fn mount_options_map_propagation_and_readonly() {
        let tmp = tempfile::tempdir().unwrap();
        let mk = |dest: &str, ro, rro, prop| MountSpec {
            source: tmp.path().to_string_lossy().into_owned(),
            destination: dest.into(),
            readonly: ro,
            recursive_read_only: rro,
            propagation: prop,
        };
        let req = ContainerRequest {
            mounts: vec![
                mk("/a", true, false, Propagation::Private), // rbind, rprivate, ro
                mk("/b", true, true, Propagation::Private),  // rbind, rprivate, rro
                mk("/c", false, false, Propagation::HostToContainer), // rbind, rslave, rw
                mk("/d", false, false, Propagation::Bidirectional), // rbind, rshared, rw
            ],
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &tmp.path().join("rootfs")).unwrap();
        let opts = |dest: &str| -> Vec<String> {
            spec.mounts()
                .as_ref()
                .unwrap()
                .iter()
                .find(|m| m.destination() == &PathBuf::from(dest))
                .and_then(|m| m.options().clone())
                .unwrap_or_default()
        };
        assert_eq!(opts("/a"), vec!["rbind", "rprivate", "ro"]);
        assert_eq!(opts("/b"), vec!["rbind", "rprivate", "rro"]);
        assert_eq!(opts("/c"), vec!["rbind", "rslave", "rw"]);
        assert_eq!(opts("/d"), vec!["rbind", "rshared", "rw"]);
        // The bidirectional mount forces rshared rootfs propagation.
        assert_eq!(
            spec.linux()
                .as_ref()
                .unwrap()
                .rootfs_propagation()
                .as_deref(),
            Some("rshared")
        );
    }

    // Regression: a non-privileged container must get containerd's default
    // capability set (14 caps), not the bare oci-spec default of 3
    // (KILL/AUDIT_WRITE/NET_BIND_SERVICE). nginx chowns its cache dir at startup
    // and needs CAP_CHOWN; without it the ReplicationController [Conformance]
    // test crashlooped with `chown(...) Operation not permitted`.
    #[test]
    fn nonprivileged_container_gets_default_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("a")).unwrap();
        let caps = spec
            .process()
            .as_ref()
            .unwrap()
            .capabilities()
            .clone()
            .expect("capabilities set");
        let eff = caps.effective().clone().expect("effective set");
        for required in [
            Capability::Chown,
            Capability::DacOverride,
            Capability::Fowner,
            Capability::Fsetid,
            Capability::Mknod,
            Capability::NetRaw,
            Capability::Setgid,
            Capability::Setuid,
            Capability::Setpcap,
            Capability::Setfcap,
            Capability::SysChroot,
            Capability::Kill,
            Capability::AuditWrite,
            Capability::NetBindService,
        ] {
            assert!(
                eff.contains(&required),
                "default caps must include {required:?}"
            );
        }
        // ...but not a privileged-only capability.
        assert!(
            !eff.contains(&Capability::SysAdmin),
            "non-privileged container must not get CAP_SYS_ADMIN"
        );
    }

    #[test]
    fn privileged_container_includes_chown_and_sys_admin() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            privileged: true,
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("p")).unwrap();
        let eff = spec
            .process()
            .as_ref()
            .unwrap()
            .capabilities()
            .clone()
            .unwrap()
            .effective()
            .clone()
            .unwrap();
        assert!(eff.contains(&Capability::Chown));
        assert!(eff.contains(&Capability::SysAdmin));
    }

    // Feature 003 US1: HostPID/HostIPC drop the container's private pid/ipc
    // namespaces so it shares the host's (critest namespace options).
    #[test]
    fn host_pid_ipc_drop_private_namespaces() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            host_pid: true,
            host_ipc: true,
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("r")).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        let types: Vec<String> = v["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["type"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(!types.contains(&"pid".to_string()), "HostPID drops pid ns");
        assert!(!types.contains(&"ipc".to_string()), "HostIPC drops ipc ns");
    }

    // Feature 002 US2: security-context fields are emitted into the OCI spec for a
    // non-privileged container (no-new-privs, AppArmor, SELinux, masked/readonly
    // overrides). Asserted against the serialized OCI JSON (stable field names).
    #[test]
    fn security_context_fields_emitted_for_nonprivileged() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            no_new_privileges: true,
            apparmor_profile: Some("my-profile".into()),
            selinux_label: Some("system_u:system_r:container_t:s0".into()),
            masked_paths: vec!["/proc/keys".into()],
            readonly_paths: vec!["/proc/sys".into()],
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("r")).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        assert_eq!(v["process"]["noNewPrivileges"], serde_json::json!(true));
        assert_eq!(
            v["process"]["apparmorProfile"],
            serde_json::json!("my-profile")
        );
        assert_eq!(
            v["process"]["selinuxLabel"],
            serde_json::json!("system_u:system_r:container_t:s0")
        );
        assert_eq!(v["linux"]["maskedPaths"], serde_json::json!(["/proc/keys"]));
        assert_eq!(
            v["linux"]["readonlyPaths"],
            serde_json::json!(["/proc/sys"])
        );
    }

    // Localhost seccomp loads and emits the profile; a missing profile fails closed
    // (feature 002 FR-016) — the container is never silently run unconfined.
    #[test]
    fn seccomp_localhost_loads_and_missing_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let prof = dir.path().join("p.json");
        std::fs::write(
            &prof,
            r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}"#,
        )
        .unwrap();
        let ok = ContainerRequest {
            command: vec!["/bin/true".into()],
            seccomp: SeccompProfile::Localhost(prof.display().to_string()),
            ..Default::default()
        };
        let spec = generate_spec(&img(), &ok, &dir.path().join("r")).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        assert!(v["linux"]["seccomp"].is_object());

        let missing = ContainerRequest {
            command: vec!["/bin/true".into()],
            seccomp: SeccompProfile::Localhost("/no/such/profile.json".into()),
            ..Default::default()
        };
        assert!(generate_spec(&img(), &missing, &dir.path().join("r2")).is_err());
    }

    // Security context (incl. a bad seccomp path) is ignored for privileged
    // containers — they are intentionally unconfined, so no error and no seccomp.
    #[test]
    fn security_context_skipped_for_privileged() {
        let dir = tempfile::tempdir().unwrap();
        let req = ContainerRequest {
            command: vec!["/bin/true".into()],
            privileged: true,
            no_new_privileges: true,
            seccomp: SeccompProfile::Localhost("/no/such.json".into()),
            ..Default::default()
        };
        let spec = generate_spec(&img(), &req, &dir.path().join("r")).unwrap();
        let v = serde_json::to_value(&spec).unwrap();
        assert!(v["linux"]["seccomp"].is_null());
    }
}
