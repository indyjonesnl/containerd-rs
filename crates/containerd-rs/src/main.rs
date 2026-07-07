//! containerd-rs daemon entrypoint.
//!
//! Brings up the subsystem stores from config and (eventually) serves the CRI
//! gRPC + streaming servers. CRI/runtime serving is scaffolding (tasks
//! T015–T038); today the daemon initializes and validates the content store,
//! snapshotter layout, and metadata DB so the foundation is exercisable.

mod config;
mod logging;

use std::path::PathBuf;

use clap::Parser;

use crate::config::Config;

/// containerd-rs: a Rust container runtime daemon (CRI for Kubernetes).
#[derive(Debug, Parser)]
#[command(name = "containerd-rs", version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(long, default_value = "/etc/containerd-rs/config.toml")]
    config: PathBuf,

    /// Initialize stores and exit (used by tests / CI smoke).
    #[arg(long)]
    check: bool,
}

fn main() -> anyhow::Result<()> {
    // Intercept the PID-namespace holder helper BEFORE any logging/tokio/thread
    // setup — it `fork`s, so it must run in a single-threaded process (see
    // `sandbox::pid_holder`). It is re-exec'd by RunPodSandbox for pods that
    // request a shared PID namespace (shareProcessNamespace).
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(String::as_str) == Some("__pid-holder") {
        let pidfile = raw
            .get(2)
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("__pid-holder requires a <pidfile> argument"))?;
        #[cfg(target_os = "linux")]
        {
            sandbox::pid_holder::run_holder(&pidfile)?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pidfile;
            anyhow::bail!("__pid-holder is Linux-only");
        }
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(daemon_main())
}

async fn daemon_main() -> anyhow::Result<()> {
    logging::init();
    let args = Args::parse();
    let cfg = Config::load(&args.config)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = ?cfg.cri_socket,
        root = ?cfg.root,
        "containerd-rs starting"
    );

    // containerd-rs targets a unified cgroup v2 hierarchy only. Refuse a v1 /
    // hybrid host up front with a clear error rather than misprogramming limits
    // (feature 002 FR-015). Detection failure is non-fatal (assume v2).
    match runtime::cgroup::detect_default() {
        Ok(runtime::cgroup::CgroupVersion::V2) => {}
        Ok(runtime::cgroup::CgroupVersion::V1OrHybrid) => {
            anyhow::bail!(
                "containerd-rs requires a unified cgroup v2 hierarchy at \
                 /sys/fs/cgroup, but this host is cgroup v1 or hybrid. Boot with \
                 systemd.unified_cgroup_hierarchy=1 (or the distro equivalent) and retry."
            );
        }
        Err(e) => tracing::warn!(error = %e, "could not detect cgroup version; assuming v2"),
    }

    // Initialize persistent subsystems. This validates the on-disk layout.
    std::fs::create_dir_all(&cfg.root)?;
    std::fs::create_dir_all(&cfg.state)?;
    let content = content::Store::open(cfg.content_dir())?;
    if let Some(parent) = cfg.metadata_db().parent() {
        std::fs::create_dir_all(parent)?;
    }
    let meta = metadata::Store::open(cfg.metadata_db())?;
    std::fs::create_dir_all(cfg.snapshots_dir())?;
    tracing::info!("subsystem stores initialized");

    if args.check {
        tracing::info!("--check requested; exiting after initialization");
        return Ok(());
    }

    let ctx = std::sync::Arc::new(cri::server::Context::new(
        content,
        meta,
        cfg.snapshots_dir(),
        cfg.state.clone(),
        &cfg.stream_server_address,
        cfg.cri.cni_conf_dir.clone(),
        cfg.cri.cni_bin_dir.clone(),
        cfg.cri.no_pivot_root,
    ));

    // Restart recovery: re-discover persisted sandboxes/containers.
    match cri::server::reconcile(&ctx) {
        Ok(r) => tracing::info!(
            sandboxes = r.sandboxes,
            containers = r.containers,
            readopted = r.readopted,
            reaped = r.reaped,
            marked_unknown = r.marked_unknown,
            "reconciled persisted state"
        ),
        Err(e) => tracing::error!(error = %e, "state reconcile failed"),
    }

    if let Some(parent) = cfg.cri_socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let stream_addr: std::net::SocketAddr = cfg.stream_server_address.parse().map_err(|e| {
        anyhow::anyhow!(
            "invalid stream_server_address {}: {e}",
            cfg.stream_server_address
        )
    })?;

    // Run the CRI gRPC server and the exec/attach streaming HTTP server
    // concurrently until SIGINT.
    let grpc = cri::server::serve(
        cfg.cri_socket.clone(),
        ctx.clone(),
        std::future::pending::<()>(),
    );
    let streaming = cri::streaming::serve(
        stream_addr,
        ctx.streaming.clone(),
        std::future::pending::<()>(),
    );

    // Notify systemd (Type=notify) that we are up (feature 002 US6 / T034).
    // No-op when not run under systemd (NOTIFY_SOCKET unset).
    sd_notify_ready();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown signal received"),
        r = grpc => r.map_err(|e| anyhow::anyhow!("CRI server error: {e}"))?,
        r = streaming => r.map_err(|e| anyhow::anyhow!("streaming server error: {e}"))?,
    }
    Ok(())
}

/// Send `READY=1` to systemd's notify socket (`$NOTIFY_SOCKET`), the `sd_notify(3)`
/// readiness protocol for `Type=notify` units. A no-op when the daemon is not run
/// under systemd (env unset). Path sockets are supported; abstract-namespace
/// sockets (`@`-prefixed) are skipped (not used by our unit files).
fn sd_notify_ready() {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    if path.is_empty() || path.starts_with('@') {
        if path.starts_with('@') {
            tracing::debug!("NOTIFY_SOCKET is an abstract socket; sd_notify skipped");
        }
        return;
    }
    match std::os::unix::net::UnixDatagram::unbound() {
        Ok(sock) => {
            if let Err(e) = sock.send_to(b"READY=1", &path) {
                tracing::debug!(error = %e, "sd_notify READY=1 failed");
            } else {
                tracing::info!("notified systemd: READY=1");
            }
        }
        Err(e) => tracing::debug!(error = %e, "sd_notify socket create failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // sd_notify is a no-op without NOTIFY_SOCKET and must never panic.
    #[test]
    fn sd_notify_is_noop_without_socket() {
        // SAFETY: single-threaded test; no other thread reads the env here.
        unsafe {
            std::env::remove_var("NOTIFY_SOCKET");
        }
        sd_notify_ready(); // must not panic
    }

    #[test]
    fn check_mode_initializes_stores() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let cfg = Config {
            root: dir.path().join("root"),
            state: dir.path().join("state"),
            ..Config::default()
        };
        // Replicate main's init path without spawning a process.
        std::fs::create_dir_all(&cfg.root)?;
        std::fs::create_dir_all(&cfg.state)?;
        content::Store::open(cfg.content_dir())?;
        std::fs::create_dir_all(cfg.metadata_db().parent().unwrap())?;
        metadata::Store::open(cfg.metadata_db())?;
        std::fs::create_dir_all(cfg.snapshots_dir())?;
        assert!(cfg.content_dir().join("blobs/sha256").is_dir());
        Ok(())
    }
}
