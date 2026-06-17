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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init();
    let args = Args::parse();
    let cfg = Config::load(&args.config)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = ?cfg.cri_socket,
        root = ?cfg.root,
        "containerd-rs starting"
    );

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
    ));

    // Restart recovery: re-discover persisted sandboxes/containers.
    match cri::server::reconcile(&ctx) {
        Ok(r) => tracing::info!(
            sandboxes = r.sandboxes,
            containers = r.containers,
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
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown signal received"),
        r = grpc => r.map_err(|e| anyhow::anyhow!("CRI server error: {e}"))?,
        r = streaming => r.map_err(|e| anyhow::anyhow!("streaming server error: {e}"))?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
