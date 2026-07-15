//! Node-local admin gRPC service (`containerdrs.admin.v1.Admin`), served on a
//! root-only unix socket. Currently one method — Import — which loads a local
//! image archive into the store inside the daemon (which owns the redb writer).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::server::Context;

pub mod pb {
    tonic::include_proto!("containerdrs.admin.v1");
}

use pb::admin_server::Admin;
use pb::{ImportReply, ImportRequest};

pub use pb::admin_server::AdminServer;

pub struct AdminSvc {
    pub ctx: Arc<Context>,
}

#[tonic::async_trait]
impl Admin for AdminSvc {
    async fn import(
        &self,
        request: Request<ImportRequest>,
    ) -> Result<Response<ImportReply>, Status> {
        let req = request.into_inner();
        if req.archive_path.is_empty() {
            return Err(Status::invalid_argument("archive_path required"));
        }
        let opts = images::import::ImportOptions {
            ref_override: (!req.ref_override.is_empty()).then(|| req.ref_override.clone()),
            ..Default::default()
        };
        let archive_path = std::path::PathBuf::from(&req.archive_path);
        let content = self.ctx.content.clone();
        let snapshots_root = self.ctx.snapshots_root.clone();

        // import_archive is blocking (tar extraction + fs IO); keep it off the
        // async reactor.
        let imported = tokio::task::spawn_blocking(move || {
            images::import::import_archive(&archive_path, &content, &snapshots_root, &opts)
        })
        .await
        .map_err(|e| Status::internal(format!("import task failed: {e}")))?
        .map_err(|e| Status::internal(format!("import {} failed: {e}", req.archive_path)))?;

        crate::server::upsert_imported_image(&self.ctx, &imported)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ImportReply {
            image_id: imported.image_id.to_string(),
            repo_tags: imported.repo_tags.clone(),
        }))
    }
}

/// Serve the Admin service on a root-only unix socket until `shutdown` resolves.
pub async fn serve(
    socket_path: impl AsRef<Path>,
    ctx: Arc<Context>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path = socket_path.as_ref();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    // Admin surface: owner-only (root), like the CRI socket's trust model.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    tracing::info!(?socket_path, "serving admin API over unix socket");
    tonic::transport::Server::builder()
        .add_service(AdminServer::new(AdminSvc { ctx }))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;
    Ok(())
}

/// Connect to the daemon's admin socket and import `archive_path` (which the
/// daemon opens directly — CLI and daemon share the node filesystem). Returns
/// the daemon's reply. Uses the tonic 0.14 UDS-client idiom (dummy authority +
/// a unix-connecting tower service).
pub async fn run_import(
    socket: &Path,
    archive_path: &Path,
    ref_override: Option<&str>,
) -> Result<ImportReply, Box<dyn std::error::Error + Send + Sync>> {
    use hyper_util::rt::TokioIo;
    use tonic::transport::Endpoint;

    let socket = socket.to_path_buf();
    let channel = Endpoint::try_from("http://127.0.0.1:0")?
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&socket).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;

    let mut client = pb::admin_client::AdminClient::new(channel);
    // Absolute path so the daemon (any cwd) resolves the same file.
    let abs = std::fs::canonicalize(archive_path)?;
    let reply = client
        .import(ImportRequest {
            archive_path: abs.to_string_lossy().into_owned(),
            ref_override: ref_override.unwrap_or_default().to_string(),
        })
        .await?
        .into_inner();
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Building AdminSvc and calling import() directly (no socket) exercises the
    // whole in-daemon path: archive → content store → metadata record.
    #[tokio::test]
    async fn import_via_service_populates_store() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::server::test_context(dir.path());
        let tar_path = dir.path().join("app.tar");
        crate::admin::testfix::write_docker_save(&tar_path, "svc:test");

        let svc = AdminSvc { ctx: ctx.clone() };
        let reply = svc
            .import(Request::new(ImportRequest {
                archive_path: tar_path.to_string_lossy().into_owned(),
                ref_override: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(reply.image_id.starts_with("sha256:"));
        assert_eq!(reply.repo_tags, vec!["svc:test".to_string()]);
        // The record is queryable in the metadata store.
        let listed = ctx
            .metadata
            .list::<metadata::records::ImageRecord>(metadata::Kind::Image, ctx.namespace.as_str())
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].repo_tags.contains(&"svc:test".to_string()));
    }

    // Full round-trip over a real unix socket: serve, connect, import.
    #[tokio::test]
    async fn import_round_trip_over_socket() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::server::test_context(dir.path());
        let socket = dir.path().join("admin.sock");
        let tar_path = dir.path().join("rt.tar");
        crate::admin::testfix::write_docker_save(&tar_path, "rt:1");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let srv = {
            let socket = socket.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                super::serve(socket, ctx, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
            })
        };
        // Wait for the socket to appear.
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let reply = super::run_import(&socket, &tar_path, None).await.unwrap();
        assert_eq!(reply.repo_tags, vec!["rt:1".to_string()]);
        assert!(reply.image_id.starts_with("sha256:"));

        let _ = tx.send(());
        let _ = srv.await;
    }
}

#[cfg(test)]
pub(crate) mod testfix {
    use std::fs;
    use std::path::Path;

    use sha2::{Digest as _, Sha256};

    fn tar_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, name, &data[..]).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn sha(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    /// Minimal single-layer docker-save archive with a RepoTag.
    pub fn write_docker_save(path: &Path, repo_tag: &str) {
        let layer = tar_bytes(&[("usr/bin/app", b"#!/bin/true")]);
        let diff = sha(&layer);
        let arch = if std::env::consts::ARCH == "aarch64" {
            "arm64"
        } else {
            "amd64"
        };
        let config = format!(
            r#"{{"architecture":"{arch}","os":"linux","rootfs":{{"type":"layers","diff_ids":["{diff}"]}},"config":{{"User":"0"}}}}"#
        );
        let manifest = format!(
            r#"[{{"Config":"config.json","RepoTags":["{repo_tag}"],"Layers":["layer0/layer.tar"]}}]"#
        );
        let archive = tar_bytes(&[
            ("config.json", config.as_bytes()),
            ("layer0/layer.tar", &layer),
            ("manifest.json", manifest.as_bytes()),
        ]);
        fs::write(path, &archive).unwrap();
    }
}
