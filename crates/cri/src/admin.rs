//! Node-local admin gRPC service (`containerdrs.admin.v1.Admin`), served on a
//! root-only unix socket. Currently one method — Import — which loads a local
//! image archive into the store inside the daemon (which owns the redb writer).

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
