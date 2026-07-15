//! Local image import: load an OCI image-layout or docker-save (`docker save`)
//! archive into the content store without a registry. The daemon reads the
//! archive from a node-local path. Mirrors `ctr images import` for single-node
//! use; cross-node distribution remains a registry's job.
//!
//! The archive is extracted into a scratch dir on the store's filesystem, its
//! format is detected (`index.json` ⇒ OCI, `manifest.json` ⇒ docker-save), blobs
//! are committed into the content store (verify-on-commit), and the shared
//! [`crate::unpack::finalize_image`] performs diffID verification + layer unpack.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use core_types::Digest;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::identity::{self, Platform};
use crate::unpack::{self, LayerInput};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("content store error: {0}")]
    Content(#[from] content::Error),
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid digest: {0}")]
    Digest(#[from] core_types::Error),
    #[error("finalize error: {0}")]
    Finalize(#[from] unpack::Error),
    #[error("unknown archive format: no index.json (OCI) or manifest.json (docker-save) at the tar root")]
    UnknownFormat,
    #[error("no manifest in the archive matches the node platform {0}")]
    NoPlatformMatch(String),
    #[error("image has no name: the archive carries no RepoTags/ref — pass --ref <name>")]
    NoName,
    #[error("malformed archive: {0}")]
    Malformed(String),
}

type Result<T> = std::result::Result<T, Error>;

/// Options controlling an import.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Override the image name/tag instead of the archive's RepoTags / ref name.
    pub ref_override: Option<String>,
    /// Node platform used to select a manifest from a multi-arch OCI index.
    pub platform: Platform,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            ref_override: None,
            platform: Platform::default_host(),
        }
    }
}

/// Result of a successful import (shape parallels `pull::PulledImage`).
#[derive(Debug, Clone)]
pub struct ImportedImage {
    pub image_id: Digest,
    /// Manifest digest (Some for OCI layout, None for docker-save).
    pub manifest_digest: Option<Digest>,
    /// Image names carried by the archive (or the `--ref` override).
    pub repo_tags: Vec<String>,
    pub size: u64,
    pub diff_ids: Vec<Digest>,
    pub chain_ids: Vec<Digest>,
    pub layer_digests: Vec<Digest>,
    pub user: String,
}

/// Import `archive_path` (an OCI-layout or docker-save tar) into `content`,
/// unpacking layers under `snapshots_root`.
pub fn import_archive(
    archive_path: &Path,
    content: &content::Store,
    snapshots_root: &Path,
    opts: &ImportOptions,
) -> Result<ImportedImage> {
    // Extract into scratch on the store's own filesystem (auto-removed on drop).
    let ingest = content.root().join("ingest");
    fs::create_dir_all(&ingest)?;
    let scratch = tempfile::Builder::new()
        .prefix("import-")
        .tempdir_in(&ingest)?;
    {
        let file = fs::File::open(archive_path)?;
        let mut ar = tar::Archive::new(file);
        // Don't restore ownership/perms from the outer archive onto scratch; the
        // per-layer perms are applied later by apply_layer into the rootfs.
        ar.set_preserve_permissions(false);
        ar.unpack(scratch.path())?;
    }
    let root = scratch.path();
    tracing::info!(archive = %archive_path.display(), "importing image archive");

    if root.join("index.json").is_file() {
        import_oci_layout(root, content, snapshots_root, opts)
    } else if root.join("manifest.json").is_file() {
        import_docker_save(root, content, snapshots_root, opts)
    } else {
        Err(Error::UnknownFormat)
    }
}

// ---- docker-save ----------------------------------------------------------

#[derive(Deserialize)]
struct DockerManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Vec<String>,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

fn import_docker_save(
    root: &Path,
    content: &content::Store,
    snapshots_root: &Path,
    opts: &ImportOptions,
) -> Result<ImportedImage> {
    let manifests: Vec<DockerManifest> = read_json(&root.join("manifest.json"))?;
    let m = manifests
        .into_iter()
        .next()
        .ok_or_else(|| Error::Malformed("manifest.json is empty".into()))?;

    let config_bytes = fs::read(safe_member(root, &m.config)?)?;
    let mut total = config_bytes.len() as u64;

    let mut layers = Vec::with_capacity(m.layers.len());
    for (i, rel) in m.layers.iter().enumerate() {
        // docker-save layers are uncompressed tars, so the layer's content digest
        // equals its diffID. Hash the file, then stream it into the store under
        // that digest.
        let path = safe_member(root, rel)?;
        let (digest, size) =
            commit_file_by_hash(content, &path, &format!("import:dockerlayer:{i}"))?;
        total += size;
        layers.push(LayerInput {
            digest,
            media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
        });
    }

    let unpacked = unpack::finalize_image(content, snapshots_root, &config_bytes, &layers)?;
    let repo_tags = resolve_tags(opts, m.repo_tags.first().map(String::as_str))?;

    Ok(ImportedImage {
        image_id: unpacked.image_id,
        manifest_digest: None,
        repo_tags,
        size: total,
        diff_ids: unpacked.diff_ids,
        chain_ids: unpacked.chain_ids,
        layer_digests: unpacked.layer_digests,
        user: unpacked.user,
    })
}

// ---- OCI layout -------------------------------------------------------

#[derive(Deserialize)]
struct OciIndex {
    manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    platform: Option<OciPlatform>,
    #[serde(default)]
    annotations: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct OciPlatform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

#[derive(Deserialize)]
struct OciManifest {
    config: OciLayerDescriptor,
    layers: Vec<OciLayerDescriptor>,
}

#[derive(Deserialize)]
struct OciLayerDescriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
}

fn import_oci_layout(
    root: &Path,
    content: &content::Store,
    snapshots_root: &Path,
    opts: &ImportOptions,
) -> Result<ImportedImage> {
    let index: OciIndex = read_json(&root.join("index.json"))?;

    // Consider only image manifests (skip nested indexes).
    let manifest_descs: Vec<&OciDescriptor> = index
        .manifests
        .iter()
        .filter(|d| d.media_type.contains("manifest"))
        .collect();
    if manifest_descs.is_empty() {
        return Err(Error::Malformed("index.json has no image manifest".into()));
    }

    // Single manifest → take it; multiple → select by node platform.
    let selected: &OciDescriptor = if manifest_descs.len() == 1 {
        manifest_descs[0]
    } else {
        let entries: Vec<(Platform, usize)> = manifest_descs
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let p = d
                    .platform
                    .as_ref()
                    .map(|p| Platform {
                        os: p.os.clone(),
                        architecture: p.architecture.clone(),
                        variant: p.variant.clone(),
                    })
                    .unwrap_or_else(|| opts.platform.clone());
                (p, i)
            })
            .collect();
        let idx = identity::select_manifest(&opts.platform, &entries).ok_or_else(|| {
            Error::NoPlatformMatch(format!(
                "{}/{}",
                opts.platform.os, opts.platform.architecture
            ))
        })?;
        manifest_descs[*idx]
    };

    let manifest_digest: Digest = selected.digest.parse()?;
    let manifest_bytes = fs::read(oci_blob_path(root, &manifest_digest))?;
    if Digest::sha256(&manifest_bytes) != manifest_digest {
        return Err(Error::Malformed(format!(
            "manifest digest mismatch: expected {manifest_digest}, blob does not match"
        )));
    }
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)?;

    let config_digest: Digest = manifest.config.digest.parse()?;
    let config_bytes = fs::read(oci_blob_path(root, &config_digest))?;
    if Digest::sha256(&config_bytes) != config_digest {
        return Err(Error::Malformed(format!(
            "config digest mismatch: expected {config_digest}, blob does not match"
        )));
    }
    let mut total = config_bytes.len() as u64;

    let mut layers = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        let digest: Digest = layer.digest.parse()?;
        let path = oci_blob_path(root, &digest);
        let size = fs::metadata(&path)?.len();
        let mut f = fs::File::open(&path)?;
        let mut w = content.writer(&format!("import:ocilayer:{digest}"))?;
        std::io::copy(&mut f, &mut w)?;
        let committed = w.commit(size, &digest)?;
        total += size;
        layers.push(LayerInput {
            digest: committed,
            media_type: layer.media_type.clone(),
        });
    }

    let unpacked = unpack::finalize_image(content, snapshots_root, &config_bytes, &layers)?;
    let ref_name = selected
        .annotations
        .as_ref()
        .and_then(|a| a.get("org.opencontainers.image.ref.name"))
        .map(String::as_str);
    let repo_tags = resolve_tags(opts, ref_name)?;

    Ok(ImportedImage {
        image_id: unpacked.image_id,
        manifest_digest: Some(manifest_digest),
        repo_tags,
        size: total,
        diff_ids: unpacked.diff_ids,
        chain_ids: unpacked.chain_ids,
        layer_digests: unpacked.layer_digests,
        user: unpacked.user,
    })
}

// ---- helpers --------------------------------------------------------------

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Hash a file (sha256), then stream it into the content store committed under
/// that digest. Returns (digest, size). Two passes (hash, copy) — acceptable for
/// a dev-only import path.
fn commit_file_by_hash(
    content: &content::Store,
    path: &Path,
    ingest_ref: &str,
) -> Result<(Digest, u64)> {
    let digest = sha256_file(path)?;
    let size = fs::metadata(path)?.len();
    let mut f = fs::File::open(path)?;
    let mut w = content.writer(ingest_ref)?;
    std::io::copy(&mut f, &mut w)?;
    let committed = w.commit(size, &digest)?;
    Ok((committed, size))
}

fn sha256_file(path: &Path) -> Result<Digest> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())).parse()?)
}

/// Resolve the image name(s): `--ref` override wins; else the archive's tag; else
/// error (an unnamed image can't be referenced by a pod).
fn resolve_tags(opts: &ImportOptions, archive_tag: Option<&str>) -> Result<Vec<String>> {
    if let Some(r) = &opts.ref_override {
        if !r.is_empty() {
            return Ok(vec![r.clone()]);
        }
    }
    match archive_tag {
        Some(t) if !t.is_empty() => Ok(vec![t.to_string()]),
        _ => Err(Error::NoName),
    }
}

// blob path inside an extracted OCI layout: blobs/sha256/<hex>
fn oci_blob_path(root: &Path, digest: &Digest) -> std::path::PathBuf {
    root.join("blobs").join(digest.blob_path())
}

/// Join an archive-controlled relative path (docker-save `Config`/`Layers`
/// entries) under `root`, rejecting anything that could escape it. Mirrors
/// `snapshots::diff::safe_join`: only `Normal`/`CurDir` components are
/// allowed, so an absolute path or a `..` component is rejected outright
/// rather than silently resolved.
fn safe_member(root: &Path, rel: &str) -> Result<PathBuf> {
    use std::path::Component;
    let rel_path = Path::new(rel);
    for c in rel_path.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(Error::Malformed(format!(
                    "archive member path escapes archive root: {rel}"
                )));
            }
        }
    }
    Ok(root.join(rel_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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

    /// Build a minimal single-layer docker-save archive to `path`.
    /// Returns the layer's (uncompressed) tar bytes for assertions.
    fn write_docker_save(path: &Path, repo_tag: Option<&str>) -> Vec<u8> {
        let layer = tar_bytes(&[("usr/bin/app", b"#!/bin/true")]);
        let layer_diff = sha(&layer);
        let config = format!(
            r#"{{"architecture":"{arch}","os":"linux","rootfs":{{"type":"layers","diff_ids":["{layer_diff}"]}},"config":{{"User":"0"}}}}"#,
            arch = if std::env::consts::ARCH == "aarch64" {
                "arm64"
            } else {
                "amd64"
            }
        );
        let repo_tags = match repo_tag {
            Some(t) => format!(r#"["{t}"]"#),
            None => "[]".to_string(),
        };
        let manifest = format!(
            r#"[{{"Config":"config.json","RepoTags":{repo_tags},"Layers":["layer0/layer.tar"]}}]"#
        );
        let archive = tar_bytes(&[
            ("config.json", config.as_bytes()),
            ("layer0/layer.tar", &layer),
            ("manifest.json", manifest.as_bytes()),
        ]);
        fs::write(path, &archive).unwrap();
        layer
    }

    #[test]
    fn imports_docker_save_archive() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("app.tar");
        write_docker_save(&tar_path, Some("myapp:dev"));

        let out = import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap();
        assert_eq!(out.repo_tags, vec!["myapp:dev".to_string()]);
        assert_eq!(out.layer_digests.len(), 1);
        assert!(out.manifest_digest.is_none());
        assert!(content.exists(&out.image_id));
        let (fs_dir, _) = snapshots::snapshot_dirs(&snaps, out.chain_ids[0].hex());
        assert!(fs_dir.join("usr/bin/app").is_file());
    }

    #[test]
    fn ref_override_wins_over_archive_tag() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("app.tar");
        write_docker_save(&tar_path, Some("myapp:dev"));
        let opts = ImportOptions {
            ref_override: Some("other:tag".to_string()),
            ..Default::default()
        };
        let out = import_archive(&tar_path, &content, &snaps, &opts).unwrap();
        assert_eq!(out.repo_tags, vec!["other:tag".to_string()]);
    }

    #[test]
    fn errors_when_no_name_available() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("app.tar");
        write_docker_save(&tar_path, None); // no RepoTags, no --ref
        let err =
            import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        assert!(matches!(err, Error::NoName));
    }

    #[test]
    fn docker_save_rejects_path_traversal_in_config() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("evil.tar");

        let layer = tar_bytes(&[("usr/bin/app", b"#!/bin/true")]);
        // Config points outside the extracted archive root.
        let manifest =
            r#"[{"Config":"../escape.json","RepoTags":["evil:1"],"Layers":["layer0/layer.tar"]}]"#;
        let archive = tar_bytes(&[
            ("layer0/layer.tar", &layer),
            ("manifest.json", manifest.as_bytes()),
        ]);
        fs::write(&tar_path, &archive).unwrap();

        let err =
            import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        match err {
            Error::Malformed(msg) => assert!(msg.contains("escapes archive root")),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn docker_save_rejects_path_traversal_in_layers() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("evil2.tar");

        // Layers entry points outside the extracted archive root.
        let manifest =
            r#"[{"Config":"config.json","RepoTags":["evil:2"],"Layers":["../../etc/passwd"]}]"#;
        let archive = tar_bytes(&[
            ("config.json", b"{}"),
            ("manifest.json", manifest.as_bytes()),
        ]);
        fs::write(&tar_path, &archive).unwrap();

        let err =
            import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        match err {
            Error::Malformed(msg) => assert!(msg.contains("escapes archive root")),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn errors_on_unknown_format() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("junk.tar");
        // A tar with neither index.json nor manifest.json.
        fs::write(&tar_path, tar_bytes(&[("random.txt", b"hi")])).unwrap();
        let err =
            import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat));
        let _ = Write::flush(&mut std::io::sink());
    }

    /// Build a minimal single-manifest OCI image-layout archive (gzip layer).
    fn write_oci_layout(path: &Path, ref_name: Option<&str>) -> Vec<u8> {
        use flate2::write::GzEncoder;
        let arch = if std::env::consts::ARCH == "aarch64" {
            "arm64"
        } else {
            "amd64"
        };
        let layer = tar_bytes(&[("etc/app.conf", b"k=v")]);
        let layer_diff = sha(&layer);
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&layer).unwrap();
        let layer_gz = enc.finish().unwrap();
        let layer_blob_digest = sha(&layer_gz);

        let config = format!(
            r#"{{"architecture":"{arch}","os":"linux","rootfs":{{"type":"layers","diff_ids":["{layer_diff}"]}},"config":{{"User":"65532"}}}}"#
        );
        let config_digest = sha(config.as_bytes());

        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{cs}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_blob_digest}","size":{ls}}}]}}"#,
            cs = config.len(),
            ls = layer_gz.len()
        );
        let manifest_digest = sha(manifest.as_bytes());

        let ann = match ref_name {
            Some(n) => format!(r#","annotations":{{"org.opencontainers.image.ref.name":"{n}"}}"#),
            None => String::new(),
        };
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{ms},"platform":{{"os":"linux","architecture":"{arch}"}}{ann}}}]}}"#,
            ms = manifest.len()
        );

        // blobs/sha256/<hex> layout.
        let hexof = |d: &str| d.strip_prefix("sha256:").unwrap().to_string();
        let archive = tar_bytes(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", index.as_bytes()),
            (
                &format!("blobs/sha256/{}", hexof(&manifest_digest)),
                manifest.as_bytes(),
            ),
            (
                &format!("blobs/sha256/{}", hexof(&config_digest)),
                config.as_bytes(),
            ),
            (
                &format!("blobs/sha256/{}", hexof(&layer_blob_digest)),
                &layer_gz,
            ),
        ]);
        fs::write(path, &archive).unwrap();
        layer
    }

    #[test]
    fn imports_oci_layout_archive() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("oci.tar");
        write_oci_layout(&tar_path, Some("ociapp:1.0"));

        let out = import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap();
        assert_eq!(out.repo_tags, vec!["ociapp:1.0".to_string()]);
        assert!(out.manifest_digest.is_some());
        assert_eq!(out.user, "65532");
        assert_eq!(out.layer_digests.len(), 1);
        let (fs_dir, _) = snapshots::snapshot_dirs(&snaps, out.chain_ids[0].hex());
        assert_eq!(
            std::fs::read_to_string(fs_dir.join("etc/app.conf")).unwrap(),
            "k=v"
        );
    }

    #[test]
    fn oci_layout_rejects_corrupted_manifest_blob() {
        // Build an OCI layout where index.json declares the correct manifest
        // digest, but the blob stored at that path has been tampered with
        // (bytes no longer hash to the declared digest).
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("corrupt.tar");

        let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000000000000000","size":2},"layers":[]}"#;
        let manifest_digest = sha(manifest.as_bytes()); // digest of the *original* bytes
        let hexof = |d: &str| d.strip_prefix("sha256:").unwrap().to_string();

        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{ms},"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#,
            ms = manifest.len()
        );

        // Store corrupted (mutated) bytes at the blob path the digest maps to.
        let corrupted_manifest = manifest.replacen("schemaVersion", "SchemaVersion", 1);
        assert_ne!(corrupted_manifest, manifest);

        let archive = tar_bytes(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", index.as_bytes()),
            (
                &format!("blobs/sha256/{}", hexof(&manifest_digest)),
                corrupted_manifest.as_bytes(),
            ),
        ]);
        fs::write(&tar_path, &archive).unwrap();

        let err =
            import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        match err {
            Error::Malformed(msg) => assert!(msg.contains("manifest digest mismatch")),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn oci_ref_from_annotation_or_override() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("oci.tar");
        write_oci_layout(&tar_path, None); // no ref.name annotation
                                           // No annotation + no override → NoName.
        let err =
            import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        assert!(matches!(err, Error::NoName));
        // Override supplies the name.
        let opts = ImportOptions {
            ref_override: Some("forced:tag".into()),
            ..Default::default()
        };
        let out = import_archive(&tar_path, &content, &snaps, &opts).unwrap();
        assert_eq!(out.repo_tags, vec!["forced:tag".to_string()]);
    }
}
