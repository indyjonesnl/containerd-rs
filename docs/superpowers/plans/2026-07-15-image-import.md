# Image Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a locally-built OCI or docker-save image archive be loaded into containerd-rs's content store on a single node, with no registry, via `containerd-rs import <tar>`.

**Architecture:** A new `images::unpack` module holds the shared tail of the pull pipeline (store config → verify diffIDs → chainIDs → unpack layers). A new `images::import` module parses an OCI-layout or docker-save archive, commits blobs into the content store, and calls `finalize_image`. A minimal `Admin` gRPC service (unary `Import`) on a root-only unix socket runs the import inside the daemon (which owns the redb writer); the daemon opens the archive path directly (CLI and daemon share the node filesystem). A new `containerd-rs import` clap subcommand drives it.

**Tech Stack:** Rust, tonic 0.14 (+ tonic-prost-build), redb, `tar`, `sha2`, existing `content`/`metadata`/`snapshots`/`images` crates.

## Global Constraints

- Author: Indy Jones <development@trucks.nl>. Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Run `make check` (fmt + clippy `-Dwarnings` + test) locally before every push — CI minutes are limited.
- Branch: `feature/image-import` (already created off `main`). One PR to `main`.
- Work is additive; the one non-additive change is the `pull.rs` tail extraction (Task 1) — existing pull tests must stay green.
- Import mirrors pull's feature envelope: single-platform selection, digest-only verification, no push, no signature check.
- Admin socket path: `<state>/admin.sock` (default `/run/containerd-rs/admin.sock`), permissions `0600`.
- Namespace for image records: the CRI namespace (`ctx.namespace`, = `k8s.io`), same as `pull_image`.

---

### Task 1: Extract the shared pull tail into `images::unpack`

Extract config-store + diffID-verify + chainID + layer-unpack from `pull.rs` into a reusable `finalize_image`, so pull and import share the delicate part. No behavior change to pull.

**Files:**
- Create: `crates/images/src/unpack.rs`
- Modify: `crates/images/src/lib.rs` (add `pub mod unpack;`)
- Modify: `crates/images/src/pull.rs` (call `unpack::finalize_image`; drop moved code/variants)

**Interfaces:**
- Produces:
  - `pub struct unpack::LayerInput { pub digest: core_types::Digest, pub media_type: String }`
  - `pub struct unpack::UnpackedImage { pub image_id: Digest, pub diff_ids: Vec<Digest>, pub chain_ids: Vec<Digest>, pub layer_digests: Vec<Digest>, pub user: String }`
  - `pub fn unpack::finalize_image(content: &content::Store, snapshots_root: &std::path::Path, config_bytes: &[u8], layers: &[LayerInput]) -> Result<UnpackedImage, unpack::Error>`
  - `pub enum unpack::Error` (Io, Content, Config, Unpack, Digest, DiffIdMismatch, LayerCountMismatch)

- [ ] **Step 1: Write `crates/images/src/unpack.rs`**

```rust
//! Shared image-finalize step: store the config blob, verify each already-
//! committed layer's diffID against the config, compute chainIDs, and unpack
//! each layer into its chainID-keyed snapshot `fs` dir (idempotent). Used by
//! both the registry pull (`pull.rs`) and the local archive import (`import.rs`)
//! so the delicate verification + unpack + identity logic lives on one path.

use std::io::Read;
use std::path::Path;

use core_types::Digest;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use snapshots::diff::{apply_layer, decompress, Compression};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("content store error: {0}")]
    Content(#[from] content::Error),
    #[error("config parse error: {0}")]
    Config(#[from] serde_json::Error),
    #[error("layer unpack error: {0}")]
    Unpack(#[from] snapshots::diff::Error),
    #[error("invalid digest: {0}")]
    Digest(#[from] core_types::Error),
    #[error("layer {index}: diffID mismatch — config has {expected}, layer computed {computed}")]
    DiffIdMismatch {
        index: usize,
        expected: Digest,
        computed: Digest,
    },
    #[error("config diff_ids ({diff_ids}) and layer count ({layers}) disagree")]
    LayerCountMismatch { diff_ids: usize, layers: usize },
}

type Result<T> = std::result::Result<T, Error>;

/// A committed layer blob plus the media type used to detect its compression.
pub struct LayerInput {
    pub digest: Digest,
    pub media_type: String,
}

/// Identity + snapshot results shared by pull and import.
pub struct UnpackedImage {
    /// Image ID = digest of the image config blob.
    pub image_id: Digest,
    pub diff_ids: Vec<Digest>,
    pub chain_ids: Vec<Digest>,
    pub layer_digests: Vec<Digest>,
    pub user: String,
}

#[derive(Deserialize)]
struct ImageConfigJson {
    rootfs: RootFs,
    #[serde(default)]
    config: OciConfig,
}

#[derive(Deserialize, Default)]
struct OciConfig {
    #[serde(default, rename = "User")]
    user: String,
}

#[derive(Deserialize)]
struct RootFs {
    diff_ids: Vec<String>,
}

/// Store `config_bytes` under its digest (== image_id), then for each layer (in
/// manifest / config-diff_ids order, blobs already committed to `content`):
/// verify the uncompressed diffID against the config and unpack the diff into
/// `snapshots/<chainID>/fs`. Idempotent: an already-populated fs dir is reused.
pub fn finalize_image(
    content: &content::Store,
    snapshots_root: &Path,
    config_bytes: &[u8],
    layers: &[LayerInput],
) -> Result<UnpackedImage> {
    let image_id = Digest::sha256(config_bytes);
    content.write_blob(&format!("config:{image_id}"), config_bytes, &image_id)?;

    let parsed: ImageConfigJson = serde_json::from_slice(config_bytes)?;
    let diff_ids = parsed
        .rootfs
        .diff_ids
        .iter()
        .map(|s| s.parse::<Digest>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if diff_ids.len() != layers.len() {
        return Err(Error::LayerCountMismatch {
            diff_ids: diff_ids.len(),
            layers: layers.len(),
        });
    }

    let chain_ids = crate::identity::chain_ids(&diff_ids);
    let mut layer_digests = Vec::with_capacity(layers.len());
    for (i, layer) in layers.iter().enumerate() {
        let compression = Compression::from_media_type(&layer.media_type);
        let computed =
            compute_diff_id_reader(Box::new(content.open_blob(&layer.digest)?), compression)?;
        if computed != diff_ids[i] {
            return Err(Error::DiffIdMismatch {
                index: i,
                expected: diff_ids[i].clone(),
                computed,
            });
        }
        let (fs_dir, _work) = snapshots::snapshot_dirs(snapshots_root, chain_ids[i].hex());
        let already = fs_dir
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if !already {
            std::fs::create_dir_all(&fs_dir)?;
            apply_layer(
                &fs_dir,
                Box::new(content.open_blob(&layer.digest)?),
                compression,
            )?;
        }
        layer_digests.push(layer.digest.clone());
    }

    Ok(UnpackedImage {
        image_id,
        diff_ids,
        chain_ids,
        layer_digests,
        user: parsed.config.user,
    })
}

/// Compute the diffID (digest of the *uncompressed* tar) of a compressed layer,
/// streaming so the layer is never materialized in memory.
fn compute_diff_id_reader(compressed: Box<dyn Read>, compression: Compression) -> Result<Digest> {
    let mut reader = decompress(compressed, compression)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hex = hex::encode(hasher.finalize());
    Ok(format!("sha256:{hex}").parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_tar(name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, name, data).unwrap();
        b.into_inner().unwrap()
    }

    fn sha256_str(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    // finalize_image stores the config, verifies the (uncompressed) layer diffID,
    // and unpacks the layer into a chainID fs dir.
    #[test]
    fn finalize_stores_verifies_and_unpacks() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");

        let layer = make_tar("usr/bin/hello", b"hi there");
        let layer_digest: Digest = sha256_str(&layer).parse().unwrap();
        content
            .write_blob("layer:0", &layer, &layer_digest)
            .unwrap();

        // Uncompressed layer → diffID == layer digest.
        let config = format!(
            r#"{{"rootfs":{{"type":"layers","diff_ids":["{layer_digest}"]}},"config":{{"User":"1000"}}}}"#
        );
        let layers = vec![LayerInput {
            digest: layer_digest.clone(),
            media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
        }];

        let out = finalize_image(&content, &snaps, config.as_bytes(), &layers).unwrap();
        assert_eq!(out.image_id, Digest::sha256(config.as_bytes()));
        assert_eq!(out.user, "1000");
        assert_eq!(out.chain_ids.len(), 1);
        let (fs_dir, _) = snapshots::snapshot_dirs(&snaps, out.chain_ids[0].hex());
        assert_eq!(
            std::fs::read_to_string(fs_dir.join("usr/bin/hello")).unwrap(),
            "hi there"
        );
    }

    #[test]
    fn finalize_rejects_diffid_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let layer = make_tar("f", b"x");
        let layer_digest: Digest = sha256_str(&layer).parse().unwrap();
        content.write_blob("l", &layer, &layer_digest).unwrap();
        // Config claims a different diffID than the layer actually hashes to.
        let wrong = sha256_str(b"not-the-layer");
        let config = format!(r#"{{"rootfs":{{"diff_ids":["{wrong}"]}}}}"#);
        let layers = vec![LayerInput {
            digest: layer_digest,
            media_type: "application/vnd.oci.image.layer.v1.tar".to_string(),
        }];
        let err = finalize_image(&content, &snaps, config.as_bytes(), &layers).unwrap_err();
        assert!(matches!(err, Error::DiffIdMismatch { .. }));
    }

    #[test]
    fn finalize_rejects_layer_count_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        // Config declares one diffID, zero layers supplied.
        let config = r#"{"rootfs":{"diff_ids":["sha256:aaaa"]}}"#;
        let err = finalize_image(&content, &snaps, config.as_bytes(), &[]).unwrap_err();
        assert!(matches!(err, Error::LayerCountMismatch { .. }));
        let _ = Write::flush(&mut std::io::sink());
    }
}
```

- [ ] **Step 2: Run the new tests to verify they fail (module not wired)**

Run: `cargo test -p images unpack::`
Expected: FAIL — `unpack` module not declared / `finalize_image` not found.

- [ ] **Step 3: Declare the module in `crates/images/src/lib.rs`**

Add `pub mod unpack;` to the module list (alphabetical placement is fine):

```rust
pub mod dockercfg;
pub mod gc;
pub mod identity;
pub mod import;
pub mod pull;
pub mod unpack;
```

(`import` is added in Task 2; adding it now is harmless only if the file exists — so for Task 1, add just `pub mod unpack;` and leave `pub mod import;` for Task 2.)

- [ ] **Step 4: Rewire `crates/images/src/pull.rs` to use `finalize_image`**

Remove from `pull.rs`: the `ImageConfigJson` / `OciConfig` / `RootFs` structs, the `compute_diff_id_reader` fn, and the `Config`, `Unpack`, `DiffIdMismatch`, `LayerCountMismatch` variants from `pull::Error`. Add one variant:

```rust
    #[error("finalize error: {0}")]
    Finalize(#[from] crate::unpack::Error),
```

Delete the imports now unused by pull (`serde::Deserialize`, `snapshots::diff::{apply_layer, decompress, Compression}`, `sha2`). Keep `use crate::identity;`? No — chainID now runs inside finalize; remove `use crate::identity;` if unused. Keep `core_types::Digest`, `futures_util::StreamExt`, `oci_client::*`, `std::io::Write`.

Replace the layer loop (current lines ~189–289, from `let config_bytes = ...` through the `Ok(PulledImage { ... })`) with:

```rust
    let config_bytes = config_string.as_bytes();
    let mut total = config_bytes.len() as u64;

    // Stream each compressed layer straight to the content store (verify-on-
    // commit), collecting the committed blob digest + media type for finalize.
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for (i, descriptor) in manifest.layers.iter().enumerate() {
        let expected_layer_digest: Digest = descriptor.digest.parse()?;
        let expected_size = u64::try_from(descriptor.size).map_err(|_| {
            Error::Reference(
                reference.to_string(),
                format!("layer {i} has negative size {}", descriptor.size),
            )
        })?;
        let mut writer = content.writer(&format!("{reference}:layer:{i}"))?;
        let mut stream = client.pull_blob_stream(&parsed, descriptor).await?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk)?;
        }
        let layer_digest = writer.commit(expected_size, &expected_layer_digest)?;
        total += expected_size;
        layers.push(crate::unpack::LayerInput {
            digest: layer_digest,
            media_type: descriptor.media_type.clone(),
        });
    }

    let unpacked = crate::unpack::finalize_image(content, snapshots_root, config_bytes, &layers)?;

    let manifest_digest = if manifest_digest_str.is_empty() {
        None
    } else {
        Some(manifest_digest_str.parse::<Digest>()?)
    };

    tracing::info!(%reference, image_id = %unpacked.image_id, layers = unpacked.layer_digests.len(), "pull complete");
    Ok(PulledImage {
        reference: reference.to_string(),
        image_id: unpacked.image_id,
        manifest_digest,
        size: total,
        diff_ids: unpacked.diff_ids,
        chain_ids: unpacked.chain_ids,
        layer_digests: unpacked.layer_digests,
        user: unpacked.user,
    })
```

Also delete the now-moved `compute_diff_id_reader_streams_and_matches` unit test from `pull.rs` (it is superseded by the `unpack` tests). Keep the `#[ignore] pull_pause_image` test.

- [ ] **Step 5: Verify pull still compiles and its tests pass**

Run: `cargo test -p images`
Expected: PASS (unpack tests pass; `pull_pause_image` is `#[ignore]`d; no warnings).
Also run: `cargo clippy -p images -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/images/src/unpack.rs crates/images/src/lib.rs crates/images/src/pull.rs
git commit -m "refactor(images): extract shared finalize_image into unpack module

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `images::import` — format detection + docker-save path

Add the import module with its types, format detection, and the docker-save reader. Add a `content::Store::root()` accessor and `tar` as a normal dep of `images`.

**Files:**
- Create: `crates/images/src/import.rs`
- Modify: `crates/images/src/lib.rs` (add `pub mod import;`)
- Modify: `crates/images/Cargo.toml` (add `tar.workspace = true` to `[dependencies]`; add `tempfile` to `[dependencies]`)
- Modify: `crates/content/src/lib.rs` (add `pub fn root()`)

**Interfaces:**
- Consumes: `unpack::{LayerInput, finalize_image, UnpackedImage}` (Task 1); `content::Store::{root, writer, write_blob}`.
- Produces:
  - `pub struct import::ImportOptions { pub ref_override: Option<String>, pub platform: identity::Platform }` + `Default`
  - `pub struct import::ImportedImage { pub image_id: Digest, pub manifest_digest: Option<Digest>, pub repo_tags: Vec<String>, pub size: u64, pub diff_ids: Vec<Digest>, pub chain_ids: Vec<Digest>, pub layer_digests: Vec<Digest>, pub user: String }`
  - `pub fn import::import_archive(archive_path: &Path, content: &content::Store, snapshots_root: &Path, opts: &ImportOptions) -> Result<ImportedImage, import::Error>`
  - `pub enum import::Error`

- [ ] **Step 1: Add `content::Store::root()` accessor**

In `crates/content/src/lib.rs`, inside `impl Store`, after `open`:

```rust
    /// The store's root directory (`io.containerd.content.v1.content`). Used by
    /// the import path to place its extraction scratch dir on the same filesystem.
    pub fn root(&self) -> &Path {
        &self.root
    }
```

- [ ] **Step 2: Add deps to `crates/images/Cargo.toml`**

Under `[dependencies]` add:

```toml
tar = { workspace = true }
tempfile = "3"
```

(Remove `tar` and `tempfile` duplication from `[dev-dependencies]` only if they now conflict — cargo allows a crate in both; leave dev-deps as-is. `flate2` stays a dev-dep.)

- [ ] **Step 3: Write the failing docker-save test into `crates/images/src/import.rs`**

Create the file with the full module below. It contains the docker-save path plus a `#[cfg(test)]` docker-save fixture + test. (The OCI path is added in Task 3; for now `import_oci_layout` returns `Err(Error::UnknownFormat)` as a stub, replaced in Task 3.)

```rust
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
use std::path::Path;

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
    let scratch = tempfile::Builder::new().prefix("import-").tempdir_in(&ingest)?;
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

    let config_bytes = fs::read(root.join(&m.config))?;
    let mut total = config_bytes.len() as u64;

    let mut layers = Vec::with_capacity(m.layers.len());
    for (i, rel) in m.layers.iter().enumerate() {
        // docker-save layers are uncompressed tars, so the layer's content digest
        // equals its diffID. Hash the file, then stream it into the store under
        // that digest.
        let path = root.join(rel);
        let (digest, size) = commit_file_by_hash(content, &path, &format!("import:dockerlayer:{i}"))?;
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

// ---- OCI layout (implemented in Task 3) -----------------------------------

fn import_oci_layout(
    _root: &Path,
    _content: &content::Store,
    _snapshots_root: &Path,
    _opts: &ImportOptions,
) -> Result<ImportedImage> {
    Err(Error::UnknownFormat) // replaced in Task 3
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

// Kept here so both format paths and Task 3 can use it.
#[allow(dead_code)]
fn platform_of(os: &str, arch: &str, variant: Option<String>) -> Platform {
    Platform {
        os: os.to_string(),
        architecture: arch.to_string(),
        variant,
    }
}

#[allow(dead_code)]
fn select<'a>(target: &Platform, entries: &'a [(Platform, usize)]) -> Option<&'a usize> {
    identity::select_manifest(target, entries)
}

// blob path inside an extracted OCI layout: blobs/sha256/<hex>
#[allow(dead_code)]
fn oci_blob_path(root: &Path, digest: &Digest) -> std::path::PathBuf {
    root.join("blobs").join(digest.blob_path())
}

#[allow(dead_code)]
fn hashmap_marker(_: &HashMap<String, String>) {}

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
            arch = if std::env::consts::ARCH == "aarch64" { "arm64" } else { "amd64" }
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
        let err = import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        assert!(matches!(err, Error::NoName));
    }

    #[test]
    fn errors_on_unknown_format() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("junk.tar");
        // A tar with neither index.json nor manifest.json.
        fs::write(&tar_path, tar_bytes(&[("random.txt", b"hi")])).unwrap();
        let err = import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat));
        let _ = Write::flush(&mut std::io::sink());
    }
}
```

- [ ] **Step 4: Declare `pub mod import;` in `crates/images/src/lib.rs`** (if not added in Task 1).

- [ ] **Step 5: Run docker-save tests**

Run: `cargo test -p images import::`
Expected: PASS — `imports_docker_save_archive`, `ref_override_wins_over_archive_tag`, `errors_when_no_name_available`, `errors_on_unknown_format`.

- [ ] **Step 6: Lint + commit**

Run: `cargo clippy -p images -p content -- -D warnings` (Expected: clean.)

```bash
git add crates/images/src/import.rs crates/images/src/lib.rs crates/images/Cargo.toml crates/content/src/lib.rs Cargo.lock
git commit -m "feat(images): import docker-save archives into the content store

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `images::import` — OCI image-layout path

Replace the `import_oci_layout` stub with a real reader: parse `index.json`, select the node-platform manifest, commit config + layer blobs (already `sha256:`-addressed under `blobs/sha256/`), and finalize.

**Files:**
- Modify: `crates/images/src/import.rs`

**Interfaces:**
- Consumes: same as Task 2. No signature changes.

- [ ] **Step 1: Write the failing OCI test** (add to the `tests` module in `import.rs`)

```rust
    /// Build a minimal single-manifest OCI image-layout archive (gzip layer).
    fn write_oci_layout(path: &Path, ref_name: Option<&str>) -> Vec<u8> {
        use flate2::write::GzEncoder;
        let arch = if std::env::consts::ARCH == "aarch64" { "arm64" } else { "amd64" };
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
    fn oci_ref_from_annotation_or_override() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");
        let tar_path = dir.path().join("oci.tar");
        write_oci_layout(&tar_path, None); // no ref.name annotation
        // No annotation + no override → NoName.
        let err = import_archive(&tar_path, &content, &snaps, &ImportOptions::default()).unwrap_err();
        assert!(matches!(err, Error::NoName));
        // Override supplies the name.
        let opts = ImportOptions {
            ref_override: Some("forced:tag".into()),
            ..Default::default()
        };
        let out = import_archive(&tar_path, &content, &snaps, &opts).unwrap();
        assert_eq!(out.repo_tags, vec!["forced:tag".to_string()]);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p images import::imports_oci_layout_archive`
Expected: FAIL — `import_oci_layout` stub returns `UnknownFormat`.

- [ ] **Step 3: Implement `import_oci_layout`** — replace the stub and remove the now-unused `#[allow(dead_code)]` helpers, adding the OCI structs.

```rust
// ---- OCI layout -----------------------------------------------------------

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
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)?;

    let config_digest: Digest = manifest.config.digest.parse()?;
    let config_bytes = fs::read(oci_blob_path(root, &config_digest))?;
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
```

Delete the four `#[allow(dead_code)]` placeholder helpers (`platform_of`, `select`, `hashmap_marker`) added in Task 2, but KEEP `oci_blob_path` (now used). Keep the `use std::collections::HashMap;` import (used by `OciDescriptor`).

- [ ] **Step 4: Run all import + images tests**

Run: `cargo test -p images`
Expected: PASS (both formats, plus Task 1 unpack tests).

- [ ] **Step 5: Lint + commit**

Run: `cargo clippy -p images -- -D warnings` (Expected: clean.)

```bash
git add crates/images/src/import.rs
git commit -m "feat(images): import OCI image-layout archives

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Admin gRPC service (proto + server) and the shared image-record upsert

Add the `Admin`/`Import` proto, compile it, add `cri::admin` with the server impl, and factor the pull_image record aggregation into a shared helper both pull and import use.

**Files:**
- Create: `proto/admin/v1/admin.proto`
- Modify: `crates/cri/build.rs`
- Create: `crates/cri/src/admin.rs`
- Modify: `crates/cri/src/lib.rs` (add `pub mod admin;`)
- Modify: `crates/cri/src/server.rs` (add `pub(crate) fn upsert_imported_image`; optionally reuse in `pull_image`)

**Interfaces:**
- Produces:
  - proto `containerdrs.admin.v1` with `service Admin { rpc Import(ImportRequest) returns (ImportReply); }`
  - `cri::admin::AdminSvc { pub ctx: Arc<Context> }` implementing the generated `Admin` trait.
  - `pub(crate) fn server::upsert_imported_image(ctx: &Context, img: &images::import::ImportedImage) -> Result<(), metadata::Error>`

- [ ] **Step 1: Write `proto/admin/v1/admin.proto`**

```proto
syntax = "proto3";

package containerdrs.admin.v1;

// Node-local administrative API (not part of CRI). Served on a root-only unix
// socket. Used by the `containerd-rs` CLI to drive operations that must run
// inside the daemon because it owns the metadata (redb) writer.
service Admin {
  // Import a local image archive (OCI image-layout or docker-save tar) that the
  // daemon reads from `archive_path` on the node filesystem.
  rpc Import(ImportRequest) returns (ImportReply);
}

message ImportRequest {
  // Absolute path to the archive on the node, readable by the daemon.
  string archive_path = 1;
  // Optional image name/tag override (else taken from the archive).
  string ref_override = 2;
}

message ImportReply {
  string image_id = 1;
  repeated string repo_tags = 2;
}
```

- [ ] **Step 2: Compile the proto** — modify `crates/cri/build.rs`:

```rust
    println!("cargo:rerun-if-changed=../../proto/runtime/v1/api.proto");
    println!("cargo:rerun-if-changed=../../proto/admin/v1/admin.proto");
```

and change the `compile_protos` call to include both:

```rust
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/runtime/v1/api.proto",
                "../../proto/admin/v1/admin.proto",
            ],
            &["../../proto"],
        )?;
```

- [ ] **Step 3: Add `upsert_imported_image` to `crates/cri/src/server.rs`**

Place it near `pull_image` (module-level fn). It mirrors the pull_image aggregation but names the image from the archive tags:

```rust
/// Persist (or merge into) the metadata `ImageRecord` for a freshly imported
/// image, aggregating by image_id exactly like `pull_image` (multiple tags of
/// the same image collapse into one record). Names come from the archive's
/// RepoTags / `--ref`. repoDigests are derived only when the archive carried a
/// manifest digest (OCI layout).
pub(crate) fn upsert_imported_image(
    ctx: &Context,
    img: &images::import::ImportedImage,
) -> Result<(), metadata::Error> {
    let image_id = img.image_id.to_string();
    let ns = ctx.namespace.as_str();
    let tags: Vec<String> = img.repo_tags.iter().map(|t| normalize_image_ref(t)).collect();

    let mut record = ctx
        .metadata
        .get::<ImageRecord>(Kind::Image, ns, &image_id)?
        .unwrap_or_else(|| ImageRecord {
            name: tags.first().cloned().unwrap_or_else(|| image_id.clone()),
            target_digest: img
                .manifest_digest
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_default(),
            image_id: image_id.clone(),
            repo_tags: Vec::new(),
            repo_digests: Vec::new(),
            size: img.size,
            layer_digests: img.layer_digests.iter().map(|d| d.to_string()).collect(),
            chain_ids: img.chain_ids.iter().map(|d| d.to_string()).collect(),
            user: img.user.clone(),
        });

    for t in &tags {
        if !record.repo_tags.contains(t) {
            record.repo_tags.push(t.clone());
        }
    }
    if let Some(md) = &img.manifest_digest {
        for t in &tags {
            let rd = format!("{}@{}", repo_name(t), md);
            if !record.repo_digests.contains(&rd) {
                record.repo_digests.push(rd);
            }
        }
    }
    ctx.metadata.put(Kind::Image, ns, &image_id, &record)
}
```

(`ImageRecord`, `Kind`, `normalize_image_ref`, `repo_name` are already in scope in `server.rs`.)

- [ ] **Step 4: Write `crates/cri/src/admin.rs`** (server half; client `run_import` is Task 5)

```rust
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
        let arch = if std::env::consts::ARCH == "aarch64" { "arm64" } else { "amd64" };
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
```

Note: this test needs a `test_context` helper and `tar`/`sha2`/`hex` available in cri tests. Check whether `crate::server` already exposes a test context builder (grep `fn test_context` / the existing `#[cfg(test)]` context setup around `server.rs:2909`). If a differently-named helper exists (e.g. building `Arc<Context>` over temp stores), use it; otherwise add a small `#[cfg(test)] pub(crate) fn test_context(dir: &Path) -> Arc<Context>` to `server.rs` mirroring the existing test setup. Add `sha2` and `hex` (and `tar`) to `crates/cri/Cargo.toml` `[dev-dependencies]` if absent.

- [ ] **Step 5: Declare the module** — in `crates/cri/src/lib.rs` add `pub mod admin;` (verify the file lists the other modules like `server`, `streaming`, `locks`).

- [ ] **Step 6: Build + test**

Run: `cargo test -p cri admin::`
Expected: PASS — `import_via_service_populates_store`.
Run: `cargo clippy -p cri -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add proto/admin crates/cri/build.rs crates/cri/src/admin.rs crates/cri/src/lib.rs crates/cri/src/server.rs crates/cri/Cargo.toml Cargo.lock
git commit -m "feat(cri): admin Import gRPC service + shared image-record upsert

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Admin socket server + client (`serve`, `run_import`)

Add the UDS-serving `admin::serve` (mirrors `server::serve`) and the client `run_import` used by the CLI. Move `tower` to a normal dep of `cri`.

**Files:**
- Modify: `crates/cri/src/admin.rs` (add `serve` + `run_import`)
- Modify: `crates/cri/Cargo.toml` (move `tower` from `[dev-dependencies]` to `[dependencies]`)

**Interfaces:**
- Produces:
  - `pub async fn admin::serve(socket_path: impl AsRef<Path>, ctx: Arc<Context>, shutdown: impl Future<Output=()>) -> Result<(), Box<dyn Error + Send + Sync>>`
  - `pub async fn admin::run_import(socket: &Path, archive_path: &Path, ref_override: Option<&str>) -> Result<ImportReply, Box<dyn Error + Send + Sync>>`

- [ ] **Step 1: Move `tower` to normal deps** in `crates/cri/Cargo.toml`

Add under `[dependencies]`:

```toml
tower = { version = "0.5", features = ["util"] }
```

and remove the duplicate `tower` line from `[dev-dependencies]` (keep other dev-deps).

- [ ] **Step 2: Add `serve` and `run_import` to `crates/cri/src/admin.rs`**

Add imports at the top:

```rust
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
```

Append:

```rust
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
```

- [ ] **Step 3: Write an end-to-end socket test** (add to `admin.rs` `tests`)

```rust
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
                super::serve(socket, ctx, async { let _ = rx.await; }).await.unwrap();
            })
        };
        // Wait for the socket to appear.
        for _ in 0..50 {
            if socket.exists() { break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let reply = super::run_import(&socket, &tar_path, None).await.unwrap();
        assert_eq!(reply.repo_tags, vec!["rt:1".to_string()]);
        assert!(reply.image_id.starts_with("sha256:"));

        let _ = tx.send(());
        let _ = srv.await;
    }
```

- [ ] **Step 4: Test + lint**

Run: `cargo test -p cri admin::`
Expected: PASS — both the direct-call and socket round-trip tests.
Run: `cargo clippy -p cri -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/cri/src/admin.rs crates/cri/Cargo.toml Cargo.lock
git commit -m "feat(cri): admin socket serve + import client (run_import)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: CLI subcommand + start the admin server in the daemon

Add the `containerd-rs import` subcommand and start `admin::serve` alongside the CRI + streaming servers.

**Files:**
- Modify: `crates/containerd-rs/src/main.rs`

**Interfaces:**
- Consumes: `cri::admin::{serve, run_import}` (Task 5).

- [ ] **Step 1: Restructure `main.rs` arg parsing into subcommands**

Replace the `Args` struct and `main()`/`daemon_main()` signatures. New `Args` + `Command`:

```rust
use clap::{Parser, Subcommand};

/// containerd-rs: a Rust container runtime daemon (CRI for Kubernetes).
#[derive(Debug, Parser)]
#[command(name = "containerd-rs", version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(long, default_value = "/etc/containerd-rs/config.toml", global = true)]
    config: PathBuf,

    /// Initialize stores and exit (used by tests / CI smoke).
    #[arg(long, global = true)]
    check: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Import a local image archive (OCI image-layout or docker-save tar) into
    /// the content store, with no registry. Requires the daemon to be running.
    Import {
        /// Path to the image archive (.tar) on this node.
        archive: PathBuf,
        /// Override the image name/tag (else taken from the archive).
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Admin socket path.
        #[arg(long, default_value = "/run/containerd-rs/admin.sock")]
        socket: PathBuf,
    },
}
```

- [ ] **Step 2: Route in `main()`** — keep the `__pid-holder` intercept first, then parse and dispatch:

```rust
fn main() -> anyhow::Result<()> {
    // (unchanged) __pid-holder intercept block stays here, before arg parsing.
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(String::as_str) == Some("__pid-holder") {
        // ... existing body unchanged ...
    }

    let args = Args::parse();
    match args.command {
        Some(Command::Import {
            archive,
            reference,
            socket,
        }) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                let reply = cri::admin::run_import(&socket, &archive, reference.as_deref())
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("imported image {}", reply.image_id);
                for t in &reply.repo_tags {
                    println!("  {t}");
                }
                Ok::<_, anyhow::Error>(())
            })
        }
        None => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(daemon_main(args.config, args.check)),
    }
}
```

Change `daemon_main` to take params instead of re-parsing:

```rust
async fn daemon_main(config_path: PathBuf, check: bool) -> anyhow::Result<()> {
    logging::init();
    let cfg = Config::load(&config_path)?;
    // ... unchanged, but replace `args.check` with `check` ...
}
```

Delete the `let args = Args::parse();` line inside `daemon_main` (parsing now happens in `main`).

- [ ] **Step 3: Start the admin server in `daemon_main`** — after building `grpc` and `streaming`, before `sd_notify_ready()`:

```rust
    let admin_socket = cfg.state.join("admin.sock");
    let admin = cri::admin::serve(
        admin_socket.clone(),
        ctx.clone(),
        std::future::pending::<()>(),
    );
    tracing::info!(socket = ?admin_socket, "admin API enabled");
```

and add it to the `tokio::select!`:

```rust
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown signal received"),
        r = grpc => r.map_err(|e| anyhow::anyhow!("CRI server error: {e}"))?,
        r = streaming => r.map_err(|e| anyhow::anyhow!("streaming server error: {e}"))?,
        r = admin => r.map_err(|e| anyhow::anyhow!("admin server error: {e}"))?,
    }
```

- [ ] **Step 4: Build the whole workspace + smoke the CLI parsing**

Run: `cargo build`
Expected: builds clean.
Run: `cargo run -q -- import --help`
Expected: prints the `import` subcommand usage (archive arg, `--ref`, `--socket`).
Run: `cargo run -q -- --check`
Expected: initializes stores and exits (daemon path still works with no subcommand).

- [ ] **Step 5: Lint + commit**

Run: `cargo clippy --all-targets -- -D warnings` (Expected: clean.)

```bash
git add crates/containerd-rs/src/main.rs
git commit -m "feat(cli): containerd-rs import subcommand + start admin server

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Manual end-to-end verification + docs

Prove the feature against a real running daemon with a real tool-produced archive, then document it.

**Files:**
- Modify: `README.md`, `docs/architecture.md`, `GAPS.md`

- [ ] **Step 1: Manual E2E (local, needs docker or skopeo to produce a fixture)**

```bash
# Produce a real archive with whatever the dev box has:
docker pull busybox:latest && docker save busybox:latest -o /tmp/busybox.tar
# (or: skopeo copy docker://busybox:latest oci-archive:/tmp/busybox-oci.tar)

# Start the daemon in one terminal (as root, cgroup v2 host):
sudo target/debug/containerd-rs --config ci/config.toml

# Import in another terminal:
sudo target/debug/containerd-rs import /tmp/busybox.tar --ref busybox:local
# Expected: "imported image sha256:..." + "  busybox:local"

# Confirm via crictl against the CRI socket:
sudo crictl --runtime-endpoint unix:///run/containerd-rs.sock images
# Expected: busybox:local listed with the imported image id.
```

Record the observed output in the PR description. If `crictl` is unavailable, assert via the metadata store path instead (the Task 5 socket round-trip test already covers the programmatic path).

- [ ] **Step 2: Update `README.md`** — in the crate table note `images` also imports local archives, and add a usage snippet:

```markdown
### Importing a local image (no registry)

Load an image built on this node straight into the store:

    containerd-rs import ./myapp.tar --ref myapp:dev

Accepts OCI image-layout and `docker save` archives (auto-detected). The daemon
must be running; it reads the archive path directly (single-node). For multi-node
clusters, use a registry — that is how image distribution works in containerd too.
```

- [ ] **Step 3: Update `docs/architecture.md`** — in the request-flow / images section, add import as a second content-store ingest entrypoint beside CRI pull:

```markdown
- **Import** (`containerd-rs import`): the admin unix socket runs
  `images::import` inside the daemon — parse an OCI-layout / docker-save archive,
  commit blobs, and reuse the pull finalize step (diffID verify → chainID →
  unpack). A single-node path for images never pushed to a registry.
```

- [ ] **Step 4: Update `GAPS.md` §7** — keep "pull only (no push)"; adjust any wording implying registry pull is the *only* way to get images in. Add a line:

```markdown
| Import | OCI-layout + docker-save via `containerd-rs import` (single-node; no push). | `crates/images/src/import.rs` |
```

- [ ] **Step 5: Full check + commit**

Run: `make check`
Expected: fmt clean, clippy `-D warnings` clean, all tests pass.

```bash
git add README.md docs/architecture.md GAPS.md
git commit -m "docs: document local image import

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Open the PR**

```bash
git push -u origin feature/image-import
gh pr create --base main --title "feat: local image import (OCI + docker-save)" \
  --body "$(cat <<'EOF'
Adds `containerd-rs import <tar>` so locally-built images enter the content store
without a registry (single-node). CLI → admin unix socket → daemon parses the
archive and reuses the pull finalize path (diffID verify → chainID → unpack →
ImageRecord).

- `images::unpack::finalize_image`: shared tail extracted from the pull pipeline.
- `images::import`: OCI image-layout + docker-save readers (auto-detected).
- `cri::admin`: minimal Admin/Import gRPC on a root-only `admin.sock`.
- `containerd-rs import` clap subcommand.

Tested locally (`make check`) + manual E2E with `docker save` / `crictl images`.
No push path (out of scope). Multi-node distribution remains a registry's job.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

**Spec coverage:**
- OCI + docker-save auto-detected → Task 2 (detection + docker), Task 3 (OCI). ✓
- CLI subcommand + admin socket, daemon does writes → Tasks 4–6. ✓
- Reuse pull finalize (diffID/chainID/unpack) → Task 1 `finalize_image`, called by both pull and import. ✓
- Naming from archive RepoTags / ref annotation with `--ref` override → `resolve_tags` (Tasks 2–3) + `upsert_imported_image` (Task 4). ✓
- Error handling: unknown format, diffID mismatch, count mismatch, no-name → tested in Tasks 1–3. ✓
- Partial-safe: blobs verify-on-commit; no ImageRecord on error (record write is the last step, after import returns Ok) → Task 4 handler ordering. ✓
- Security: 0600 admin socket → Task 5 `serve`. ✓
- Single-platform / digest-only / no push → honored (no push code; single manifest selection). ✓
- Testing: unit (both formats, errors), refactor guard (pull tests green), integration (socket round-trip), manual E2E → Tasks 1–7. ✓
- Docs → Task 7. ✓

**Deviation from spec (intentional, flagged):** the admin RPC passes the archive *path* (unary) instead of streaming tar bytes — valid because CLI and daemon share the node filesystem on a single node. Simpler protocol, same trust model. Spec transport section to be updated to match.

**Placeholder scan:** no TBD/TODO; every code step has complete code. The Task 2 `#[allow(dead_code)]` helpers are explicitly removed in Task 3 Step 3.

**Type consistency:** `finalize_image`/`LayerInput`/`UnpackedImage` (Task 1) match their uses in `pull.rs` (Task 1) and `import.rs` (Tasks 2–3). `ImportedImage` fields match `upsert_imported_image` (Task 4) and the `ImportReply` construction (Task 4). `run_import`/`serve` signatures (Task 5) match the `main.rs` calls (Task 6). `content::Store::root()` (Task 2) is used by `import_archive` (Task 2) and `oci_blob_path` (Task 3).

**Open verification items for the implementer (grep-and-confirm, not assumptions):**
1. `crates/cri/src/lib.rs` module list — confirm the `pub mod` style before adding `pub mod admin;`.
2. Whether a test-context builder already exists in `server.rs` (around line 2909); reuse it as `test_context` or add one.
3. `crates/cri/Cargo.toml` dev-deps already include `tempfile`; add `tar`, `sha2`, `hex` to dev-deps if the admin tests need them (they do).
