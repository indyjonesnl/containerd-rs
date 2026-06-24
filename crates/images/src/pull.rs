//! Image pull pipeline.
//!
//! Mirrors containerd's flow: resolve the reference, select the node-platform
//! manifest, fetch the config + layer blobs into the content store (digest is
//! verified on commit), assert each layer's diffID against the image config,
//! compute chainIDs, and unpack each layer's tar (whiteout-aware) into a
//! per-snapshot `fs` directory keyed by its chainID.
//!
//! Registry access uses `oci-client`; the heavy lifting of the OCI
//! distribution-spec HTTP API and bearer-token auth lives there.

use std::io::{Read, Write};
use std::path::Path;

use core_types::Digest;
use futures_util::StreamExt;
use oci_client::client::ClientConfig;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::identity;
use snapshots::diff::{apply_layer, decompress, Compression};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid reference {0:?}: {1}")]
    Reference(String, String),
    #[error("registry error: {0}")]
    Registry(#[from] oci_client::errors::OciDistributionError),
    #[error("content store error: {0}")]
    Content(#[from] content::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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

/// Registry credentials for a pull (from the CRI `AuthConfig`).
#[derive(Debug, Clone)]
pub enum Auth {
    Anonymous,
    Basic {
        username: String,
        password: String,
    },
    /// A pre-issued bearer token (CRI `identity_token` / `registry_token`).
    Bearer(String),
}

impl Auth {
    fn to_registry_auth(&self) -> RegistryAuth {
        match self {
            Auth::Anonymous => RegistryAuth::Anonymous,
            Auth::Basic { username, password } => {
                RegistryAuth::Basic(username.clone(), password.clone())
            }
            Auth::Bearer(token) => RegistryAuth::Bearer(token.clone()),
        }
    }
}

impl Error {
    /// Whether this pull failed because of registry authentication/authorization
    /// (so callers can surface `Unauthenticated` rather than a generic error).
    pub fn is_auth_error(&self) -> bool {
        use oci_client::errors::OciDistributionError as E;
        matches!(
            self,
            Error::Registry(E::AuthenticationFailure(_))
                | Error::Registry(E::UnauthorizedError { .. })
        )
    }
}

/// Result of a successful pull.
#[derive(Debug, Clone)]
pub struct PulledImage {
    pub reference: String,
    /// Image ID = digest of the image config blob.
    pub image_id: Digest,
    /// Manifest (or index-selected manifest) digest.
    pub manifest_digest: Option<Digest>,
    /// Total stored bytes (config + compressed layers).
    pub size: u64,
    /// Uncompressed-layer digests, in order (from the image config).
    pub diff_ids: Vec<Digest>,
    /// Per-layer chainIDs (committed snapshot keys), in order.
    pub chain_ids: Vec<Digest>,
    /// Compressed layer blob digests, in order.
    pub layer_digests: Vec<Digest>,
    /// OCI image config `User` (empty == root).
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

/// Pull `reference` into `content`, unpacking layers under `snapshots_root`.
pub async fn pull(
    reference: &str,
    content: &content::Store,
    snapshots_root: &Path,
    auth: &Auth,
) -> Result<PulledImage> {
    let parsed: Reference = reference.parse().map_err(|e: oci_client::ParseError| {
        Error::Reference(reference.to_string(), e.to_string())
    })?;

    // Select the node platform when the reference points at a multi-arch index.
    let config = ClientConfig {
        platform_resolver: Some(Box::new(oci_client::client::linux_amd64_resolver)),
        ..Default::default()
    };
    let client = Client::new(config);

    tracing::info!(%reference, "pulling image");

    // Fetch the manifest (platform-selected for multi-arch indexes) and the
    // small config blob. The config stays in memory (it is tiny); layers do not.
    let (manifest, manifest_digest_str, config_string) = client
        .pull_manifest_and_config(&parsed, &auth.to_registry_auth())
        .await?;

    // Store and identify the config blob; image_id == config digest.
    let config_bytes = config_string.as_bytes();
    let image_id = Digest::sha256(config_bytes);
    content.write_blob(&format!("config:{reference}"), config_bytes, &image_id)?;
    let mut total = config_bytes.len() as u64;

    let parsed_config: ImageConfigJson = serde_json::from_slice(config_bytes)?;
    let diff_ids = parsed_config
        .rootfs
        .diff_ids
        .iter()
        .map(|s| s.parse::<Digest>())
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // `manifest.layers` is already in manifest order, which matches the config's
    // `diff_ids` order — no re-sort needed.
    if diff_ids.len() != manifest.layers.len() {
        return Err(Error::LayerCountMismatch {
            diff_ids: diff_ids.len(),
            layers: manifest.layers.len(),
        });
    }

    let chain_ids = identity::chain_ids(&diff_ids);
    let mut layer_digests = Vec::with_capacity(manifest.layers.len());

    for (i, descriptor) in manifest.layers.iter().enumerate() {
        let expected_layer_digest: Digest = descriptor.digest.parse()?;
        let expected_size = u64::try_from(descriptor.size).map_err(|_| {
            Error::Reference(
                reference.to_string(),
                format!("layer {i} has negative size {}", descriptor.size),
            )
        })?;

        // Stream the compressed layer straight to the content store: chunk in,
        // chunk written + hashed, never buffering the whole layer. The content
        // store verifies the digest and size on commit.
        let mut writer = content.writer(&format!("{reference}:layer:{i}"))?;
        let mut stream = client.pull_blob_stream(&parsed, descriptor).await?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk)?;
        }
        let layer_digest = writer.commit(expected_size, &expected_layer_digest)?;
        total += expected_size;
        layer_digests.push(layer_digest);

        let compression = Compression::from_media_type(&descriptor.media_type);

        // Assert the uncompressed layer matches the config's diffID, streaming
        // the now-on-disk compressed blob through the decompressor (no Vec).
        let computed = compute_diff_id_reader(
            Box::new(content.open_blob(&expected_layer_digest)?),
            compression,
        )?;
        if computed != diff_ids[i] {
            return Err(Error::DiffIdMismatch {
                index: i,
                expected: diff_ids[i].clone(),
                computed,
            });
        }

        // Unpack this layer's diff into its chainID-keyed snapshot fs dir.
        // Snapshots are immutable + content-addressed by chainID, so an already
        // populated dir is reused (pulls are idempotent; re-pulling `:latest`
        // must not fail re-extracting existing files). Extraction reads from the
        // on-disk blob file, not from memory.
        let (fs_dir, _work) = snapshots::snapshot_dirs(snapshots_root, chain_ids[i].hex());
        let already = fs_dir
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if !already {
            std::fs::create_dir_all(&fs_dir)?;
            apply_layer(
                &fs_dir,
                Box::new(content.open_blob(&expected_layer_digest)?),
                compression,
            )?;
        }
    }

    let manifest_digest = if manifest_digest_str.is_empty() {
        None
    } else {
        Some(manifest_digest_str.parse::<Digest>()?)
    };

    tracing::info!(%reference, %image_id, layers = layer_digests.len(), "pull complete");
    Ok(PulledImage {
        reference: reference.to_string(),
        image_id,
        manifest_digest,
        size: total,
        diff_ids,
        chain_ids,
        layer_digests,
        user: parsed_config.config.user,
    })
}

/// Compute the diffID (digest of the *uncompressed* tar) of a compressed layer,
/// streaming from `compressed` so the layer is never materialized in memory.
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

    /// Build an uncompressed tar with one regular file.
    fn make_tar(name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, name, data).unwrap();
        b.into_inner().unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn sha256_str(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    // Streaming diffID: hashing the *uncompressed* tar via a reader (no whole
    // blob in memory) must equal the sha256 of the uncompressed bytes — this is
    // the assertion the pull path relies on after streaming a layer to disk.
    #[test]
    fn compute_diff_id_reader_streams_and_matches() {
        let uncompressed = make_tar("usr/bin/hello", b"hi there");
        let compressed = gzip(&uncompressed);
        let expected: Digest = sha256_str(&uncompressed).parse().unwrap();

        // From the compressed blob held on disk in a content store.
        let dir = tempfile::tempdir().unwrap();
        let store = content::Store::open(dir.path()).unwrap();
        let blob_digest: Digest = sha256_str(&compressed).parse().unwrap();
        store
            .write_blob("layer:0", &compressed, &blob_digest)
            .unwrap();

        let got = compute_diff_id_reader(
            Box::new(store.open_blob(&blob_digest).unwrap()),
            Compression::Gzip,
        )
        .unwrap();
        assert_eq!(got, expected);

        // And apply_layer reading from the same on-disk file extracts the entry.
        let target = dir.path().join("rootfs");
        std::fs::create_dir_all(&target).unwrap();
        apply_layer(
            &target,
            Box::new(store.open_blob(&blob_digest).unwrap()),
            Compression::Gzip,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(target.join("usr/bin/hello")).unwrap(),
            "hi there"
        );
    }

    // Requires network access to registry.k8s.io. Run with:
    //   cargo test -p images -- --ignored
    #[tokio::test]
    #[ignore = "requires network: pulls registry.k8s.io/pause:3.10"]
    async fn pull_pause_image() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");

        let img = pull(
            "registry.k8s.io/pause:3.10",
            &content,
            &snaps,
            &Auth::Anonymous,
        )
        .await
        .expect("pull should succeed");

        // Config blob stored under its digest (== image_id).
        assert!(content.exists(&img.image_id));
        // At least one layer, all blobs stored, chainIDs match layer count.
        assert!(!img.layer_digests.is_empty());
        assert_eq!(img.chain_ids.len(), img.layer_digests.len());
        assert_eq!(img.diff_ids.len(), img.layer_digests.len());
        for d in &img.layer_digests {
            assert!(content.exists(d));
        }
        // Each layer unpacked into a chainID-keyed fs dir.
        for c in &img.chain_ids {
            let (fs_dir, _) = snapshots::snapshot_dirs(&snaps, c.hex());
            assert!(fs_dir.is_dir(), "missing rootfs dir for {c}");
        }
    }
}
