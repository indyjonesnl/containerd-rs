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

use std::io::{Cursor, Read};
use std::path::Path;

use core_types::Digest;
use oci_client::client::{ClientConfig, ImageData};
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
}

#[derive(Deserialize)]
struct ImageConfigJson {
    rootfs: RootFs,
}

#[derive(Deserialize)]
struct RootFs {
    diff_ids: Vec<String>,
}

/// Layer media types this runtime accepts from a registry.
fn accepted_media_types() -> Vec<&'static str> {
    vec![
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    ]
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
    let mut image: ImageData = client
        .pull(&parsed, &auth.to_registry_auth(), accepted_media_types())
        .await?;

    // `oci-client` may return layers out of order (parallel fetch); the config's
    // `diff_ids` are in manifest order, so re-sort layers to match the manifest
    // before the positional `layers[i] <-> diff_ids[i]` alignment below.
    if let Some(manifest) = &image.manifest {
        let order: Vec<String> = manifest.layers.iter().map(|d| d.digest.clone()).collect();
        image.layers.sort_by_key(|l| {
            order
                .iter()
                .position(|d| d == &l.sha256_digest())
                .unwrap_or(usize::MAX)
        });
    }

    // Store and identify the config blob; image_id == config digest.
    let config_bytes: &[u8] = image.config.data.as_ref();
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

    if diff_ids.len() != image.layers.len() {
        return Err(Error::LayerCountMismatch {
            diff_ids: diff_ids.len(),
            layers: image.layers.len(),
        });
    }

    let chain_ids = identity::chain_ids(&diff_ids);
    let mut layer_digests = Vec::with_capacity(image.layers.len());

    for (i, layer) in image.layers.iter().enumerate() {
        let layer_digest: Digest = layer.sha256_digest().parse()?;
        let layer_bytes: &[u8] = layer.data.as_ref();
        // Digest is verified on commit by the content store.
        content.write_blob(
            &format!("{reference}:layer:{i}"),
            layer_bytes,
            &layer_digest,
        )?;
        total += layer_bytes.len() as u64;
        layer_digests.push(layer_digest);

        let compression = Compression::from_media_type(&layer.media_type);

        // Assert the uncompressed layer matches the config's diffID.
        let computed = compute_diff_id(layer_bytes, compression)?;
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
        // must not fail re-extracting existing files).
        let (fs_dir, _work) = snapshots::snapshot_dirs(snapshots_root, chain_ids[i].hex());
        let already = fs_dir
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if !already {
            std::fs::create_dir_all(&fs_dir)?;
            apply_layer(
                &fs_dir,
                Box::new(Cursor::new(layer.data.clone())),
                compression,
            )?;
        }
    }

    let manifest_digest = match &image.digest {
        Some(d) => Some(d.parse::<Digest>()?),
        None => None,
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
    })
}

/// Compute the diffID (digest of the *uncompressed* tar) of a compressed layer.
fn compute_diff_id(compressed: &[u8], compression: Compression) -> Result<Digest> {
    let mut reader = decompress(Box::new(Cursor::new(compressed)), compression)?;
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
