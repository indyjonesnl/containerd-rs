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

use std::io::Write;
use std::path::Path;

use core_types::Digest;
use futures_util::StreamExt;
use oci_client::client::ClientConfig;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

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
    #[error("invalid digest: {0}")]
    Digest(#[from] core_types::Error),
    #[error("finalize error: {0}")]
    Finalize(#[from] crate::unpack::Error),
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

/// Resolve pull credentials with a fallback chain (feature 002 US4 / T029): the
/// kubelet-provided auth wins; otherwise consult the node's docker config
/// (`config.json` / cred helpers) for the reference's registry. Falls back to
/// anonymous when nothing matches. (Cloud ECR/GCR/ACR exchange is deferred, T028.)
pub fn resolve_auth(reference: &str, provided: Auth) -> Auth {
    if !matches!(provided, Auth::Anonymous) {
        return provided;
    }
    crate::dockercfg::load_default()
        .and_then(|c| c.resolve(reference))
        .unwrap_or(Auth::Anonymous)
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
    // Build the list of insecure (HTTP) registries: always includes localhost,
    // plus any registries named in the CONTAINERD_RS_INSECURE_REGISTRIES env
    // var (comma-separated, e.g. "10.88.0.1:5000,my-registry:5000").
    let mut insecure: Vec<String> = vec![
        "localhost".to_string(),
        // mikronetes M2a: local registry mirror on the host bridge (10.88.0.1:5000)
        // used when the VM has no internet access (no NAT masquerade).
        "10.88.0.1:5000".to_string(),
    ];
    if let Ok(extra) = std::env::var("CONTAINERD_RS_INSECURE_REGISTRIES") {
        for r in extra.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            insecure.push(r.to_string());
        }
    }
    let config = ClientConfig {
        platform_resolver: Some(Box::new(oci_client::client::linux_amd64_resolver)),
        protocol: oci_client::client::ClientProtocol::HttpsExcept(insecure),
        // Musl Alpine has no system CA bundle; accept_invalid_certificates skips
        // rustls-platform-verifier (which panics on "No CA certificates were loaded
        // from the system") and uses NoVerifier instead — safe for the local HTTP
        // registry used in M2a. HTTPS pulls from public registries also bypass CA
        // verification, which is acceptable for a dev-only build.
        accept_invalid_certificates: true,
        ..Default::default()
    };
    let client = Client::new(config);

    tracing::info!(%reference, "pulling image");

    // Fetch the manifest (platform-selected for multi-arch indexes) and the
    // small config blob. The config stays in memory (it is tiny); layers do not.
    let (manifest, manifest_digest_str, config_string) = client
        .pull_manifest_and_config(&parsed, &auth.to_registry_auth())
        .await?;

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
