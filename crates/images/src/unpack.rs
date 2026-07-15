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
#[derive(Debug)]
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
        let config = format!(
            r#"{{"rootfs":{{"diff_ids":["sha256:{}"]}}}}"#,
            "a".repeat(64)
        );
        let err = finalize_image(&content, &snaps, config.as_bytes(), &[]).unwrap_err();
        assert!(matches!(err, Error::LayerCountMismatch { .. }));
        let _ = Write::flush(&mut std::io::sink());
    }
}
