//! Image reference garbage collection.
//!
//! containerd uses a label-driven tri-color mark-and-sweep; we use the
//! equivalent reachability idea in a simpler form: after an image record is
//! removed, a blob or snapshot is reclaimed only if no *remaining* image still
//! references it. References are the config + layer blob digests and the
//! per-layer snapshot chainIDs recorded on each [`ImageRecord`].

use std::collections::HashSet;
use std::path::Path;

use core_types::Digest;
use metadata::records::ImageRecord;

/// What a reclaim pass deleted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReclaimReport {
    pub blobs_removed: usize,
    pub snapshots_removed: usize,
}

/// The full set of blob digests an image references (config + layers).
fn referenced_blobs(rec: &ImageRecord) -> impl Iterator<Item = &str> {
    std::iter::once(rec.image_id.as_str()).chain(rec.layer_digests.iter().map(String::as_str))
}

/// Reclaim blobs and snapshot dirs referenced by `removed` that are no longer
/// referenced by any record in `live`.
pub fn reclaim(
    content: &content::Store,
    snapshots_root: &Path,
    removed: &ImageRecord,
    live: &[ImageRecord],
) -> ReclaimReport {
    let live_blobs: HashSet<&str> = live.iter().flat_map(referenced_blobs).collect();
    let live_chains: HashSet<&str> = live
        .iter()
        .flat_map(|r| r.chain_ids.iter().map(String::as_str))
        .collect();

    let mut report = ReclaimReport::default();

    for blob in referenced_blobs(removed) {
        if live_blobs.contains(blob) {
            continue;
        }
        if let Ok(digest) = blob.parse::<Digest>() {
            if content.remove(&digest).unwrap_or(false) {
                report.blobs_removed += 1;
            }
        }
    }

    for chain in &removed.chain_ids {
        if live_chains.contains(chain.as_str()) {
            continue;
        }
        // Remove the whole snapshots/<chainID> dir (fs + work).
        if let Some(dir) = snapshots::snapshot_dirs(snapshots_root, chain).0.parent() {
            if dir.is_dir() && std::fs::remove_dir_all(dir).is_ok() {
                report.snapshots_removed += 1;
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, layers: &[&str], chains: &[&str]) -> ImageRecord {
        ImageRecord {
            name: format!("img-{id}"),
            target_digest: String::new(),
            image_id: id.to_string(),
            repo_tags: vec![],
            repo_digests: vec![],
            size: 0,
            layer_digests: layers.iter().map(|s| s.to_string()).collect(),
            chain_ids: chains.iter().map(|s| s.to_string()).collect(),
            user: String::new(),
        }
    }

    fn seed_blob(store: &content::Store, bytes: &[u8]) -> String {
        let d = Digest::sha256(bytes);
        store.write_blob("seed", bytes, &d).unwrap();
        d.to_string()
    }

    #[test]
    fn reclaims_only_unreferenced() {
        let dir = tempfile::tempdir().unwrap();
        let content = content::Store::open(dir.path().join("content")).unwrap();
        let snaps = dir.path().join("snapshots");

        // Two blobs: one shared, one unique to the removed image.
        let cfg = seed_blob(&content, b"config-A");
        let shared = seed_blob(&content, b"shared-layer");
        let unique = seed_blob(&content, b"unique-layer");

        // Snapshot dirs for two chainIDs.
        let shared_chain = "sha256:aaaa";
        let unique_chain = "sha256:bbbb";
        for c in [shared_chain, unique_chain] {
            let (fs, _) = snapshots::snapshot_dirs(&snaps, c);
            std::fs::create_dir_all(&fs).unwrap();
        }

        let removed = rec(&cfg, &[&shared, &unique], &[shared_chain, unique_chain]);
        // A live image still references the shared blob + chain.
        let live_cfg = seed_blob(&content, b"config-B");
        let live = vec![rec(&live_cfg, &[&shared], &[shared_chain])];

        let report = reclaim(&content, &snaps, &removed, &live);
        assert_eq!(report.blobs_removed, 2); // cfg(A) + unique
        assert_eq!(report.snapshots_removed, 1); // unique_chain

        // Shared survives; unique gone.
        assert!(content.exists(&shared.parse().unwrap()));
        assert!(!content.exists(&unique.parse().unwrap()));
        assert!(!content.exists(&cfg.parse().unwrap()));
        assert!(snapshots::snapshot_dirs(&snaps, shared_chain).0.exists());
        assert!(!snapshots::snapshot_dirs(&snaps, unique_chain).0.exists());
    }
}
