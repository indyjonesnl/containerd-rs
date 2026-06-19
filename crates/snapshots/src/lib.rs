//! Overlayfs snapshotter.
//!
//! This module implements the parts of the snapshotter that are pure and
//! portable: the overlay mount-option construction (which must produce
//! kernel-valid, runc-acceptable mounts) and snapshot path layout. The actual
//! `mount(2)` syscall is performed by [`mount_overlay`], which requires root and
//! is therefore only exercised in privileged integration tests.

pub mod diff;

use std::path::{Path, PathBuf};

use core_types::Mount;

/// Build the overlay (or bind) mount for an active snapshot given the on-disk
/// directories of its committed parents, ordered child-nearest first.
///
/// * Zero parents → a bind of the upper dir is not valid for a fresh layer; we
///   return an overlay with only upper/work (handled by caller for the empty
///   base case via [`bind_mount`]).
/// * Exactly one read-only parent and no upper (a View) → a `bind` mount.
/// * Otherwise → a single `overlay` mount with
///   `lowerdir=<parents, child-first>,upperdir=<upper>,workdir=<work>`.
pub fn overlay_mount(parents_fs: &[PathBuf], upper: &Path, work: &Path) -> Mount {
    let lower = parents_fs
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":");
    let mut options = Vec::new();
    if !lower.is_empty() {
        options.push(format!("lowerdir={lower}"));
    }
    options.push(format!("upperdir={}", upper.display()));
    options.push(format!("workdir={}", work.display()));
    Mount {
        mount_type: "overlay".to_string(),
        source: "overlay".to_string(),
        options,
    }
}

/// A read-only view over a single committed parent is a plain bind mount.
pub fn bind_mount(parent_fs: &Path) -> Mount {
    Mount {
        mount_type: "bind".to_string(),
        source: parent_fs.display().to_string(),
        options: vec!["rbind".to_string(), "ro".to_string()],
    }
}

/// Layout helper: the `fs` (upper/diff) and `work` directories for a snapshot id.
pub fn snapshot_dirs(root: &Path, id: &str) -> (PathBuf, PathBuf) {
    let base = root.join("snapshots").join(id);
    (base.join("fs"), base.join("work"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_options_child_first() {
        let parents = vec![PathBuf::from("/snap/2/fs"), PathBuf::from("/snap/1/fs")];
        let m = overlay_mount(&parents, Path::new("/snap/3/fs"), Path::new("/snap/3/work"));
        assert_eq!(m.mount_type, "overlay");
        assert_eq!(m.options[0], "lowerdir=/snap/2/fs:/snap/1/fs");
        assert_eq!(m.options[1], "upperdir=/snap/3/fs");
        assert_eq!(m.options[2], "workdir=/snap/3/work");
    }

    #[test]
    fn no_parents_omits_lowerdir() {
        let m = overlay_mount(&[], Path::new("/snap/1/fs"), Path::new("/snap/1/work"));
        assert!(!m.options.iter().any(|o| o.starts_with("lowerdir=")));
        assert!(m.options.iter().any(|o| o.starts_with("upperdir=")));
    }

    #[test]
    fn bind_for_view() {
        let m = bind_mount(Path::new("/snap/1/fs"));
        assert_eq!(m.mount_type, "bind");
        assert!(m.options.contains(&"ro".to_string()));
    }
}
