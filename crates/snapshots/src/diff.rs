//! Layer diff application: decompress a layer blob and extract its tar onto an
//! upper directory, applying OCI whiteouts. The compression detection and
//! whiteout classification are pure and unit-tested; the extraction itself is a
//! thin wrapper over the `tar` crate.

use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Supported layer compression, detected from the media type suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

impl Compression {
    /// Detect compression from an OCI/docker layer media type.
    pub fn from_media_type(media_type: &str) -> Self {
        if media_type.ends_with("gzip") {
            Compression::Gzip
        } else if media_type.ends_with("zstd") {
            Compression::Zstd
        } else {
            Compression::None
        }
    }

    /// Detect compression from a blob's magic bytes (when the media type is
    /// unknown, e.g. reconstructing from a stored layer).
    pub fn detect(bytes: &[u8]) -> Self {
        if bytes.starts_with(&[0x1f, 0x8b]) {
            Compression::Gzip
        } else if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Compression::Zstd
        } else {
            Compression::None
        }
    }
}

/// Classification of a tar entry path with respect to OCI whiteouts.
#[derive(Debug, PartialEq, Eq)]
pub enum Whiteout {
    /// Not a whiteout; a normal entry.
    None,
    /// `<dir>/.wh.<name>` — remove the sibling `name` from the merged view.
    Remove(PathBuf),
    /// `<dir>/.wh..wh..opq` — opaque dir: hide all of `<dir>`'s lower contents.
    Opaque(PathBuf),
}

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_MARKER: &str = ".wh..wh..opq";

/// Classify a tar entry path. Mirrors the OCI image-spec layer change rules.
pub fn classify(path: &Path) -> Whiteout {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return Whiteout::None,
    };
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    if file_name == OPAQUE_MARKER {
        return Whiteout::Opaque(parent);
    }
    if let Some(stripped) = file_name.strip_prefix(WHITEOUT_PREFIX) {
        return Whiteout::Remove(parent.join(stripped));
    }
    Whiteout::None
}

/// Wrap a reader with the appropriate decompressor.
pub fn decompress<'a>(
    reader: Box<dyn Read + 'a>,
    compression: Compression,
) -> std::io::Result<Box<dyn Read + 'a>> {
    Ok(match compression {
        Compression::None => reader,
        Compression::Gzip => Box::new(flate2::read::GzDecoder::new(reader)),
        Compression::Zstd => Box::new(zstd::stream::read::Decoder::new(reader)?),
    })
}

/// Apply a single layer onto `target` (the upper/diff dir): decompress, then
/// extract each entry, honoring whiteouts by deleting the corresponding target
/// paths instead of writing the marker files.
pub fn apply_layer(
    target: &Path,
    blob: Box<dyn Read + '_>,
    compression: Compression,
) -> Result<(), Error> {
    let decoded = decompress(blob, compression)?;
    let mut archive = tar::Archive::new(decoded);
    // Preserve the full file mode including setuid/setgid/sticky bits. Without
    // this the `tar` crate masks the mode with `& 0o777`, stripping the setuid
    // bit off binaries like `su`/`ping`/the cri-tools nonewprivs helper — which
    // then cannot escalate privileges (breaks NoNewPrivs=false conformance and
    // any image relying on setuid binaries). Mirrors containerd's layer applier.
    archive.set_preserve_permissions(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        match classify(&path) {
            Whiteout::None => {
                entry.unpack_in(target)?;
            }
            Whiteout::Remove(rel) => {
                // Guard against a malicious layer whose whiteout path escapes the
                // rootfs (e.g. `../../.wh.x`) and would delete host files.
                if let Some(victim) = safe_join(target, &rel) {
                    remove_path(&victim);
                }
            }
            Whiteout::Opaque(rel) => {
                // Opaque dir: clear existing children in the upper dir.
                if let Some(dir) = safe_join(target, &rel) {
                    if dir.is_dir() {
                        for child in std::fs::read_dir(&dir)?.flatten() {
                            remove_path(&child.path());
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn remove_path(p: &Path) {
    if p.is_dir() {
        let _ = std::fs::remove_dir_all(p);
    } else {
        let _ = std::fs::remove_file(p);
    }
}

/// Join `rel` under `target`, returning `None` if `rel` would escape `target`
/// (absolute, a root/prefix component, or any `..`). Whiteout paths come from
/// untrusted image layers, so they must not delete outside the rootfs.
fn safe_join(target: &Path, rel: &Path) -> Option<PathBuf> {
    use std::path::Component;
    for c in rel.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => return None,
        }
    }
    Some(target.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_detect_from_magic() {
        assert_eq!(
            Compression::detect(&[0x1f, 0x8b, 0x08, 0x00]),
            Compression::Gzip
        );
        assert_eq!(
            Compression::detect(&[0x28, 0xb5, 0x2f, 0xfd, 0x00]),
            Compression::Zstd
        );
        assert_eq!(Compression::detect(b"ustar  plain tar"), Compression::None);
        assert_eq!(Compression::detect(&[]), Compression::None);
    }

    #[test]
    fn compression_detection() {
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+gzip"),
            Compression::Gzip
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+zstd"),
            Compression::Zstd
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar"),
            Compression::None
        );
    }

    #[test]
    fn classify_normal() {
        assert_eq!(classify(Path::new("usr/bin/sh")), Whiteout::None);
    }

    #[test]
    fn classify_remove() {
        assert_eq!(
            classify(Path::new("usr/bin/.wh.oldfile")),
            Whiteout::Remove(PathBuf::from("usr/bin/oldfile"))
        );
    }

    #[test]
    fn classify_opaque() {
        assert_eq!(
            classify(Path::new("var/cache/.wh..wh..opq")),
            Whiteout::Opaque(PathBuf::from("var/cache"))
        );
    }

    #[test]
    fn safe_join_blocks_escapes() {
        let t = Path::new("/rootfs");
        assert_eq!(
            safe_join(t, Path::new("a/b")),
            Some(PathBuf::from("/rootfs/a/b"))
        );
        assert!(safe_join(t, Path::new("../etc/passwd")).is_none());
        assert!(safe_join(t, Path::new("a/../../etc")).is_none());
        assert!(safe_join(t, Path::new("/etc/passwd")).is_none());
    }

    /// Build an uncompressed tar from (path, contents) pairs.
    fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
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

    #[test]
    fn apply_layer_extracts_files() {
        let dir = tempfile::tempdir().unwrap();
        let blob = tar(&[("usr/bin/hello", b"hi")]);
        apply_layer(
            dir.path(),
            Box::new(std::io::Cursor::new(blob)),
            Compression::None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("usr/bin/hello")).unwrap(),
            "hi"
        );
    }

    #[test]
    fn apply_layer_preserves_setuid_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // Build a tar with a setuid-root binary (mode 04755).
        let mut b = tar::Builder::new(Vec::new());
        let data = b"#!/bin/true";
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o4755);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, "usr/bin/suidbin", &data[..]).unwrap();
        let blob = b.into_inner().unwrap();

        apply_layer(
            dir.path(),
            Box::new(std::io::Cursor::new(blob)),
            Compression::None,
        )
        .unwrap();
        let mode = std::fs::metadata(dir.path().join("usr/bin/suidbin"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o4000,
            0o4000,
            "setuid bit must survive layer extraction (got mode {mode:o})"
        );
    }

    #[test]
    fn apply_layer_whiteout_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
        std::fs::write(dir.path().join("usr/bin/old"), b"x").unwrap();
        let blob = tar(&[("usr/bin/.wh.old", b"")]);
        apply_layer(
            dir.path(),
            Box::new(std::io::Cursor::new(blob)),
            Compression::None,
        )
        .unwrap();
        assert!(
            !dir.path().join("usr/bin/old").exists(),
            "whiteout removed it"
        );
    }

    #[test]
    fn apply_layer_opaque_clears_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/cache")).unwrap();
        std::fs::write(dir.path().join("var/cache/a"), b"a").unwrap();
        std::fs::write(dir.path().join("var/cache/b"), b"b").unwrap();
        let blob = tar(&[("var/cache/.wh..wh..opq", b"")]);
        apply_layer(
            dir.path(),
            Box::new(std::io::Cursor::new(blob)),
            Compression::None,
        )
        .unwrap();
        assert!(!dir.path().join("var/cache/a").exists());
        assert!(!dir.path().join("var/cache/b").exists());
    }

    // Note: an end-to-end "malicious whiteout" tar can't be built here because the
    // `tar` crate refuses to write `..` into an archive. The escape guard is proven
    // by `safe_join_blocks_escapes` above, and `apply_layer` routes every whiteout
    // (Remove/Opaque) through `safe_join`.
}
