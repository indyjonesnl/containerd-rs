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
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        match classify(&path) {
            Whiteout::None => {
                entry.unpack_in(target)?;
            }
            Whiteout::Remove(rel) => {
                let victim = target.join(&rel);
                remove_path(&victim);
            }
            Whiteout::Opaque(rel) => {
                // Opaque dir: clear existing children in the upper dir.
                let dir = target.join(&rel);
                if dir.is_dir() {
                    for child in std::fs::read_dir(&dir)?.flatten() {
                        remove_path(&child.path());
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
}
