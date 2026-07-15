//! Content-addressable blob store.
//!
//! Mirrors containerd's on-disk layout (`blobs/sha256/<hex>` with an `ingest/`
//! staging area) and the critical semantic: the digest and size are verified at
//! **commit** time (not while copying). A verified blob is moved into the
//! digest-keyed path with an atomic rename; committing a digest that already
//! exists is success (content is deduplicated).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use core_types::Digest;
use sha2::{Digest as _, Sha256};

/// Per-process counter making each ingest staging file unique, so concurrent
/// writers for the same `ingest_ref` (and stale files from an interrupted/
/// crashed write) never collide.
static INGEST_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: Digest, computed: Digest },
    #[error("size mismatch: expected {expected}, wrote {wrote}")]
    SizeMismatch { expected: u64, wrote: u64 },
}

type Result<T> = std::result::Result<T, Error>;

/// A filesystem content store rooted at a directory
/// (`io.containerd.content.v1.content` in containerd's layout).
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open (creating if needed) a content store at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs/sha256"))?;
        fs::create_dir_all(root.join("ingest"))?;
        Ok(Self { root })
    }

    /// The store's root directory (`io.containerd.content.v1.content`). Used by
    /// the import path to place its extraction scratch dir on the same filesystem.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join(digest.blob_path())
    }

    /// Whether a blob with this digest is already committed.
    pub fn exists(&self, digest: &Digest) -> bool {
        self.blob_path(digest).is_file()
    }

    /// Read a committed blob's bytes.
    pub fn read(&self, digest: &Digest) -> Result<Vec<u8>> {
        Ok(fs::read(self.blob_path(digest))?)
    }

    /// Open a committed blob as a file handle, for streaming reads (so a caller
    /// can process a large blob without loading it fully into memory).
    pub fn open_blob(&self, digest: &Digest) -> Result<fs::File> {
        Ok(fs::File::open(self.blob_path(digest))?)
    }

    /// Delete a committed blob. Returns whether it existed. Idempotent.
    pub fn remove(&self, digest: &Digest) -> Result<bool> {
        let path = self.blob_path(digest);
        if path.is_file() {
            fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Total size in bytes of all committed blobs.
    pub fn total_size(&self) -> Result<u64> {
        let mut total = 0;
        let dir = self.root.join("blobs/sha256");
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total += meta.len();
                    }
                }
            }
        }
        Ok(total)
    }

    /// Open a writer that stages bytes in `ingest/<ref>` and verifies on commit.
    pub fn writer(&self, ingest_ref: &str) -> Result<Writer> {
        let staging_dir = self.root.join("ingest");
        fs::create_dir_all(&staging_dir)?;
        // Stage under a per-writer-unique name (ref hash + process id + a counter)
        // so concurrent ingests of the same ref don't clobber each other and a
        // leftover staging file from an interrupted write can't block a retry. The
        // committed blob is content-addressed, so the staging name is irrelevant
        // after commit.
        let seq = INGEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let staging = staging_dir.join(format!(
            "{}.{}.{}",
            Digest::sha256(ingest_ref.as_bytes()).hex(),
            std::process::id(),
            seq
        ));
        let file = fs::File::create(&staging)?;
        Ok(Writer {
            root: self.root.clone(),
            staging,
            file: Some(file),
            hasher: Sha256::new(),
            written: 0,
        })
    }

    /// Convenience: write a complete blob and verify it equals `expected`.
    pub fn write_blob(&self, ingest_ref: &str, bytes: &[u8], expected: &Digest) -> Result<Digest> {
        let mut w = self.writer(ingest_ref)?;
        w.write_all(bytes)?;
        w.commit(bytes.len() as u64, expected)
    }
}

/// Staged blob writer. Bytes are hashed as they are written; `commit` enforces
/// the expected digest and size before the atomic rename into the blob store.
pub struct Writer {
    root: PathBuf,
    staging: PathBuf,
    file: Option<fs::File>,
    hasher: Sha256,
    written: u64,
}

impl Writer {
    /// Bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Finalize: verify size and digest, then atomically move into the store.
    /// If the blob already exists, the staging file is discarded (dedup).
    pub fn commit(mut self, expected_size: u64, expected: &Digest) -> Result<Digest> {
        // Flush and drop the file handle before renaming.
        if let Some(mut f) = self.file.take() {
            f.flush()?;
            f.sync_all()?;
        }
        if self.written != expected_size {
            let _ = fs::remove_file(&self.staging);
            return Err(Error::SizeMismatch {
                expected: expected_size,
                wrote: self.written,
            });
        }
        let computed = Digest::from_hasher(std::mem::take(&mut self.hasher));
        if &computed != expected {
            let _ = fs::remove_file(&self.staging);
            return Err(Error::DigestMismatch {
                expected: expected.clone(),
                computed,
            });
        }
        let dest = self.root.join("blobs").join(computed.blob_path());
        if dest.is_file() {
            // Already present: dedup, discard staging.
            let _ = fs::remove_file(&self.staging);
            return Ok(computed);
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&self.staging, &dest)?;
        tracing::debug!(digest = %computed, "committed blob");
        Ok(computed)
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self
            .file
            .as_mut()
            .expect("writer used after commit")
            .write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.flush()
        } else {
            Ok(())
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // If never committed, clean up the staging file.
        if self.file.is_some() {
            let _ = fs::remove_file(&self.staging);
        }
    }
}

// Helper to build a Digest from a finished hasher without re-hashing.
trait FromHasher {
    fn from_hasher(h: Sha256) -> Digest;
}
impl FromHasher for Digest {
    fn from_hasher(h: Sha256) -> Digest {
        let hex = hex::encode(h.finalize());
        // Reconstruct via the canonical string parser to keep one source of truth.
        format!("sha256:{hex}")
            .parse()
            .expect("valid sha256 digest")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_verifies_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let data = b"layer-bytes";
        let expected = Digest::sha256(data);

        let d = store.write_blob("ref-1", data, &expected).unwrap();
        assert_eq!(d, expected);
        assert!(store.exists(&expected));
        assert_eq!(store.read(&expected).unwrap(), data);

        // Re-commit identical content: dedup, still success.
        let d2 = store.write_blob("ref-2", data, &expected).unwrap();
        assert_eq!(d2, expected);
    }

    #[test]
    fn commit_rejects_digest_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let wrong = Digest::sha256(b"something-else");
        let err = store.write_blob("ref", b"actual", &wrong).unwrap_err();
        assert!(matches!(err, Error::DigestMismatch { .. }));
        // Corrupt content must not be present.
        assert!(!store.exists(&wrong));
    }

    #[test]
    fn commit_rejects_size_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let data = b"abcdef";
        let expected = Digest::sha256(data);
        let mut w = store.writer("ref").unwrap();
        w.write_all(data).unwrap();
        let err = w.commit(999, &expected).unwrap_err();
        assert!(matches!(err, Error::SizeMismatch { .. }));
    }

    #[test]
    fn read_and_exists_of_absent_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let absent = Digest::sha256(b"never-written");
        assert!(!store.exists(&absent));
        assert!(
            store.read(&absent).is_err(),
            "reading an absent blob errors"
        );
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let data = b"to-remove";
        let d = store
            .write_blob("ref", data, &Digest::sha256(data))
            .unwrap();
        assert!(store.remove(&d).unwrap(), "first remove reports it existed");
        assert!(!store.exists(&d));
        assert!(
            !store.remove(&d).unwrap(),
            "removing an already-gone blob succeeds and reports false"
        );
    }

    #[test]
    fn empty_blob_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let empty = Digest::sha256(b"");
        let d = store.write_blob("ref", b"", &empty).unwrap();
        assert_eq!(d, empty);
        assert!(store.exists(&empty));
        assert_eq!(store.read(&empty).unwrap(), b"");
    }

    #[test]
    fn total_size_counts_committed_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.total_size().unwrap(), 0);
        store
            .write_blob("a", b"abc", &Digest::sha256(b"abc"))
            .unwrap();
        store
            .write_blob("b", b"de", &Digest::sha256(b"de"))
            .unwrap();
        assert_eq!(store.total_size().unwrap(), 5);
        // Dedup: re-committing identical content doesn't double-count.
        store
            .write_blob("c", b"abc", &Digest::sha256(b"abc"))
            .unwrap();
        assert_eq!(store.total_size().unwrap(), 5);
    }

    // T047: an interrupted write (writer dropped without commit) must leave no
    // committed blob and no staging junk, so the store stays clean + retryable.
    #[test]
    fn interrupted_write_leaves_no_blob_or_staging() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        {
            let mut w = store.writer("layer:0").unwrap();
            w.write_all(b"half-written").unwrap();
            // Dropped here without commit (simulates an interrupted pull).
        }
        assert_eq!(store.total_size().unwrap(), 0, "no blob committed");
        let staged = fs::read_dir(dir.path().join("ingest")).unwrap().count();
        assert_eq!(staged, 0, "staging file cleaned up on drop");
    }

    // T047: a fresh write after an interrupted one (same ref) commits cleanly.
    #[test]
    fn retry_after_interrupted_write_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        {
            let mut w = store.writer("layer:0").unwrap();
            w.write_all(b"partial").unwrap();
        }
        let data = b"the full layer";
        let d = store
            .write_blob("layer:0", data, &Digest::sha256(data))
            .unwrap();
        assert!(store.exists(&d));
    }

    // T046/T047: concurrent writers for the SAME ref must not clobber each other
    // (unique staging) — all commit and the content-addressed blob is present.
    #[test]
    fn concurrent_writers_same_ref_all_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let data = b"shared-layer-bytes";
        let expected = Digest::sha256(data);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = store.clone();
                let e = expected.clone();
                std::thread::spawn(move || s.write_blob("same-ref", data, &e).unwrap())
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
        assert!(store.exists(&expected));
        assert_eq!(store.read(&expected).unwrap(), data);
    }
}
