//! Shared types for containerd-rs: content digests, OCI descriptors, runtime
//! namespaces, and mounts. These mirror the externally-observable contracts
//! described in `specs/001-rust-containerd/contracts/`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Errors produced when parsing or validating core types.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid digest {0:?}: expected `algo:hex`")]
    InvalidDigest(String),
    #[error("unsupported digest algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    #[error("digest hex has wrong length: expected {expected}, got {got}")]
    DigestLength { expected: usize, got: usize },
    #[error("digest mismatch: expected {expected}, got {got}")]
    DigestMismatch { expected: Digest, got: Digest },
    #[error("size mismatch: expected {expected}, got {got}")]
    SizeMismatch { expected: u64, got: u64 },
}

/// A content-addressable digest, e.g. `sha256:<64-hex>`.
///
/// Only sha256 is supported, matching what kubelet/CRI and the OCI image-spec
/// exercise. The string form is canonical and what appears on disk under
/// `blobs/sha256/<hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest {
    hex: String,
}

impl Digest {
    /// Compute the sha256 digest of `bytes`.
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self {
            hex: hex::encode(hasher.finalize()),
        }
    }

    /// The lowercase hex of the digest (no algorithm prefix).
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The algorithm component. Always `sha256` for now.
    pub fn algorithm(&self) -> &'static str {
        "sha256"
    }

    /// The on-disk relative path for this blob: `sha256/<hex>`.
    pub fn blob_path(&self) -> String {
        format!("sha256/{}", self.hex)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (algo, hex_part) = s
            .split_once(':')
            .ok_or_else(|| Error::InvalidDigest(s.to_string()))?;
        if algo != "sha256" {
            return Err(Error::UnsupportedAlgorithm(algo.to_string()));
        }
        if hex_part.len() != 64 {
            return Err(Error::DigestLength {
                expected: 64,
                got: hex_part.len(),
            });
        }
        if !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidDigest(s.to_string()));
        }
        Ok(Self {
            hex: hex_part.to_ascii_lowercase(),
        })
    }
}

/// An OCI content descriptor. Note: the containerd wire `Descriptor` carries no
/// platform field — platform selection happens against the index/config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
}

/// A runtime metadata namespace. Partitions metadata only (not Linux/security
/// namespaces). CRI uses `k8s.io`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace(pub String);

impl Namespace {
    pub const CRI: &'static str = "k8s.io";
    pub const DEFAULT: &'static str = "default";

    pub fn cri() -> Self {
        Self(Self::CRI.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self(Self::DEFAULT.to_string())
    }
}

/// A filesystem mount as produced by a snapshotter and consumed by the kernel
/// and runc (`type`, `source`, `options`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    pub mount_type: String,
    pub source: String,
    pub options: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_roundtrip() {
        let d = Digest::sha256(b"hello");
        let s = d.to_string();
        assert!(s.starts_with("sha256:"));
        let parsed: Digest = s.parse().unwrap();
        assert_eq!(d, parsed);
        assert_eq!(d.blob_path(), format!("sha256/{}", d.hex()));
    }

    #[test]
    fn known_sha256_vector() {
        // sha256("") = e3b0c442...855
        let d = Digest::sha256(b"");
        assert_eq!(
            d.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rejects_bad_digests() {
        assert!("md5:abc".parse::<Digest>().is_err());
        assert!("sha256:xyz".parse::<Digest>().is_err());
        assert!("nocolon".parse::<Digest>().is_err());
        assert!("sha256:abcd".parse::<Digest>().is_err()); // wrong length
    }

    #[test]
    fn namespace_defaults() {
        assert_eq!(Namespace::cri().as_str(), "k8s.io");
        assert_eq!(Namespace::default().as_str(), "default");
    }
}
