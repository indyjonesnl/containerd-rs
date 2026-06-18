//! OCI identity algorithms that must match containerd / image-spec byte-for-byte
//! so that snapshot keys and content dedup interoperate.

use core_types::Digest;

/// Compute the chainID for each layer from the ordered list of diffIDs.
///
/// Per `opencontainers/image-spec/identity`:
/// * `ChainID(0) = diffID_0`
/// * `ChainID(N) = sha256( ChainID(N-1) + " " + diffID_N )`  (single ASCII space)
///
/// The committed snapshot key for layer N is `ChainID(N)`. Returns a vec the
/// same length as `diff_ids`.
pub fn chain_ids(diff_ids: &[Digest]) -> Vec<Digest> {
    let mut chain = Vec::with_capacity(diff_ids.len());
    for (i, diff) in diff_ids.iter().enumerate() {
        if i == 0 {
            chain.push(diff.clone());
        } else {
            let prev = &chain[i - 1];
            // Hash over the canonical string form: "<prev> <diff>".
            let input = format!("{prev} {diff}");
            chain.push(Digest::sha256(input.as_bytes()));
        }
    }
    chain
}

/// The final chainID for the full stack, or `None` for an empty layer list.
pub fn chain_id(diff_ids: &[Digest]) -> Option<Digest> {
    chain_ids(diff_ids).pop()
}

/// A target platform (os/architecture[/variant]) for image selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
}

impl Platform {
    /// The host's default platform (compile-time target os/arch).
    pub fn default_host() -> Self {
        let architecture = match std::env::consts::ARCH {
            // Canonicalize to OCI arch names.
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        }
        .to_string();
        Self {
            os: std::env::consts::OS.to_string(),
            architecture,
            variant: default_variant(&architecture_static()),
        }
    }

    /// Does `self` (the node platform) accept image `candidate`?
    ///
    /// Mirrors `platforms.Only(Default())`: os and architecture must match;
    /// variants must match when both specify one, with arm64/v8 canonicalized
    /// so the common arm64 ⇄ arm64+v8 case is treated as compatible.
    pub fn matches(&self, candidate: &Platform) -> bool {
        if self.os != candidate.os || self.architecture != candidate.architecture {
            return false;
        }
        match (
            canonical_variant(&self.architecture, self.variant.as_deref()),
            canonical_variant(&candidate.architecture, candidate.variant.as_deref()),
        ) {
            (Some(a), Some(b)) => a == b,
            // If either is unspecified, treat as compatible.
            _ => true,
        }
    }
}

fn architecture_static() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
    .to_string()
}

fn default_variant(arch: &str) -> Option<String> {
    match arch {
        "arm64" => Some("v8".to_string()),
        _ => None,
    }
}

/// Canonicalize a variant: arm64 with no variant is equivalent to arm64/v8.
fn canonical_variant(arch: &str, variant: Option<&str>) -> Option<String> {
    match (arch, variant) {
        ("arm64", None) => Some("v8".to_string()),
        (_, v) => v.map(|s| s.to_string()),
    }
}

/// Select the single best manifest from an index for `target`.
///
/// Mirrors `FilterPlatforms` + `LimitManifests(.., 1)`: keep entries whose
/// platform the target accepts, then return the first. Returns `None` when no
/// variant matches the node platform (the spec's "no matching arch/OS" edge).
pub fn select_manifest<'a, T>(target: &Platform, entries: &'a [(Platform, T)]) -> Option<&'a T> {
    entries
        .iter()
        .find(|(p, _)| target.matches(p))
        .map(|(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Digest {
        format!("sha256:{}", s.repeat(64 / s.len().max(1)))
            .parse()
            .unwrap()
    }

    #[test]
    fn chain_id_single_layer_is_diff_id() {
        let diff = Digest::sha256(b"layer0");
        assert_eq!(chain_ids(std::slice::from_ref(&diff)), vec![diff.clone()]);
        assert_eq!(chain_id(std::slice::from_ref(&diff)), Some(diff));
    }

    #[test]
    fn chain_id_recursion_uses_single_space() {
        let l0 = Digest::sha256(b"l0");
        let l1 = Digest::sha256(b"l1");
        let chain = chain_ids(&[l0.clone(), l1.clone()]);
        // Expected: ChainID(1) = sha256("<l0> <l1>")
        let expected = Digest::sha256(format!("{l0} {l1}").as_bytes());
        assert_eq!(chain[0], l0);
        assert_eq!(chain[1], expected);
    }

    #[test]
    fn chain_id_empty() {
        assert_eq!(chain_id(&[]), None);
        assert!(chain_ids(&[]).is_empty());
    }

    #[test]
    fn chain_ids_three_layers_recurse() {
        let l0 = Digest::sha256(b"l0");
        let l1 = Digest::sha256(b"l1");
        let l2 = Digest::sha256(b"l2");
        let chain = chain_ids(&[l0.clone(), l1.clone(), l2.clone()]);
        assert_eq!(chain.len(), 3, "one chainID per diffID");
        let c1 = Digest::sha256(format!("{l0} {l1}").as_bytes());
        let c2 = Digest::sha256(format!("{c1} {l2}").as_bytes());
        assert_eq!(chain[0], l0);
        assert_eq!(chain[1], c1);
        assert_eq!(
            chain[2], c2,
            "ChainID(n) = sha256(ChainID(n-1) + ' ' + diff[n])"
        );
        assert_eq!(chain_id(&[l0, l1, l2]), Some(c2));
    }

    #[test]
    fn platform_match_exact_and_variant() {
        let host = Platform {
            os: "linux".into(),
            architecture: "arm64".into(),
            variant: Some("v8".into()),
        };
        // arm64 without variant is compatible (canonicalized to v8).
        let cand = Platform {
            os: "linux".into(),
            architecture: "arm64".into(),
            variant: None,
        };
        assert!(host.matches(&cand));

        let amd = Platform {
            os: "linux".into(),
            architecture: "amd64".into(),
            variant: None,
        };
        assert!(!host.matches(&amd));
    }

    #[test]
    fn select_returns_none_when_no_match() {
        let host = Platform {
            os: "linux".into(),
            architecture: "amd64".into(),
            variant: None,
        };
        let entries = vec![
            (
                Platform {
                    os: "linux".into(),
                    architecture: "arm64".into(),
                    variant: Some("v8".into()),
                },
                "arm",
            ),
            (
                Platform {
                    os: "windows".into(),
                    architecture: "amd64".into(),
                    variant: None,
                },
                "win",
            ),
        ];
        assert_eq!(select_manifest(&host, &entries), None);

        let entries2 = vec![(
            Platform {
                os: "linux".into(),
                architecture: "amd64".into(),
                variant: None,
            },
            "linux-amd64",
        )];
        assert_eq!(select_manifest(&host, &entries2), Some(&"linux-amd64"));
    }

    #[test]
    fn unused_helper_compiles() {
        // touch d() so the helper is exercised
        let _ = d("ab");
        let _ = Platform::default_host();
    }
}
