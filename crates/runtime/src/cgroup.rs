//! cgroup hierarchy version detection.
//!
//! `containerd-rs` targets **cgroup v2 only** (a unified, delegated v2 hierarchy).
//! This module detects what is mounted at `/sys/fs/cgroup` so the daemon can
//! refuse to start on a legacy v1 / hybrid host with a clear error rather than
//! silently misprogramming limits (see the startup guard in `containerd-rs`).

use std::path::Path;

/// Which cgroup hierarchy is mounted at the cgroup root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    /// Unified cgroup v2 (`cgroup2` filesystem). Supported.
    V2,
    /// Legacy cgroup v1, or a hybrid v1+v2 layout (the root is `tmpfs`).
    /// Unsupported by this daemon.
    V1OrHybrid,
}

/// `CGROUP2_SUPER_MAGIC` from `<linux/magic.h>`. A pure v2 host mounts the
/// unified hierarchy as a `cgroup2` filesystem reporting this magic; v1 and
/// hybrid layouts mount a `tmpfs` root with per-controller `cgroup` mounts and
/// therefore report a different magic.
pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

/// Classify a filesystem magic number (as returned by `statfs`) as v2 or not.
/// Pure helper, separated for unit-testing without touching the host.
pub fn version_from_magic(magic: u64) -> CgroupVersion {
    if magic == CGROUP2_SUPER_MAGIC {
        CgroupVersion::V2
    } else {
        CgroupVersion::V1OrHybrid
    }
}

/// Detect the cgroup version at `mount` (normally `/sys/fs/cgroup`) via `statfs`.
pub fn detect(mount: &Path) -> std::io::Result<CgroupVersion> {
    let st = rustix::fs::statfs(mount)?;
    Ok(version_from_magic(st.f_type as u64))
}

/// Detect the cgroup version at the standard `/sys/fs/cgroup` mount point.
pub fn detect_default() -> std::io::Result<CgroupVersion> {
    detect(Path::new("/sys/fs/cgroup"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_classifies_v2() {
        assert_eq!(version_from_magic(CGROUP2_SUPER_MAGIC), CgroupVersion::V2);
    }

    #[test]
    fn other_magic_is_v1_or_hybrid() {
        // tmpfs magic (0x01021994) — a hybrid/v1 cgroup root.
        assert_eq!(version_from_magic(0x0102_1994), CgroupVersion::V1OrHybrid);
        assert_eq!(version_from_magic(0), CgroupVersion::V1OrHybrid);
    }
}
