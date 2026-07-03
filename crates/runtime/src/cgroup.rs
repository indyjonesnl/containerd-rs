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

/// A one-shot sample of a container's cgroup-v2 resource usage, read directly
/// from the cgroup files (feature 002 US3 / T021). Feeds the CRI stats/metrics
/// RPCs and OOM detection without shelling out to `crun events`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CgroupStats {
    /// Total CPU time in nanoseconds (`cpu.stat` `usage_usec` × 1000).
    pub cpu_usage_nanos: u64,
    /// Current memory usage in bytes (`memory.current`).
    pub memory_current_bytes: u64,
    /// Anonymous memory in bytes (`memory.stat` `anon`) — the working-set basis.
    pub memory_anon_bytes: u64,
    /// Total bytes read across block devices (`io.stat` summed `rbytes`).
    pub io_rbytes: u64,
    /// Total bytes written across block devices (`io.stat` summed `wbytes`).
    pub io_wbytes: u64,
    /// Cumulative OOM-kill count (`memory.events` `oom_kill`). `> 0` ⇒ OOMKilled.
    pub oom_kill: u64,
}

/// Parse a value from a cgroup "flat-keyed" file (lines `"<key> <value>"`, e.g.
/// `cpu.stat`, `memory.stat`, `memory.events`). Returns `None` if the key is
/// absent or unparuseable. Pure — unit-tested without touching the host.
pub fn parse_flat_keyed(content: &str, key: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some(k), Some(v)) if k == key => v.parse().ok(),
            _ => None,
        }
    })
}

/// Sum the `field` column across all devices in a cgroup `io.stat` file
/// (lines `"<maj:min> rbytes=.. wbytes=.. ..."`). Pure.
pub fn sum_io_field(content: &str, field: &str) -> u64 {
    content
        .lines()
        .flat_map(|line| line.split_whitespace())
        .filter_map(|tok| tok.strip_prefix(field).and_then(|r| r.strip_prefix('=')))
        .filter_map(|v| v.parse::<u64>().ok())
        .sum()
}

/// Read a single-value cgroup file (e.g. `memory.current`) as a `u64`.
fn read_single(dir: &Path, file: &str) -> u64 {
    std::fs::read_to_string(dir.join(file))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn read_flat_keyed(dir: &Path, file: &str, key: &str) -> u64 {
    std::fs::read_to_string(dir.join(file))
        .ok()
        .and_then(|s| parse_flat_keyed(&s, key))
        .unwrap_or(0)
}

/// Sample a container's cgroup-v2 stats from its cgroup directory (normally
/// `/sys/fs/cgroup/<cgroupsPath>`). Missing files/fields read as 0 (best-effort,
/// so a partially-populated or transitioning cgroup never errors the stats path).
pub fn read_stats(cgroup_dir: &Path) -> CgroupStats {
    let io_stat = std::fs::read_to_string(cgroup_dir.join("io.stat")).unwrap_or_default();
    CgroupStats {
        cpu_usage_nanos: read_flat_keyed(cgroup_dir, "cpu.stat", "usage_usec").saturating_mul(1000),
        memory_current_bytes: read_single(cgroup_dir, "memory.current"),
        memory_anon_bytes: read_flat_keyed(cgroup_dir, "memory.stat", "anon"),
        io_rbytes: sum_io_field(&io_stat, "rbytes"),
        io_wbytes: sum_io_field(&io_stat, "wbytes"),
        oom_kill: read_flat_keyed(cgroup_dir, "memory.events", "oom_kill"),
    }
}

/// Whether the container's cgroup recorded an OOM kill (`memory.events`
/// `oom_kill > 0`). Used to set the CRI `OOMKilled` termination reason.
pub fn was_oom_killed(cgroup_dir: &Path) -> bool {
    read_flat_keyed(cgroup_dir, "memory.events", "oom_kill") > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_classifies_v2() {
        assert_eq!(version_from_magic(CGROUP2_SUPER_MAGIC), CgroupVersion::V2);
    }

    #[test]
    fn parse_flat_keyed_finds_key() {
        let cpu = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n";
        assert_eq!(parse_flat_keyed(cpu, "usage_usec"), Some(123456));
        assert_eq!(parse_flat_keyed(cpu, "system_usec"), Some(23456));
        assert_eq!(parse_flat_keyed(cpu, "missing"), None);
        let ev = "low 0\nhigh 0\nmax 2\noom 1\noom_kill 3\n";
        assert_eq!(parse_flat_keyed(ev, "oom_kill"), Some(3));
    }

    #[test]
    fn sum_io_field_sums_across_devices() {
        let io = "8:0 rbytes=1000 wbytes=2000 rios=1 wios=2\n\
                  259:0 rbytes=500 wbytes=250 rios=1 wios=1\n";
        assert_eq!(sum_io_field(io, "rbytes"), 1500);
        assert_eq!(sum_io_field(io, "wbytes"), 2250);
        assert_eq!(sum_io_field("", "rbytes"), 0);
    }

    #[test]
    fn read_stats_from_fixture_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("cpu.stat"), "usage_usec 5000\nuser_usec 3000\n").unwrap();
        std::fs::write(p.join("memory.current"), "1048576\n").unwrap();
        std::fs::write(p.join("memory.stat"), "anon 524288\nfile 100\n").unwrap();
        std::fs::write(p.join("io.stat"), "8:0 rbytes=10 wbytes=20\n").unwrap();
        std::fs::write(p.join("memory.events"), "oom 0\noom_kill 2\n").unwrap();

        let s = read_stats(p);
        assert_eq!(s.cpu_usage_nanos, 5_000_000); // usec -> nanos
        assert_eq!(s.memory_current_bytes, 1_048_576);
        assert_eq!(s.memory_anon_bytes, 524_288);
        assert_eq!(s.io_rbytes, 10);
        assert_eq!(s.io_wbytes, 20);
        assert_eq!(s.oom_kill, 2);
        assert!(was_oom_killed(p));

        // Missing files read as 0, never error.
        let empty = tempfile::tempdir().unwrap();
        let z = read_stats(empty.path());
        assert_eq!(z, CgroupStats::default());
        assert!(!was_oom_killed(empty.path()));
    }

    #[test]
    fn other_magic_is_v1_or_hybrid() {
        // tmpfs magic (0x01021994) — a hybrid/v1 cgroup root.
        assert_eq!(version_from_magic(0x0102_1994), CgroupVersion::V1OrHybrid);
        assert_eq!(version_from_magic(0), CgroupVersion::V1OrHybrid);
    }
}
