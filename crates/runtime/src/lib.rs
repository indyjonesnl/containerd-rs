//! Runtime-v2 shim client, OCI bundle generation, and crun task supervision.
//!
//! STATUS: scaffolding. The TTRPC `containerd.task.v3.Task` client, the shim
//! bootstrap handshake, bundle generation, and restart recovery are tasks
//! T014–T016 and T031 in `specs/001-rust-containerd/tasks.md`. The decision
//! (see research.md) is to reuse the upstream `containerd-shim-crun-v2` binary
//! and shell out to `crun`, so this crate will own the daemon-side TTRPC client
//! and bundle layout rather than reimplementing container execution.

pub mod bundle;
pub mod cgroup;
pub mod crun;
pub mod shim;

/// Default OCI runtime handler containerd-rs targets.
pub const DEFAULT_RUNTIME: &str = "io.containerd.crun.v2";
