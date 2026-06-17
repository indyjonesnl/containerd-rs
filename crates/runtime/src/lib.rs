//! Runtime-v2 shim client, OCI bundle generation, and runc task supervision.
//!
//! STATUS: scaffolding. The TTRPC `containerd.task.v3.Task` client, the shim
//! bootstrap handshake, bundle generation, and restart recovery are tasks
//! T014–T016 and T031 in `specs/001-rust-containerd/tasks.md`. The decision
//! (see research.md) is to reuse the upstream `containerd-shim-runc-v2` binary
//! and shell out to `runc`, so this crate will own the daemon-side TTRPC client
//! and bundle layout rather than reimplementing container execution.

pub mod bundle;
pub mod runc;
pub mod shim;

/// Default OCI runtime handler containerd-rs targets.
pub const DEFAULT_RUNTIME: &str = "io.containerd.runc.v2";
