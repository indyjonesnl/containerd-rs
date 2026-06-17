//! CRI v1 gRPC server (RuntimeService + ImageService) and the exec/attach/
//! port-forward streaming HTTP server.
//!
//! The generated proto bindings live in [`v1`]. [`server`] implements the
//! service traits — `Version` and `Status` are real; the remaining RPCs return
//! `unimplemented` until their tasks (T024–T038) land.

/// Generated CRI v1 proto types and service traits (`package runtime.v1`).
pub mod v1 {
    // Generated code: silence lints we don't control (proto doc-comment style, etc.).
    #![allow(clippy::all, clippy::pedantic, clippy::doc_lazy_continuation)]
    tonic::include_proto!("runtime.v1");
}

pub mod server;
pub mod streaming;

/// Crate version string, surfaced by the `Version` RPC.
pub fn runtime_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
