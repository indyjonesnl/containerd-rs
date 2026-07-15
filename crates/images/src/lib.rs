//! Image subsystem. The pull pipeline (resolver, registry auth, fetch, unpack)
//! is built atop the `identity` module below, which implements the two
//! byte-exact OCI algorithms a Rust reimplementation must match: chainID
//! computation and platform matching.

pub mod dockercfg;
pub mod gc;
pub mod identity;
pub mod pull;
pub mod unpack;
