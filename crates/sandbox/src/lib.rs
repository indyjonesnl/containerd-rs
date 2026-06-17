//! Pod sandbox model: pause-container lifecycle, network namespace creation, and
//! CNI integration.
//!
//! STATUS: scaffolding. The netns + CNI integration and the pause-container
//! sandbox controller are tasks T024–T025 in
//! `specs/001-rust-containerd/tasks.md`.

pub mod net;

/// Default pause image used to anchor a pod sandbox's namespaces.
pub const DEFAULT_PAUSE_IMAGE: &str = "registry.k8s.io/pause:3.10";
