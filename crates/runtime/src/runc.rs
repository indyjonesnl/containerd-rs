//! Thin wrapper over the `runc` OCI runtime CLI.
//!
//! This is the daemon-side equivalent of what `containerd-shim-runc-v2` does:
//! drive `runc` against an OCI bundle. We shell out (as containerd does) rather
//! than embedding a runtime, so the container process is supervised out of the
//! daemon's address space.

use std::path::Path;
use std::process::{Command, Output};

/// Runtime binary to invoke (overridable for crun/youki, which share the CLI).
pub const DEFAULT_BIN: &str = "runc";

/// Whether a runtime binary is on `PATH`.
pub fn available(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a container to completion: `runc --root <root> run --bundle <bundle> <id>`.
///
/// `runc run` performs create + start + wait + delete, returning the captured
/// stdout/stderr and exit status. The bundle must contain `config.json` and a
/// populated `rootfs/`.
pub fn run(bin: &str, runc_root: &Path, bundle_dir: &Path, id: &str) -> std::io::Result<Output> {
    Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("run")
        .arg("--bundle")
        .arg(bundle_dir)
        .arg(id)
        .output()
}

/// Execute a command inside a running container: `runc exec <id> <cmd...>`.
/// Captures stdout/stderr/exit. Used by CRI `ExecSync` and the streaming exec.
pub fn exec(bin: &str, runc_root: &Path, id: &str, cmd: &[String]) -> std::io::Result<Output> {
    Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("exec")
        .arg(id)
        .args(cmd)
        .output()
}

/// Sample one-shot cgroup stats for a container: `runc events --stats <id>`.
/// Emits a single JSON `{"type":"stats","data":{...}}` line.
pub fn stats(bin: &str, runc_root: &Path, id: &str) -> std::io::Result<Output> {
    Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("events")
        .arg("--stats")
        .arg(id)
        .output()
}

/// Send a signal to a container: `runc kill <id> <signal>`.
pub fn kill(bin: &str, runc_root: &Path, id: &str, signal: &str) -> std::io::Result<Output> {
    Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("kill")
        .arg(id)
        .arg(signal)
        .output()
}

/// Best-effort cleanup of a (possibly leftover) container: `runc delete -f <id>`.
pub fn delete(bin: &str, runc_root: &Path, id: &str) -> std::io::Result<Output> {
    Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("delete")
        .arg("--force")
        .arg(id)
        .output()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{generate_spec, write_bundle, ContainerRequest, ImageConfig};
    use std::os::unix::fs::PermissionsExt;

    // Runs a REAL rootless container via runc. Requires runc + unprivileged user
    // namespaces (both present on this host). Self-contained: builds a rootfs
    // from the statically-linked host busybox.
    //   cargo test -p runtime -- --ignored
    #[test]
    #[ignore = "requires runc + unprivileged userns; launches a real rootless container"]
    fn runc_runs_rootless_busybox() {
        assert!(available(DEFAULT_BIN), "runc must be installed");

        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("bundle");
        let rootfs = bundle.join("rootfs");
        std::fs::create_dir_all(rootfs.join("bin")).unwrap();

        // Static busybox -> our rootfs (no external image needed).
        let bb = rootfs.join("bin/busybox");
        std::fs::copy("/usr/bin/busybox", &bb).expect("host busybox present");
        std::fs::set_permissions(&bb, std::fs::Permissions::from_mode(0o755)).unwrap();

        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let req = ContainerRequest {
            command: vec!["/bin/busybox".into()],
            args: vec!["echo".into(), "hi-from-containerd-rs".into()],
            rootless_host_ids: Some((uid, gid)),
            ..Default::default()
        };
        let spec = generate_spec(&ImageConfig::default(), &req, &rootfs).unwrap();
        write_bundle(&bundle, &spec).unwrap();

        let runc_root = dir.path().join("state");
        let out = run(DEFAULT_BIN, &runc_root, &bundle, "crs-test").expect("runc run");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains("hi-from-containerd-rs"),
            "container stdout missing marker.\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}
