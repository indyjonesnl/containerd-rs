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

/// Run a TTY container and return the PTY master fd. A `terminal: true` container
/// cannot share runc's foreground stdio, so we bind a console socket, launch
/// `runc run --detach --console-socket`, and receive the master end of the pty
/// that runc passes back over the socket (SCM_RIGHTS). The caller pumps the
/// master (container stdout/stdin) and reaps the container on EOF.
pub fn run_tty(
    bin: &str,
    runc_root: &Path,
    bundle_dir: &Path,
    id: &str,
    console_sock: &Path,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::unix::net::UnixListener;
    let _ = std::fs::remove_file(console_sock);
    let listener = UnixListener::bind(console_sock)?;
    // Detached, so this returns once the container is created+started; runc
    // connects to the console socket during setup to hand over the pty master.
    let mut child = Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("run")
        .arg("--detach")
        .arg("--console-socket")
        .arg(console_sock)
        .arg("--bundle")
        .arg(bundle_dir)
        .arg(id)
        .spawn()?;
    let (conn, _) = listener.accept()?;
    let master = recv_console_fd(&conn);
    let status = child.wait()?;
    let master = master?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "runc run --detach exited with {status}"
        )));
    }
    Ok(master)
}

/// Receive a single file descriptor sent over a unix socket via `SCM_RIGHTS`
/// (runc's console-socket protocol passes the pty master this way).
fn recv_console_fd(conn: &std::os::unix::net::UnixStream) -> std::io::Result<std::os::fd::OwnedFd> {
    use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
    use std::io::IoSliceMut;
    use std::mem::MaybeUninit;
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut data = [0u8; 64];
    let mut iov = [IoSliceMut::new(&mut data)];
    recvmsg(conn, &mut iov, &mut control, RecvFlags::empty())?;
    for msg in control.drain() {
        if let RecvAncillaryMessage::ScmRights(fds) = msg {
            if let Some(fd) = fds.into_iter().next() {
                return Ok(fd);
            }
        }
    }
    Err(std::io::Error::other("console socket sent no fd"))
}

/// Query container state: `runc state <id>`. Exit status is success once the
/// container exists in the runc state dir. Used to close the race between our
/// async `runc run` and an immediately-following `exec` (e.g. a postStart hook).
pub fn state(bin: &str, runc_root: &Path, id: &str) -> std::io::Result<Output> {
    Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("state")
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

/// A live `runc exec` with piped stdio, for interactive streaming exec (the SPDY
/// `remotecommand` path). `stderr` is `None` for a TTY exec (runc merges it into
/// stdout). Caller pumps the handles to the client's streams and awaits `child`.
pub struct ExecHandle {
    pub child: tokio::process::Child,
    pub stdin: tokio::process::ChildStdin,
    pub stdout: tokio::process::ChildStdout,
    pub stderr: Option<tokio::process::ChildStderr>,
}

/// Spawn `runc --root <root> exec [-t] <id> <cmd...>` with piped stdin/stdout
/// (and stderr when not a TTY) for bidirectional streaming. Unlike [`exec`],
/// this does not block — the caller drives the streams and waits on the child.
pub fn exec_streaming(
    bin: &str,
    runc_root: &Path,
    id: &str,
    cmd: &[String],
    tty: bool,
) -> std::io::Result<ExecHandle> {
    use std::process::Stdio;
    let mut command = tokio::process::Command::new(bin);
    command.arg("--root").arg(runc_root).arg("exec");
    if tty {
        command.arg("-t");
    }
    command
        .arg(id)
        .args(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if tty { Stdio::null() } else { Stdio::piped() });
    let mut child = command.spawn()?;
    let stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take();
    Ok(ExecHandle {
        child,
        stdin,
        stdout,
        stderr,
    })
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

/// Build the argument list for `runc kill`. Separated for unit-testability.
pub fn kill_args(runc_root: &Path, id: &str, signal: &str) -> Vec<String> {
    vec![
        "--root".into(),
        runc_root.to_string_lossy().into_owned(),
        "kill".into(),
        id.into(),
        signal.into(),
    ]
}

/// Build the argument list for `runc delete --force`. Separated for unit-testability.
pub fn delete_force_args(runc_root: &Path, id: &str) -> Vec<String> {
    vec![
        "--root".into(),
        runc_root.to_string_lossy().into_owned(),
        "delete".into(),
        "--force".into(),
        id.into(),
    ]
}

/// Send a signal to a container: `runc kill <id> <signal>`.
pub fn kill(bin: &str, runc_root: &Path, id: &str, signal: &str) -> std::io::Result<Output> {
    Command::new(bin)
        .args(kill_args(runc_root, id, signal))
        .output()
}

/// Best-effort cleanup of a (possibly leftover) container: `runc delete --force <id>`.
pub fn delete(bin: &str, runc_root: &Path, id: &str) -> std::io::Result<Output> {
    Command::new(bin)
        .args(delete_force_args(runc_root, id))
        .output()
}

/// Live-update a running container's cgroup limits: `runc update <flags> <id>`.
/// runc applies the new limits to the existing cgroup in place (cgroup v2:
/// `memory.max`, `cpu.max`, `cpu.weight`), which is how CRI `UpdateContainerResources`
/// (in-place pod resize) takes effect without a restart.
pub fn update(
    bin: &str,
    runc_root: &Path,
    id: &str,
    res: &crate::bundle::Resources,
) -> std::io::Result<Output> {
    Command::new(bin)
        .arg("--root")
        .arg(runc_root)
        .arg("update")
        .args(update_args(res))
        .arg(id)
        .output()
}

/// Build the `runc update` flags from CRI resources. Only set fields are passed
/// so unspecified limits keep their current value.
fn update_args(res: &crate::bundle::Resources) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(m) = res.memory_limit {
        args.push("--memory".into());
        args.push(m.to_string());
    }
    if let Some(q) = res.cpu_quota {
        args.push("--cpu-quota".into());
        args.push(q.to_string());
    }
    if let Some(p) = res.cpu_period {
        args.push("--cpu-period".into());
        args.push(p.to_string());
    }
    if let Some(s) = res.cpu_shares {
        args.push("--cpu-share".into());
        args.push(s.to_string());
    }
    if let Some(c) = res.cpuset_cpus.as_deref().filter(|s| !s.is_empty()) {
        args.push("--cpuset-cpus".into());
        args.push(c.to_string());
    }
    if let Some(m) = res.cpuset_mems.as_deref().filter(|s| !s.is_empty()) {
        args.push("--cpuset-mems".into());
        args.push(m.to_string());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{generate_spec, write_bundle, ContainerRequest, ImageConfig, Resources};
    use std::os::unix::fs::PermissionsExt;

    // kill_args builds the correct CLI argv for SIGTERM and SIGKILL escalation.
    // This ensures stop_container sends the right signal to runc on both the
    // graceful path (SIGTERM) and the forced-reap path (SIGKILL).
    #[test]
    fn kill_args_passes_signal_through() {
        let root = std::path::Path::new("/var/run/containerd-rs/runc");
        let sigterm_args = kill_args(root, "ctr-abc", "SIGTERM");
        assert_eq!(
            sigterm_args,
            vec![
                "--root",
                "/var/run/containerd-rs/runc",
                "kill",
                "ctr-abc",
                "SIGTERM"
            ],
        );
        let sigkill_args = kill_args(root, "ctr-abc", "KILL");
        assert_eq!(
            sigkill_args,
            vec![
                "--root",
                "/var/run/containerd-rs/runc",
                "kill",
                "ctr-abc",
                "KILL"
            ],
            "SIGKILL escalation must use signal name KILL (not SIGKILL) for runc"
        );
    }

    // delete_force_args builds `runc delete --force <id>` correctly.
    // stop_container must force-delete after kill so process trees are reaped.
    #[test]
    fn delete_force_args_includes_force_flag() {
        let root = std::path::Path::new("/var/run/containerd-rs/runc");
        let args = delete_force_args(root, "ctr-xyz");
        assert_eq!(
            args,
            vec![
                "--root",
                "/var/run/containerd-rs/runc",
                "delete",
                "--force",
                "ctr-xyz",
            ]
        );
    }

    // Regression for in-place resize (UpdateContainerResources): the requested
    // CPU/memory map to the right `runc update` flags; unset fields are omitted.
    #[test]
    fn update_args_maps_set_fields_only() {
        let args = update_args(&Resources {
            cpu_quota: Some(2000),
            cpu_period: Some(100_000),
            cpu_shares: Some(204),
            memory_limit: Some(33_554_432),
            ..Default::default()
        });
        assert_eq!(
            args,
            vec![
                "--memory",
                "33554432",
                "--cpu-quota",
                "2000",
                "--cpu-period",
                "100000",
                "--cpu-share",
                "204",
            ]
        );
        // Nothing requested -> no flags (runc keeps current limits).
        assert!(update_args(&Resources::default()).is_empty());
    }

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
