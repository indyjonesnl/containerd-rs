//! Shared PID/IPC namespace holder for a pod sandbox.
//!
//! Kubernetes' `shareProcessNamespace` (CRI `NamespaceOption.pid == POD`) makes
//! every container in a pod share one PID namespace, so a container sees the
//! other containers' processes and is NOT PID 1. Upstream containerd anchors
//! this on the pod's **pause container** (which is PID 1 and owns the pod's
//! namespaces). containerd-rs runs no pause container, so instead we spawn a
//! tiny **holder**: a process that is PID 1 in a fresh PID (+IPC) namespace and
//! stays alive reaping orphans for the sandbox's lifetime. Workload containers
//! then join `/proc/<holder>/ns/pid` (and `.../ns/ipc`).
//!
//! Unlike a network namespace, a PID namespace cannot be kept alive by a
//! bind-mount alone — once its PID 1 exits the namespace becomes unusable
//! (`ENOMEM` on new processes). Hence a long-lived PID-1 holder, not an anchor.
//!
//! The holder is a re-exec of the daemon binary as `__pid-holder <pidfile>`
//! (see `run_holder`), which avoids any pause image/rootfs dependency.

use std::path::{Path, PathBuf};

/// A running PID/IPC namespace holder for a sandbox.
#[derive(Debug, Clone)]
pub struct Holder {
    /// Host-visible pid of the reaper (PID 1 inside the new namespace).
    pub pid: i32,
    /// `/proc/<pid>/ns/pid` — the namespace a container joins for pod PID sharing.
    pub pid_ns_path: String,
    /// `/proc/<pid>/ns/ipc` — likewise for pod IPC sharing.
    pub ipc_ns_path: String,
}

#[cfg(target_os = "linux")]
mod ffi {
    extern "C" {
        pub fn fork() -> i32;
        pub fn wait(status: *mut i32) -> i32;
    }
}

/// Spawn a namespace holder for sandbox `id`, returning once its PID 1 is live.
///
/// Re-execs the current daemon binary as `__pid-holder <pidfile>`; that helper
/// unshares a new PID+IPC namespace, forks the reaper (PID 1), writes the
/// reaper's host pid to `<pidfile>`, and exits — so this call returns as soon as
/// the reaper is running and its namespaces are referenceable.
#[cfg(target_os = "linux")]
pub fn spawn_holder(run_dir: &Path, id: &str) -> std::io::Result<Holder> {
    let pidfile = run_dir.join(format!("pidns-{id}.pid"));
    let _ = std::fs::remove_file(&pidfile);
    let exe = std::env::current_exe()?;
    let status = std::process::Command::new(exe)
        .arg("__pid-holder")
        .arg(&pidfile)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "pid-holder helper exited with {status}"
        )));
    }
    let pid: i32 = std::fs::read_to_string(&pidfile)?
        .trim()
        .parse()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad holder pid: {e}"),
            )
        })?;
    Ok(Holder {
        pid,
        pid_ns_path: format!("/proc/{pid}/ns/pid"),
        ipc_ns_path: format!("/proc/{pid}/ns/ipc"),
    })
}

/// Kill a sandbox's namespace holder (best-effort); the namespace goes away once
/// its PID 1 exits.
#[cfg(target_os = "linux")]
pub fn kill_holder(pid: i32) {
    if let Some(p) = rustix::process::Pid::from_raw(pid) {
        let _ = rustix::process::kill_process(p, rustix::process::Signal::KILL);
    }
}

/// The `__pid-holder <pidfile>` subprocess body. MUST be called from a freshly
/// exec'd, single-threaded process (before any tokio runtime or thread spawns),
/// because it `fork`s.
///
/// Unshares a new PID+IPC namespace, forks the reaper (PID 1 of that namespace),
/// records the reaper's host pid to `pidfile`, and returns (parent path). The
/// reaper never returns — it reaps orphaned children forever so the namespace
/// stays usable, and reparents to init when this parent exits.
#[cfg(target_os = "linux")]
pub fn run_holder(pidfile: &Path) -> std::io::Result<()> {
    use rustix::thread::{unshare_unsafe, UnshareFlags};
    // Our children (the reaper) will be in a fresh PID + IPC namespace. Safety:
    // NEWPID/NEWIPC only affect this process's future children; nothing shared
    // is mutated.
    unsafe { unshare_unsafe(UnshareFlags::NEWPID | UnshareFlags::NEWIPC) }
        .map_err(std::io::Error::from)?;
    // Safety: single-threaded fresh process; the child only reaps/sleeps and
    // never touches the Rust heap in an unsafe way.
    let pid = unsafe { ffi::fork() };
    match pid {
        -1 => Err(std::io::Error::last_os_error()),
        0 => {
            // Reaper: PID 1 of the new namespace. Reap orphaned children forever
            // (a PID namespace whose PID 1 stops reaping leaks zombies); sleep
            // when there is nothing to reap.
            loop {
                let mut status: i32 = 0;
                let r = unsafe { ffi::wait(&mut status as *mut i32) };
                if r < 0 {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
        child => {
            // Parent: publish the reaper's host pid and exit; the reaper
            // reparents to init and keeps the namespace alive on its own.
            std::fs::write(pidfile, child.to_string())?;
            Ok(())
        }
    }
}

/// Non-Linux stub: no namespace sharing.
#[cfg(not(target_os = "linux"))]
pub fn spawn_holder(_run_dir: &Path, _id: &str) -> std::io::Result<Holder> {
    Err(std::io::Error::other("pid namespace holder is Linux-only"))
}

/// Path to a sandbox's holder pidfile (for cleanup bookkeeping).
pub fn pidfile_path(run_dir: &Path, id: &str) -> PathBuf {
    run_dir.join(format!("pidns-{id}.pid"))
}
