# Design — containerd-rs v0.1.1: k0s-worker CRI gaps

**Date:** 2026-06-21
**Status:** Approved (design); implementation pending
**Branch:** `fix/k0s-worker-cri-gaps` (worktree off `origin/main`)

## Goal

Make containerd-rs able to host a **full k0s worker node** — where the kubelet
runs with per-QoS cgroups enabled and CNI is installed *asynchronously* (by a
kube-router DaemonSet) after the daemon is already serving. Four gaps currently
break this; this work fixes them and ships **v0.1.1**, unblocking the mikronetes
worker1 canary (containerd-rs + crun under a k0s worker at 512 MB).

## Background

Running containerd-rs v0.1.0 as the CRI under a k0s worker produced a cascade:
CNI setup failed on the first sandbox (before kube-router installed the conf) and
containerd-rs silently fell back to host networking for every pod; the kubelet
rejected `runAsNonRoot` system pods because the image User was never reported;
the kubelet could not read pod-level cgroup limit files; and `UpdateRuntimeConfig`
returned Unimplemented. The churn drove the worker over its 512 MB cap (OOM, exit
137).

**Critically, containerd-rs's own CI masks two of these gaps:** the conformance
harness pre-installs the CNI conflist *before* the daemon starts (so the
first-sandbox CNI race never fires) and defaults `CGROUPS_PER_QOS=false` (so the
kubelet never reads pod-level cgroup files). Both only surface under a real k0s
worker. The mikronetes canary smoke test is therefore the true integration
regression test for gaps 1 and 3.

## Gaps and fixes

### Gap 1 — CNI hostnet fallback (keystone)
**Current:** `crates/cri/src/server.rs:571-575` — when CNI `setup()` fails for a
non-hostNetwork pod, the `Err(e)` arm logs a warning and rewrites the sandbox to
`netns_path = "host"`, records it Ready, and returns success. The error origin is
`load_conflist()` reading a missing `/etc/cni/net.d` (`Io(ENOENT)` →
"No such file or directory (os error 2)") at `crates/sandbox/src/cni.rs:79-94`.

**Fix:** for a pod that did **not** request hostNetwork, a CNI failure must
**fail `RunPodSandbox`** (best-effort `teardown` first, then return
`Status::internal/unavailable` with a clear message). The kubelet then retries the
sandbox; once kube-router installs the conf + binaries, the retry succeeds and the
pod gets real networking. The explicit-hostNetwork branch
(`server.rs:558-559`) is unchanged.

### Gap 2 — image User not surfaced (`runAsNonRoot`)
**Current:** `record_to_image` (`crates/cri/src/server.rs:122-133`) hardcodes
`uid: None, username: ""`. `ImageRecord` (`crates/metadata/src/records.rs:152`)
has no User field, and the pull path (`crates/images/src/pull.rs:108-116`) drops
`config.User`. The kubelet, seeing empty uid/username, treats every image as root
and rejects `runAsNonRoot` pods.

**Fix:**
1. Add `user: String` (with `#[serde(default)]`) to `ImageRecord`.
2. Populate it at pull time from the OCI image config `User` (reuse the existing
   `OciImageConfig`/`OciConfigInner` parser at `server.rs:368-387`, or extend
   `ImageConfigJson`).
3. In `record_to_image`, map the stored user to CRI fields: numeric (`"65532"` or
   `"65532:65532"`) → `uid: Some(Int64Value{..})`; non-numeric (`"nonroot"`) →
   `username`. **Never collapse a username to UID 0** (the `parse_user` helper at
   `bundle.rs:249` does that for the runtime path — do not reuse it for the CRI
   surface).

### Gap 3 — pod-level cgroup not created
**Current:** `run_pod_sandbox` (`server.rs:512-645`) stores/logs `cgroup_parent`
but never creates any cgroup; only container *leaves* get a cgroupsPath
(`cgroups_path` at `server.rs:1658`). The kubelet (cgroupfs driver, QoS cgroups
on) reads `memory.max`/`cpu.max` at the **pod-level** cgroup
`/sys/fs/cgroup/kubepods/<qos>/pod<uid>/`, which nothing creates.

**Fix (minimal-correct):** in `run_pod_sandbox`, when `cgroup_parent` is non-empty
and the driver is cgroupfs, create the pod-level cgroup directory
(`/sys/fs/cgroup` + `cgroup_parent`) and enable the required controllers in the
parent's `cgroup.subtree_control` so the cgroup-v2 limit files
(`memory.max`/`cpu.max`, default `max`) exist for the kubelet to read. Respect the
cgroup-v2 "no internal processes" rule — the pod cgroup is an intermediate node;
containers remain in leaf children. **Pod-level limit *enforcement* is out of
scope** — creating the cgroup so reads succeed is sufficient.

### Gap 4 — `UpdateRuntimeConfig` unimplemented
**Current:** listed in the `unary_unimpl!` block (`server.rs:1399`), returns
`Status::unimplemented`.

**Fix:** remove it from the macro list and add a real handler that accepts
`req.runtime_config.network_config.pod_cidr`, optionally stashes it on `Context`
for later CNI use, logs it, and returns `Ok(UpdateRuntimeConfigResponse{})`.

## Testing

Per-fix, TDD against existing patterns (run with `make test` / `cargo test -p <crate>`):
- **Gap 1:** new `crates/cri` test — `RunPodSandbox` for a non-hostNetwork pod
  returns an error (not a host-networked Ready sandbox) when the CNI conf dir is
  absent. (Existing CNI unit tests live in `crates/sandbox/src/cni.rs:323`.)
- **Gap 2:** extend `crates/cri/tests/contract_image_service.rs` — after pulling an
  image whose config sets `User`, `ImageStatus` surfaces the matching
  `uid`/`username`. Cover numeric and `nonroot`-style users.
- **Gap 3:** unit-test the pod-cgroup path helper + creation (mirror the
  `bundle.rs` cgroup tests); assert the pod cgroup dir + controllers are created
  for a cgroupfs sandbox.
- **Gap 4:** assert `UpdateRuntimeConfig` returns `Ok` (the existing
  "still-unimplemented" assertion uses `pod_sandbox_stats`, so it won't break).

**Regression guard for the CI-masked gaps:** enable `CGROUPS_PER_QOS=true` in the
conformance harness path (now available on `main`) so gap 3 is exercised in CI.
Gap 1's regression is covered by the new `crates/cri` unit test (CI cannot easily
reproduce the async-CNI race).

**Cross-repo integration proof (the real gate):** build the v0.1.1 binary, cut the
release, re-point the mikronetes worker1 canary at it, and run
`scripts/smoke-test.sh` green at 512 MB — both workers Ready, the hello pod
served from worker1 on containerd-rs+crun, no OOM. This resumes Task 7 of the
mikronetes canary plan.

## Release

Merge `fix/k0s-worker-cri-gaps` to `main`; bump the workspace version to `0.1.1`;
tag `v0.1.1` (the `release.yml` workflow publishes the musl tarballs + GHCR image).
mikronetes then pins `CRS_VERSION=v0.1.1`.

## Out of scope

- Pod-level cgroup limit *enforcement* (only creation, so reads succeed).
- Other `GAPS.md` items (runtime-v2 shim, streaming stats, parallel layer fetch).
- Swapping worker2 / both workers to containerd-rs.

## Success criteria

All four fixes merged with passing unit/contract tests; `CGROUPS_PER_QOS=true`
exercised in CI; v0.1.1 released; and the mikronetes worker1 canary smoke test
passes at 512 MB with worker1 on containerd-rs+crun (worker2 stock k0s), no OOM.
