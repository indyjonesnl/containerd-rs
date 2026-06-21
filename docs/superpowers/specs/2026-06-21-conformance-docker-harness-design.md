# Local conformance harness in a privileged container

**Date:** 2026-06-21
**Status:** Design approved, pending implementation plan

## Context

Conformance suites (sig-node, sig-network, sig-storage) currently run only in
GitHub Actions, on a bare `ubuntu-latest` VM via `ci/kubeadm-init.sh` +
`ci/run-conformance.sh`. Running them locally is painful: the scripts need root,
and `make cluster-up` mutates the host (kubeadm reset, kubelet, host networking,
and — to test crun — replacing the host `runc` binary). CI minutes are limited,
so iterating by pushing-and-dispatching is slow and costly.

The immediate trigger: we swapped the conformance runtime from runc to crun
(commit `7b516af`) and want to validate it without burning CI minutes or
mutating the developer's host.

The developer's machine can run `docker` **without sudo** (member of the
`docker` group), the host is cgroup v2, and the existing CI scripts already use
a bare-process bring-up model (they background the daemon and kubelet directly,
not under systemd-pid1). That model runs unchanged inside a `--privileged`
container, which gives us root-in-container with no host sudo and full isolation
of the mutation.

## Goal

A reusable `make conformance-docker` target that runs any conformance focus
locally inside a privileged container, mirroring GitHub CI as closely as
possible: **same scripts, same pinned tool versions, same runtime (crun), same
bring-up env**. No host sudo, no host runc changes, no CI minutes.

## Non-goals

- Byte-identical parity with the CI VM. A privileged container is a stand-in for
  the `ubuntu-latest` VM, not a replica.
- Replacing the GitHub conformance workflows. This is a local complement.
- A `RUNTIME=runc` knob. CI uses crun; the harness does whatever CI does.

## Design

The container is only an *environment*. It runs the existing `ci/` scripts
verbatim — those remain the single source of truth that CI also uses.

### 1. `ci/install-tooling.sh` — shared install, single source of truth

Extract the inline install block from
`.github/workflows/conformance-reusable.yml` (currently ~lines 59–79: k8s
binaries, crun, crictl, CNI plugins, hydrophone) into a standalone script.
Versions come from environment variables with the current workflow values as
defaults (`K8S_VERSION`, `CRUN_VERSION`, `CRICTL_VERSION`, `CNI_PLUGINS_VERSION`).

- The workflow's install step becomes `run: bash ci/install-tooling.sh`.
- The Dockerfile invokes the same script.

This guarantees CI and the local harness install identical tooling — they can't
drift, because there is only one definition.

### 2. `ci/conformance.Dockerfile`

`FROM ubuntu:24.04`. Installs base prerequisites (curl, iproute2, iptables,
etc.) and runs `ci/install-tooling.sh` as a cached layer. It does **not** bake
the containerd-rs daemon binary — that is rebuilt frequently and is mounted at
run time instead. Tool versions are passed as build args so a version bump
busts the cache deterministically.

(Named `conformance.Dockerfile`, not `Dockerfile.conformance`, so the IDE
recognises it as a Dockerfile by suffix.)

### 3. `ci/conformance-docker.sh` + `make conformance-docker`

A wrapper script, invoked by the make target, that:

1. Builds the image (cached after first run).
2. `docker run --privileged` with the mounts the bring-up needs:
   - cgroup v2 (`/sys/fs/cgroup`) and `/lib/modules` (ro) for kubelet/netfilter,
   - the repo (ro) and the freshly built daemon binary,
   - a host `conformance-results/` dir (rw) for output.
3. Inside the container, runs the **same** `ci/kubeadm-init.sh` then
   `ci/run-conformance.sh`, with the **same env CI passes**: `CGROUPS_PER_QOS=true`,
   `DAEMON_BIN`, `CONFIG=ci/config.toml`, `K8S_VERSION`, and `FOCUS`.
4. Removes the container on exit (`--rm`); results persist on the host via the
   mount.

The daemon binary path respects the repo's `CARGO_TARGET_DIR`
(`/home/jones/.cache/rusternetes-target/release/containerd-rs`); the make target
resolves it rather than assuming `target/release`.

### 4. Usage

```
make conformance-docker FOCUS='\[sig-node\].*\[Conformance\]'
```

Default focus = full conformance (matches `run-conformance.sh` semantics: empty
FOCUS → `--conformance`). Results in `conformance-results/{e2e.log,junit_01.xml}`.

## Data flow

```
make conformance-docker FOCUS=...
  └─ ci/conformance-docker.sh
       ├─ docker build -f ci/conformance.Dockerfile     (runs install-tooling.sh)
       └─ docker run --privileged  (mounts: repo ro, daemon, cgroup, results rw)
            ├─ ci/kubeadm-init.sh   (daemon + kubelet bring-up, crun via PATH)
            └─ ci/run-conformance.sh (hydrophone --focus FOCUS → results/)
```

## Error handling

- Preconditions checked up front: `docker` reachable, daemon binary built
  (point the user at `make release` if missing).
- `set -euo pipefail` in the wrapper; container started with `--rm` so a failed
  run leaves no dangling container.
- On bring-up failure, dump `/var/log/crs.log` and `kubectl get pods -A` from the
  container before teardown so failures are diagnosable.

## Testing / verification

1. `make conformance-docker FOCUS='Simple pod should contain last line of the log'`
   — fast smoke; confirms image build, privileged bring-up, and crun all work.
2. Then the in-flight goal: `FOCUS='\[sig-node\].*\[Conformance\]'` to validate
   crun against the full sig-node slice, watching the `crun events --stats` /
   `crun update` paths (ContainerStats, in-place resize).
3. Confirm `ci/install-tooling.sh` refactor is inert for CI: the next workflow
   run installs the same versions and stays green.

## Risks / callouts

- Editing `conformance-reusable.yml` to call `install-tooling.sh` is a pure
  extraction, but the next CI run exercises it — verify parity.
- crun compatibility on `events --stats` / `update` is the substantive unknown
  this harness exists to derisk.
- `--privileged` + host `/lib/modules` mount assumes the host kernel has the
  needed modules (overlay, br_netfilter, nf_* ); true on this dev machine.
- `--cgroupns host` + rw `/sys/fs/cgroup` means cgroups created during a run
  are not guaranteed to be fully torn down on container exit; residual cgroup
  directories may remain under the host hierarchy and require manual cleanup
  (e.g. `systemd-cgls` to inspect, `rmdir` on empty leaves).
