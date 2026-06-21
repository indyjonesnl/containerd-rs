# Local conformance docker harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A reusable `make conformance-docker` target that runs the existing `ci/` conformance scripts inside a `--privileged` container, mirroring GitHub CI (same scripts, pinned tool versions, crun) with no host sudo, no host runc changes, and no CI minutes.

**Architecture:** Factor the workflow's inline tooling install into a shared `ci/install-tooling.sh` (single source of truth used by both CI and the Dockerfile). Build an `ubuntu:24.04` image via `ci/conformance.Dockerfile` that runs that script. A wrapper `ci/conformance-docker.sh` (driven by the make target) runs the image `--privileged`, mounting the repo, the freshly built daemon binary, cgroup2, and a results dir, then runs the unchanged `ci/kubeadm-init.sh` + `ci/run-conformance.sh` inside.

**Tech Stack:** bash, Docker (rootless via `docker` group), GNU make, Ubuntu 24.04 base image, existing Kubernetes conformance toolchain (kubeadm/kubelet/kubectl, crictl, CNI plugins, hydrophone), crun 1.28.

## Global Constraints

- Runtime is **crun 1.28** — no `RUNTIME=runc` knob. The harness does whatever CI does.
- Tool versions live in **one place** (`ci/install-tooling.sh`), consumed by both the workflow and the Dockerfile. CI and local must not drift.
- The `ci/` scripts (`kubeadm-init.sh`, `run-conformance.sh`) are the single source of truth and are run **unchanged** — the container is only an environment.
- `CGROUPS_PER_QOS` defaults **true** in the harness, matching CI. (Post-implementation update: the original plan defaulted this false believing nested containers can't create `/kubepods`. That was a container-launch gap, not a hard limit — CI itself runs in a container. The shipped wrapper launches `--cgroupns=private` with no host `/sys/fs/cgroup` mount, moves its procs into an `init.scope` leaf, and enables root `subtree_control`, so the kubelet creates `/kubepods` nested. The `false`-default code in Task 3 below is superseded by this.)
- Daemon binary path must respect `CARGO_TARGET_DIR` (this repo builds to `/home/jones/.cache/rusternetes-target/release/containerd-rs`, not `target/release`).
- Pinned versions (workflow defaults, copied verbatim): `K8S_VERSION=v1.35.6`, `CRUN_VERSION=1.28`, `CRICTL_VERSION=v1.35.0`, `CNI_PLUGINS_VERSION=v1.5.1`, flannel CNI plugin `v1.5.1-flannel2`.

---

## File structure

- `ci/install-tooling.sh` (new) — downloads k8s bins, crun (+runc symlink), crictl, CNI plugins, hydrophone into `/usr/local/bin` + `/opt/cni/bin`.
- `.github/workflows/conformance-reusable.yml` (modify) — replace the inline install block with `bash ci/install-tooling.sh`.
- `ci/conformance.Dockerfile` (new) — `ubuntu:24.04` + prereqs + `install-tooling.sh`.
- `ci/conformance-docker.sh` (new) — build image, run privileged, run `kubeadm-init.sh` + `run-conformance.sh` inside, recover results.
- `Makefile` (modify) — add `conformance-docker` target + `.PHONY` entry.

---

## Task 1: Shared tooling install script + workflow refactor

**Files:**
- Create: `ci/install-tooling.sh`
- Modify: `.github/workflows/conformance-reusable.yml` (the "Install Kubernetes, crun, crictl, CNI plugins, hydrophone" step, ~lines 59–79)

**Interfaces:**
- Produces: an executable `ci/install-tooling.sh` that, run as root, installs the full conformance toolchain. Reads env vars `K8S_VERSION`, `CRUN_VERSION`, `CRICTL_VERSION`, `CNI_PLUGINS_VERSION` (each defaulted). Consumed by the workflow (Task 1) and the Dockerfile (Task 2).

- [ ] **Step 1: Write `ci/install-tooling.sh`**

This is a verbatim extraction of the current workflow install block (so CI behaviour is unchanged), with versions read from env. The crun + runc-symlink lines and the `go install` of hydrophone are exactly what the workflow does today.

```bash
#!/usr/bin/env bash
# Install the conformance toolchain into /usr/local/bin + /opt/cni/bin.
# Single source of truth shared by the GitHub conformance workflow
# (.github/workflows/conformance-reusable.yml) and the local docker harness
# (ci/conformance.Dockerfile) so the two never drift. Run as root.
# Versions come from env with the workflow defaults.
set -euxo pipefail

K8S_VERSION="${K8S_VERSION:-v1.35.6}"
CRUN_VERSION="${CRUN_VERSION:-1.28}"
CRICTL_VERSION="${CRICTL_VERSION:-v1.35.0}"
CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.5.1}"

cd /usr/local/bin
for b in kubeadm kubelet kubectl; do
  curl -fsSLo "$b" "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/$b"
  chmod +x "$b"
done
curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz" \
  | tar -xz -C /usr/local/bin
# crun is a drop-in OCI runtime (CLI-compatible with runc) but faster and
# lighter. The daemon execs "runc" from PATH, so install crun under both names.
curl -fsSLo /usr/local/bin/crun \
  "https://github.com/containers/crun/releases/download/${CRUN_VERSION}/crun-${CRUN_VERSION}-linux-amd64"
chmod +x /usr/local/bin/crun
ln -sf /usr/local/bin/crun /usr/local/bin/runc
mkdir -p /opt/cni/bin
curl -fsSL "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz" \
  | tar -xz -C /opt/cni/bin
curl -fsSL "https://github.com/flannel-io/cni-plugin/releases/download/v1.5.1-flannel2/cni-plugin-flannel-linux-amd64-v1.5.1-flannel2.tgz" \
  | tar -xz -C /opt/cni/bin
test -f /opt/cni/bin/flannel || cp /opt/cni/bin/flannel-amd64 /opt/cni/bin/flannel || true
go install sigs.k8s.io/hydrophone@latest
cp "$(go env GOPATH)/bin/hydrophone" /usr/local/bin/hydrophone
```

- [ ] **Step 2: Make it executable and syntax-check**

Run:
```bash
chmod +x ci/install-tooling.sh
bash -n ci/install-tooling.sh && echo "SYNTAX OK"
```
Expected: `SYNTAX OK`. (Full execution is exercised by the image build in Task 2 — it needs root + network, so it is not run directly on the host here.)

- [ ] **Step 3: Refactor the workflow to call the script**

In `.github/workflows/conformance-reusable.yml`, replace the body of the "Install Kubernetes, crun, crictl, CNI plugins, hydrophone" step (the `cd /usr/local/bin … cp … hydrophone` block, ~lines 60–79) with:

```yaml
      - name: Install Kubernetes, crun, crictl, CNI plugins, hydrophone
        run: sudo --preserve-env=K8S_VERSION,CRUN_VERSION,CRICTL_VERSION,CNI_PLUGINS_VERSION bash ci/install-tooling.sh
```

The `env:` block at the top of the file already exports `K8S_VERSION`, `CRUN_VERSION`, `CRICTL_VERSION`, `CNI_PLUGINS_VERSION`, so the defaults inside the script are overridden by the workflow's pinned values. (`go` is preinstalled on `ubuntu-latest` runners, so `go install hydrophone` keeps working; `sudo` needs `--preserve-env` to pass the versions and a login shell already has `go` on PATH for root via the runner image — if root lacks `go`, drop `sudo` here and let the script's `go install` run as the runner user, then `sudo cp`. Verify in Step 5.)

- [ ] **Step 4: Lint the changed YAML**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/conformance-reusable.yml')); print('YAML OK')"
```
Expected: `YAML OK`

- [ ] **Step 5: Commit**

```bash
git add ci/install-tooling.sh .github/workflows/conformance-reusable.yml
git commit -m "ci: factor conformance tooling install into ci/install-tooling.sh

Single source of truth shared by the workflow and the upcoming local
docker harness, so CI and local installs cannot drift."
```

> Note: the workflow change is validated for real only by a CI run. Defer that to the end (it is not gated on CI minutes here — the local harness in Tasks 2–3 exercises the same script). Flag in the final summary that the next conformance CI run confirms parity.

---

## Task 2: Conformance image

**Files:**
- Create: `ci/conformance.Dockerfile`

**Interfaces:**
- Consumes: `ci/install-tooling.sh` (Task 1) — copied in and executed at build time.
- Produces: a local image tag `containerd-rs-conformance:latest` with the full toolchain on PATH. Consumed by Task 3.

- [ ] **Step 1: Write `ci/conformance.Dockerfile`**

Named with the `.Dockerfile` suffix so the IDE recognises it. Installs the prereqs `kubeadm-init.sh` expects on a minimal host (it apt-installs some itself, but bake the heavy ones for speed) plus `golang-go`/`git` for the hydrophone `go install`. Runs `install-tooling.sh` as a cached layer keyed on the version build args. Does **not** bake the daemon binary.

```dockerfile
# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ARG K8S_VERSION=v1.35.6
ARG CRUN_VERSION=1.28
ARG CRICTL_VERSION=v1.35.0
ARG CNI_PLUGINS_VERSION=v1.5.1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      ca-certificates curl iproute2 iptables ethtool socat conntrack kmod \
      procps iputils-ping mount util-linux golang-go git \
    && rm -rf /var/lib/apt/lists/*

# Tooling install — same script CI uses. Version args bust the cache on bump.
COPY ci/install-tooling.sh /tmp/install-tooling.sh
RUN K8S_VERSION="$K8S_VERSION" CRUN_VERSION="$CRUN_VERSION" \
    CRICTL_VERSION="$CRICTL_VERSION" CNI_PLUGINS_VERSION="$CNI_PLUGINS_VERSION" \
    bash /tmp/install-tooling.sh

WORKDIR /work
```

- [ ] **Step 2: Build the image**

Run:
```bash
docker build -f ci/conformance.Dockerfile -t containerd-rs-conformance:latest .
```
Expected: build succeeds (`naming to docker.io/library/containerd-rs-conformance:latest done`).

- [ ] **Step 3: Verify the toolchain is present and crun is the runtime**

Run:
```bash
docker run --rm containerd-rs-conformance:latest sh -c \
  'set -e; kubeadm version -o short; crun --version | head -1; \
   readlink -f "$(command -v runc)"; crictl --version; hydrophone --help >/dev/null && echo hydrophone-ok; \
   ls /opt/cni/bin/flannel'
```
Expected: kubeadm `v1.35.6`, a crun version line, `runc` resolves to `/usr/local/bin/crun`, a crictl version, `hydrophone-ok`, and the flannel plugin path printed.

- [ ] **Step 4: Commit**

```bash
git add ci/conformance.Dockerfile
git commit -m "ci: conformance image (ubuntu + pinned toolchain via install-tooling.sh)"
```

---

## Task 3: Harness wrapper + make target

**Files:**
- Create: `ci/conformance-docker.sh`
- Modify: `Makefile` (add `conformance-docker` target; add it to `.PHONY`)

**Interfaces:**
- Consumes: the image `containerd-rs-conformance:latest` (Task 2); the built daemon binary; `ci/kubeadm-init.sh` and `ci/run-conformance.sh` (existing, unchanged).
- Produces: `make conformance-docker [FOCUS=...] [CGROUPS_PER_QOS=...]` → results in `./conformance-results/`.

- [ ] **Step 1: Write `ci/conformance-docker.sh`**

```bash
#!/usr/bin/env bash
# Run a conformance focus locally inside a privileged container, mirroring CI
# (same ci/ scripts, same pinned tooling via the conformance image, crun).
# No host sudo, no host runc changes, no CI minutes.
#
# Env:
#   FOCUS            ginkgo --focus regex (empty = full [Conformance] suite)
#   K8S_VERSION      kubernetes version (default v1.35.6)
#   CGROUPS_PER_QOS  default false — a nested container cannot create /kubepods
#   RESULTS_DIR      host output dir (default ./conformance-results)
#   IMAGE            conformance image tag (default containerd-rs-conformance:latest)
#   DAEMON_BIN       host path to the built daemon (default: resolve via cargo)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-containerd-rs-conformance:latest}"
K8S_VERSION="${K8S_VERSION:-v1.35.6}"
CGROUPS_PER_QOS="${CGROUPS_PER_QOS:-false}"
FOCUS="${FOCUS:-}"
RESULTS_DIR="${RESULTS_DIR:-${REPO}/conformance-results}"

# Resolve the daemon binary, honouring CARGO_TARGET_DIR.
if [[ -z "${DAEMON_BIN:-}" ]]; then
  target_dir="$(cd "$REPO" && cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
  DAEMON_BIN="${target_dir}/release/containerd-rs"
fi
[[ -x "$DAEMON_BIN" ]] || { echo "daemon not built at $DAEMON_BIN — run 'make release'" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  echo "image $IMAGE missing — run: docker build -f ci/conformance.Dockerfile -t $IMAGE ." >&2; exit 1; }

mkdir -p "$RESULTS_DIR"

# --privileged + cgroup2 + modules so kubelet/CNI/netfilter work nested.
# The daemon is mounted to the path kubeadm-init.sh defaults to inside /work.
docker run --rm --privileged \
  --tmpfs /run --tmpfs /var/run \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v /lib/modules:/lib/modules:ro \
  -v "$REPO":/work:ro \
  -v "$DAEMON_BIN":/work/target/release/containerd-rs:ro \
  -v "$RESULTS_DIR":/work/conformance-results:rw \
  -e K8S_VERSION="$K8S_VERSION" \
  -e CGROUPS_PER_QOS="$CGROUPS_PER_QOS" \
  -e FOCUS="$FOCUS" \
  "$IMAGE" bash -euxc '
    DAEMON_BIN=/work/target/release/containerd-rs CONFIG=/work/ci/config.toml \
    CRI_SOCKET=unix:///run/containerd-rs.sock CGROUPS_PER_QOS="$CGROUPS_PER_QOS" \
    K8S_VERSION="$K8S_VERSION" \
      bash /work/ci/kubeadm-init.sh
    chmod 0644 /etc/kubernetes/admin.conf
    KUBECONFIG=/etc/kubernetes/admin.conf FOCUS="$FOCUS" \
    RESULTS_DIR=/work/conformance-results \
    CONFORMANCE_IMAGE=registry.k8s.io/conformance:'"$K8S_VERSION"' \
      bash /work/ci/run-conformance.sh
  '
echo "[conformance-docker] results in $RESULTS_DIR"
```

> `/work` is mounted read-only, but the daemon, config, and scripts are read from there and outputs go to the `conformance-results` rw mount and to `/etc`, `/var`, `/run` (container-writable). If `kubeadm-init.sh` needs to write inside the repo tree, change the `:ro` on `/work` to `:rw` — verify in Step 3.

- [ ] **Step 2: Add the make target**

In `Makefile`, add `conformance-docker` to the `.PHONY` line, and add the target after `conformance`:

```makefile
conformance-docker:
	FOCUS='$(FOCUS)' K8S_VERSION=$(K8S_VERSION) RESULTS_DIR=$(RESULTS_DIR) \
		./ci/conformance-docker.sh
```

Update the `.PHONY` list to include it:
```makefile
.PHONY: all build release test lint fmt fmt-check check ci \
        cluster-up cluster-down conformance conformance-docker conformance-smoke crictl-validate clean
```

- [ ] **Step 3: Smoke test end-to-end**

Run (after `make release` and the Task 2 image build):
```bash
make conformance-docker FOCUS='Simple pod should contain last line of the log'
```
Expected: cluster comes up inside the container, hydrophone runs the single focused spec, and `conformance-results/e2e.log` + `junit_01.xml` appear on the host with `0 Failed`. If bring-up fails, the `-x` trace + kubeadm-init.sh's own `/var/log/crs.log` dump pinpoint where.

- [ ] **Step 4: Commit**

```bash
git add ci/conformance-docker.sh Makefile
git commit -m "ci: make conformance-docker — run conformance locally in a privileged container"
```

---

## Final validation (after all tasks)

1. **crun sig-node, the in-flight goal:**
   ```bash
   make conformance-docker FOCUS='\[sig-node\].*\[Conformance\]'
   ```
   Watch the crun `events --stats` (ContainerStats) path. Resize specs now run for real: `CGROUPS_PER_QOS=true` works nested (delegated cgroup scope), so per-pod cgroup limits are exercised locally — no longer CI-only.
2. **CI parity:** the next dispatched conformance workflow run installs via `ci/install-tooling.sh` and must stay green — confirms the Task 1 refactor is inert.

## Self-review notes

- Spec coverage: install-tooling.sh (spec §1) = Task 1; Dockerfile (§2) = Task 2; wrapper + make target (§3, §4) = Task 3; error handling (§Error handling) = preconditions + `-x` trace in Task 3. The spec's `CGROUPS_PER_QOS=true` claim is corrected to default-false here (nested-container limitation) and called out in Global Constraints + Final validation.
- The `go install hydrophone` + `sudo --preserve-env` interaction in Task 1 Step 3 is the one genuinely uncertain bit (root PATH for `go` on the runner); the step says how to fall back. The local harness does not depend on it (the image installs golang-go itself).
