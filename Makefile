# containerd-rs — local == CI entrypoints.
# Every CI job calls these same targets so a green local run predicts green CI
# (the rule: never let CI be the first place a failure appears).

CARGO ?= cargo
# Conformance image minor MUST match K8S_VERSION (the cluster kubeadm stands up).
K8S_VERSION ?= v1.35.6
CONFORMANCE_IMAGE ?= registry.k8s.io/conformance:$(K8S_VERSION)
PAUSE_IMAGE ?= registry.k8s.io/pause:3.10
CRI_SOCKET ?= unix:///run/containerd-rs.sock
RESULTS_DIR ?= conformance-results
# Per-QoS pod cgroups, on by default to mirror CI. The conformance-docker
# harness gives its container a delegated cgroup-v2 scope so this works nested.
CGROUPS_PER_QOS ?= true

.PHONY: all build release test lint fmt fmt-check check ci \
        cluster-up cluster-down conformance conformance-docker conformance-smoke \
        crictl-validate critest critest-docker clean

all: check

## --- Things that run today (foundation) ---

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --workspace --release

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

# Full local gate — run before every push.
check: fmt-check lint test
	@echo "OK: fmt + clippy + tests passed"

ci: check

## --- Conformance pipeline (pending CRI runtime: tasks T015-T038) ---
## These targets are the eventual proof harness. They require root, crun,
## kubeadm/kubelet, CNI, and hydrophone. Run locally before pushing.

cluster-up:
	sudo K8S_VERSION=$(K8S_VERSION) CONFORMANCE_IMAGE=$(CONFORMANCE_IMAGE) PAUSE_IMAGE=$(PAUSE_IMAGE) \
		CRI_SOCKET=$(CRI_SOCKET) ./ci/kubeadm-init.sh

conformance-smoke:
	RESULTS_DIR=$(RESULTS_DIR) FOCUS='Simple pod should contain last line of the log' \
		./ci/run-conformance.sh

conformance:
	RESULTS_DIR=$(RESULTS_DIR) CONFORMANCE_IMAGE=$(CONFORMANCE_IMAGE) \
		./ci/run-conformance.sh

conformance-docker:
	FOCUS='$(FOCUS)' K8S_VERSION=$(K8S_VERSION) RESULTS_DIR=$(RESULTS_DIR) CGROUPS_PER_QOS='$(CGROUPS_PER_QOS)' \
		./ci/conformance-docker.sh

crictl-validate:
	sudo CRI_SOCKET=$(CRI_SOCKET) ./ci/crictl-validate.sh

# CRI-conformance suite (cri-tools critest) — the suite Go containerd/CRI-O use.
# critest: against an already-running daemon + CNI. critest-docker: self-contained
# privileged container, no host sudo / CI minutes (needs the conformance image).
critest:
	CRI_SOCKET=$(CRI_SOCKET) FOCUS='$(FOCUS)' SKIP='$(SKIP)' RESULTS_DIR=$(RESULTS_DIR) ./ci/critest.sh

critest-docker:
	FOCUS='$(FOCUS)' SKIP='$(SKIP)' ./ci/critest-docker.sh

cluster-down:
	-sudo kubeadm reset -f
	-sudo pkill -x kubelet || true
	-sudo pkill -x containerd-rs || true

clean:
	$(CARGO) clean
	rm -rf $(RESULTS_DIR)
