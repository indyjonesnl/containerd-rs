# Image Import — Design

Date: 2026-07-15
Status: Approved (design), pending implementation plan

## Problem

containerd-rs can only populate its content store by pulling from a registry over
HTTP, driven by the kubelet CRI `PullImage` RPC. There is no import/load/sideload
path (no `ctr images import` / `docker load` equivalent), no push, no content-store
CLI, and no registry server.

Rusternetes runs self-written, self-compiled binaries packaged as images that are
built on a dev machine and never published to any registry. On a single-node
deployment (containerd-rs on the same box, or one node with tars copied in) there is
currently no supported way to get those images into containerd-rs.

Real containerd faces the same gap and solves it with `ctr images import`: a CLI
client streams a `docker save` / OCI archive to the daemon, which writes the blobs
into its content store and creates the image record. Cross-node distribution in
containerd is always a registry's job; import is a single-node local convenience.
This spec adds the single-node import path.

## Scope

In scope:
- Import an OCI image layout/archive **and** a `docker save` archive, auto-detected.
- Trigger via a new `containerd-rs import <tar>` CLI subcommand talking to the running
  daemon over an admin unix socket; the daemon performs all store + metadata writes.
- Single-platform selection, digest-only verification — identical envelope to the
  existing pull pipeline.

Out of scope (matches existing pull gaps, YAGNI):
- Image push / registry write path.
- Multi-arch import (select the node platform, like pull does today).
- Signature verification (cosign/notary).
- Cross-node distribution (that is a registry's job, per containerd's own model).
- A general content/images/leases gRPC surface (containerd-native services). Only a
  single `Import` admin method is added.

## Architecture

Import reuses the entire risky tail of the pull pipeline. Only the blob **source**
(local tar vs registry HTTP) and the **trigger** (admin socket vs CRI `PullImage`)
are new.

```
containerd-rs import <tar>          (CLI client)
        │  stream tar bytes
        ▼
/run/containerd-rs/admin.sock       (daemon: new admin tonic service)
        │  buffer to content ingest/ temp file
        ▼
images::import::import_archive(...) (new; pure archive→store logic)
        │  detect format → materialize OCI manifest+config+layers
        ▼
[shared tail extracted from pull.rs]
   verify diffIDs vs config → chainIDs (images::identity)
   → unpack layers to snapshots/<chainID>/fs (snapshots::diff::apply_layer)
   → write metadata::ImageRecord
```

### Components

**`crates/images/src/import.rs` (new) — archive→store logic, no transport.**

Public entry:

```
pub async fn import_archive(
    reader: impl AsyncRead,          // or a path to the buffered temp tar
    content: &content::Store,
    meta: &metadata::Store,
    snapshots_root: &Path,
    opts: ImportOptions,             // { ref_override: Option<String>, namespace, platform }
) -> Result<ImportedImage>           // { image_id, repo_tags, repo_digests, size }
```

- **Format detection:** scan tar entries. `index.json` present ⇒ OCI image layout;
  `manifest.json` present and no `index.json` ⇒ docker-save archive; neither ⇒ error
  `unknown archive format`.
- **OCI layout:** parse `index.json` → select the node-platform manifest descriptor
  (reuse `images::identity` platform matching) → read config + layer descriptors.
  Blobs are already `sha256:`-addressed; stream each into `content::Store` (existing
  verify-on-commit + dedup). Layers may be gzip/zstd/uncompressed — the existing
  `snapshots::diff` compression detection already handles this at unpack time.
- **docker-save:** parse `manifest.json` (`Config`, `Layers[]`, `RepoTags`). Layers in
  a docker-save archive are uncompressed tars. Stream each into the content store,
  computing its digest during the write (the content `Writer` already hashes as it
  writes). Synthesize an OCI image manifest + descriptors from the config digest and
  the computed layer digests so the downstream path is format-agnostic. Carry
  `RepoTags` forward for naming.
- **Shared tail (see refactor below):** assert each layer's diffID against the config's
  `rootfs.diff_ids`, compute chainIDs, unpack each layer into its chainID-keyed
  `fs` dir idempotently, write the `ImageRecord`.
- **Naming:** image name from `--ref` override if given, else docker-save `RepoTags[0]`
  / OCI `org.opencontainers.image.ref.name` annotation. `image_id` = config digest.
  `repo_digests` derived from the manifest digest as pull does.

**Refactor `crates/images/src/pull.rs`.** Extract the tail — diffID assertion →
chainID computation → layer unpack → `ImageRecord` construction — into a shared helper
(e.g. `images::unpack::finalize_image(content, meta, snapshots_root, manifest, config, name, ...)`)
that both `pull_with_options` and `import_archive` call. This keeps the verification +
unpack + metadata logic on a single code path rather than duplicating the delicate
part. No behavior change to pull.

**`crates/cri/src/admin.rs` (new) — admin transport.**

- A tonic service bound to a unix socket at the state dir (default
  `/run/containerd-rs/admin.sock`; derived like the existing CRI/streaming sockets).
- One **unary** RPC: `Import(ImportRequest{archive_path, ref_override}) -> ImportReply{image_id, repo_tags}`.
  The daemon opens `archive_path` **directly** — on a single node the CLI and daemon
  share the node filesystem, so passing the path is simpler than streaming tar bytes
  (same trust model; no server-side buffering). `images::import::import_archive`
  extracts the archive to a scratch dir on the store filesystem and returns the
  imported-image data; the handler then writes the `ImageRecord`. Streaming would only
  be needed for a remote CLI, which is out of scope (multi-node = registry).
- Proto: a minimal `.proto` (or hand-written tonic types) for the admin service,
  compiled in the same build step as the existing CRI protos.
- Started alongside the CRI and streaming servers in `crates/containerd-rs/src/main.rs`.

**`crates/containerd-rs/src/main.rs` — CLI subcommand.**

- The binary is currently flags-only (`--config`, `--check`, hidden `__pid-holder`).
  Introduce a `clap` subcommand layout while preserving the default (no-subcommand)
  daemon behavior for backward compatibility.
- `containerd-rs import <tar> [--ref <name>] [--socket <path>]`: open the file, connect
  to the admin socket, stream the tar, print the returned image ID + repoTags to
  stdout, exit non-zero with the server error message on failure.

## Data flow (happy path)

1. `containerd-rs import ./myapp.tar --ref myapp:dev`
2. CLI streams tar to `admin.sock` `Import`.
3. Daemon buffers tar to `content/ingest/<unique>.tar`.
4. `import_archive`: detect format → materialize OCI config + layer descriptors →
   stream blobs into content store (verify-on-commit, dedup) → shared finalize:
   diffID assert → chainIDs → unpack to `snapshots/<chainID>/fs` → write `ImageRecord`
   (name `myapp:dev`).
5. Daemon removes temp tar, returns `image_id` + `repo_tags`.
6. CLI prints them. `crictl images` now lists `myapp:dev`; a pod referencing it runs
   with no registry configured.

## Error handling

- Unknown/neither-format archive → hard error `unknown archive format`.
- Missing config or layer blob referenced by the manifest → hard error.
- Digest/size mismatch on commit → hard error (existing content store behavior).
- diffID mismatch vs config → hard error.
- On any error, no `ImageRecord` is written. Blobs already committed to the content
  store are unreferenced and reclaimed by the existing refcount GC. The buffered temp
  tar is always deleted (success or failure). Partial-safe: a failed import leaves no
  half-registered image.
- Import of an already-present image (same digests) is idempotent — dedup on blobs,
  unpack is idempotent, `ImageRecord` upsert.

## Security

- Admin socket is unauthenticated, root-only filesystem permissions (0600 / owned by
  the daemon user), same trust model as the existing CRI socket. No TLS. Documented as
  a local-node admin interface.

## Testing

Local-first (CI minutes are limited; run `make check` before every push).

- **Unit (`crates/images`):**
  - Format detection: OCI `index.json`, docker `manifest.json`, and neither.
  - docker-save → OCI descriptor synthesis (correct config digest + computed layer
    digests).
  - Import a tiny fixture in **both** formats (`docker save busybox` and
    `skopeo copy docker://busybox oci-archive:...`): assert the `ImageRecord` fields and
    that `snapshots/<chainID>/fs` dirs exist.
  - Idempotent re-import.
  - Error cases: truncated tar, missing layer, diffID mismatch → no `ImageRecord`.
- **Refactor guard:** existing pull tests must stay green after the tail extraction.
- **Integration (local docker harness / single-node):** daemon up → `containerd-rs
  import busybox.tar` → `crictl images` shows it → run a pod using that ref with no
  registry configured → container reaches Running.

## Documentation

- README: note import as a supported local path; add a usage example.
- `docs/architecture.md`: add import as a second content-store ingest entrypoint
  alongside CRI pull.
- `GAPS.md` §7: remove/adjust the implication that registry pull is the only ingest;
  keep "pull only (no push)" — push is still out of scope.

## Follow-ups (not this spec)

- Multi-arch import.
- `containerd-rs images ls` / `rm` CLI parity with `ctr`.
- Signature verification (shared with pull).
