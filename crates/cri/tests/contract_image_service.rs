//! T032 — ImageService contract tests.
//!
//! Asserts the ImageService request/response shapes per
//! `specs/001-rust-containerd/contracts/cri-v1.md`: ListImages, ImageStatus on a
//! hit and a miss, RemoveImage idempotency, ImageFsInfo, and PullImage argument
//! handling. The real network pull (honoring `PullImageRequest.Auth`) is gated
//! behind `#[ignore]`. Requires no crun.

mod common;

use cri::v1;

#[tokio::test]
async fn list_images_empty_on_fresh_store() {
    let mut h = common::start().await;
    let list = h
        .img
        .list_images(v1::ListImagesRequest { filter: None })
        .await
        .unwrap()
        .into_inner();
    assert!(list.images.is_empty());
}

#[tokio::test]
async fn image_status_miss_returns_none() {
    let mut h = common::start().await;
    let st = h
        .img
        .image_status(v1::ImageStatusRequest {
            image: Some(v1::ImageSpec {
                image: "registry.k8s.io/pause:3.10".into(),
                ..Default::default()
            }),
            verbose: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(st.image.is_none(), "absent image => no ImageStatus");
}

#[tokio::test]
async fn remove_absent_image_is_idempotent() {
    let mut h = common::start().await;
    // Contract: removing an already-gone image succeeds.
    h.img
        .remove_image(v1::RemoveImageRequest {
            image: Some(v1::ImageSpec {
                image: "registry.k8s.io/does-not-exist:0".into(),
                ..Default::default()
            }),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn image_fs_info_returns_usage() {
    let mut h = common::start().await;
    let info = h
        .img
        .image_fs_info(v1::ImageFsInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    // At least one filesystem usage entry (the snapshots store), with a
    // populated identifier and timestamp.
    assert!(
        !info.image_filesystems.is_empty(),
        "image_fs_info reports a filesystem"
    );
    let fs = &info.image_filesystems[0];
    assert!(fs.timestamp > 0, "fs usage has a timestamp");
    assert!(fs.fs_id.is_some(), "fs usage has an fs_id mountpoint");
}

#[tokio::test]
async fn pull_image_rejects_empty_reference() {
    let mut h = common::start().await;
    // An unparseable/empty reference must fail cleanly (no network, no panic).
    let res = h
        .img
        .pull_image(v1::PullImageRequest {
            image: Some(v1::ImageSpec {
                image: String::new(),
                ..Default::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await;
    assert!(res.is_err(), "empty image reference must error");
}

// Real pull (anonymous, node-platform) — requires network to registry.k8s.io.
//   cargo test -p cri --test contract_image_service -- --ignored
#[tokio::test]
#[ignore = "requires network: pulls registry.k8s.io/pause:3.10"]
async fn pull_then_status_and_list() {
    let mut h = common::start().await;
    let pulled = h
        .img
        .pull_image(v1::PullImageRequest {
            image: Some(v1::ImageSpec {
                image: "registry.k8s.io/pause:3.10".into(),
                ..Default::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!pulled.image_ref.is_empty());

    let st = h
        .img
        .image_status(v1::ImageStatusRequest {
            image: Some(v1::ImageSpec {
                image: "registry.k8s.io/pause:3.10".into(),
                ..Default::default()
            }),
            verbose: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(st.image.is_some(), "pulled image is reported by status");
    // pause:3.10 has no `User` set -> root -> no uid/username surfaced.
    let im = st.image.expect("status has image");
    assert!(im.uid.is_none() && im.username.is_empty());

    let list = h
        .img
        .list_images(v1::ListImagesRequest { filter: None })
        .await
        .unwrap()
        .into_inner();
    assert!(!list.images.is_empty());
}
