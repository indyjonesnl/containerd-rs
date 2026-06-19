//! T033 — ImageService integration: pull (by tag and by digest), list,
//! remove+reclaim, and corrupt-layer rejection.
//!
//! The corrupt-layer guard runs always (deterministic, no network): the content
//! store verifies every blob's digest on commit, which is what makes a tampered
//! pulled layer fail. The pull/list/remove journey hits a real registry and is
//! gated behind `#[ignore]`.

mod common;

use core_types::Digest;
use cri::v1;

/// A corrupt layer (bytes that don't hash to the claimed digest) must be
/// rejected on commit — the integrity guard the pull pipeline relies on.
#[tokio::test]
async fn corrupt_layer_is_rejected_on_commit() {
    let dir = tempfile::tempdir().unwrap();
    let store = content::Store::open(dir.path().join("content")).unwrap();
    let real = b"the real layer bytes";
    let claimed = Digest::sha256(b"a different layer"); // wrong on purpose
    let err = store
        .write_blob("registry.example/x:layer:0", real, &claimed)
        .expect_err("digest mismatch must be rejected");
    assert!(
        matches!(err, content::Error::DigestMismatch { .. }),
        "expected DigestMismatch, got {err:?}"
    );
    // And the bad blob must not be left behind under the claimed digest.
    assert!(!store.exists(&claimed));
}

/// Pull by tag, see it via ImageStatus/ListImages, then remove and confirm it's
/// gone (storage reclaimed). Requires network to registry.k8s.io.
///   cargo test -p cri --test integration_image_mgmt -- --ignored
#[tokio::test]
#[ignore = "requires network: pulls registry.k8s.io/pause:3.10"]
async fn pull_by_tag_status_list_remove() {
    let mut h = common::start().await;
    let img = v1::ImageSpec {
        image: "registry.k8s.io/pause:3.10".into(),
        ..Default::default()
    };

    let pulled = h
        .img
        .pull_image(v1::PullImageRequest {
            image: Some(img.clone()),
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
            image: Some(img.clone()),
            verbose: false,
        })
        .await
        .unwrap()
        .into_inner();
    let image = st.image.expect("pulled image present");
    assert!(image.size > 0, "image size reported");

    let list = h
        .img
        .list_images(v1::ListImagesRequest { filter: None })
        .await
        .unwrap()
        .into_inner();
    assert!(list.images.iter().any(|i| i.id == image.id));

    h.img
        .remove_image(v1::RemoveImageRequest {
            image: Some(img.clone()),
        })
        .await
        .unwrap();
    let after = h
        .img
        .image_status(v1::ImageStatusRequest {
            image: Some(img),
            verbose: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(after.image.is_none(), "image removed");
}

/// Pull the same image by digest (immutable reference). Requires network.
#[tokio::test]
#[ignore = "requires network: pulls registry.k8s.io/pause by digest"]
async fn pull_by_digest() {
    let mut h = common::start().await;
    // pause:3.10 manifest-list digest (immutable).
    let by_digest = "registry.k8s.io/pause@sha256:7c38f24774e3cbd906d2d33c38354ccf787635581c122965132c9bd309754d4a";
    let pulled = h
        .img
        .pull_image(v1::PullImageRequest {
            image: Some(v1::ImageSpec {
                image: by_digest.into(),
                ..Default::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!pulled.image_ref.is_empty());
}
