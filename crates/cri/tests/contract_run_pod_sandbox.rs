//! Gap 1 — RunPodSandbox must FAIL (not silently host-network) when CNI is
//! unavailable for a non-hostNetwork pod, so the kubelet retries once
//! kube-router installs the conflist + binaries.

mod common;

use cri::v1;

fn sandbox_config(host_network: bool) -> v1::PodSandboxConfig {
    let ns = v1::NamespaceOption {
        // Node == host network; Pod (0) == needs CNI.
        network: if host_network {
            v1::NamespaceMode::Node as i32
        } else {
            v1::NamespaceMode::Pod as i32
        },
        ..Default::default()
    };
    v1::PodSandboxConfig {
        metadata: Some(v1::PodSandboxMetadata {
            name: "p".into(),
            uid: "u".into(),
            namespace: "default".into(),
            attempt: 0,
        }),
        linux: Some(v1::LinuxPodSandboxConfig {
            security_context: Some(v1::LinuxSandboxSecurityContext {
                namespace_options: Some(ns),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn run_pod_sandbox_fails_when_cni_unavailable() {
    let mut h = common::start().await;
    let res =
        h.rt.run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(sandbox_config(false)),
            runtime_handler: String::new(),
        })
        .await;
    let err = res.expect_err("non-hostNetwork pod must fail when CNI is absent");
    assert!(
        matches!(err.code(), tonic::Code::Unavailable | tonic::Code::Internal),
        "got {:?}",
        err.code()
    );
    // It must not have silently created a Ready sandbox.
    let list =
        h.rt.list_pod_sandbox(v1::ListPodSandboxRequest { filter: None })
            .await
            .unwrap()
            .into_inner();
    assert!(
        list.items
            .iter()
            .all(|s| s.state != v1::PodSandboxState::SandboxReady as i32),
        "no Ready sandbox may exist after a CNI failure"
    );
}

#[tokio::test]
async fn run_pod_sandbox_host_network_still_succeeds() {
    // The explicit-hostNetwork branch is unchanged: it never touches CNI.
    let mut h = common::start().await;
    let resp =
        h.rt.run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(sandbox_config(true)),
            runtime_handler: String::new(),
        })
        .await
        .expect("hostNetwork pod succeeds without CNI")
        .into_inner();
    assert!(!resp.pod_sandbox_id.is_empty());
}
