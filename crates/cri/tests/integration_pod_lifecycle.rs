//! T022 — pod-lifecycle integration test.
//!
//! Drives the full CRI journey crictl exercises — pull → RunPodSandbox →
//! CreateContainer → StartContainer → logs → ExecSync → StopContainer →
//! RemoveContainer → StopPodSandbox → RemovePodSandbox — against the real gRPC
//! server, asserting the container state transitions (CREATED → RUNNING →
//! EXITED) and that logs + exec work. Requires crun (rootless) + network for the
//! image pull, so it is `#[ignore]`d:
//!   cargo test -p cri --test integration_pod_lifecycle -- --ignored

mod common;

use std::collections::HashMap;
use std::time::Duration;

use cri::v1;

const BUSYBOX: &str = "docker.io/library/busybox:1.36";

fn host_network_sandbox(log_directory: &str) -> v1::PodSandboxConfig {
    let mut labels = HashMap::new();
    labels.insert("io.kubernetes.pod.uid".to_string(), "uid-lc".to_string());
    v1::PodSandboxConfig {
        metadata: Some(v1::PodSandboxMetadata {
            name: "lc-pod".into(),
            uid: "uid-lc".into(),
            namespace: "default".into(),
            attempt: 0,
        }),
        hostname: "lc-pod".into(),
        log_directory: log_directory.to_string(),
        labels,
        linux: Some(v1::LinuxPodSandboxConfig {
            security_context: Some(v1::LinuxSandboxSecurityContext {
                namespace_options: Some(v1::NamespaceOption {
                    network: v1::NamespaceMode::Node as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn container_state(h: &mut common::Harness, cid: &str) -> i32 {
    h.rt.container_status(v1::ContainerStatusRequest {
        container_id: cid.to_string(),
        verbose: false,
    })
    .await
    .unwrap()
    .into_inner()
    .status
    .unwrap()
    .state
}

#[tokio::test]
#[ignore = "requires rootless crun + network (pulls busybox)"]
async fn full_pod_lifecycle() {
    let mut h = common::start().await;
    let logdir = tempfile::tempdir().unwrap();
    let logdir_s = logdir.path().display().to_string();

    // Pull a shell image.
    h.img
        .pull_image(v1::PullImageRequest {
            image: Some(v1::ImageSpec {
                image: BUSYBOX.into(),
                ..Default::default()
            }),
            auth: None,
            sandbox_config: None,
        })
        .await
        .expect("pull busybox");

    // Sandbox (host network -> no CNI needed).
    let sb = host_network_sandbox(&logdir_s);
    let sid =
        h.rt.run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(sb.clone()),
            runtime_handler: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pod_sandbox_id;

    // Create a container that logs a marker then sleeps.
    let cc = v1::ContainerConfig {
        metadata: Some(v1::ContainerMetadata {
            name: "c0".into(),
            attempt: 0,
        }),
        image: Some(v1::ImageSpec {
            image: BUSYBOX.into(),
            ..Default::default()
        }),
        command: vec![
            "sh".into(),
            "-c".into(),
            "echo lifecycle-marker; sleep 300".into(),
        ],
        log_path: "0.log".into(),
        ..Default::default()
    };
    let cid =
        h.rt.create_container(v1::CreateContainerRequest {
            pod_sandbox_id: sid.clone(),
            config: Some(cc),
            sandbox_config: Some(sb),
        })
        .await
        .unwrap()
        .into_inner()
        .container_id;
    assert_eq!(
        container_state(&mut h, &cid).await,
        v1::ContainerState::ContainerCreated as i32,
        "freshly created -> CREATED"
    );

    // Start and wait for RUNNING.
    h.rt.start_container(v1::StartContainerRequest {
        container_id: cid.clone(),
    })
    .await
    .unwrap();
    let mut running = false;
    for _ in 0..50 {
        if container_state(&mut h, &cid).await == v1::ContainerState::ContainerRunning as i32 {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running, "container reached RUNNING");

    // Logs: the supervisor writes the container's stdout to <log_directory>/0.log
    // in the CRI log format; the marker must appear.
    let log_path = logdir.path().join("0.log");
    let mut found = false;
    for _ in 0..50 {
        if let Ok(s) = std::fs::read_to_string(&log_path) {
            if s.contains("lifecycle-marker") {
                found = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(found, "container log contains the marker");

    // ExecSync inside the running container.
    let exec =
        h.rt.exec_sync(v1::ExecSyncRequest {
            container_id: cid.clone(),
            cmd: vec!["echo".into(), "exec-ok".into()],
            timeout: 5,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exec.exit_code, 0, "exec_sync exit 0");
    assert!(
        String::from_utf8_lossy(&exec.stdout).contains("exec-ok"),
        "exec_sync stdout"
    );

    // Stop -> EXITED, then remove the container and tear down the sandbox.
    h.rt.stop_container(v1::StopContainerRequest {
        container_id: cid.clone(),
        timeout: 0,
    })
    .await
    .unwrap();
    assert_eq!(
        container_state(&mut h, &cid).await,
        v1::ContainerState::ContainerExited as i32,
        "stopped -> EXITED"
    );
    h.rt.remove_container(v1::RemoveContainerRequest { container_id: cid })
        .await
        .unwrap();
    h.rt.stop_pod_sandbox(v1::StopPodSandboxRequest {
        pod_sandbox_id: sid.clone(),
    })
    .await
    .unwrap();
    h.rt.remove_pod_sandbox(v1::RemovePodSandboxRequest {
        pod_sandbox_id: sid,
    })
    .await
    .unwrap();
}
