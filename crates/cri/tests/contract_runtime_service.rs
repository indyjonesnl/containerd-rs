//! T021 — RuntimeService contract tests.
//!
//! Asserts the request/response shapes and state-enum mappings the kubelet
//! relies on (per `specs/001-rust-containerd/contracts/cri-v1.md`): the Version
//! handshake, sandbox/container lifecycle + status, list filters, the
//! SANDBOX/CONTAINER state enums, idempotent stop/remove, the streaming-URL
//! contract for Exec/Attach/PortForward, and the Status runtime conditions.
//! Requires no runc/network (host-network sandbox, container stays Created).

mod common;

use std::collections::HashMap;

use cri::v1;

fn host_network_sandbox(name: &str, uid: &str) -> v1::PodSandboxConfig {
    let mut labels = HashMap::new();
    labels.insert("io.kubernetes.pod.uid".to_string(), uid.to_string());
    let mut annotations = HashMap::new();
    annotations.insert("greeting".to_string(), "hi".to_string());
    v1::PodSandboxConfig {
        metadata: Some(v1::PodSandboxMetadata {
            name: name.to_string(),
            uid: uid.to_string(),
            namespace: "default".to_string(),
            attempt: 0,
        }),
        hostname: name.to_string(),
        log_directory: "/tmp".to_string(),
        labels,
        annotations,
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

#[tokio::test]
async fn version_handshake() {
    let mut h = common::start().await;
    let v =
        h.rt.version(v1::VersionRequest {
            version: "v1".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(v.runtime_name, "containerd-rs");
    assert_eq!(v.runtime_api_version, "v1");
    assert!(!v.version.is_empty());
}

#[tokio::test]
async fn status_reports_runtime_and_network_ready() {
    let mut h = common::start().await;
    let s =
        h.rt.status(v1::StatusRequest { verbose: false })
            .await
            .unwrap()
            .into_inner();
    let conds = s.status.unwrap().conditions;
    assert!(conds.iter().any(|c| c.r#type == "RuntimeReady" && c.status));
    assert!(conds.iter().any(|c| c.r#type == "NetworkReady" && c.status));
}

#[tokio::test]
async fn runtime_config_reports_cgroupfs_driver() {
    let mut h = common::start().await;
    let cfg =
        h.rt.runtime_config(v1::RuntimeConfigRequest {})
            .await
            .unwrap()
            .into_inner();
    let driver = cfg.linux.unwrap().cgroup_driver;
    assert_eq!(driver, v1::CgroupDriver::Cgroupfs as i32);
}

#[tokio::test]
async fn sandbox_lifecycle_status_filters_and_enums() {
    let mut h = common::start().await;
    let cfg = host_network_sandbox("pod-a", "uid-a");

    let id =
        h.rt.run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(cfg.clone()),
            runtime_handler: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pod_sandbox_id;
    assert!(!id.is_empty());

    // PodSandboxStatus: state enum + metadata round-trip + IP + netns mode +
    // labels/annotations preserved.
    let st =
        h.rt.pod_sandbox_status(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id.clone(),
            verbose: false,
        })
        .await
        .unwrap()
        .into_inner();
    let status = st.status.unwrap();
    assert_eq!(status.state, v1::PodSandboxState::SandboxReady as i32);
    let meta = status.metadata.unwrap();
    assert_eq!(meta.name, "pod-a");
    assert_eq!(meta.uid, "uid-a");
    assert_eq!(meta.namespace, "default");
    assert!(
        !status.network.unwrap().ip.is_empty(),
        "host-network IP set"
    );
    let net = status
        .linux
        .unwrap()
        .namespaces
        .unwrap()
        .options
        .unwrap()
        .network;
    assert_eq!(net, v1::NamespaceMode::Node as i32, "host => NODE netns");
    assert_eq!(status.labels.get("io.kubernetes.pod.uid").unwrap(), "uid-a");
    assert_eq!(status.annotations.get("greeting").unwrap(), "hi");

    // ListPodSandbox: by id, by state filter, by label_selector.
    let by_id =
        h.rt.list_pod_sandbox(v1::ListPodSandboxRequest {
            filter: Some(v1::PodSandboxFilter {
                id: id.clone(),
                ..Default::default()
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_id.items.len(), 1);
    assert_eq!(
        by_id.items[0].state,
        v1::PodSandboxState::SandboxReady as i32
    );

    let mut sel = HashMap::new();
    sel.insert("io.kubernetes.pod.uid".to_string(), "uid-a".to_string());
    let by_label =
        h.rt.list_pod_sandbox(v1::ListPodSandboxRequest {
            filter: Some(v1::PodSandboxFilter {
                label_selector: sel,
                ..Default::default()
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_label.items.len(), 1);

    // Stop -> NOTREADY.
    h.rt.stop_pod_sandbox(v1::StopPodSandboxRequest {
        pod_sandbox_id: id.clone(),
    })
    .await
    .unwrap();
    let st2 =
        h.rt.pod_sandbox_status(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id.clone(),
            verbose: false,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        st2.status.unwrap().state,
        v1::PodSandboxState::SandboxNotready as i32
    );

    // Remove -> gone.
    h.rt.remove_pod_sandbox(v1::RemovePodSandboxRequest {
        pod_sandbox_id: id.clone(),
    })
    .await
    .unwrap();
    let gone =
        h.rt.pod_sandbox_status(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id,
            verbose: false,
        })
        .await;
    assert!(gone.is_err(), "status of removed sandbox errors");
}

#[tokio::test]
async fn container_create_status_enum_is_created() {
    let mut h = common::start().await;
    let sb = host_network_sandbox("pod-c", "uid-c");
    let sandbox_id =
        h.rt.run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(sb.clone()),
            runtime_handler: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pod_sandbox_id;

    let cc = v1::ContainerConfig {
        metadata: Some(v1::ContainerMetadata {
            name: "c0".into(),
            attempt: 0,
        }),
        image: Some(v1::ImageSpec {
            image: "registry.k8s.io/pause:3.10".into(),
            ..Default::default()
        }),
        command: vec!["/pause".into()],
        ..Default::default()
    };
    let cid =
        h.rt.create_container(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox_id.clone(),
            config: Some(cc),
            sandbox_config: Some(sb),
        })
        .await
        .unwrap()
        .into_inner()
        .container_id;
    assert!(!cid.is_empty());

    let st =
        h.rt.container_status(v1::ContainerStatusRequest {
            container_id: cid.clone(),
            verbose: false,
        })
        .await
        .unwrap()
        .into_inner();
    let status = st.status.unwrap();
    assert_eq!(status.state, v1::ContainerState::ContainerCreated as i32);
    assert_eq!(status.metadata.unwrap().name, "c0");

    let list =
        h.rt.list_containers(v1::ListContainersRequest {
            filter: Some(v1::ContainerFilter {
                pod_sandbox_id: sandbox_id,
                ..Default::default()
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.containers.len(), 1);
}

/// Create a host-network sandbox + a (Created) container; return their ids.
/// No runc needed — CreateContainer writes the bundle/record without starting.
async fn make_pod_and_container(h: &mut common::Harness) -> (String, String) {
    let sb = host_network_sandbox("pod-x", "uid-x");
    let sid =
        h.rt.run_pod_sandbox(v1::RunPodSandboxRequest {
            config: Some(sb.clone()),
            runtime_handler: String::new(),
        })
        .await
        .unwrap()
        .into_inner()
        .pod_sandbox_id;
    let cc = v1::ContainerConfig {
        metadata: Some(v1::ContainerMetadata {
            name: "c0".into(),
            attempt: 0,
        }),
        image: Some(v1::ImageSpec {
            image: "registry.k8s.io/pause:3.10".into(),
            ..Default::default()
        }),
        command: vec!["/pause".into()],
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
    (sid, cid)
}

#[tokio::test]
async fn exec_attach_portforward_return_streaming_urls() {
    let mut h = common::start().await;
    let (sid, cid) = make_pod_and_container(&mut h).await;
    // These mint a one-time URL into the streaming server without touching runc.
    let exec =
        h.rt.exec(v1::ExecRequest {
            container_id: cid.clone(),
            cmd: vec!["ls".into()],
            tty: false,
            stdin: false,
            stdout: true,
            stderr: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(exec.url.contains("/exec/"), "exec url: {}", exec.url);

    let attach =
        h.rt.attach(v1::AttachRequest {
            container_id: cid,
            stdin: false,
            tty: false,
            stdout: true,
            stderr: true,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        attach.url.contains("/attach/"),
        "attach url: {}",
        attach.url
    );

    let pf =
        h.rt.port_forward(v1::PortForwardRequest {
            pod_sandbox_id: sid,
            port: vec![8080],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        pf.url.contains("/portforward/"),
        "portforward url: {}",
        pf.url
    );
}

#[tokio::test]
async fn stop_and_remove_of_absent_objects_are_idempotent() {
    let mut h = common::start().await;
    // Contract: stop/remove of an already-gone object succeeds.
    h.rt.stop_pod_sandbox(v1::StopPodSandboxRequest {
        pod_sandbox_id: "ghost".into(),
    })
    .await
    .unwrap();
    h.rt.remove_pod_sandbox(v1::RemovePodSandboxRequest {
        pod_sandbox_id: "ghost".into(),
    })
    .await
    .unwrap();
    h.rt.stop_container(v1::StopContainerRequest {
        container_id: "ghost".into(),
        timeout: 0,
    })
    .await
    .unwrap();
    h.rt.remove_container(v1::RemoveContainerRequest {
        container_id: "ghost".into(),
    })
    .await
    .unwrap();
}
