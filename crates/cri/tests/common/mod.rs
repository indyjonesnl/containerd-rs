//! Shared harness for the CRI contract tests: spin up the real gRPC server over
//! a unix socket and hand back connected RuntimeService + ImageService clients.

use std::sync::Arc;

use cri::server::{serve, Context};
use cri::v1::image_service_client::ImageServiceClient;
use cri::v1::runtime_service_client::RuntimeServiceClient;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};

pub struct Harness {
    // Each test binary compiles `common` separately and may use only one client,
    // so allow the other to look unused.
    #[allow(dead_code)]
    pub rt: RuntimeServiceClient<Channel>,
    #[allow(dead_code)]
    pub img: ImageServiceClient<Channel>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.handle.abort();
    }
}

/// Start a fresh in-process CRI server (empty stores, host networking) and
/// return connected clients. Requires no crun/network.
pub async fn start() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("cri.sock");
    let content = content::Store::open(dir.path().join("content")).unwrap();
    let metadata = metadata::Store::open(dir.path().join("meta.db")).unwrap();
    let ctx = Arc::new(Context::new(
        content,
        metadata,
        dir.path().join("snapshots"),
        dir.path().join("state"),
        "127.0.0.1:10010",
        dir.path().join("cni/net.d"),
        dir.path().join("cni/bin"),
    ));

    let sock_server = sock.clone();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        serve(sock_server, ctx, async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let sock_client = sock.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let p = sock_client.clone();
            async move {
                let stream = UnixStream::connect(p).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .unwrap();

    Harness {
        rt: RuntimeServiceClient::new(channel.clone()),
        img: ImageServiceClient::new(channel),
        shutdown: Some(tx),
        handle,
        _dir: dir,
    }
}
