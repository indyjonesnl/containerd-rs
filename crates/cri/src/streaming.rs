//! CRI exec/attach/port-forward streaming server.
//!
//! The CRI `Exec`/`Attach`/`PortForward` RPCs do not stream over the gRPC
//! connection — they return a one-time URL into this separate HTTP server, which
//! the kubelet then connects to and upgrades to the Kubernetes remotecommand
//! protocol. Recent Kubernetes speaks this over **WebSocket** (the
//! `v4.channel.k8s.io` subprotocol: each binary frame is `[channel_byte] ++
//! payload`, with stdin=0, stdout=1, stderr=2, error=3). This module issues the
//! tokens, serves the WebSocket endpoints, and drives `runc exec` for the
//! container's stdio.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxPath, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;

/// v4 stream channels.
const CH_STDOUT: u8 = 1;
const CH_STDERR: u8 = 2;
const CH_ERROR: u8 = 3;

/// A pending exec session, consumed when its URL is dialed.
#[derive(Debug, Clone)]
pub struct ExecSession {
    pub container_id: String,
    pub cmd: Vec<String>,
    pub tty: bool,
}

/// A pending port-forward session, consumed when its URL is dialed.
#[derive(Debug, Clone)]
pub struct PortForwardSession {
    pub pod_sandbox_id: String,
}

/// One-time-token registry for streaming sessions, shared between the CRI
/// service (which registers) and the HTTP server (which consumes).
pub struct Sessions {
    exec: Mutex<HashMap<String, ExecSession>>,
    portforward: Mutex<HashMap<String, PortForwardSession>>,
    runc_root: PathBuf,
    runc_bin: String,
    counter: AtomicU64,
}

impl Sessions {
    pub fn new(runc_root: PathBuf) -> Self {
        Self {
            exec: Mutex::new(HashMap::new()),
            portforward: Mutex::new(HashMap::new()),
            runc_root,
            runc_bin: runtime::runc::DEFAULT_BIN.to_string(),
            counter: AtomicU64::new(0),
        }
    }

    /// Register a port-forward session, returning its one-time token.
    pub fn register_portforward(&self, session: PortForwardSession) -> String {
        let token = self.token();
        self.portforward
            .lock()
            .unwrap()
            .insert(token.clone(), session);
        token
    }

    fn take_portforward(&self, token: &str) -> Option<PortForwardSession> {
        self.portforward.lock().unwrap().remove(token)
    }

    fn token(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        core_types::Digest::sha256(format!("{n}/{nanos}").as_bytes())
            .hex()
            .to_string()
    }

    /// Register an exec session, returning its one-time token.
    pub fn register_exec(&self, session: ExecSession) -> String {
        let token = self.token();
        self.exec.lock().unwrap().insert(token.clone(), session);
        token
    }

    fn take_exec(&self, token: &str) -> Option<ExecSession> {
        self.exec.lock().unwrap().remove(token)
    }

    /// Number of pending sessions (tests/diagnostics).
    pub fn pending(&self) -> usize {
        self.exec.lock().unwrap().len()
    }
}

/// Build the streaming router.
pub fn router(sessions: Arc<Sessions>) -> Router {
    Router::new()
        .route("/exec/{token}", get(exec_ws))
        .route("/portforward/{token}", get(portforward_ws))
        .with_state(sessions)
}

/// Serve the streaming server on `addr` until `shutdown` resolves.
pub async fn serve(
    addr: SocketAddr,
    sessions: Arc<Sessions>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(?addr, "serving CRI streaming server");
    axum::serve(listener, router(sessions))
        .with_graceful_shutdown(shutdown)
        .await
}

async fn exec_ws(
    State(sessions): State<Arc<Sessions>>,
    AxPath(token): AxPath<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.protocols(["v4.channel.k8s.io", "channel.k8s.io"])
        .on_upgrade(move |socket| handle_exec(socket, sessions, token))
}

/// Frame a payload for a v4 channel: `[channel] ++ data`.
fn frame(channel: u8, data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(data.len() + 1);
    f.push(channel);
    f.extend_from_slice(data);
    f
}

async fn handle_exec(mut socket: WebSocket, sessions: Arc<Sessions>, token: String) {
    let Some(session) = sessions.take_exec(&token) else {
        let _ = socket
            .send(Message::Binary(
                frame(
                    CH_ERROR,
                    b"{\"status\":\"Failure\",\"message\":\"unknown or expired exec token\"}",
                )
                .into(),
            ))
            .await;
        return;
    };

    let runc_root = sessions.runc_root.clone();
    let bin = sessions.runc_bin.clone();
    let result = tokio::task::spawn_blocking(move || {
        runtime::runc::exec(&bin, &runc_root, &session.container_id, &session.cmd)
    })
    .await;

    match result {
        Ok(Ok(output)) => {
            if !output.stdout.is_empty() {
                let _ = socket
                    .send(Message::Binary(frame(CH_STDOUT, &output.stdout).into()))
                    .await;
            }
            if !output.stderr.is_empty() {
                let _ = socket
                    .send(Message::Binary(frame(CH_STDERR, &output.stderr).into()))
                    .await;
            }
            // v4 error channel carries a metav1.Status; success unless non-zero.
            let status = match output.status.code() {
                Some(0) => "{\"status\":\"Success\"}".to_string(),
                code => format!(
                    "{{\"status\":\"Failure\",\"reason\":\"NonZeroExitCode\",\"details\":{{\"causes\":[{{\"reason\":\"ExitCode\",\"message\":\"{}\"}}]}}}}",
                    code.unwrap_or(-1)
                ),
            };
            let _ = socket
                .send(Message::Binary(frame(CH_ERROR, status.as_bytes()).into()))
                .await;
        }
        Ok(Err(e)) => {
            let _ = socket
                .send(Message::Binary(
                    frame(
                        CH_ERROR,
                        format!("{{\"status\":\"Failure\",\"message\":\"runc exec: {e}\"}}")
                            .as_bytes(),
                    )
                    .into(),
                ))
                .await;
        }
        Err(e) => {
            let _ = socket
                .send(Message::Binary(
                    frame(
                        CH_ERROR,
                        format!("{{\"status\":\"Failure\",\"message\":\"{e}\"}}").as_bytes(),
                    )
                    .into(),
                ))
                .await;
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}

async fn portforward_ws(
    State(sessions): State<Arc<Sessions>>,
    AxPath(token): AxPath<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.protocols(["v4.channel.k8s.io", "portforward.k8s.io"])
        .on_upgrade(move |socket| handle_portforward(socket, sessions, token))
}

/// Proxy the Kubernetes port-forward WebSocket protocol to a localhost TCP
/// connection. Channels come in pairs per forwarded port: data = `2*i`,
/// error = `2*i + 1`; the first frame on each carries the port as 2 LE bytes.
/// Because pods are host-network, the container's port is reachable at
/// `127.0.0.1:<port>`.
async fn handle_portforward(socket: WebSocket, sessions: Arc<Sessions>, token: String) {
    use futures_util::{SinkExt, StreamExt};
    use std::collections::HashMap as Map;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if sessions.take_portforward(&token).is_none() {
        return;
    }
    let (sink, mut stream) = socket.split();
    let sink = Arc::new(tokio::sync::Mutex::new(sink));
    // data channel -> TCP write half
    let mut writers: Map<u8, tokio::io::WriteHalf<tokio::net::TcpStream>> = Map::new();

    while let Some(Ok(msg)) = stream.next().await {
        let Message::Binary(data) = msg else { continue };
        if data.is_empty() {
            continue;
        }
        let channel = data[0];
        let payload = &data[1..];

        // Error channels (odd) only carry the initial port header; ignore.
        if channel % 2 == 1 {
            continue;
        }
        if let std::collections::hash_map::Entry::Vacant(e) = writers.entry(channel) {
            // First data-channel frame: 2-byte LE port; open the TCP connection.
            if payload.len() < 2 {
                continue;
            }
            let port = u16::from_le_bytes([payload[0], payload[1]]);
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(tcp) => {
                    let (mut rd, wr) = tokio::io::split(tcp);
                    e.insert(wr);
                    // Pump TCP -> WS (framed on the same data channel).
                    let sink = sink.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 8192];
                        loop {
                            match rd.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let f = frame(channel, &buf[..n]);
                                    if sink
                                        .lock()
                                        .await
                                        .send(Message::Binary(f.into()))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                    // Any data after the port header goes straight to TCP.
                    if payload.len() > 2 {
                        if let Some(w) = writers.get_mut(&channel) {
                            let _ = w.write_all(&payload[2..]).await;
                        }
                    }
                }
                Err(e2) => {
                    let f = frame(
                        channel + 1,
                        format!("{{\"status\":\"Failure\",\"message\":\"connect 127.0.0.1:{port}: {e2}\"}}").as_bytes(),
                    );
                    let _ = sink.lock().await.send(Message::Binary(f.into())).await;
                }
            }
        } else if let Some(w) = writers.get_mut(&channel) {
            let _ = w.write_all(payload).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_consumed_once() {
        let s = Sessions::new(PathBuf::from("/run/x"));
        let t1 = s.register_exec(ExecSession {
            container_id: "c".into(),
            cmd: vec!["echo".into()],
            tty: false,
        });
        let t2 = s.register_exec(ExecSession {
            container_id: "c".into(),
            cmd: vec!["echo".into()],
            tty: false,
        });
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64);
        assert_eq!(s.pending(), 2);
        assert!(s.take_exec(&t1).is_some());
        assert!(s.take_exec(&t1).is_none(), "one-time");
        assert_eq!(s.pending(), 1);
    }

    #[test]
    fn frame_prefixes_channel() {
        assert_eq!(frame(CH_STDOUT, b"hi"), vec![1, b'h', b'i']);
        assert_eq!(frame(CH_ERROR, b""), vec![3]);
    }
}
