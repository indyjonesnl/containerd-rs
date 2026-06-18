//! CRI exec/attach/port-forward streaming server.
//!
//! The CRI `Exec`/`Attach`/`PortForward` RPCs do not stream over the gRPC
//! connection — they return a one-time URL into this separate HTTP server, which
//! the kubelet then connects to and upgrades the connection.
//!
//! The **kubelet→runtime leg is SPDY/3.1** (Kubernetes KEP-4006 keeps this leg on
//! SPDY permanently; the WebSocket transition only covers kubectl↔apiserver↔
//! kubelet). So `kubectl exec/attach/port-forward` only work over SPDY — see
//! [`crate::spdy`]. We also keep WebSocket (`v4.channel.k8s.io`) handlers as a
//! fallback for clients that connect that way (e.g. crictl). Each endpoint
//! branches on the request's `Upgrade` header. Frames carry the Kubernetes
//! remotecommand channels: stdin=0, stdout=1, stderr=2, error=3.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path as AxPath, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::spdy;

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

/// A pending attach session, consumed when its URL is dialed.
#[derive(Debug, Clone)]
pub struct AttachSession {
    pub container_id: String,
}

/// A live container-output frame: `(channel, bytes)` where channel 1=stdout,
/// 2=stderr (matching the v4 streaming channels).
pub type LiveFrame = (u8, Vec<u8>);

/// One-time-token registry for streaming sessions, shared between the CRI
/// service (which registers) and the HTTP server (which consumes).
pub struct Sessions {
    exec: Mutex<HashMap<String, ExecSession>>,
    portforward: Mutex<HashMap<String, PortForwardSession>>,
    attach: Mutex<HashMap<String, AttachSession>>,
    /// Per-running-container live-output broadcast buses (for Attach / log follow).
    live: Mutex<HashMap<String, tokio::sync::broadcast::Sender<LiveFrame>>>,
    runc_root: PathBuf,
    runc_bin: String,
    counter: AtomicU64,
}

impl Sessions {
    pub fn new(runc_root: PathBuf) -> Self {
        Self {
            exec: Mutex::new(HashMap::new()),
            portforward: Mutex::new(HashMap::new()),
            attach: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            runc_root,
            runc_bin: runtime::runc::DEFAULT_BIN.to_string(),
            counter: AtomicU64::new(0),
        }
    }

    /// Get (creating if needed) the live-output broadcast sender for a container.
    pub fn live_channel(&self, container_id: &str) -> tokio::sync::broadcast::Sender<LiveFrame> {
        self.live
            .lock()
            .unwrap()
            .entry(container_id.to_string())
            .or_insert_with(|| tokio::sync::broadcast::channel(512).0)
            .clone()
    }

    /// Subscribe to a container's live output, if it is currently running.
    pub fn subscribe_live(
        &self,
        container_id: &str,
    ) -> Option<tokio::sync::broadcast::Receiver<LiveFrame>> {
        self.live
            .lock()
            .unwrap()
            .get(container_id)
            .map(|s| s.subscribe())
    }

    /// Drop a container's live bus (on exit); subscribers then see `Closed`.
    pub fn close_live(&self, container_id: &str) {
        self.live.lock().unwrap().remove(container_id);
    }

    /// Register an attach session, returning its one-time token.
    pub fn register_attach(&self, session: AttachSession) -> String {
        let token = self.token();
        self.attach.lock().unwrap().insert(token.clone(), session);
        token
    }

    fn take_attach(&self, token: &str) -> Option<AttachSession> {
        self.attach.lock().unwrap().remove(token)
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

/// Build the streaming router. The kubelet's remotecommand client dials these
/// with **POST** (port-forward with GET), so accept any method — like the Go CRI
/// streaming server, which registers both GET and POST.
pub fn router(sessions: Arc<Sessions>) -> Router {
    Router::new()
        .route("/exec/{token}", any(exec_entry))
        .route("/attach/{token}", any(attach_entry))
        .route("/portforward/{token}", any(portforward_entry))
        .with_state(sessions)
}

/// Which streaming endpoint a SPDY upgrade is for.
#[derive(Clone, Copy)]
enum Endpoint {
    Exec,
    Attach,
    PortForward,
}

/// True if the request is an HTTP/1.1 upgrade to SPDY/3.1 (the kubelet's client).
fn wants_spdy(headers: &axum::http::HeaderMap) -> bool {
    let up = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    up.eq_ignore_ascii_case("SPDY/3.1")
}

/// Respond `101 Switching Protocols` for a SPDY upgrade and drive the chosen
/// endpoint over the upgraded byte stream in a background task.
fn spdy_upgrade(
    mut req: Request,
    sessions: Arc<Sessions>,
    token: String,
    endpoint: Endpoint,
) -> Response {
    // Negotiate the remotecommand subprotocol and echo it back in the 101, as the
    // Go streaming server does. We implement v4 (streamType streams + an error
    // stream carrying the exit-code metav1.Status); without echoing this header
    // the client mis-handles the success/exit-code status on close.
    let offered: Vec<String> = req
        .headers()
        .get_all("X-Stream-Protocol-Version")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .collect();
    let negotiated = if offered.iter().any(|p| p == "v4.channel.k8s.io") {
        "v4.channel.k8s.io".to_string()
    } else {
        offered
            .first()
            .cloned()
            .unwrap_or_else(|| "v4.channel.k8s.io".to_string())
    };
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "spdy upgrade failed");
                return;
            }
        };
        let io = hyper_util::rt::TokioIo::new(upgraded);
        let server = match spdy::serve(io).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "spdy handshake failed");
                return;
            }
        };
        tracing::info!("spdy connection established");
        match endpoint {
            Endpoint::Exec => spdy_exec(server, sessions, token).await,
            Endpoint::Attach => spdy_attach(server, sessions, token).await,
            Endpoint::PortForward => spdy_portforward(server, sessions, token).await,
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "SPDY/3.1")
        .header("X-Stream-Protocol-Version", negotiated)
        .body(axum::body::Body::empty())
        .unwrap()
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

async fn exec_entry(
    State(sessions): State<Arc<Sessions>>,
    AxPath(token): AxPath<String>,
    req: Request,
) -> Response {
    tracing::info!(method = %req.method(), upgrade = ?req.headers().get(header::UPGRADE), "exec stream request");
    if wants_spdy(req.headers()) {
        return spdy_upgrade(req, sessions, token, Endpoint::Exec);
    }
    let (mut parts, _) = req.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws
            .protocols(["v4.channel.k8s.io", "channel.k8s.io"])
            .on_upgrade(move |socket| handle_exec(socket, sessions, token)),
        Err(rej) => rej.into_response(),
    }
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

async fn attach_entry(
    State(sessions): State<Arc<Sessions>>,
    AxPath(token): AxPath<String>,
    req: Request,
) -> Response {
    if wants_spdy(req.headers()) {
        return spdy_upgrade(req, sessions, token, Endpoint::Attach);
    }
    let (mut parts, _) = req.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws
            .protocols(["v4.channel.k8s.io", "channel.k8s.io"])
            .on_upgrade(move |socket| handle_attach(socket, sessions, token)),
        Err(rej) => rej.into_response(),
    }
}

/// Stream a running container's live stdout/stderr to the attach WebSocket,
/// framed on the v4 channels, until the container exits (bus closes).
async fn handle_attach(mut socket: WebSocket, sessions: Arc<Sessions>, token: String) {
    let Some(session) = sessions.take_attach(&token) else {
        return;
    };
    let Some(mut rx) = sessions.subscribe_live(&session.container_id) else {
        let _ = socket
            .send(Message::Binary(
                frame(
                    CH_ERROR,
                    b"{\"status\":\"Failure\",\"message\":\"container not running\"}",
                )
                .into(),
            ))
            .await;
        return;
    };
    loop {
        match rx.recv().await {
            Ok((channel, data)) => {
                if socket
                    .send(Message::Binary(frame(channel, &data).into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    let _ = socket
        .send(Message::Binary(
            frame(CH_ERROR, b"{\"status\":\"Success\"}").into(),
        ))
        .await;
    let _ = socket.send(Message::Close(None)).await;
}

async fn portforward_entry(
    State(sessions): State<Arc<Sessions>>,
    AxPath(token): AxPath<String>,
    req: Request,
) -> Response {
    if wants_spdy(req.headers()) {
        return spdy_upgrade(req, sessions, token, Endpoint::PortForward);
    }
    let (mut parts, _) = req.into_parts();
    match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws
            .protocols(["v4.channel.k8s.io", "portforward.k8s.io"])
            .on_upgrade(move |socket| handle_portforward(socket, sessions, token)),
        Err(rej) => rej.into_response(),
    }
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

// ===================== SPDY/3.1 handlers (kubelet path) =====================

/// Collect the inbound remotecommand streams the client opens up front. Returns
/// once the mandatory set has arrived (or a short idle timeout elapses).
/// `(error_id, stdout_id, stderr_id, stdin_rx)`.
async fn collect_rc_streams<W>(
    server: &mut spdy::SpdyServer<W>,
    want_stdin: bool,
    want_stderr: bool,
) -> (
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
)
where
    W: AsyncWriteExt + Unpin,
{
    let (mut error_id, mut stdout_id, mut stderr_id, mut stdin_rx) = (None, None, None, None);
    loop {
        let have = error_id.is_some()
            && stdout_id.is_some()
            && (!want_stdin || stdin_rx.is_some())
            && (!want_stderr || stderr_id.is_some());
        if have {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(10), server.accept()).await {
            Ok(Some(stream)) => match stream.stream_type() {
                Some(spdy::ST_ERROR) => error_id = Some(stream.id),
                Some(spdy::ST_STDOUT) => stdout_id = Some(stream.id),
                Some(spdy::ST_STDERR) => stderr_id = Some(stream.id),
                Some(spdy::ST_STDIN) => stdin_rx = Some(stream.data),
                Some(spdy::ST_RESIZE) => {
                    // Resize is best-effort (no PTY yet): drain so the channel
                    // never backs up.
                    let mut d = stream.data;
                    tokio::spawn(async move { while d.recv().await.is_some() {} });
                }
                _ => {}
            },
            _ => break, // closed or idle
        }
    }
    (error_id, stdout_id, stderr_id, stdin_rx)
}

async fn spdy_exec<W>(mut server: spdy::SpdyServer<W>, sessions: Arc<Sessions>, token: String)
where
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let writer = server.writer.clone();
    let Some(session) = sessions.take_exec(&token) else {
        let _ = writer.goaway(0).await;
        return;
    };
    let (error_id, stdout_id, stderr_id, stdin_rx) =
        collect_rc_streams(&mut server, true, !session.tty).await;

    let handle = match runtime::runc::exec_streaming(
        &sessions.runc_bin,
        &sessions.runc_root,
        &session.container_id,
        &session.cmd,
        session.tty,
    ) {
        Ok(h) => h,
        Err(e) => {
            if let Some(eid) = error_id {
                let _ = writer
                    .send_data(eid, true, &spdy::status_failure(&format!("runc exec: {e}")))
                    .await;
            }
            let _ = writer.goaway(0).await;
            return;
        }
    };
    let runtime::runc::ExecHandle {
        mut child,
        mut stdin,
        mut stdout,
        stderr,
    } = handle;

    // stdin: client -> process (detached; may never close).
    if let Some(mut rx) = stdin_rx {
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                if stdin.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            // Dropping `stdin` here closes the process's stdin (EOF).
        });
    }

    // stdout/stderr: process -> client. Await these before the exit status so the
    // final output is delivered first.
    let mut pumps = Vec::new();
    if let Some(oid) = stdout_id {
        let w = writer.clone();
        pumps.push(tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if w.send_data(oid, false, &buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }));
    }
    if let (Some(eid), Some(mut se)) = (stderr_id, stderr) {
        let w = writer.clone();
        pumps.push(tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match se.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if w.send_data(eid, false, &buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }));
    }

    let code = child.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
    for p in pumps {
        let _ = p.await;
    }
    if let Some(eid) = error_id {
        let _ = writer.send_data(eid, true, &spdy::status_exit(code)).await;
    }
    let _ = writer.goaway(0).await;
}

async fn spdy_attach<W>(mut server: spdy::SpdyServer<W>, sessions: Arc<Sessions>, token: String)
where
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let writer = server.writer.clone();
    let Some(session) = sessions.take_attach(&token) else {
        let _ = writer.goaway(0).await;
        return;
    };
    let (error_id, stdout_id, stderr_id, _) = collect_rc_streams(&mut server, false, true).await;

    let Some(mut rx) = sessions.subscribe_live(&session.container_id) else {
        if let Some(eid) = error_id {
            let _ = writer
                .send_data(eid, true, &spdy::status_failure("container not running"))
                .await;
        }
        let _ = writer.goaway(0).await;
        return;
    };
    loop {
        match rx.recv().await {
            Ok((channel, data)) => {
                let target = if channel == CH_STDERR {
                    stderr_id
                } else {
                    stdout_id
                };
                if let Some(id) = target {
                    if writer.send_data(id, false, &data).await.is_err() {
                        break;
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    if let Some(eid) = error_id {
        let _ = writer.send_data(eid, true, &spdy::status_success()).await;
    }
    let _ = writer.goaway(0).await;
}

async fn spdy_portforward<W>(
    mut server: spdy::SpdyServer<W>,
    sessions: Arc<Sessions>,
    token: String,
) where
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let writer = server.writer.clone();
    if sessions.take_portforward(&token).is_none() {
        let _ = writer.goaway(0).await;
        return;
    }
    // Per forwarded port the client opens an `error` stream and a `data` stream,
    // both carrying a `port` header. Connect localhost TCP on the data stream
    // (pods are host-network) and pump bidirectionally.
    let mut error_ids: HashMap<u16, u32> = HashMap::new();
    while let Some(stream) = server.accept().await {
        let port: u16 = spdy::header(&stream.headers, spdy::HEADER_PORT)
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let stype = stream.stream_type().map(str::to_string);
        if stype.as_deref() == Some(spdy::ST_ERROR) {
            error_ids.insert(port, stream.id);
            continue;
        }
        // data stream
        let data_id = stream.id;
        let mut rx = stream.data;
        let w = writer.clone();
        let err_id = error_ids.get(&port).copied().unwrap_or(data_id);
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(tcp) => {
                let (mut rd, mut wr) = tokio::io::split(tcp);
                // client -> TCP
                tokio::spawn(async move {
                    while let Some(chunk) = rx.recv().await {
                        if wr.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                });
                // TCP -> client (on the data stream)
                let w2 = w.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        match rd.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if w2.send_data(data_id, false, &buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
            Err(e) => {
                let _ = w
                    .send_data(
                        err_id,
                        true,
                        &spdy::status_failure(&format!("connect 127.0.0.1:{port}: {e}")),
                    )
                    .await;
            }
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
