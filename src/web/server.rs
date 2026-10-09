//! Axum-based web server for the NetScope dashboard.
//!
//! Responsibilities:
//! - Serve the embedded static frontend (HTML/CSS/JS)
//! - Accept WebSocket connections and broadcast real-time data
//! - Handle client requests (e.g. packet detail lookup)
//!
//! The server runs on a dedicated tokio runtime in its own thread so that
//! the synchronous pcap capture loop on the main thread is undisturbed.

use axum::{
    Router,
    extract::{
        Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_embed::Embed;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{RwLock, Semaphore, broadcast, mpsc};
use tokio::time::Instant;

const MAX_WS_CLIENTS: usize = 32;
const MAX_WS_REQUEST_BYTES: usize = 4096;
const MAX_WS_REQUESTS_PER_SECOND: u32 = 60;
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_PACKETS: usize = 8192;
const MAX_PENDING_ALERTS: usize = 1024;

use super::messages::{
    AlertMsg, CaptureEvent, Frame, PacketDetail, PacketSample, WsClientMsg, WsServerMsg,
};
use super::packet_store::PacketStore;

#[derive(Clone)]
struct BroadcastFrame {
    frame_seq: Option<u64>,
    json: Arc<str>,
}

// ---------------------------------------------------------------------------
// Embedded static assets
// ---------------------------------------------------------------------------

#[derive(Embed)]
#[folder = "web/static/"]
struct Assets;

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

/// State shared across all axum handlers.
pub struct AppState {
    /// Broadcast channel: every connected WS client subscribes here.
    broadcast_tx: broadcast::Sender<BroadcastFrame>,
    latest_frame: RwLock<Option<BroadcastFrame>>,
    /// Packet ring buffer for on-demand detail retrieval.
    pub packet_store: RwLock<PacketStore>,
    /// Tick interval so we can tell the client in the hello message.
    pub tick_ms: u64,
    /// Optional HTTP Basic auth credentials.
    basic_auth: Option<BasicAuthCredentials>,
    origin_policy: crate::web::origin::DashboardPolicy,
    ws_clients: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
struct BasicAuthCredentials {
    username: String,
    password: String,
}

// ---------------------------------------------------------------------------
// Public API: start the server
// ---------------------------------------------------------------------------

/// Configuration for the web server.
#[derive(Debug, Clone)]
pub struct WebServerConfig {
    pub allowed_origins: Vec<String>,
    pub bind: String,
    pub port: u16,
    pub tick_ms: u64,
    pub packet_buffer: usize,
    pub tls: Option<WebServerTlsConfig>,
    pub auth: Option<WebServerAuthConfig>,
}

#[derive(Debug, Clone)]
pub struct WebServerTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WebServerAuthConfig {
    pub username: String,
    pub password: String,
}

/// Handle returned by `start()` so the capture thread can feed data in.
pub struct WebHandle {
    /// Send capture events into the web server.
    pub event_tx: mpsc::Sender<CaptureEvent>,
}

/// Start the web server in a background tokio runtime.
///
/// Returns a `WebHandle` the caller uses to push capture events.
pub fn start(config: WebServerConfig) -> Result<WebHandle, std::io::Error> {
    let WebServerConfig {
        allowed_origins,
        bind,
        port,
        tick_ms,
        packet_buffer,
        tls,
        auth,
    } = config;

    let rustls_config = if let Some(tls_config) = tls {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(std::io::Error::other)?;
        Some(rt.block_on(RustlsConfig::from_pem_file(
            &tls_config.cert_path,
            &tls_config.key_path,
        ))?)
    } else {
        None
    };

    let (event_tx, event_rx) = mpsc::channel::<CaptureEvent>(4096);
    let (broadcast_tx, _) = broadcast::channel::<BroadcastFrame>(16);

    let bind_addr = format!("{}:{}", bind, port);
    let listener = std::net::TcpListener::bind(&bind_addr)?;
    listener.set_nonblocking(true)?;
    crate::config::WebConfig::validate_remote_access(
        listener.local_addr()?.ip().is_loopback(),
        rustls_config.is_some(),
        auth.is_some(),
    )
    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    let state = Arc::new(AppState {
        broadcast_tx: broadcast_tx.clone(),
        latest_frame: RwLock::new(None),
        packet_store: RwLock::new(PacketStore::new(packet_buffer)),
        tick_ms,
        origin_policy: crate::web::origin::DashboardPolicy::new(
            &bind,
            listener.local_addr()?.port(),
            rustls_config.is_some(),
            &allowed_origins,
        )
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?,
        basic_auth: auth.map(|auth| BasicAuthCredentials {
            username: auth.username,
            password: auth.password,
        }),
        ws_clients: Arc::new(Semaphore::new(MAX_WS_CLIENTS)),
    });

    // Spawn a dedicated thread with its own tokio runtime
    let state_clone = state.clone();
    std::thread::Builder::new()
        .name("netscope-web".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("failed to build tokio runtime for web server");

            rt.block_on(async move {
                // Spawn the ingest task (reads from event_rx, broadcasts to clients)
                let ingest_state = state_clone.clone();
                tokio::spawn(ingest_task(event_rx, ingest_state));

                // Build the router
                let app = Router::new()
                    .route("/ws", get(ws_handler))
                    .route("/api/health", get(health_handler))
                    .route("/metrics", get(metrics_handler))
                    .fallback(get(static_handler))
                    .with_state(state_clone.clone())
                    .layer(middleware::from_fn_with_state(state_clone, auth_middleware));

                if let Some(rustls_config) = rustls_config {
                    let server = match axum_server::from_tcp_rustls(listener, rustls_config) {
                        Ok(server) => server,
                        Err(err) => {
                            tracing::error!(
                                "failed to start HTTPS listener on {}: {}",
                                bind_addr,
                                err
                            );
                            return;
                        }
                    };

                    println!("Web dashboard: https://{}", bind_addr);
                    tracing::info!("web dashboard listening on https://{}", bind_addr);

                    if let Err(err) = server.serve(app.into_make_service()).await {
                        tracing::error!("web server stopped unexpectedly: {}", err);
                    }
                } else {
                    let server = match axum_server::from_tcp(listener) {
                        Ok(server) => server,
                        Err(err) => {
                            tracing::error!(
                                "failed to start HTTP listener on {}: {}",
                                bind_addr,
                                err
                            );
                            return;
                        }
                    };

                    println!("Web dashboard: http://{}", bind_addr);
                    tracing::info!("web dashboard listening on http://{}", bind_addr);

                    if let Err(err) = server.serve(app.into_make_service()).await {
                        tracing::error!("web server stopped unexpectedly: {}", err);
                    }
                }
            });
        })
        .map_err(std::io::Error::other)?;

    Ok(WebHandle { event_tx })
}

// ---------------------------------------------------------------------------
// Ingest task: capture events -> broadcast + packet store
// ---------------------------------------------------------------------------

async fn ingest_task(mut rx: mpsc::Receiver<CaptureEvent>, state: Arc<AppState>) {
    let mut pending_packets: Vec<PacketSample> = Vec::new();
    let mut pending_alerts: Vec<AlertMsg> = Vec::new();

    while let Some(event) = rx.recv().await {
        match event {
            CaptureEvent::Tick(tick) => {
                let frame_seq = tick.frame_seq;
                let frame = Frame {
                    frame_seq,
                    tick,
                    packets: std::mem::take(&mut pending_packets),
                    alerts: std::mem::take(&mut pending_alerts),
                };
                broadcast_frame(&state, frame_seq, frame).await;
            }
            CaptureEvent::Packet(sample) => {
                if pending_packets.len() < MAX_PENDING_PACKETS {
                    pending_packets.push(sample);
                }
            }
            CaptureEvent::PacketStored(stored) => {
                let mut store = state.packet_store.write().await;
                store.push(stored);
            }
            CaptureEvent::Alert(alert) => {
                if pending_alerts.len() < MAX_PENDING_ALERTS {
                    pending_alerts.push(alert);
                }
            }
        }
    }

    // Flush buffered live events on shutdown so the last partial interval isn't lost.
    for sample in pending_packets {
        broadcast_message(&state, WsServerMsg::PacketSample(sample)).await;
    }
    for alert in pending_alerts {
        broadcast_message(&state, WsServerMsg::Alert(alert)).await;
    }
}

async fn broadcast_frame(state: &Arc<AppState>, frame_seq: u64, frame: Frame) {
    let msg = WsServerMsg::Frame(frame);
    match serde_json::to_string(&msg) {
        Ok(json) => {
            let frame = BroadcastFrame {
                frame_seq: Some(frame_seq),
                json: Arc::<str>::from(json),
            };
            {
                let mut latest = state.latest_frame.write().await;
                *latest = Some(frame.clone());
            }
            let _ = state.broadcast_tx.send(frame);
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to serialize websocket frame");
        }
    }
}

async fn broadcast_message(state: &Arc<AppState>, msg: WsServerMsg) {
    match serde_json::to_string(&msg) {
        Ok(json) => {
            let _ = state.broadcast_tx.send(BroadcastFrame {
                frame_seq: None,
                json: Arc::<str>::from(json),
            });
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to serialize websocket message");
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> &'static str {
    "ok"
}

async fn metrics_handler() -> Response {
    let body = crate::metrics::render_prometheus_text();
    let mut response = Response::new(axum::body::Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(crate::metrics::prometheus_content_type()),
    );
    response
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Ok(permit) = state.ws_clients.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.read_buffer_size(MAX_WS_REQUEST_BYTES)
        .max_message_size(MAX_WS_REQUEST_BYTES)
        .max_frame_size(MAX_WS_REQUEST_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            handle_ws(socket, state).await;
        })
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if !state.origin_policy.allows(request.headers(), request.uri()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(credentials) = &state.basic_auth else {
        return next.run(request).await;
    };

    let authorized =
        is_request_authorized(request.headers().get(header::AUTHORIZATION), credentials);
    if !authorized {
        return unauthorized_response();
    }

    next.run(request).await
}

fn is_request_authorized(
    authorization: Option<&axum::http::HeaderValue>,
    credentials: &BasicAuthCredentials,
) -> bool {
    let Some(value) = authorization else {
        return false;
    };

    let Ok(raw_header) = value.to_str() else {
        return false;
    };

    let Some((scheme, encoded)) = raw_header.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }

    let Ok(decoded) = BASE64_STANDARD.decode(encoded.as_bytes()) else {
        return false;
    };
    let Ok(decoded) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((username, password)) = decoded.split_once(':') else {
        return false;
    };

    let username_matches = constant_time_eq(username.as_bytes(), credentials.username.as_bytes());
    let password_matches = constant_time_eq(password.as_bytes(), credentials.password.as_bytes());

    username_matches & password_matches
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&l, &r) in left.iter().zip(right.iter()) {
        diff |= l ^ r;
    }

    diff == 0
}

fn unauthorized_response() -> Response {
    match Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"NetScope\"")
        .body(axum::body::Body::from("unauthorized"))
    {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(error = %err, "failed to build unauthorized response");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("internal error"))
                .expect("response builder failed")
        }
    }
}

struct RequestBudget {
    window_start: Instant,
    remaining: u32,
}

impl RequestBudget {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            remaining: MAX_WS_REQUESTS_PER_SECOND,
        }
    }

    fn admit(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.remaining = MAX_WS_REQUESTS_PER_SECOND;
        }
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

async fn send_ws(socket: &mut WebSocket, message: Message) -> Result<(), ()> {
    tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("ws client connected");
    let mut request_budget = RequestBudget::new(Instant::now());
    // Send hello
    let hello = WsServerMsg::Hello {
        version: env!("CARGO_PKG_VERSION").to_string(),
        tick_ms: state.tick_ms,
    };
    if let Ok(json) = serde_json::to_string(&hello)
        && send_ws(&mut socket, Message::Text(json.into()))
            .await
            .is_err()
    {
        tracing::debug!("ws client disconnected during hello send");
        return;
    }

    // Subscribe to broadcast
    let mut broadcast_rx = state.broadcast_tx.subscribe();
    let mut last_sent_frame_seq: Option<u64> = None;

    // Send the latest frame so newly connected clients start from current state.
    if let Some(frame) = { state.latest_frame.read().await.clone() } {
        last_sent_frame_seq = frame.frame_seq;
        if send_ws(
            &mut socket,
            Message::Text(frame.json.as_ref().to_owned().into()),
        )
        .await
        .is_err()
        {
            tracing::debug!("ws client disconnected during initial frame send");
            return;
        }
    }

    loop {
        tokio::select! {
            // Forward broadcasts to this client
            result = broadcast_rx.recv() => {
                match result {
                    Ok(msg) => {
                        if should_skip_frame(msg.frame_seq, last_sent_frame_seq) {
                            continue;
                        }
                        last_sent_frame_seq = msg.frame_seq.or(last_sent_frame_seq);
                        if send_ws(&mut socket, Message::Text(msg.json.as_ref().to_owned().into()))
                            .await
                            .is_err()
                        {
                            tracing::debug!("ws client disconnected during broadcast send");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("ws client lagged, skipped {} messages", n);
                        // Drop buffered backlog and resume from newest broadcast position.
                        broadcast_rx = state.broadcast_tx.subscribe();
                        // Resync by sending the newest merged frame instead of replaying history.
                        if let Some(frame) = { state.latest_frame.read().await.clone() } {
                            if !should_send_resync(frame.frame_seq, last_sent_frame_seq) {
                                continue;
                            }
                            last_sent_frame_seq = frame.frame_seq.or(last_sent_frame_seq);
                            if send_ws(&mut socket, Message::Text(frame.json.as_ref().to_owned().into()))
                                .await
                                .is_err()
                            {
                                tracing::debug!("ws client disconnected during lag recovery send");
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            // Handle messages from the client
            result = socket.recv() => {
                if result.as_ref().is_some_and(|message| message.is_ok())
                    && !request_budget.admit(Instant::now())
                {
                    tracing::debug!("ws client exceeded request rate limit");
                    break;
                }
                match result {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<WsClientMsg>(&text) {
                            Ok(client_msg) => match client_msg {
                                WsClientMsg::GetPacketDetail { id } => {
                                    let store = state.packet_store.read().await;
                                    let response = match store.get(id) {
                                        Some(stored) => WsServerMsg::PacketDetail(PacketDetail {
                                            id: stored.id,
                                            ts: stored.ts,
                                            layers: stored.layers.clone(),
                                            hex_dump: stored.hex_dump.clone(),
                                        }),
                                        None => {
                                            // Packet no longer in buffer -- ignore
                                            continue;
                                        }
                                    };
                                    drop(store);
                                    if let Ok(json) = serde_json::to_string(&response)
                                        && send_ws(&mut socket, Message::Text(json.into())).await.is_err() {
                                            tracing::debug!("ws client disconnected during packet detail send");
                                            break;
                                        }
                                }
                                WsClientMsg::PerfPing { client_ts } => {
                                    let server_ts = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64;
                                    let response = WsServerMsg::PerfPong {
                                        client_ts,
                                        server_ts,
                                    };
                                    if let Ok(json) = serde_json::to_string(&response)
                                        && send_ws(&mut socket, Message::Text(json.into())).await.is_err() {
                                            tracing::debug!("ws client disconnected during perf pong send");
                                            break;
                                        }
                                }
                            },
                            Err(err) => {
                                tracing::debug!(error = %err, "invalid ws client message");
                                let response = WsServerMsg::Error {
                                    message: "invalid request".into(),
                                };
                                if let Ok(json) = serde_json::to_string(&response)
                                    && send_ws(&mut socket, Message::Text(json.into())).await.is_err() {
                                        tracing::debug!("ws client disconnected during error response send");
                                        break;
                                    }
                            }
                        }
                    }
                    Some(Err(_)) | Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    tracing::info!("ws client disconnected");
}

fn should_skip_frame(frame_seq: Option<u64>, last_sent_frame_seq: Option<u64>) -> bool {
    match (frame_seq, last_sent_frame_seq) {
        (Some(seq), Some(last_seq)) => seq <= last_seq,
        _ => false,
    }
}

fn should_send_resync(latest_frame_seq: Option<u64>, last_sent_frame_seq: Option<u64>) -> bool {
    match latest_frame_seq {
        Some(seq) => last_sent_frame_seq != Some(seq),
        None => true,
    }
}

// ---------------------------------------------------------------------------
// Static file serving (embedded assets)
// ---------------------------------------------------------------------------

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    if path == "api" || path.starts_with("api/") {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("not found"))
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "failed to build not found response");
                Response::new(axum::body::Body::from("not found"))
            });
    }

    // Try the exact path first, then fall back to index.html (SPA)
    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(axum::body::Body::from(content.data.to_vec()))
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "failed to build static file response");
                Response::new(axum::body::Body::from("internal error"))
            })
    } else if should_serve_spa(path) {
        let content = match Assets::get("index.html") {
            Some(content) => content,
            None => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(axum::body::Body::from("not found"))
                    .unwrap_or_else(|err| {
                        tracing::error!(error = %err, "failed to build not found response");
                        Response::new(axum::body::Body::from("not found"))
                    });
            }
        };
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(axum::body::Body::from(content.data.to_vec()))
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "failed to build index.html response");
                Response::new(axum::body::Body::from("internal error"))
            })
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("not found"))
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "failed to build not found response");
                Response::new(axum::body::Body::from("not found"))
            })
    }
}

fn should_serve_spa(path: &str) -> bool {
    path.is_empty() || !path.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::messages::StatsTick;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use futures_util::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tower::util::ServiceExt;

    fn test_state(auth: Option<BasicAuthCredentials>) -> Arc<AppState> {
        let (broadcast_tx, _) = broadcast::channel::<BroadcastFrame>(16);
        Arc::new(AppState {
            broadcast_tx,
            latest_frame: RwLock::new(None),
            packet_store: RwLock::new(PacketStore::new(8)),
            tick_ms: 1000,
            basic_auth: auth,
            origin_policy: crate::web::origin::DashboardPolicy::new("127.0.0.1", 8080, false, &[])
                .unwrap(),
            ws_clients: Arc::new(Semaphore::new(MAX_WS_CLIENTS)),
        })
    }

    fn test_router(auth: Option<BasicAuthCredentials>) -> Router {
        let state = test_state(auth);
        Router::new()
            .route("/ws", get(ws_handler))
            .route("/api/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .with_state(state.clone())
            .layer(middleware::from_fn_with_state(state, auth_middleware))
    }

    async fn spawn_ws_server(
        state: Arc<AppState>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/ws", get(ws_handler))
            .with_state(state);

        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind websocket test listener");
        let addr = listener.local_addr().expect("listener addr");
        listener
            .set_nonblocking(true)
            .expect("listener nonblocking");
        let server = axum_server::from_tcp(listener).expect("create axum server");

        let handle = tokio::spawn(async move {
            let _ = server.serve(app.into_make_service()).await;
        });

        (addr, handle)
    }

    fn test_tick(frame_seq: u64) -> StatsTick {
        StatsTick {
            ts: 0.0,
            frame_seq,
            server_ts: 0,
            interval_ms: 1000,
            bytes: 0,
            packets: 0,
            mbps: 0.0,
            pps: 0.0,
            active_flows: 0,
            dispatch_drops: 0,
            dispatch_drops_total: 0,
            kernel_drops: 0,
            kernel_drops_total: 0,
            kernel_if_drops: 0,
            kernel_if_drops_total: 0,
            top_flows: Vec::new(),
        }
    }

    fn ws_upgrade_request() -> Request<Body> {
        Request::builder()
            .header(header::HOST, "127.0.0.1:8080")
            .uri("/ws")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .expect("request should build")
    }

    #[tokio::test]
    async fn foreign_origins_and_hosts_are_rejected_even_with_valid_auth() {
        let credentials = BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        };
        for auth in [None, Some(credentials)] {
            let app = test_router(auth);
            let mut request = ws_upgrade_request();
            request
                .headers_mut()
                .insert(header::ORIGIN, "http://unrelated.invalid".parse().unwrap());
            request.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64_STANDARD.encode("netscope:secret"))
                    .parse()
                    .unwrap(),
            );
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
            let request = Request::builder()
                .uri("/api/health")
                .header(header::HOST, "attacker.invalid:8080")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app.oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
    }

    #[tokio::test]
    async fn websocket_origin_policy_is_enforced_before_the_upgrade() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut state = test_state(None);
        Arc::get_mut(&mut state).unwrap().origin_policy =
            crate::web::origin::DashboardPolicy::new("127.0.0.1", addr.port(), false, &[]).unwrap();
        let app = Router::new()
            .route("/ws", get(ws_handler))
            .with_state(state.clone())
            .layer(middleware::from_fn_with_state(state, auth_middleware));
        let server = axum_server::from_tcp(listener).unwrap();
        let task = tokio::spawn(async move {
            server.serve(app.into_make_service()).await.unwrap();
        });
        let url = format!("ws://{addr}/ws");
        let mut request = url.clone().into_client_request().unwrap();
        request
            .headers_mut()
            .insert("origin", "http://unrelated.invalid".parse().unwrap());
        match tokio_tungstenite::connect_async(request).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 403)
            }
            _ => panic!("foreign origin was not rejected before upgrading"),
        }
        for origin in [None, Some(format!("http://{addr}"))] {
            let mut request = url.clone().into_client_request().unwrap();
            if let Some(origin) = origin {
                request
                    .headers_mut()
                    .insert("origin", origin.parse().unwrap());
            }
            let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
            assert_eq!(response.status().as_u16(), 101);
            socket.close(None).await.unwrap();
        }
        task.abort();
    }

    #[tokio::test]
    async fn health_without_auth_config_is_public() {
        let app = test_router(None);
        let request = Request::builder()
            .header(header::HOST, "127.0.0.1:8080")
            .uri("/api/health")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_requires_auth_when_configured() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let request = Request::builder()
            .header(header::HOST, "127.0.0.1:8080")
            .uri("/api/health")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .expect("WWW-Authenticate header should be present"),
            "Basic realm=\"NetScope\""
        );
    }

    #[tokio::test]
    async fn health_accepts_valid_basic_auth_header() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let token = BASE64_STANDARD.encode("netscope:secret");
        let request = Request::builder()
            .header(header::HOST, "127.0.0.1:8080")
            .uri("/api/health")
            .header(header::AUTHORIZATION, format!("Basic {}", token))
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_without_auth_config_is_public() {
        let app = test_router(None);
        let request = Request::builder()
            .header(header::HOST, "127.0.0.1:8080")
            .uri("/metrics")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content type header should be present"),
            crate::metrics::prometheus_content_type()
        );
    }

    #[tokio::test]
    async fn metrics_requires_auth_when_configured() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let request = Request::builder()
            .header(header::HOST, "127.0.0.1:8080")
            .uri("/metrics")
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_accepts_valid_basic_auth_header() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let token = BASE64_STANDARD.encode("netscope:secret");
        let request = Request::builder()
            .header(header::HOST, "127.0.0.1:8080")
            .uri("/metrics")
            .header(header::AUTHORIZATION, format!("Basic {}", token))
            .body(Body::empty())
            .expect("request should build");

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        let body = String::from_utf8(body.to_vec()).expect("response body should be valid utf8");
        assert!(body.contains("netscope_build_info"));
    }

    #[tokio::test]
    async fn ws_requires_auth_when_configured() {
        let app = test_router(Some(BasicAuthCredentials {
            username: "netscope".into(),
            password: "secret".into(),
        }));
        let request = ws_upgrade_request();

        let response = app.oneshot(request).await.expect("router should respond");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ws_connection_succeeds_without_auth() {
        let state = test_state(None);
        let (addr, server_handle) = spawn_ws_server(state.clone()).await;

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect websocket");

        let hello = socket.next().await.expect("hello").expect("hello msg");
        let hello_text = match hello {
            WsMessage::Text(t) => t,
            other => panic!("unexpected: {other:?}"),
        };
        let hello_json: serde_json::Value = serde_json::from_str(&hello_text).expect("hello json");
        assert_eq!(hello_json["type"], "hello");

        server_handle.abort();
    }

    #[test]
    fn ws_skip_frame_rejects_duplicates() {
        assert!(should_skip_frame(Some(10), Some(10)));
        assert!(should_skip_frame(Some(9), Some(10)));
        assert!(!should_skip_frame(Some(11), Some(10)));
        assert!(!should_skip_frame(None, Some(10)));
    }

    #[test]
    fn ws_resync_skips_duplicate_latest_frame() {
        assert!(should_send_resync(Some(10), None));
        assert!(should_send_resync(Some(11), Some(10)));
        assert!(!should_send_resync(Some(10), Some(10)));
        assert!(should_send_resync(None, Some(10)));
    }

    #[test]
    fn websocket_request_budget_expires_and_rearms() {
        let now = Instant::now();
        let mut budget = RequestBudget::new(now);
        for _ in 0..MAX_WS_REQUESTS_PER_SECOND {
            assert!(budget.admit(now));
        }
        assert!(!budget.admit(now + Duration::from_millis(999)));
        assert!(budget.admit(now + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn websocket_connection_limit_releases_slots_after_disconnect() {
        let state = test_state(None);
        let (addr, server_handle) = spawn_ws_server(state.clone()).await;
        let url = format!("ws://{addr}/ws");
        let mut sockets = Vec::new();
        for _ in 0..MAX_WS_CLIENTS {
            let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
            socket.next().await.unwrap().unwrap(); // hello confirms upgrade completion
            sockets.push(socket);
        }
        match tokio_tungstenite::connect_async(&url).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 503);
            }
            _ => panic!("websocket connection limit was not enforced"),
        }
        let mut socket = sockets.pop().unwrap();
        socket.close(None).await.unwrap();
        drop(socket);
        let permit = tokio::time::timeout(Duration::from_secs(2), state.ws_clients.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap();
        server_handle.abort();
    }

    #[tokio::test]
    async fn oversized_and_fragmented_websocket_requests_disconnect() {
        use tokio_tungstenite::tungstenite::protocol::frame::{
            Frame,
            coding::{Data, OpCode},
        };
        let state = test_state(None);
        let (addr, server_handle) = spawn_ws_server(state.clone()).await;
        let url = format!("ws://{addr}/ws");
        for fragmented in [false, true] {
            let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
            socket.next().await.unwrap().unwrap();
            if fragmented {
                let half = MAX_WS_REQUEST_BYTES / 2;
                socket
                    .send(WsMessage::Frame(Frame::message(
                        vec![b' '; half],
                        OpCode::Data(Data::Text),
                        false,
                    )))
                    .await
                    .unwrap();
                socket
                    .send(WsMessage::Frame(Frame::message(
                        vec![b' '; half + 1],
                        OpCode::Data(Data::Continue),
                        true,
                    )))
                    .await
                    .unwrap();
            } else {
                socket
                    .send(WsMessage::Text(" ".repeat(MAX_WS_REQUEST_BYTES + 1)))
                    .await
                    .unwrap();
            }
            let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap();
            assert!(matches!(
                response,
                None | Some(Err(_)) | Some(Ok(WsMessage::Close(_)))
            ));
        }
        server_handle.abort();
    }

    #[tokio::test]
    async fn ingest_bounds_samples_when_ticks_are_missing() {
        let state = test_state(None);
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(ingest_task(rx, state.clone()));
        for id in 0..=MAX_PENDING_PACKETS {
            tx.send(CaptureEvent::Packet(PacketSample {
                id: id as u64,
                ts: 0.0,
                len: 0,
                protocol: String::new(),
                src: String::new(),
                dst: String::new(),
                info: String::new(),
            }))
            .await
            .unwrap();
        }
        tx.send(CaptureEvent::Tick(test_tick(1))).await.unwrap();
        drop(tx);
        task.await.unwrap();
        let frame = state.latest_frame.read().await;
        let json: serde_json::Value = serde_json::from_str(&frame.as_ref().unwrap().json).unwrap();
        assert_eq!(
            json["packets"].as_array().unwrap().len(),
            MAX_PENDING_PACKETS
        );
    }

    #[tokio::test]
    async fn ws_happy_path_receives_hello_and_frame() {
        let state = test_state(None);
        let (addr, server_handle) = spawn_ws_server(state.clone()).await;

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect websocket");

        let hello = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("hello timeout")
            .expect("hello message")
            .expect("hello result");
        let hello_text = match hello {
            WsMessage::Text(text) => text,
            other => panic!("unexpected hello message: {other:?}"),
        };
        let hello_json: serde_json::Value = serde_json::from_str(&hello_text).expect("hello json");
        assert_eq!(hello_json["type"], "hello");

        let frame_seq = 1;
        let tick = test_tick(frame_seq);
        let frame = Frame {
            frame_seq,
            tick,
            packets: Vec::new(),
            alerts: Vec::new(),
        };
        broadcast_frame(&state, frame_seq, frame).await;

        let msg = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("frame timeout")
            .expect("frame message")
            .expect("frame result");
        let frame_text = match msg {
            WsMessage::Text(text) => text,
            other => panic!("unexpected frame message: {other:?}"),
        };
        let frame_json: serde_json::Value = serde_json::from_str(&frame_text).expect("frame json");
        assert_eq!(frame_json["type"], "frame");
        assert_eq!(frame_json["frame_seq"].as_u64(), Some(frame_seq));

        server_handle.abort();
    }

    #[tokio::test]
    async fn ws_lag_recovery_no_duplicate_after_reconnect() {
        let state = test_state(None);
        let (addr, server_handle) = spawn_ws_server(state.clone()).await;

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("first connect");

        let _hello = socket.next().await.expect("hello").expect("hello msg");

        let frame1 = Frame {
            frame_seq: 1,
            tick: test_tick(1),
            packets: Vec::new(),
            alerts: Vec::new(),
        };
        broadcast_frame(&state, 1, frame1).await;

        let msg = socket.next().await.expect("frame 1").expect("msg");
        let text = match msg {
            WsMessage::Text(t) => t,
            other => panic!("unexpected: {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert_eq!(json["frame_seq"], 1);

        drop(socket);

        let frame2 = Frame {
            frame_seq: 2,
            tick: test_tick(2),
            packets: Vec::new(),
            alerts: Vec::new(),
        };
        broadcast_frame(&state, 2, frame2).await;

        let (mut socket2, _) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("reconnect");

        let hello2 = socket2
            .next()
            .await
            .expect("hello after reconnect")
            .expect("msg");
        let hello2_text = match hello2 {
            WsMessage::Text(t) => t,
            other => panic!("unexpected: {other:?}"),
        };
        let hello2_json: serde_json::Value = serde_json::from_str(&hello2_text).expect("parse");
        assert_eq!(hello2_json["type"], "hello");

        let resync = socket2.next().await.expect("resync").expect("msg");
        let resync_text = match resync {
            WsMessage::Text(t) => t,
            other => panic!("unexpected: {other:?}"),
        };
        let resync_json: serde_json::Value = serde_json::from_str(&resync_text).expect("parse");
        assert_eq!(resync_json["type"], "frame");
        assert_eq!(resync_json["frame_seq"], 2);

        let frame3 = Frame {
            frame_seq: 3,
            tick: test_tick(3),
            packets: Vec::new(),
            alerts: Vec::new(),
        };
        broadcast_frame(&state, 3, frame3).await;

        let msg = socket2.next().await.expect("frame 3").expect("msg");
        let text = match msg {
            WsMessage::Text(t) => t,
            other => panic!("unexpected: {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert_eq!(json["frame_seq"], 3);

        server_handle.abort();
    }
}
