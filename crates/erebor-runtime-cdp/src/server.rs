use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use cdp_protocol::{
    fetch, network, page, runtime as cdp_runtime, target,
    types::{CallId, Event as ProtocolEvent, Method},
};
use erebor_runtime_audit::{FilteredAuditSink, JsonlAuditSink};
use erebor_runtime_core::{AuditRecord, AuditSink, LocalEnforcementEngine, RuntimeAuditConfig};
use erebor_runtime_events::{
    ActionKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata, TargetRef,
};
use erebor_runtime_policy::{Decision, PolicySet};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::{Error as WebSocketError, Message},
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, info, warn};

use crate::{
    decode_cdp_command, decode_cdp_event, enforce_cdp_command_with_client_state_outcome,
    enforce_cdp_event_outcome, observe_cdp_event, BrowserTargetId, CdpCommand,
    CdpEnforcementAction, CdpError, CdpEvent, CdpSessionContext, CdpSessionState,
    ClientTargetSessions, GovernedCdpCommand,
};

type CdpEngine = LocalEnforcementEngine<PolicySet>;
const OBSERVER_BOOTSTRAP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const OBSERVER_RECONNECT_DELAY: Duration = Duration::from_millis(250);
const OBSERVER_SET_DISCOVER_TARGETS_ID: CallId = 10_000;
const OBSERVER_SET_AUTO_ATTACH_ID: CallId = 10_001;
const OBSERVER_GET_TARGETS_ID: CallId = 10_002;
const OBSERVER_PAGE_ENABLE_ID: CallId = 10_003;
const OBSERVER_RUNTIME_ENABLE_ID: CallId = 10_004;
const OBSERVER_GET_FRAME_TREE_ID: CallId = 10_005;
const OBSERVER_FETCH_ENABLE_ID: CallId = 10_006;
const OBSERVER_TARGET_COMMAND_ID_START: CallId = 20_000;
const HTTP_DISCOVERY_HEADER_LIMIT: usize = 8192;
const HTTP_DISCOVERY_PEEK_ATTEMPTS: usize = 8;
const HTTP_DISCOVERY_PEEK_TIMEOUT: Duration = Duration::from_millis(250);
const UPSTREAM_HTTP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
struct CdpAuditRecorder {
    sink: FilteredAuditSink<JsonlAuditSink>,
}

impl CdpAuditRecorder {
    fn new(path: impl Into<PathBuf>, audit: RuntimeAuditConfig) -> Self {
        let path = path.into();
        Self {
            sink: FilteredAuditSink::new(JsonlAuditSink::new(path), audit),
        }
    }

    fn record(&self, record: &AuditRecord) {
        if let Err(error) = self.sink.record(record) {
            warn!(
                path = %self.sink.inner().path().display(),
                error = %error,
                "failed to append CDP audit record"
            );
        }
    }
}

fn record_audit_outcome(audit_recorder: Option<&CdpAuditRecorder>, record: Option<&AuditRecord>) {
    let (Some(audit_recorder), Some(record)) = (audit_recorder, record) else {
        return;
    };

    audit_recorder.record(record);
}

#[derive(Clone, Debug, PartialEq)]
pub struct CdpProxyServerConfig {
    pub listen: SocketAddr,
    pub browser_url: String,
    pub context: CdpSessionContext,
    pub audit_jsonl: Option<PathBuf>,
    pub audit: RuntimeAuditConfig,
}

pub struct CdpProxyServer {
    listener: TcpListener,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
    session_state: CdpSessionState,
    audit_recorder: Option<CdpAuditRecorder>,
}

impl CdpProxyServer {
    pub async fn bind(config: CdpProxyServerConfig, engine: CdpEngine) -> Result<Self, CdpError> {
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(CdpError::io)?;
        let local_addr = listener.local_addr().map_err(CdpError::io)?;

        info!(
            listen = %local_addr,
            "CDP proxy server bound"
        );

        let session_state = CdpSessionState::from_browser_url(&config.browser_url);
        let engine = Arc::new(engine);
        let audit_recorder = config
            .audit_jsonl
            .clone()
            .map(|path| CdpAuditRecorder::new(path, config.audit.clone()));
        if should_start_browser_state_observer(&config.browser_url) {
            let browser_url = config.browser_url.clone();
            let context = config.context.clone();
            let observer_state = session_state.clone();
            let observer_engine = Arc::clone(&engine);
            let observer_audit = audit_recorder.clone();
            let handle = tokio::spawn(async move {
                run_browser_state_observer(
                    browser_url,
                    context,
                    observer_state,
                    observer_engine,
                    observer_audit,
                )
                .await;
            });
            drop(handle);
        } else if should_start_page_state_observer(&config.browser_url) {
            let browser_url = config.browser_url.clone();
            let context = config.context.clone();
            let observer_state = session_state.clone();
            let observer_engine = Arc::clone(&engine);
            let observer_audit = audit_recorder.clone();
            let handle = tokio::spawn(async move {
                run_page_state_observer(
                    browser_url,
                    context,
                    observer_state,
                    observer_engine,
                    observer_audit,
                )
                .await;
            });
            drop(handle);
        }

        Ok(Self {
            listener,
            browser_url: config.browser_url,
            engine,
            context: config.context,
            session_state,
            audit_recorder,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, CdpError> {
        self.listener.local_addr().map_err(CdpError::io)
    }

    pub async fn run(self) -> Result<(), CdpError> {
        let local_addr = self.local_addr()?;
        info!(listen = %local_addr, "CDP proxy server accepting connections");

        loop {
            let (stream, address) = self.listener.accept().await.map_err(CdpError::io)?;
            let browser_url = self.browser_url.clone();
            let engine = Arc::clone(&self.engine);
            let context = self.context.clone();
            let session_state = self.session_state.clone();
            let audit_recorder = self.audit_recorder.clone();
            debug!(client = %address, "accepted CDP proxy connection");
            let handle = tokio::spawn(async move {
                match handle_client_connection(
                    stream,
                    local_addr,
                    browser_url,
                    engine,
                    context,
                    session_state,
                    audit_recorder,
                )
                .await
                {
                    Ok(()) => debug!(client = %address, "CDP proxy connection closed"),
                    Err(error) => {
                        warn!(
                            client = %address,
                            error = %error,
                            "CDP proxy connection failed"
                        );
                    }
                }
            });
            drop(handle);
        }
    }
}

async fn handle_client_connection(
    mut stream: TcpStream,
    local_addr: SocketAddr,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
    session_state: CdpSessionState,
    audit_recorder: Option<CdpAuditRecorder>,
) -> Result<(), CdpError> {
    if handle_http_discovery_if_present(&mut stream, local_addr, &browser_url).await? {
        return Ok(());
    }

    proxy_connection(
        stream,
        browser_url,
        engine,
        context,
        session_state,
        audit_recorder,
    )
    .await
}

async fn handle_http_discovery_if_present(
    stream: &mut TcpStream,
    local_addr: SocketAddr,
    browser_url: &str,
) -> Result<bool, CdpError> {
    let Some(request) = peek_http_request(stream).await? else {
        return Ok(false);
    };
    if is_websocket_upgrade(&request) {
        return Ok(false);
    }

    let response = discovery_http_response(&request, local_addr, browser_url).await;
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(CdpError::io)?;
    stream.shutdown().await.map_err(CdpError::io)?;
    Ok(true)
}

async fn peek_http_request(stream: &TcpStream) -> Result<Option<String>, CdpError> {
    let mut buffer = [0_u8; HTTP_DISCOVERY_HEADER_LIMIT];

    for _attempt in 0..HTTP_DISCOVERY_PEEK_ATTEMPTS {
        let bytes_read = match timeout(HTTP_DISCOVERY_PEEK_TIMEOUT, stream.peek(&mut buffer)).await
        {
            Ok(Ok(bytes_read)) => bytes_read,
            Ok(Err(error)) => return Err(CdpError::io(error)),
            Err(_) => return Ok(None),
        };
        if bytes_read == 0 {
            return Ok(None);
        }
        if !looks_like_http_request(&buffer[..bytes_read]) {
            return Ok(None);
        }
        if let Some(header_end) = find_http_header_end(&buffer[..bytes_read]) {
            return Ok(Some(
                String::from_utf8_lossy(&buffer[..header_end]).into_owned(),
            ));
        }

        sleep(Duration::from_millis(10)).await;
    }

    Ok(None)
}

fn looks_like_http_request(bytes: &[u8]) -> bool {
    bytes.starts_with(b"GET ")
        || bytes.starts_with(b"PUT ")
        || bytes.starts_with(b"POST ")
        || bytes.starts_with(b"OPTIONS ")
        || bytes.starts_with(b"HEAD ")
}

fn find_http_header_end(bytes: &[u8]) -> Option<usize> {
    if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some(position + 4);
    }

    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2)
}

fn is_websocket_upgrade(request: &str) -> bool {
    request.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };

        name.trim().eq_ignore_ascii_case("upgrade")
            && value.trim().eq_ignore_ascii_case("websocket")
    })
}

async fn discovery_http_response(
    request: &str,
    local_addr: SocketAddr,
    browser_url: &str,
) -> String {
    let Some((method, path)) = request_line(request) else {
        return http_response(
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            "bad request",
        );
    };
    let governed_ws_url = governed_websocket_url(request, local_addr);

    match discovery_payload(method, path, &governed_ws_url, browser_url).await {
        Some(payload) => http_response(
            200,
            "OK",
            "application/json; charset=utf-8",
            &payload.to_string(),
        ),
        None => http_response(404, "Not Found", "text/plain; charset=utf-8", "not found"),
    }
}

fn request_line(request: &str) -> Option<(&str, &str)> {
    let mut parts = request.lines().next()?.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

fn governed_websocket_url(request: &str, local_addr: SocketAddr) -> String {
    let host = request
        .lines()
        .find_map(|line| {
            line.strip_prefix("Host: ")
                .or_else(|| line.strip_prefix("host: "))
        })
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| socket_host(local_addr));

    format!("ws://{host}/")
}

fn socket_host(address: SocketAddr) -> String {
    if address.ip().is_ipv6() {
        format!("[{}]:{}", address.ip(), address.port())
    } else {
        address.to_string()
    }
}

async fn discovery_payload(
    method: &str,
    path: &str,
    governed_ws_url: &str,
    browser_url: &str,
) -> Option<Value> {
    let path_without_query = path.split('?').next().unwrap_or(path);

    if method == "GET" && matches!(path_without_query, "/json/version" | "/json" | "/json/list") {
        if let Some(mut payload) =
            upstream_discovery_payload(browser_url, method, path_without_query).await
        {
            rewrite_discovery_websocket_urls(&mut payload, governed_ws_url);
            return Some(payload);
        }
    }

    match (method, path_without_query) {
        ("GET", "/json/version") => Some(json!({
            "Browser": "Erebor Runtime Governed Browser",
            "Protocol-Version": "1.3",
            "User-Agent": "Erebor Runtime",
            "V8-Version": "",
            "WebKit-Version": "",
            "webSocketDebuggerUrl": governed_ws_url
        })),
        ("GET", "/json") | ("GET", "/json/list") => {
            Some(json!([target_descriptor(governed_ws_url)]))
        }
        ("GET", "/json/protocol") => Some(json!({
            "version": {
                "major": "1",
                "minor": "3"
            },
            "domains": []
        })),
        _ => None,
    }
}

async fn upstream_discovery_payload(browser_url: &str, method: &str, path: &str) -> Option<Value> {
    let (host, port) = devtools_http_host(browser_url)?;
    let address = format!("{host}:{port}");
    let mut stream = timeout(
        UPSTREAM_HTTP_DISCOVERY_TIMEOUT,
        TcpStream::connect(address.as_str()),
    )
    .await
    .ok()?
    .ok()?;
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    timeout(
        UPSTREAM_HTTP_DISCOVERY_TIMEOUT,
        stream.write_all(request.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;

    let (head, body) = read_upstream_http_response(&mut stream).await?;
    if !head.starts_with("HTTP/1.1 200 ") && !head.starts_with("HTTP/1.0 200 ") {
        return None;
    }

    serde_json::from_str(&body).ok()
}

async fn read_upstream_http_response(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let bytes_read = timeout(UPSTREAM_HTTP_DISCOVERY_TIMEOUT, stream.read(&mut buffer))
            .await
            .ok()?
            .ok()?;
        if bytes_read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..bytes_read]);
        if http_response_complete(&response) {
            break;
        }
    }

    split_http_response(&response)
}

fn http_response_complete(response: &[u8]) -> bool {
    let Some(header_end) = find_http_header_end(response) else {
        return false;
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let Some(content_length) = http_content_length(&headers) else {
        return false;
    };

    response.len() >= header_end + content_length
}

fn split_http_response(response: &[u8]) -> Option<(String, String)> {
    let header_end = find_http_header_end(response)?;
    let head = String::from_utf8_lossy(&response[..header_end]).into_owned();
    let body = String::from_utf8(response[header_end..].to_vec()).ok()?;
    Some((head, body))
}

fn http_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())?
    })
}

fn devtools_http_host(browser_url: &str) -> Option<(String, u16)> {
    let without_scheme = browser_url
        .strip_prefix("ws://")
        .or_else(|| browser_url.strip_prefix("http://"))?;
    let authority = without_scheme.split('/').next()?;
    let (host, port) = authority.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port.parse().ok()?;
    Some((host.to_owned(), port))
}

fn rewrite_discovery_websocket_urls(payload: &mut Value, governed_ws_url: &str) {
    match payload {
        Value::Object(map) => {
            if map.contains_key("webSocketDebuggerUrl") {
                map.insert(
                    String::from("webSocketDebuggerUrl"),
                    Value::String(governed_ws_url.to_owned()),
                );
            }
            if map.contains_key("devtoolsFrontendUrl") {
                map.insert(
                    String::from("devtoolsFrontendUrl"),
                    Value::String(governed_devtools_frontend_url(governed_ws_url)),
                );
            }
            for value in map.values_mut() {
                rewrite_discovery_websocket_urls(value, governed_ws_url);
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite_discovery_websocket_urls(value, governed_ws_url);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn target_descriptor(governed_ws_url: &str) -> Value {
    json!({
        "description": "Erebor governed browser endpoint",
        "devtoolsFrontendUrl": governed_devtools_frontend_url(governed_ws_url),
        "id": "erebor-governed-browser",
        "title": "Erebor Governed Browser",
        "type": "page",
        "url": "about:blank",
        "webSocketDebuggerUrl": governed_ws_url
    })
}

fn governed_devtools_frontend_url(governed_ws_url: &str) -> String {
    format!(
        "/devtools/inspector.html?ws={}",
        governed_ws_url.trim_start_matches("ws://")
    )
}

fn http_response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn proxy_connection(
    stream: TcpStream,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
    session_state: CdpSessionState,
    audit_recorder: Option<CdpAuditRecorder>,
) -> Result<(), CdpError> {
    debug!("accepting client websocket");
    let client_socket = accept_async(stream).await.map_err(websocket_error)?;
    debug!(browser_url = %browser_url, "connecting to upstream CDP websocket");
    let (browser_socket, _response) = connect_async(browser_url.as_str())
        .await
        .map_err(websocket_error)?;
    let (mut client_write, mut client_read) = client_socket.split();
    let (mut browser_write, mut browser_read) = browser_socket.split();
    let mut client_targets = ClientTargetSessions::default();

    loop {
        tokio::select! {
            client_message = client_read.next() => {
                let Some(client_message) = client_message else {
                    break;
                };
                let client_message = client_message.map_err(websocket_error)?;

                if client_message.is_text() {
                    let source = client_message.into_text().map_err(websocket_error)?.to_string();
                    match handle_client_text_with_audit(
                        engine.as_ref(),
                        &context,
                        &session_state,
                        &mut client_targets,
                        &source,
                        audit_recorder.as_ref(),
                    )? {
                        ClientTextAction::Forward { payload } => {
                            browser_write
                                .send(Message::Text(payload.into()))
                                .await
                                .map_err(websocket_error)?;
                        }
                        ClientTextAction::Reply { payload } => {
                            client_write
                                .send(Message::Text(payload.to_string().into()))
                                .await
                                .map_err(websocket_error)?;
                        }
                        ClientTextAction::HoldForApproval => {}
                    }
                } else {
                    let should_close = client_message.is_close();
                    browser_write
                        .send(client_message)
                        .await
                        .map_err(websocket_error)?;
                    if should_close {
                        break;
                    }
                }
            }
            browser_message = browser_read.next() => {
                let Some(browser_message) = browser_message else {
                    break;
                };
                let browser_message = browser_message.map_err(websocket_error)?;

                if browser_message.is_text() {
                    let source = browser_message.into_text().map_err(websocket_error)?.to_string();
                    observe_browser_response_text(&mut client_targets, &source)?;
                    let _event = observe_browser_event_text(
                        &context,
                        &session_state,
                        Some(&mut client_targets),
                        &source,
                    )?;
                    client_write
                        .send(Message::Text(source.into()))
                        .await
                        .map_err(websocket_error)?;
                } else {
                    let should_close = browser_message.is_close();
                    client_write
                        .send(browser_message)
                        .await
                        .map_err(websocket_error)?;
                    if should_close {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn should_start_page_state_observer(browser_url: &str) -> bool {
    browser_url.contains("/devtools/page/")
}

fn should_start_browser_state_observer(browser_url: &str) -> bool {
    browser_url.contains("/devtools/browser/")
}

async fn run_browser_state_observer(
    browser_url: String,
    context: CdpSessionContext,
    session_state: CdpSessionState,
    engine: Arc<CdpEngine>,
    audit_recorder: Option<CdpAuditRecorder>,
) {
    loop {
        match observe_browser_state_connection(
            &browser_url,
            &context,
            &session_state,
            &engine,
            audit_recorder.as_ref(),
        )
        .await
        {
            Ok(()) => warn!(browser_url = %browser_url, "browser state observer stopped"),
            Err(error) => warn!(
                browser_url = %browser_url,
                error = %error,
                "browser state observer failed"
            ),
        }

        sleep(OBSERVER_RECONNECT_DELAY).await;
    }
}

async fn observe_browser_state_connection(
    browser_url: &str,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    engine: &CdpEngine,
    audit_recorder: Option<&CdpAuditRecorder>,
) -> Result<(), CdpError> {
    let (mut browser_socket, _response) =
        connect_async(browser_url).await.map_err(websocket_error)?;
    bootstrap_browser_state_observer(
        &mut browser_socket,
        context,
        session_state,
        engine,
        audit_recorder,
    )
    .await?;
    let mut observer_targets = ClientTargetSessions::default();
    let mut frame_tree_requests = FrameTreeRequests::default();
    let mut next_observer_command_id = ObserverCommandIds::default();

    while let Some(message) = browser_socket.next().await {
        let message = message.map_err(websocket_error)?;
        let Message::Text(source) = message else {
            continue;
        };
        observe_browser_level_message(
            &mut browser_socket,
            BrowserObserverRefs {
                context,
                session_state,
                engine,
                audit_recorder,
            },
            BrowserObserverScratch {
                observer_targets: &mut observer_targets,
                frame_tree_requests: &mut frame_tree_requests,
                next_observer_command_id: &mut next_observer_command_id,
            },
            source.as_ref(),
        )
        .await?;
    }

    Ok(())
}

async fn bootstrap_browser_state_observer(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    engine: &CdpEngine,
    audit_recorder: Option<&CdpAuditRecorder>,
) -> Result<(), CdpError> {
    send_internal_method(
        browser_socket,
        target::SetDiscoverTargets {
            discover: true,
            filter: None,
        },
        OBSERVER_SET_DISCOVER_TARGETS_ID,
    )
    .await?;
    send_internal_method(
        browser_socket,
        target::SetAutoAttach {
            auto_attach: true,
            wait_for_debugger_on_start: false,
            flatten: Some(true),
            filter: None,
        },
        OBSERVER_SET_AUTO_ATTACH_ID,
    )
    .await?;
    send_internal_method(
        browser_socket,
        target::GetTargets { filter: None },
        OBSERVER_GET_TARGETS_ID,
    )
    .await?;

    let mut discover_enabled = false;
    let mut auto_attach_enabled = false;
    let mut targets_loaded = false;
    let mut observer_targets = ClientTargetSessions::default();
    let mut frame_tree_requests = FrameTreeRequests::default();
    let mut next_observer_command_id = ObserverCommandIds::default();

    while !(discover_enabled && auto_attach_enabled && targets_loaded) {
        let message = timeout(OBSERVER_BOOTSTRAP_RESPONSE_TIMEOUT, browser_socket.next())
            .await
            .map_err(|_| {
                CdpError::browser_state_sync("timed out waiting for browser observer bootstrap")
            })?
            .ok_or_else(|| {
                CdpError::browser_state_sync("browser socket closed during observer bootstrap")
            })?
            .map_err(websocket_error)?;

        let Message::Text(source) = message else {
            continue;
        };
        let source = source.to_string();
        let head = serde_json::from_str::<ObserverBootstrapMessageHead>(&source)
            .map_err(CdpError::invalid_protocol)?;

        if head.method.is_some() {
            observe_browser_level_message(
                browser_socket,
                BrowserObserverRefs {
                    context,
                    session_state,
                    engine,
                    audit_recorder,
                },
                BrowserObserverScratch {
                    observer_targets: &mut observer_targets,
                    frame_tree_requests: &mut frame_tree_requests,
                    next_observer_command_id: &mut next_observer_command_id,
                },
                &source,
            )
            .await?;
            continue;
        }

        match head.id {
            Some(OBSERVER_SET_DISCOVER_TARGETS_ID) => {
                parse_internal_method_response::<target::SetDiscoverTargets>(&source)?;
                discover_enabled = true;
            }
            Some(OBSERVER_SET_AUTO_ATTACH_ID) => {
                parse_internal_method_response::<target::SetAutoAttach>(&source)?;
                auto_attach_enabled = true;
            }
            Some(OBSERVER_GET_TARGETS_ID) => {
                let response = parse_internal_method_response::<target::GetTargets>(&source)?;
                for target_info in response.target_infos {
                    session_state.record_target_info(&target_info);
                }
                audit_state_recovery(
                    engine,
                    audit_recorder,
                    context,
                    "browser_observer_bootstrap_targets",
                    None,
                );
                targets_loaded = true;
            }
            Some(id) => {
                if let Some(target_id) = frame_tree_requests.remove(id) {
                    let response = parse_internal_method_response::<page::GetFrameTree>(&source)?;
                    audit_state_recovery(
                        engine,
                        audit_recorder,
                        context,
                        "browser_observer_frame_tree_response",
                        Some(&target_id),
                    );
                    session_state.record_frame_tree_for_target(target_id, &response.frame_tree);
                }
            }
            None => {}
        }
    }

    debug!("bootstrapped browser-level state observer from upstream CDP");
    Ok(())
}

async fn run_page_state_observer(
    browser_url: String,
    context: CdpSessionContext,
    session_state: CdpSessionState,
    engine: Arc<CdpEngine>,
    audit_recorder: Option<CdpAuditRecorder>,
) {
    loop {
        match observe_page_state_connection(
            &browser_url,
            &context,
            &session_state,
            &engine,
            audit_recorder.as_ref(),
        )
        .await
        {
            Ok(()) => warn!(browser_url = %browser_url, "page state observer stopped"),
            Err(error) => warn!(
                browser_url = %browser_url,
                error = %error,
                "page state observer failed"
            ),
        }

        sleep(OBSERVER_RECONNECT_DELAY).await;
    }
}

async fn observe_page_state_connection(
    browser_url: &str,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    engine: &CdpEngine,
    audit_recorder: Option<&CdpAuditRecorder>,
) -> Result<(), CdpError> {
    let (mut browser_socket, _response) =
        connect_async(browser_url).await.map_err(websocket_error)?;
    bootstrap_page_state_observer(
        &mut browser_socket,
        context,
        session_state,
        engine,
        audit_recorder,
    )
    .await?;
    let mut next_observer_command_id = ObserverCommandIds::default();

    while let Some(message) = browser_socket.next().await {
        let message = message.map_err(websocket_error)?;
        if let Message::Text(source) = message {
            if let Some(event) =
                observe_browser_event_text(context, session_state, None, source.as_ref())?
            {
                handle_fetch_request_paused(
                    &mut browser_socket,
                    engine,
                    context,
                    &event,
                    &mut next_observer_command_id,
                    audit_recorder,
                )
                .await?;
            }
        }
    }

    Ok(())
}

async fn bootstrap_page_state_observer(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    engine: &CdpEngine,
    audit_recorder: Option<&CdpAuditRecorder>,
) -> Result<(), CdpError> {
    send_internal_method(
        browser_socket,
        page::Enable {
            enable_file_chooser_opened_event: None,
        },
        OBSERVER_PAGE_ENABLE_ID,
    )
    .await?;
    send_internal_method(
        browser_socket,
        cdp_runtime::Enable(None),
        OBSERVER_RUNTIME_ENABLE_ID,
    )
    .await?;
    send_internal_method(
        browser_socket,
        fetch_document_request_pausing(),
        OBSERVER_FETCH_ENABLE_ID,
    )
    .await?;
    send_internal_method(
        browser_socket,
        page::GetFrameTree(None),
        OBSERVER_GET_FRAME_TREE_ID,
    )
    .await?;

    let mut page_enabled = false;
    let mut runtime_enabled = false;
    let mut fetch_enabled = false;
    let mut frame_tree_loaded = false;

    while !(page_enabled && runtime_enabled && fetch_enabled && frame_tree_loaded) {
        let message = timeout(OBSERVER_BOOTSTRAP_RESPONSE_TIMEOUT, browser_socket.next())
            .await
            .map_err(|_| CdpError::browser_state_sync("timed out waiting for observer bootstrap"))?
            .ok_or_else(|| {
                CdpError::browser_state_sync("browser socket closed during observer bootstrap")
            })?
            .map_err(websocket_error)?;

        let Message::Text(source) = message else {
            continue;
        };
        let source = source.to_string();
        let head = serde_json::from_str::<ObserverBootstrapMessageHead>(&source)
            .map_err(CdpError::invalid_protocol)?;

        if head.method.is_some() {
            let _event = observe_browser_event_text(context, session_state, None, &source)?;
            continue;
        }

        match head.id {
            Some(OBSERVER_PAGE_ENABLE_ID) => {
                parse_internal_method_response::<page::Enable>(&source)?;
                page_enabled = true;
            }
            Some(OBSERVER_RUNTIME_ENABLE_ID) => {
                parse_internal_method_response::<cdp_runtime::Enable>(&source)?;
                runtime_enabled = true;
            }
            Some(OBSERVER_FETCH_ENABLE_ID) => {
                parse_internal_method_response::<fetch::Enable>(&source)?;
                fetch_enabled = true;
            }
            Some(OBSERVER_GET_FRAME_TREE_ID) => {
                let response = parse_internal_method_response::<page::GetFrameTree>(&source)?;
                audit_state_recovery(
                    engine,
                    audit_recorder,
                    context,
                    "page_observer_bootstrap_frame_tree",
                    None,
                );
                session_state.record_frame_tree(&response.frame_tree);
                frame_tree_loaded = true;
            }
            Some(_) | None => {}
        }
    }

    debug!("bootstrapped page state observer from upstream CDP");
    Ok(())
}

async fn observe_browser_level_message(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    refs: BrowserObserverRefs<'_>,
    scratch: BrowserObserverScratch<'_>,
    source: &str,
) -> Result<(), CdpError> {
    if let Some(target_id) = frame_tree_response_target(source, scratch.frame_tree_requests)? {
        let response = parse_internal_method_response::<page::GetFrameTree>(source)?;
        audit_state_recovery(
            refs.engine,
            refs.audit_recorder,
            refs.context,
            "browser_observer_frame_tree_response",
            Some(&target_id),
        );
        refs.session_state
            .record_frame_tree_for_target(target_id, &response.frame_tree);
        return Ok(());
    }

    let Some(event) = observe_browser_event_text(
        refs.context,
        refs.session_state,
        Some(scratch.observer_targets),
        source,
    )?
    else {
        return Ok(());
    };

    handle_fetch_request_paused(
        browser_socket,
        refs.engine,
        refs.context,
        &event,
        scratch.next_observer_command_id,
        refs.audit_recorder,
    )
    .await?;

    if let Some((session_id, target_id)) = attached_page_target(&event) {
        send_internal_session_method(
            browser_socket,
            page::Enable {
                enable_file_chooser_opened_event: None,
            },
            scratch.next_observer_command_id.next(),
            &session_id,
        )
        .await?;
        send_internal_session_method(
            browser_socket,
            cdp_runtime::Enable(None),
            scratch.next_observer_command_id.next(),
            &session_id,
        )
        .await?;
        send_internal_session_method(
            browser_socket,
            fetch_document_request_pausing(),
            scratch.next_observer_command_id.next(),
            &session_id,
        )
        .await?;
        let get_frame_tree_id = scratch.next_observer_command_id.next();
        audit_state_recovery(
            refs.engine,
            refs.audit_recorder,
            refs.context,
            "browser_observer_target_attach_frame_tree",
            Some(&target_id),
        );
        scratch
            .frame_tree_requests
            .insert(get_frame_tree_id, target_id);
        send_internal_session_method(
            browser_socket,
            page::GetFrameTree(None),
            get_frame_tree_id,
            &session_id,
        )
        .await?;
    }

    Ok(())
}

async fn handle_fetch_request_paused(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    engine: &CdpEngine,
    context: &CdpSessionContext,
    event: &CdpEvent,
    next_observer_command_id: &mut ObserverCommandIds,
    audit_recorder: Option<&CdpAuditRecorder>,
) -> Result<(), CdpError> {
    let Some(paused) = paused_fetch_request(event) else {
        return Ok(());
    };

    let outcome = enforce_cdp_event_outcome(engine, context, event)?;
    record_audit_outcome(audit_recorder, outcome.audit_record());

    match outcome.action() {
        CdpEnforcementAction::Forward => {
            debug!(
                request_id = %paused.request_id,
                url = %paused.url,
                "continuing observed Fetch request"
            );
            send_internal_target_method(
                browser_socket,
                fetch::ContinueRequest {
                    request_id: paused.request_id,
                    url: None,
                    method: None,
                    post_data: None,
                    headers: None,
                    intercept_response: None,
                },
                next_observer_command_id.next(),
                paused.session_id.as_deref(),
            )
            .await
        }
        CdpEnforcementAction::Block { reason } | CdpEnforcementAction::AwaitApproval { reason } => {
            warn!(
                request_id = %paused.request_id,
                url = %paused.url,
                reason = %reason,
                "failing observed Fetch request"
            );
            send_internal_target_method(
                browser_socket,
                fetch::FailRequest {
                    request_id: paused.request_id,
                    error_reason: network::ErrorReason::BlockedByClient,
                },
                next_observer_command_id.next(),
                paused.session_id.as_deref(),
            )
            .await
        }
    }
}

fn fetch_document_request_pausing() -> fetch::Enable {
    fetch::Enable {
        patterns: Some(vec![fetch::RequestPattern {
            url_pattern: Some(String::from("*")),
            resource_type: Some(network::ResourceType::Document),
            request_stage: Some(fetch::RequestStage::Request),
        }]),
        handle_auth_requests: Some(false),
    }
}

#[derive(Debug)]
struct PausedFetchRequest {
    request_id: String,
    url: String,
    session_id: Option<String>,
}

fn paused_fetch_request(event: &CdpEvent) -> Option<PausedFetchRequest> {
    let ProtocolEvent::FetchRequestPaused(paused) = event.protocol_event() else {
        return None;
    };

    Some(PausedFetchRequest {
        request_id: paused.params.request_id.clone(),
        url: paused.params.request.url.clone(),
        session_id: event.session_id().map(ToOwned::to_owned),
    })
}

#[derive(Clone, Copy)]
struct BrowserObserverRefs<'a> {
    context: &'a CdpSessionContext,
    session_state: &'a CdpSessionState,
    engine: &'a CdpEngine,
    audit_recorder: Option<&'a CdpAuditRecorder>,
}

struct BrowserObserverScratch<'a> {
    observer_targets: &'a mut ClientTargetSessions,
    frame_tree_requests: &'a mut FrameTreeRequests,
    next_observer_command_id: &'a mut ObserverCommandIds,
}

async fn send_internal_method<T>(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    method: T,
    id: CallId,
) -> Result<(), CdpError>
where
    T: Method + Serialize,
{
    let payload =
        serde_json::to_string(&method.to_method_call(id)).map_err(CdpError::invalid_protocol)?;
    browser_socket
        .send(Message::Text(payload.into()))
        .await
        .map_err(websocket_error)
}

async fn send_internal_session_method<T>(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    method: T,
    id: CallId,
    session_id: &str,
) -> Result<(), CdpError>
where
    T: Method + Serialize,
{
    let mut payload =
        serde_json::to_value(method.to_method_call(id)).map_err(CdpError::invalid_protocol)?;
    payload["sessionId"] = Value::String(session_id.to_owned());
    browser_socket
        .send(Message::Text(payload.to_string().into()))
        .await
        .map_err(websocket_error)
}

async fn send_internal_target_method<T>(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    method: T,
    id: CallId,
    session_id: Option<&str>,
) -> Result<(), CdpError>
where
    T: Method + Serialize,
{
    if let Some(session_id) = session_id {
        send_internal_session_method(browser_socket, method, id, session_id).await
    } else {
        send_internal_method(browser_socket, method, id).await
    }
}

#[derive(Debug, Default)]
struct FrameTreeRequests {
    requests: std::collections::HashMap<CallId, BrowserTargetId>,
}

impl FrameTreeRequests {
    fn insert(&mut self, id: CallId, target_id: BrowserTargetId) {
        self.requests.insert(id, target_id);
    }

    fn remove(&mut self, id: CallId) -> Option<BrowserTargetId> {
        self.requests.remove(&id)
    }
}

#[derive(Debug)]
struct ObserverCommandIds {
    next: CallId,
}

impl Default for ObserverCommandIds {
    fn default() -> Self {
        Self {
            next: OBSERVER_TARGET_COMMAND_ID_START,
        }
    }
}

impl ObserverCommandIds {
    fn next(&mut self) -> CallId {
        let id = self.next;
        self.next = self.next.saturating_add(1);
        id
    }
}

fn parse_internal_method_response<M>(source: &str) -> Result<M::ReturnObject, CdpError>
where
    M: Method,
{
    let response: ObserverBootstrapMethodResponse<M::ReturnObject> =
        serde_json::from_str(source).map_err(CdpError::invalid_protocol)?;
    if let Some(error) = response.error {
        return Err(CdpError::browser_state_sync(format!(
            "{} failed: {}",
            M::NAME,
            error.message
        )));
    }

    response
        .result
        .ok_or_else(|| CdpError::browser_state_sync(format!("{} did not return a result", M::NAME)))
}

fn frame_tree_response_target(
    source: &str,
    frame_tree_requests: &mut FrameTreeRequests,
) -> Result<Option<BrowserTargetId>, CdpError> {
    let response: ObserverBootstrapMessageHead =
        serde_json::from_str(source).map_err(CdpError::invalid_protocol)?;
    Ok(response.id.and_then(|id| frame_tree_requests.remove(id)))
}

fn attached_page_target(event: &CdpEvent) -> Option<(String, BrowserTargetId)> {
    let cdp_protocol::types::Event::AttachedToTarget(attached) = event.protocol_event() else {
        return None;
    };
    let target_id = BrowserTargetId::new(attached.params.target_info.target_id.clone());
    let kind = crate::BrowserTargetKind::from_cdp_target_type(&attached.params.target_info.r#type);
    kind.is_page_like()
        .then(|| (attached.params.session_id.clone(), target_id))
}

fn audit_state_recovery(
    engine: &CdpEngine,
    audit_recorder: Option<&CdpAuditRecorder>,
    context: &CdpSessionContext,
    trigger: &'static str,
    target_id: Option<&BrowserTargetId>,
) {
    let target = target_id.map(|target_id| TargetRef {
        label: Some(target_id.as_str().to_owned()),
        uri: None,
    });
    let event = erebor_runtime_events::RuntimeEvent {
        id: EventId::new(format!(
            "cdp-state-recovery-{trigger}-{}",
            target_id.map_or("browser", BrowserTargetId::as_str)
        )),
        session_id: context.session_id.clone(),
        actor: context.actor.clone(),
        surface: ExecutionSurface::BrowserCdp,
        action: ActionKind::BrowserStateRecovery,
        target,
        payload: json!({
            "kind": "state_recovery",
            "trigger": trigger,
            "target_id": target_id.map(BrowserTargetId::as_str),
        }),
        risk: RiskMetadata {
            level: RiskLevel::Low,
            reasons: vec![String::from("CDP observer state recovery")],
        },
        timestamp: context.timestamp.clone(),
    };
    let decision = Decision::Allow {
        rule_id: Some(String::from("cdp-state-maintenance")),
    };
    let record = AuditRecord {
        event,
        policy_decision: decision.clone(),
        final_decision: decision,
    };

    if let Some(error) = engine.record_audit_record(&record) {
        warn!(
            trigger,
            error = %error,
            "failed to audit CDP state recovery"
        );
    } else {
        debug!(trigger, "audited CDP state recovery");
    }

    record_audit_outcome(audit_recorder, Some(&record));
}

#[derive(Debug, Deserialize)]
struct ObserverBootstrapMessageHead {
    id: Option<CallId>,
    method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ObserverBootstrapMethodResponse<T> {
    result: Option<T>,
    error: Option<ObserverBootstrapMethodError>,
}

#[derive(Debug, Deserialize)]
struct ObserverBootstrapMethodError {
    message: String,
}

#[derive(Debug, PartialEq)]
enum ClientTextAction {
    Forward { payload: String },
    Reply { payload: Value },
    HoldForApproval,
}

#[cfg(test)]
fn handle_client_text(
    engine: &CdpEngine,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    client_targets: &mut ClientTargetSessions,
    source: &str,
) -> Result<ClientTextAction, CdpError> {
    handle_client_text_with_audit(engine, context, session_state, client_targets, source, None)
}

fn handle_client_text_with_audit(
    engine: &CdpEngine,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    client_targets: &mut ClientTargetSessions,
    source: &str,
    audit_recorder: Option<&CdpAuditRecorder>,
) -> Result<ClientTextAction, CdpError> {
    let command = decode_cdp_command(source)?;
    let outcome = enforce_cdp_command_with_client_state_outcome(
        engine,
        context,
        &command,
        session_state,
        Some(client_targets),
    )?;
    record_audit_outcome(audit_recorder, outcome.audit_record());

    match outcome.action() {
        CdpEnforcementAction::Forward => {
            if let Some(protocol_command) = command.protocol_command() {
                record_pending_client_target_command(&command, protocol_command, client_targets);
                session_state.record_provisional_forwarded_command_for_client_session(
                    protocol_command,
                    command.session_id.as_deref(),
                    Some(client_targets),
                );
            }
            debug!(
                method = %command.method,
                id = ?command.id,
                "forwarding CDP command"
            );
            Ok(ClientTextAction::Forward {
                payload: source.to_owned(),
            })
        }
        CdpEnforcementAction::Block { reason } => {
            warn!(
                method = %command.method,
                id = ?command.id,
                reason = %reason,
                "blocking CDP command"
            );
            Ok(ClientTextAction::Reply {
                payload: error_response(&command, -32000, reason),
            })
        }
        CdpEnforcementAction::AwaitApproval { reason } => {
            info!(
                method = %command.method,
                id = ?command.id,
                reason = %reason,
                "holding CDP command for approval"
            );
            Ok(ClientTextAction::HoldForApproval)
        }
    }
}

fn observe_browser_event_text(
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    client_targets: Option<&mut ClientTargetSessions>,
    source: &str,
) -> Result<Option<CdpEvent>, CdpError> {
    let event = match decode_cdp_event(source) {
        Ok(Some(event)) => event,
        Ok(None) | Err(CdpError::InvalidJson { .. }) => return Ok(None),
        Err(error) => return Err(error),
    };
    session_state.record_browser_event_for_client_session(&event, client_targets);
    let runtime_event = observe_cdp_event(context, &event)?;
    debug!(
        method = %event.method(),
        event_id = %runtime_event.id.as_str(),
        "observed CDP context message"
    );

    Ok(Some(event))
}

fn observe_browser_response_text(
    client_targets: &mut ClientTargetSessions,
    source: &str,
) -> Result<(), CdpError> {
    let response = match serde_json::from_str::<ClientTargetMethodResponse>(source) {
        Ok(response) => response,
        Err(error) if error.is_data() => return Ok(()),
        Err(error) if error.is_syntax() || error.is_eof() => {
            return Err(CdpError::invalid_json(error));
        }
        Err(error) => return Err(CdpError::invalid_protocol(error)),
    };

    let Some(session_id) = response
        .result
        .and_then(|result| result.session_id)
        .filter(|session_id| !session_id.is_empty())
    else {
        return Ok(());
    };

    let _target_id = client_targets.record_attach_response(response.id, session_id);
    Ok(())
}

fn record_pending_client_target_command(
    command: &CdpCommand,
    protocol_command: &GovernedCdpCommand,
    client_targets: &mut ClientTargetSessions,
) {
    let GovernedCdpCommand::TargetManagement(target_command) = protocol_command else {
        return;
    };
    if target_command.method() != target::AttachToTarget::NAME {
        return;
    }
    let Some(target_id) = target_command
        .target()
        .and_then(|target| target.label)
        .filter(|target_id| !target_id.is_empty())
    else {
        return;
    };

    client_targets.record_attach_request(command.id, BrowserTargetId::new(target_id));
}

fn error_response(command: &CdpCommand, code: i64, reason: &str) -> Value {
    let mut response = json!({
        "id": command.id,
        "error": {
            "code": code,
            "message": reason
        }
    });

    if let Some(session_id) = command.session_id.as_ref() {
        response["sessionId"] = Value::String(session_id.clone());
    }

    response
}

#[derive(Debug, Deserialize)]
struct ClientTargetMethodResponse {
    id: CallId,
    result: Option<ClientTargetMethodResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientTargetMethodResult {
    session_id: Option<String>,
}

fn websocket_error(error: WebSocketError) -> CdpError {
    CdpError::websocket(error)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use erebor_runtime_audit::read_audit_records;
    use erebor_runtime_core::{AuditCommandLogLevel, RuntimeAuditConfig};
    use erebor_runtime_events::{
        ActionKind, ActorIdentity, ActorKind, ExecutionSurface, SessionId,
    };
    use erebor_runtime_policy::{Decision, LocalPolicy, PolicySet};
    use serde_json::json;

    use super::{
        handle_client_text, handle_client_text_with_audit, observe_browser_event_text,
        observe_browser_response_text, CdpAuditRecorder, ClientTextAction,
    };
    use crate::{BrowserTargetId, CdpSessionContext, CdpSessionState, ClientTargetSessions};

    fn context() -> CdpSessionContext {
        CdpSessionContext {
            session_id: SessionId::new("session-1"),
            actor: ActorIdentity {
                id: String::from("agent-1"),
                kind: ActorKind::Agent,
            },
            timestamp: String::from("2026-05-13T00:00:00Z"),
        }
    }

    fn temp_audit_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "erebor-cdp-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn client_text_forwards_allowed_commands() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source = r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://example.com/" } }"#;

        let mut client_targets = ClientTargetSessions::default();
        let action = handle_client_text(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
        )?;

        assert_eq!(
            action,
            ClientTextAction::Forward {
                payload: source.to_owned()
            }
        );
        Ok(())
    }

    #[test]
    fn client_text_replies_to_denied_commands() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "deny",
                  "reason": "script evaluation denied"
                }
              ]
            }
            "#,
        )?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source =
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;

        let mut client_targets = ClientTargetSessions::default();
        let action = handle_client_text(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
        )?;

        assert_eq!(
            action,
            ClientTextAction::Reply {
                payload: json!({
                    "id": 1,
                    "error": {
                        "code": -32000,
                        "message": "script evaluation denied"
                    }
                })
            }
        );
        Ok(())
    }

    #[test]
    fn client_text_appends_denied_command_audit_jsonl() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "deny",
                  "reason": "script evaluation denied"
                }
              ]
            }
            "#,
        )?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source =
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;
        let audit_path = temp_audit_path("denied-command");
        let _cleanup_before = fs::remove_file(&audit_path);
        let recorder = CdpAuditRecorder::new(audit_path.clone(), RuntimeAuditConfig::default());

        let mut client_targets = ClientTargetSessions::default();
        let action = handle_client_text_with_audit(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
            Some(&recorder),
        )?;

        assert_eq!(
            action,
            ClientTextAction::Reply {
                payload: json!({
                    "id": 1,
                    "error": {
                        "code": -32000,
                        "message": "script evaluation denied"
                    }
                })
            }
        );

        let records = read_audit_records(&audit_path)?;
        let _cleanup_after = fs::remove_file(&audit_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.event.session_id, SessionId::new("session-1"));
        assert_eq!(record.event.surface, ExecutionSurface::BrowserCdp);
        assert_eq!(record.event.action, ActionKind::BrowserScriptEval);
        assert_eq!(
            record.policy_decision,
            Decision::Deny {
                reason: String::from("script evaluation denied"),
                rule_id: Some(String::from("deny-script-eval")),
            }
        );
        assert_eq!(record.final_decision, record.policy_decision);
        Ok(())
    }

    #[test]
    fn client_text_appends_allowed_command_audit_jsonl() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source = r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://example.com/" } }"#;
        let audit_path = temp_audit_path("allowed-command");
        let _cleanup_before = fs::remove_file(&audit_path);
        let recorder = CdpAuditRecorder::new(audit_path.clone(), RuntimeAuditConfig::default());

        let mut client_targets = ClientTargetSessions::default();
        let action = handle_client_text_with_audit(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
            Some(&recorder),
        )?;

        assert_eq!(
            action,
            ClientTextAction::Forward {
                payload: source.to_owned()
            }
        );

        let records = read_audit_records(&audit_path)?;
        let _cleanup_after = fs::remove_file(&audit_path);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.event.surface, ExecutionSurface::BrowserCdp);
        assert_eq!(record.event.action, ActionKind::BrowserNavigate);
        assert_eq!(
            record
                .event
                .target
                .as_ref()
                .and_then(|target| target.uri.as_deref()),
            Some("https://example.com/")
        );
        assert_eq!(record.final_decision, Decision::Allow { rule_id: None });
        Ok(())
    }

    #[test]
    fn client_text_skips_allowed_debug_command_audit_jsonl(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source =
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;
        let audit_path = temp_audit_path("debug-command");
        let _cleanup_before = fs::remove_file(&audit_path);
        let mut audit = RuntimeAuditConfig::default();
        audit.surfaces.browser_cdp.level = AuditCommandLogLevel::Signal;
        audit.surfaces.browser_cdp.debug_methods = vec![String::from("Runtime.evaluate")];
        let recorder = CdpAuditRecorder::new(audit_path.clone(), audit);

        let mut client_targets = ClientTargetSessions::default();
        let action = handle_client_text_with_audit(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
            Some(&recorder),
        )?;

        assert_eq!(
            action,
            ClientTextAction::Forward {
                payload: source.to_owned()
            }
        );
        assert!(!audit_path.exists());
        Ok(())
    }

    #[test]
    fn client_text_preserves_session_id_in_block_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "deny",
                  "reason": "script evaluation denied"
                }
              ]
            }
            "#,
        )?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source = r#"{ "id": 5, "sessionId": "cdp-session-1", "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;

        let mut client_targets = ClientTargetSessions::default();
        client_targets.record_attached("cdp-session-1", BrowserTargetId::new("target-1"));
        let action = handle_client_text(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
        )?;

        assert_eq!(
            action,
            ClientTextAction::Reply {
                payload: json!({
                    "id": 5,
                    "sessionId": "cdp-session-1",
                    "error": {
                        "code": -32000,
                        "message": "script evaluation denied"
                    }
                })
            }
        );
        Ok(())
    }

    #[test]
    fn client_text_fails_closed_for_unknown_browser_session(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source = r#"{ "id": 5, "sessionId": "unknown-session", "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;
        let mut client_targets = ClientTargetSessions::default();

        let action = handle_client_text(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
        )?;

        assert_eq!(
            action,
            ClientTextAction::Reply {
                payload: json!({
                    "id": 5,
                    "sessionId": "unknown-session",
                    "error": {
                        "code": -32000,
                        "message": "browser target is unknown for CDP session"
                    }
                })
            }
        );
        Ok(())
    }

    #[test]
    fn client_text_holds_approval_required_commands() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "approve-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "require_approval",
                  "reason": "script evaluation requires approval"
                }
              ]
            }
            "#,
        )?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let source =
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#;

        let mut client_targets = ClientTargetSessions::default();
        let action = handle_client_text(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            source,
        )?;

        assert_eq!(action, ClientTextAction::HoldForApproval);
        Ok(())
    }

    #[test]
    fn browser_attach_response_maps_client_session_to_target(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
        let engine =
            erebor_runtime_core::LocalEnforcementEngine::new(PolicySet::from_policies(vec![
                policy,
            ]));
        let mut client_targets = ClientTargetSessions::default();
        let attach = r#"{ "id": 11, "method": "Target.attachToTarget", "params": { "targetId": "target-1", "flatten": true } }"#;
        let action = handle_client_text(
            &engine,
            &context(),
            &CdpSessionState::default(),
            &mut client_targets,
            attach,
        )?;
        assert!(matches!(action, ClientTextAction::Forward { .. }));

        observe_browser_response_text(
            &mut client_targets,
            r#"{ "id": 11, "result": { "sessionId": "session-1" } }"#,
        )?;

        assert!(client_targets.has_session("session-1"));
        Ok(())
    }

    #[test]
    fn browser_text_ignores_command_responses() -> Result<(), Box<dyn std::error::Error>> {
        observe_browser_event_text(
            &context(),
            &CdpSessionState::default(),
            None,
            r#"{ "id": 1, "result": {} }"#,
        )?;

        Ok(())
    }
}
