use std::{net::SocketAddr, sync::Arc};

use cdp_protocol::{
    page, runtime as cdp_runtime, target,
    types::{CallId, Method},
};
use erebor_runtime_core::{AuditRecord, LocalEnforcementEngine};
use erebor_runtime_events::{
    ActionKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata, TargetRef,
};
use erebor_runtime_policy::{Decision, PolicySet};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};
use tokio_tungstenite::{
    accept_hdr_async, connect_async,
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        http::StatusCode,
        Error as WebSocketError, Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, info, warn};

use crate::{
    decode_cdp_command, decode_cdp_event, enforce_cdp_command_with_client_state, observe_cdp_event,
    BrowserTargetId, CdpCommand, CdpEnforcementAction, CdpError, CdpEvent, CdpSessionContext,
    CdpSessionState, ClientTargetSessions, GovernedCdpCommand,
};

type CdpEngine = LocalEnforcementEngine<PolicySet>;
const OBSERVER_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(1);
const OBSERVER_RECONNECT_DELAY: Duration = Duration::from_millis(250);
const OBSERVER_SET_DISCOVER_TARGETS_ID: CallId = CallId::MAX - 5;
const OBSERVER_SET_AUTO_ATTACH_ID: CallId = CallId::MAX - 4;
const OBSERVER_GET_TARGETS_ID: CallId = CallId::MAX - 3;
const OBSERVER_PAGE_ENABLE_ID: CallId = CallId::MAX - 2;
const OBSERVER_RUNTIME_ENABLE_ID: CallId = CallId::MAX - 1;
const OBSERVER_GET_FRAME_TREE_ID: CallId = CallId::MAX;

#[derive(Clone, Debug, PartialEq)]
pub struct CdpProxyServerConfig {
    pub listen: SocketAddr,
    pub browser_url: String,
    pub context: CdpSessionContext,
    pub auth_token: Option<String>,
}

pub struct CdpProxyServer {
    listener: TcpListener,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
    auth_token: Option<String>,
    session_state: CdpSessionState,
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
        if should_start_browser_state_observer(&config.browser_url) {
            let browser_url = config.browser_url.clone();
            let context = config.context.clone();
            let observer_state = session_state.clone();
            let observer_engine = Arc::clone(&engine);
            let handle = tokio::spawn(async move {
                run_browser_state_observer(browser_url, context, observer_state, observer_engine)
                    .await;
            });
            drop(handle);
        } else if should_start_page_state_observer(&config.browser_url) {
            let browser_url = config.browser_url.clone();
            let context = config.context.clone();
            let observer_state = session_state.clone();
            let observer_engine = Arc::clone(&engine);
            let handle = tokio::spawn(async move {
                run_page_state_observer(browser_url, context, observer_state, observer_engine)
                    .await;
            });
            drop(handle);
        }

        Ok(Self {
            listener,
            browser_url: config.browser_url,
            engine,
            context: config.context,
            auth_token: config.auth_token,
            session_state,
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
            let auth_token = self.auth_token.clone();
            let session_state = self.session_state.clone();
            debug!(client = %address, "accepted CDP proxy connection");
            let handle = tokio::spawn(async move {
                match proxy_connection(
                    stream,
                    browser_url,
                    engine,
                    context,
                    auth_token,
                    session_state,
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

async fn proxy_connection(
    stream: TcpStream,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
    auth_token: Option<String>,
    session_state: CdpSessionState,
) -> Result<(), CdpError> {
    debug!("accepting client websocket");
    let client_socket = accept_client(stream, auth_token)
        .await
        .map_err(websocket_error)?;
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
                    match handle_client_text(
                        engine.as_ref(),
                        &context,
                        &session_state,
                        &mut client_targets,
                        &source,
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
) {
    loop {
        match observe_browser_state_connection(&browser_url, &context, &session_state, &engine)
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
) -> Result<(), CdpError> {
    let (mut browser_socket, _response) =
        connect_async(browser_url).await.map_err(websocket_error)?;
    bootstrap_browser_state_observer(&mut browser_socket, context, session_state, engine).await?;
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
        let message = timeout(OBSERVER_BOOTSTRAP_TIMEOUT, browser_socket.next())
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
                parse_internal_response::<target::SetDiscoverTargetsReturnObject>(
                    &source,
                    "Target.setDiscoverTargets",
                )?;
                discover_enabled = true;
            }
            Some(OBSERVER_SET_AUTO_ATTACH_ID) => {
                parse_internal_response::<target::SetAutoAttachReturnObject>(
                    &source,
                    "Target.setAutoAttach",
                )?;
                auto_attach_enabled = true;
            }
            Some(OBSERVER_GET_TARGETS_ID) => {
                let response = parse_internal_response::<target::GetTargetsReturnObject>(
                    &source,
                    "Target.getTargets",
                )?;
                for target_info in response.target_infos {
                    session_state.record_target_info(&target_info);
                }
                audit_state_recovery(engine, context, "browser_observer_bootstrap_targets", None);
                targets_loaded = true;
            }
            Some(id) => {
                if let Some(target_id) = frame_tree_requests.remove(id) {
                    let response = parse_internal_response::<page::GetFrameTreeReturnObject>(
                        &source,
                        "Page.getFrameTree",
                    )?;
                    audit_state_recovery(
                        engine,
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
) {
    loop {
        match observe_page_state_connection(&browser_url, &context, &session_state, &engine).await {
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
) -> Result<(), CdpError> {
    let (mut browser_socket, _response) =
        connect_async(browser_url).await.map_err(websocket_error)?;
    bootstrap_page_state_observer(&mut browser_socket, context, session_state, engine).await?;

    while let Some(message) = browser_socket.next().await {
        let message = message.map_err(websocket_error)?;
        if let Message::Text(source) = message {
            let _event = observe_browser_event_text(context, session_state, None, source.as_ref())?;
        }
    }

    Ok(())
}

async fn bootstrap_page_state_observer(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    engine: &CdpEngine,
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
        page::GetFrameTree(None),
        OBSERVER_GET_FRAME_TREE_ID,
    )
    .await?;

    let mut page_enabled = false;
    let mut runtime_enabled = false;
    let mut frame_tree_loaded = false;

    while !(page_enabled && runtime_enabled && frame_tree_loaded) {
        let message = timeout(OBSERVER_BOOTSTRAP_TIMEOUT, browser_socket.next())
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
                parse_internal_response::<Value>(&source, "Page.enable")?;
                page_enabled = true;
            }
            Some(OBSERVER_RUNTIME_ENABLE_ID) => {
                parse_internal_response::<Value>(&source, "Runtime.enable")?;
                runtime_enabled = true;
            }
            Some(OBSERVER_GET_FRAME_TREE_ID) => {
                let response = parse_internal_response::<page::GetFrameTreeReturnObject>(
                    &source,
                    "Page.getFrameTree",
                )?;
                audit_state_recovery(engine, context, "page_observer_bootstrap_frame_tree", None);
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
        let response =
            parse_internal_response::<page::GetFrameTreeReturnObject>(source, "Page.getFrameTree")?;
        audit_state_recovery(
            refs.engine,
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
        let get_frame_tree_id = scratch.next_observer_command_id.next();
        audit_state_recovery(
            refs.engine,
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

#[derive(Clone, Copy)]
struct BrowserObserverRefs<'a> {
    context: &'a CdpSessionContext,
    session_state: &'a CdpSessionState,
    engine: &'a CdpEngine,
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
        Self { next: 1 }
    }
}

impl ObserverCommandIds {
    fn next(&mut self) -> CallId {
        let id = self.next;
        self.next = self.next.saturating_add(1);
        id
    }
}

fn parse_internal_response<T>(source: &str, method: &str) -> Result<T, CdpError>
where
    T: serde::de::DeserializeOwned,
{
    let response: ObserverBootstrapMethodResponse<T> =
        serde_json::from_str(source).map_err(CdpError::invalid_protocol)?;
    if let Some(error) = response.error {
        return Err(CdpError::browser_state_sync(format!(
            "{method} failed: {}",
            error.message
        )));
    }

    response
        .result
        .ok_or_else(|| CdpError::browser_state_sync(format!("{method} did not return a result")))
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

async fn accept_client(
    stream: TcpStream,
    auth_token: Option<String>,
) -> Result<tokio_tungstenite::WebSocketStream<TcpStream>, WebSocketError> {
    let callback = move |request: &Request, response: Response| {
        if let Some(expected_token) = auth_token.as_deref() {
            if !request_has_auth_token(request, expected_token) {
                return Err(unauthorized_response());
            }
        }

        Ok(response)
    };

    accept_hdr_async(stream, callback).await
}

fn request_has_auth_token(request: &Request, expected_token: &str) -> bool {
    request.uri().query().is_some_and(|query| {
        query.split('&').any(|pair| {
            pair.split_once('=')
                .is_some_and(|(name, value)| name == "erebor_session" && value == expected_token)
        })
    })
}

fn unauthorized_response() -> ErrorResponse {
    let mut response = ErrorResponse::new(Some(String::from("missing or invalid erebor_session")));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
}

#[derive(Debug, PartialEq)]
enum ClientTextAction {
    Forward { payload: String },
    Reply { payload: Value },
    HoldForApproval,
}

fn handle_client_text(
    engine: &CdpEngine,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
    client_targets: &mut ClientTargetSessions,
    source: &str,
) -> Result<ClientTextAction, CdpError> {
    let command = decode_cdp_command(source)?;

    match enforce_cdp_command_with_client_state(
        engine,
        context,
        &command,
        session_state,
        Some(client_targets),
    )? {
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
                payload: error_response(&command, -32000, &reason),
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
    if target_command.method != target::AttachToTarget::NAME {
        return;
    }
    let Some(target_id) = target_command
        .target
        .as_ref()
        .and_then(|target| target.label.as_ref())
        .filter(|target_id| !target_id.is_empty())
    else {
        return;
    };

    client_targets.record_attach_request(command.id, BrowserTargetId::new(target_id.clone()));
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
    use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
    use erebor_runtime_policy::{LocalPolicy, PolicySet};
    use serde_json::json;

    use tokio_tungstenite::tungstenite::http::Request;

    use super::{
        handle_client_text, observe_browser_event_text, observe_browser_response_text,
        request_has_auth_token, ClientTextAction,
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

    #[test]
    fn auth_token_is_required_when_configured() -> Result<(), Box<dyn std::error::Error>> {
        let request = Request::builder()
            .uri("/?erebor_session=session-token")
            .body(())?;
        let missing = Request::builder().uri("/").body(())?;

        assert!(request_has_auth_token(&request, "session-token"));
        assert!(!request_has_auth_token(&request, "other-token"));
        assert!(!request_has_auth_token(&missing, "session-token"));
        Ok(())
    }
}
