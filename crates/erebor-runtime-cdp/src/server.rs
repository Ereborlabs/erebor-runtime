use std::{net::SocketAddr, sync::Arc};

use cdp_protocol::{
    page, runtime as cdp_runtime,
    types::{CallId, Method},
};
use erebor_runtime_core::LocalEnforcementEngine;
use erebor_runtime_policy::PolicySet;
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
    decode_cdp_command, decode_cdp_event, enforce_cdp_command_with_session_state,
    observe_cdp_event, CdpCommand, CdpEnforcementAction, CdpError, CdpSessionContext,
    CdpSessionState,
};

type CdpEngine = LocalEnforcementEngine<PolicySet>;
const OBSERVER_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(1);
const OBSERVER_RECONNECT_DELAY: Duration = Duration::from_millis(250);
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
        if should_start_page_state_observer(&config.browser_url) {
            let browser_url = config.browser_url.clone();
            let context = config.context.clone();
            let observer_state = session_state.clone();
            let handle = tokio::spawn(async move {
                run_page_state_observer(browser_url, context, observer_state).await;
            });
            drop(handle);
        }

        Ok(Self {
            listener,
            browser_url: config.browser_url,
            engine: Arc::new(engine),
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

    loop {
        tokio::select! {
            client_message = client_read.next() => {
                let Some(client_message) = client_message else {
                    break;
                };
                let client_message = client_message.map_err(websocket_error)?;

                if client_message.is_text() {
                    let source = client_message.into_text().map_err(websocket_error)?.to_string();
                    match handle_client_text(engine.as_ref(), &context, &session_state, &source)? {
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
                    observe_browser_event_text(&context, &session_state, &source)?;
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

async fn run_page_state_observer(
    browser_url: String,
    context: CdpSessionContext,
    session_state: CdpSessionState,
) {
    loop {
        match observe_page_state_connection(&browser_url, &context, &session_state).await {
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
) -> Result<(), CdpError> {
    let (mut browser_socket, _response) =
        connect_async(browser_url).await.map_err(websocket_error)?;
    bootstrap_page_state_observer(&mut browser_socket, context, session_state).await?;

    while let Some(message) = browser_socket.next().await {
        let message = message.map_err(websocket_error)?;
        if let Message::Text(source) = message {
            observe_browser_event_text(context, session_state, source.as_ref())?;
        }
    }

    Ok(())
}

async fn bootstrap_page_state_observer(
    browser_socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    context: &CdpSessionContext,
    session_state: &CdpSessionState,
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
            observe_browser_event_text(context, session_state, &source)?;
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
                session_state.record_frame_tree(&response.frame_tree);
                frame_tree_loaded = true;
            }
            Some(_) | None => {}
        }
    }

    debug!("bootstrapped page state observer from upstream CDP");
    Ok(())
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
    source: &str,
) -> Result<ClientTextAction, CdpError> {
    let command = decode_cdp_command(source)?;

    match enforce_cdp_command_with_session_state(engine, context, &command, session_state)? {
        CdpEnforcementAction::Forward => {
            if let Some(command) = command.protocol_command() {
                session_state.record_provisional_forwarded_command(command);
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
    source: &str,
) -> Result<(), CdpError> {
    let event = match decode_cdp_event(source) {
        Ok(Some(event)) => event,
        Ok(None) | Err(CdpError::InvalidJson { .. }) => return Ok(()),
        Err(error) => return Err(error),
    };
    session_state.record_browser_event(&event);
    let runtime_event = observe_cdp_event(context, &event)?;
    debug!(
        method = %event.method(),
        event_id = %runtime_event.id.as_str(),
        "observed CDP context message"
    );

    Ok(())
}

fn error_response(command: &CdpCommand, code: i64, reason: &str) -> Value {
    json!({
        "id": command.id,
        "error": {
            "code": code,
            "message": reason
        }
    })
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
        handle_client_text, observe_browser_event_text, request_has_auth_token, ClientTextAction,
    };
    use crate::{CdpSessionContext, CdpSessionState};

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

        let action = handle_client_text(&engine, &context(), &CdpSessionState::default(), source)?;

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

        let action = handle_client_text(&engine, &context(), &CdpSessionState::default(), source)?;

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

        let action = handle_client_text(&engine, &context(), &CdpSessionState::default(), source)?;

        assert_eq!(action, ClientTextAction::HoldForApproval);
        Ok(())
    }

    #[test]
    fn browser_text_ignores_command_responses() -> Result<(), Box<dyn std::error::Error>> {
        observe_browser_event_text(
            &context(),
            &CdpSessionState::default(),
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
