use std::{net::SocketAddr, sync::Arc};

use erebor_runtime_core::LocalEnforcementEngine;
use erebor_runtime_policy::PolicySet;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async, connect_async,
    tungstenite::{Error as WebSocketError, Message},
};
use tracing::{debug, info, warn};

use crate::{
    decode_cdp_command, decode_cdp_event, enforce_cdp_command, observe_cdp_event, CdpCommand,
    CdpEnforcementAction, CdpError, CdpSessionContext,
};

type CdpEngine = LocalEnforcementEngine<PolicySet>;

#[derive(Clone, Debug, PartialEq)]
pub struct CdpProxyServerConfig {
    pub listen: SocketAddr,
    pub browser_url: String,
    pub context: CdpSessionContext,
}

pub struct CdpProxyServer {
    listener: TcpListener,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
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

        Ok(Self {
            listener,
            browser_url: config.browser_url,
            engine: Arc::new(engine),
            context: config.context,
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
            debug!(client = %address, "accepted CDP proxy connection");
            let handle = tokio::spawn(async move {
                match proxy_connection(stream, browser_url, engine, context).await {
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
) -> Result<(), CdpError> {
    debug!("accepting client websocket");
    let client_socket = accept_async(stream).await.map_err(websocket_error)?;
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
                    match handle_client_text(engine.as_ref(), &context, &source)? {
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
                    observe_browser_text(&context, &source)?;
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

#[derive(Debug, PartialEq)]
enum ClientTextAction {
    Forward { payload: String },
    Reply { payload: Value },
    HoldForApproval,
}

fn handle_client_text(
    engine: &CdpEngine,
    context: &CdpSessionContext,
    source: &str,
) -> Result<ClientTextAction, CdpError> {
    let command = decode_cdp_command(source)?;

    match enforce_cdp_command(engine, context, &command)? {
        CdpEnforcementAction::Forward => {
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

fn observe_browser_text(context: &CdpSessionContext, source: &str) -> Result<(), CdpError> {
    let event = match decode_cdp_event(source) {
        Ok(Some(event)) => event,
        Ok(None) | Err(CdpError::InvalidJson { .. }) => return Ok(()),
        Err(error) => return Err(error),
    };
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

    use super::{handle_client_text, observe_browser_text, ClientTextAction};
    use crate::CdpSessionContext;

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

        let action = handle_client_text(&engine, &context(), source)?;

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

        let action = handle_client_text(&engine, &context(), source)?;

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

        let action = handle_client_text(&engine, &context(), source)?;

        assert_eq!(action, ClientTextAction::HoldForApproval);
        Ok(())
    }

    #[test]
    fn browser_text_ignores_command_responses() -> Result<(), Box<dyn std::error::Error>> {
        observe_browser_text(&context(), r#"{ "id": 1, "result": {} }"#)?;

        Ok(())
    }
}
