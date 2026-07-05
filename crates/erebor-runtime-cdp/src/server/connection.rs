use std::{net::SocketAddr, sync::Arc};

use erebor_runtime_telemetry::debug;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};

use super::{
    audit::CdpAuditRecorder,
    client_text::{BrowserTextObserver, ClientTextAction, ClientTextHandler},
    http_discovery::HttpDiscoveryProxy,
    observer_wire::WebSocketFailure,
    CdpEngine,
};
use crate::{CdpError, CdpSessionContext, CdpSessionState, ClientTargetSessions};

pub(super) struct CdpClientConnection {
    stream: TcpStream,
    local_addr: SocketAddr,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
    session_state: CdpSessionState,
    audit_recorder: Option<CdpAuditRecorder>,
}

impl CdpClientConnection {
    pub(super) fn new(
        stream: TcpStream,
        local_addr: SocketAddr,
        browser_url: String,
        engine: Arc<CdpEngine>,
        context: CdpSessionContext,
        session_state: CdpSessionState,
        audit_recorder: Option<CdpAuditRecorder>,
    ) -> Self {
        Self {
            stream,
            local_addr,
            browser_url,
            engine,
            context,
            session_state,
            audit_recorder,
        }
    }

    pub(super) async fn run(self) -> Result<(), CdpError> {
        let Self {
            mut stream,
            local_addr,
            browser_url,
            engine,
            context,
            session_state,
            audit_recorder,
        } = self;

        if HttpDiscoveryProxy::handle(&mut stream, local_addr, &browser_url).await? {
            drop(stream);
            return Ok(());
        }

        debug!(
            session_id = %context.session_id.as_str(),
            "accepting client websocket"
        );
        let client_socket = accept_async(stream)
            .await
            .map_err(WebSocketFailure::from_error)?;
        debug!(
            browser_url = %browser_url,
            session_id = %context.session_id.as_str(),
            "connecting to upstream CDP websocket"
        );
        let (browser_socket, _response) = connect_async(browser_url.as_str())
            .await
            .map_err(WebSocketFailure::from_error)?;
        let (mut client_write, mut client_read) = client_socket.split();
        let (mut browser_write, mut browser_read) = browser_socket.split();
        let mut client_targets = ClientTargetSessions::default();

        loop {
            tokio::select! {
                client_message = client_read.next() => {
                    let Some(client_message) = client_message else {
                        break;
                    };
                    let client_message = client_message.map_err(WebSocketFailure::from_error)?;

                    if client_message.is_text() {
                        let source = client_message.into_text()
                            .map_err(WebSocketFailure::from_error)?
                            .to_string();
                        match ClientTextHandler::handle(
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
                                    .map_err(WebSocketFailure::from_error)?;
                            }
                            ClientTextAction::Reply { payload } => {
                                client_write
                                    .send(Message::Text(payload.to_string().into()))
                                    .await
                                    .map_err(WebSocketFailure::from_error)?;
                            }
                            ClientTextAction::HoldForApproval => {}
                        }
                    } else {
                        let should_close = client_message.is_close();
                        browser_write
                            .send(client_message)
                            .await
                            .map_err(WebSocketFailure::from_error)?;
                        if should_close {
                            break;
                        }
                    }
                }
                browser_message = browser_read.next() => {
                    let Some(browser_message) = browser_message else {
                        break;
                    };
                    let browser_message = browser_message.map_err(WebSocketFailure::from_error)?;

                    if browser_message.is_text() {
                        let source = browser_message.into_text()
                            .map_err(WebSocketFailure::from_error)?
                            .to_string();
                        BrowserTextObserver::observe_response(&mut client_targets, &source)?;
                        let _event = BrowserTextObserver::observe_event(
                            &context,
                            &session_state,
                            Some(&mut client_targets),
                            &source,
                        )?;
                        client_write
                            .send(Message::Text(source.into()))
                            .await
                            .map_err(WebSocketFailure::from_error)?;
                    } else {
                        let should_close = browser_message.is_close();
                        client_write
                            .send(browser_message)
                            .await
                            .map_err(WebSocketFailure::from_error)?;
                        if should_close {
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
