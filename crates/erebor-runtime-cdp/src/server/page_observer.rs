use std::sync::Arc;

use cdp_protocol::{fetch, page, runtime as cdp_runtime};
use erebor_runtime_telemetry::{debug, warn};
use futures_util::StreamExt;
use snafu::ResultExt;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::{
    audit::CdpAuditRecorder,
    client_text::BrowserTextObserver,
    fetch::{FetchRequestPausing, PausedFetchHandler},
    observer_wire::{
        BrowserSocket, InternalResponseParser, ObserverBootstrapMessageHead, ObserverCommandIds,
        ObserverSocket, StateRecoveryAuditor, WebSocketFailure, BOOTSTRAP_RESPONSE_TIMEOUT,
        FETCH_ENABLE_ID, GET_FRAME_TREE_ID, PAGE_ENABLE_ID, RECONNECT_DELAY, RUNTIME_ENABLE_ID,
    },
    CdpEngine,
};
use crate::{
    error::{BrowserStateSyncSnafu, InvalidProtocolSnafu},
    CdpError, CdpSessionContext, CdpSessionState,
};

pub(super) struct PageStateObserver;

impl PageStateObserver {
    pub(super) fn should_start(browser_url: &str) -> bool {
        browser_url.contains("/devtools/page/")
    }

    pub(super) fn spawn(
        browser_url: String,
        context: CdpSessionContext,
        session_state: CdpSessionState,
        engine: Arc<CdpEngine>,
        audit_recorder: Option<CdpAuditRecorder>,
    ) {
        let handle = tokio::spawn(async move {
            Self::run(browser_url, context, session_state, engine, audit_recorder).await;
        });
        drop(handle);
    }

    async fn run(
        browser_url: String,
        context: CdpSessionContext,
        session_state: CdpSessionState,
        engine: Arc<CdpEngine>,
        audit_recorder: Option<CdpAuditRecorder>,
    ) {
        loop {
            match Self::observe_connection(
                &browser_url,
                &context,
                &session_state,
                &engine,
                audit_recorder.as_ref(),
            )
            .await
            {
                Ok(()) => warn!(
                    "page state observer stopped",
                    browser_url = %browser_url,
                    session_id = %context.session_id.as_str()
                ),
                Err(error) => warn!(
                    error;
                    "page state observer failed",
                    browser_url = %browser_url,
                    session_id = %context.session_id.as_str()
                ),
            }

            sleep(RECONNECT_DELAY).await;
        }
    }

    async fn observe_connection(
        browser_url: &str,
        context: &CdpSessionContext,
        session_state: &CdpSessionState,
        engine: &CdpEngine,
        audit_recorder: Option<&CdpAuditRecorder>,
    ) -> Result<(), CdpError> {
        let (mut browser_socket, _response) = connect_async(browser_url)
            .await
            .map_err(WebSocketFailure::from_error)?;
        Self::bootstrap(
            &mut browser_socket,
            context,
            session_state,
            engine,
            audit_recorder,
        )
        .await?;
        let mut next_observer_command_id = ObserverCommandIds::default();

        while let Some(message) = browser_socket.next().await {
            let message = message.map_err(WebSocketFailure::from_error)?;
            if let Message::Text(source) = message {
                if let Some(event) = BrowserTextObserver::observe_event(
                    context,
                    session_state,
                    None,
                    source.as_ref(),
                )? {
                    PausedFetchHandler::handle(
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

    async fn bootstrap(
        browser_socket: &mut BrowserSocket,
        context: &CdpSessionContext,
        session_state: &CdpSessionState,
        engine: &CdpEngine,
        audit_recorder: Option<&CdpAuditRecorder>,
    ) -> Result<(), CdpError> {
        ObserverSocket::send_method(
            browser_socket,
            page::Enable {
                enable_file_chooser_opened_event: None,
            },
            PAGE_ENABLE_ID,
        )
        .await?;
        ObserverSocket::send_method(browser_socket, cdp_runtime::Enable(None), RUNTIME_ENABLE_ID)
            .await?;
        ObserverSocket::send_method(
            browser_socket,
            FetchRequestPausing::enable(),
            FETCH_ENABLE_ID,
        )
        .await?;
        ObserverSocket::send_method(browser_socket, page::GetFrameTree(None), GET_FRAME_TREE_ID)
            .await?;

        Self::wait_for_bootstrap(
            browser_socket,
            context,
            session_state,
            engine,
            audit_recorder,
        )
        .await
    }

    async fn wait_for_bootstrap(
        browser_socket: &mut BrowserSocket,
        context: &CdpSessionContext,
        session_state: &CdpSessionState,
        engine: &CdpEngine,
        audit_recorder: Option<&CdpAuditRecorder>,
    ) -> Result<(), CdpError> {
        let mut page_enabled = false;
        let mut runtime_enabled = false;
        let mut fetch_enabled = false;
        let mut frame_tree_loaded = false;

        while !(page_enabled && runtime_enabled && fetch_enabled && frame_tree_loaded) {
            let message = timeout(BOOTSTRAP_RESPONSE_TIMEOUT, browser_socket.next())
                .await
                .map_err(|_| {
                    BrowserStateSyncSnafu {
                        reason: String::from("timed out waiting for observer bootstrap"),
                    }
                    .build()
                })?
                .ok_or_else(|| {
                    BrowserStateSyncSnafu {
                        reason: String::from("browser socket closed during observer bootstrap"),
                    }
                    .build()
                })?
                .map_err(WebSocketFailure::from_error)?;

            let Message::Text(source) = message else {
                continue;
            };
            let source = source.to_string();
            let head = serde_json::from_str::<ObserverBootstrapMessageHead>(&source)
                .context(InvalidProtocolSnafu)?;

            if head.method.is_some() {
                let _event =
                    BrowserTextObserver::observe_event(context, session_state, None, &source)?;
                continue;
            }

            match head.id {
                Some(PAGE_ENABLE_ID) => {
                    InternalResponseParser::parse::<page::Enable>(&source)?;
                    page_enabled = true;
                }
                Some(RUNTIME_ENABLE_ID) => {
                    InternalResponseParser::parse::<cdp_runtime::Enable>(&source)?;
                    runtime_enabled = true;
                }
                Some(FETCH_ENABLE_ID) => {
                    InternalResponseParser::parse::<fetch::Enable>(&source)?;
                    fetch_enabled = true;
                }
                Some(GET_FRAME_TREE_ID) => {
                    let response = InternalResponseParser::parse::<page::GetFrameTree>(&source)?;
                    StateRecoveryAuditor::audit(
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
}
