mod flow;

use std::sync::Arc;

use cdp_protocol::target;
use erebor_runtime_telemetry::warn;
use futures_util::StreamExt;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::{
    audit::CdpAuditRecorder,
    observer_wire::{
        BrowserSocket, FrameTreeRequests, ObserverCommandIds, ObserverSocket, WebSocketFailure,
        GET_TARGETS_ID, RECONNECT_DELAY, SET_AUTO_ATTACH_ID, SET_DISCOVER_TARGETS_ID,
    },
    CdpEngine,
};
use crate::{CdpError, CdpSessionContext, CdpSessionState, ClientTargetSessions};

pub(super) struct BrowserStateObserver;

impl BrowserStateObserver {
    pub(super) fn should_start(browser_url: &str) -> bool {
        browser_url.contains("/devtools/browser/")
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
                    "browser state observer stopped",
                    browser_url = %browser_url,
                    session_id = %context.session_id.as_str()
                ),
                Err(error) => warn!(
                    error;
                    "browser state observer failed",
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
        let mut observer_targets = ClientTargetSessions::default();
        let mut frame_tree_requests = FrameTreeRequests::default();
        let mut next_observer_command_id = ObserverCommandIds::default();

        while let Some(message) = browser_socket.next().await {
            let message = message.map_err(WebSocketFailure::from_error)?;
            let Message::Text(source) = message else {
                continue;
            };
            Self::observe_message(
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

    async fn bootstrap(
        browser_socket: &mut BrowserSocket,
        context: &CdpSessionContext,
        session_state: &CdpSessionState,
        engine: &CdpEngine,
        audit_recorder: Option<&CdpAuditRecorder>,
    ) -> Result<(), CdpError> {
        ObserverSocket::send_method(
            browser_socket,
            target::SetDiscoverTargets {
                discover: true,
                filter: None,
            },
            SET_DISCOVER_TARGETS_ID,
        )
        .await?;
        ObserverSocket::send_method(
            browser_socket,
            target::SetAutoAttach {
                auto_attach: true,
                wait_for_debugger_on_start: false,
                flatten: Some(true),
                filter: None,
            },
            SET_AUTO_ATTACH_ID,
        )
        .await?;
        ObserverSocket::send_method(
            browser_socket,
            target::GetTargets { filter: None },
            GET_TARGETS_ID,
        )
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
}

#[derive(Clone, Copy)]
pub(super) struct BrowserObserverRefs<'a> {
    context: &'a CdpSessionContext,
    session_state: &'a CdpSessionState,
    engine: &'a CdpEngine,
    audit_recorder: Option<&'a CdpAuditRecorder>,
}

pub(super) struct BrowserObserverScratch<'a> {
    observer_targets: &'a mut ClientTargetSessions,
    frame_tree_requests: &'a mut FrameTreeRequests,
    next_observer_command_id: &'a mut ObserverCommandIds,
}
