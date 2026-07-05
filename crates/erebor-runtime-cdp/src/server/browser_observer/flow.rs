use cdp_protocol::{page, runtime as cdp_runtime, target, types::Event as ProtocolEvent};
use erebor_runtime_telemetry::debug;
use futures_util::StreamExt;
use snafu::ResultExt;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

use super::{BrowserObserverRefs, BrowserObserverScratch, BrowserStateObserver};
use crate::{
    error::{BrowserStateSyncSnafu, InvalidProtocolSnafu},
    BrowserTargetId, CdpError, CdpEvent, CdpSessionContext, CdpSessionState, ClientTargetSessions,
};

use crate::server::{
    audit::CdpAuditRecorder,
    client_text::BrowserTextObserver,
    fetch::{FetchRequestPausing, PausedFetchHandler},
    observer_wire::{
        BrowserSocket, FrameTreeRequests, InternalResponseParser, ObserverBootstrapMessageHead,
        ObserverCommandIds, ObserverSocket, StateRecoveryAuditor, WebSocketFailure,
        BOOTSTRAP_RESPONSE_TIMEOUT, GET_TARGETS_ID, SET_AUTO_ATTACH_ID, SET_DISCOVER_TARGETS_ID,
    },
    CdpEngine,
};

impl BrowserStateObserver {
    pub(super) async fn wait_for_bootstrap(
        browser_socket: &mut BrowserSocket,
        context: &CdpSessionContext,
        session_state: &CdpSessionState,
        engine: &CdpEngine,
        audit_recorder: Option<&CdpAuditRecorder>,
    ) -> Result<(), CdpError> {
        let mut discover_enabled = false;
        let mut auto_attach_enabled = false;
        let mut targets_loaded = false;
        let mut observer_targets = ClientTargetSessions::default();
        let mut frame_tree_requests = FrameTreeRequests::default();
        let mut next_observer_command_id = ObserverCommandIds::default();

        while !(discover_enabled && auto_attach_enabled && targets_loaded) {
            let message = timeout(BOOTSTRAP_RESPONSE_TIMEOUT, browser_socket.next())
                .await
                .map_err(|_| {
                    BrowserStateSyncSnafu {
                        reason: String::from("timed out waiting for browser observer bootstrap"),
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
                Self::observe_message(
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
                Some(SET_DISCOVER_TARGETS_ID) => {
                    InternalResponseParser::parse::<target::SetDiscoverTargets>(&source)?;
                    discover_enabled = true;
                }
                Some(SET_AUTO_ATTACH_ID) => {
                    InternalResponseParser::parse::<target::SetAutoAttach>(&source)?;
                    auto_attach_enabled = true;
                }
                Some(GET_TARGETS_ID) => {
                    let response = InternalResponseParser::parse::<target::GetTargets>(&source)?;
                    for target_info in response.target_infos {
                        session_state.record_target_info(&target_info);
                    }
                    StateRecoveryAuditor::audit(
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
                        let response =
                            InternalResponseParser::parse::<page::GetFrameTree>(&source)?;
                        StateRecoveryAuditor::audit(
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

    pub(super) async fn observe_message(
        browser_socket: &mut BrowserSocket,
        refs: BrowserObserverRefs<'_>,
        scratch: BrowserObserverScratch<'_>,
        source: &str,
    ) -> Result<(), CdpError> {
        if let Some(target_id) = scratch.frame_tree_requests.remove_for_response(source)? {
            let response = InternalResponseParser::parse::<page::GetFrameTree>(source)?;
            StateRecoveryAuditor::audit(
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

        let Some(event) = BrowserTextObserver::observe_event(
            refs.context,
            refs.session_state,
            Some(scratch.observer_targets),
            source,
        )?
        else {
            return Ok(());
        };

        PausedFetchHandler::handle(
            browser_socket,
            refs.engine,
            refs.context,
            &event,
            scratch.next_observer_command_id,
            refs.audit_recorder,
        )
        .await?;

        if let Some((session_id, target_id)) = AttachedPageTarget::from_event(&event) {
            ObserverSocket::send_session_method(
                browser_socket,
                page::Enable {
                    enable_file_chooser_opened_event: None,
                },
                scratch.next_observer_command_id.next(),
                &session_id,
            )
            .await?;
            ObserverSocket::send_session_method(
                browser_socket,
                cdp_runtime::Enable(None),
                scratch.next_observer_command_id.next(),
                &session_id,
            )
            .await?;
            ObserverSocket::send_session_method(
                browser_socket,
                FetchRequestPausing::enable(),
                scratch.next_observer_command_id.next(),
                &session_id,
            )
            .await?;
            let get_frame_tree_id = scratch.next_observer_command_id.next();
            StateRecoveryAuditor::audit(
                refs.engine,
                refs.audit_recorder,
                refs.context,
                "browser_observer_target_attach_frame_tree",
                Some(&target_id),
            );
            scratch
                .frame_tree_requests
                .insert(get_frame_tree_id, target_id);
            ObserverSocket::send_session_method(
                browser_socket,
                page::GetFrameTree(None),
                get_frame_tree_id,
                &session_id,
            )
            .await?;
        }

        Ok(())
    }
}

struct AttachedPageTarget;

impl AttachedPageTarget {
    fn from_event(event: &CdpEvent) -> Option<(String, BrowserTargetId)> {
        let ProtocolEvent::AttachedToTarget(attached) = event.protocol_event() else {
            return None;
        };
        let target_id = BrowserTargetId::new(attached.params.target_info.target_id.clone());
        let kind =
            crate::BrowserTargetKind::from_cdp_target_type(&attached.params.target_info.r#type);
        kind.is_page_like()
            .then(|| (attached.params.session_id.clone(), target_id))
    }
}
