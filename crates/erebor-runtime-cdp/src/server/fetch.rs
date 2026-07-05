use cdp_protocol::{fetch, network, types::Event as ProtocolEvent};
use erebor_runtime_telemetry::{debug, info};

use super::{
    audit::CdpAuditRecorder,
    observer_wire::{BrowserSocket, ObserverCommandIds, ObserverSocket},
    CdpEngine,
};
use crate::{CdpEnforcementAction, CdpError, CdpEvent, CdpEventEnforcer, CdpSessionContext};

pub(super) struct PausedFetchHandler;

impl PausedFetchHandler {
    pub(super) async fn handle(
        browser_socket: &mut BrowserSocket,
        engine: &CdpEngine,
        context: &CdpSessionContext,
        event: &CdpEvent,
        next_observer_command_id: &mut ObserverCommandIds,
        audit_recorder: Option<&CdpAuditRecorder>,
    ) -> Result<(), CdpError> {
        let Some(paused) = PausedFetchRequest::from_event(event) else {
            return Ok(());
        };

        let outcome = CdpEventEnforcer::outcome(engine, context, event)?;
        CdpAuditRecorder::record_optional(audit_recorder, outcome.audit_record());
        let rule_id = outcome
            .audit_record()
            .and_then(|record| record.final_decision.rule_id())
            .unwrap_or("none");

        match outcome.action() {
            CdpEnforcementAction::Forward => {
                debug!(
                    session_id = %context.session_id.as_str(),
                    method = %event.method(),
                    request_id = %paused.request_id,
                    url = %paused.url,
                    "continuing observed Fetch request"
                );
                ObserverSocket::send_target_method(
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
            CdpEnforcementAction::Block { reason }
            | CdpEnforcementAction::AwaitApproval { reason } => {
                info!(
                    session_id = %context.session_id.as_str(),
                    method = %event.method(),
                    request_id = %paused.request_id,
                    url = %paused.url,
                    reason = %reason,
                    rule_id = %rule_id,
                    "failing observed Fetch request"
                );
                ObserverSocket::send_target_method(
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
}

pub(super) struct FetchRequestPausing;

impl FetchRequestPausing {
    pub(super) fn enable() -> fetch::Enable {
        fetch::Enable {
            patterns: Some(vec![fetch::RequestPattern {
                url_pattern: Some(String::from("*")),
                resource_type: Some(network::ResourceType::Document),
                request_stage: Some(fetch::RequestStage::Request),
            }]),
            handle_auth_requests: Some(false),
        }
    }
}

#[derive(Debug)]
struct PausedFetchRequest {
    request_id: String,
    url: String,
    session_id: Option<String>,
}

impl PausedFetchRequest {
    fn from_event(event: &CdpEvent) -> Option<Self> {
        let ProtocolEvent::FetchRequestPaused(paused) = event.protocol_event() else {
            return None;
        };

        Some(Self {
            request_id: paused.params.request_id.clone(),
            url: paused.params.request.url.clone(),
            session_id: event.session_id().map(ToOwned::to_owned),
        })
    }
}
