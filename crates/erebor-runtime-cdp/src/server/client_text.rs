#[cfg(test)]
mod tests;

use cdp_protocol::{target, types::CallId, types::Method};
use erebor_runtime_telemetry::{debug, info};
use serde::Deserialize;
use serde_json::{json, Value};
use snafu::Location;

use super::{audit::CdpAuditRecorder, CdpEngine};
use crate::{
    CdpCommand, CdpCommandDecoder, CdpCommandEnforcer, CdpEnforcementAction, CdpError, CdpEvent,
    CdpEventDecoder, CdpEventObserver, CdpSessionContext, CdpSessionState, ClientTargetSessions,
    GovernedCdpCommand,
};

#[derive(Debug, PartialEq)]
pub(super) enum ClientTextAction {
    Forward { payload: String },
    Reply { payload: Value },
    HoldForApproval,
}

pub(super) struct ClientTextHandler;

impl ClientTextHandler {
    pub(super) fn handle(
        engine: &CdpEngine,
        context: &CdpSessionContext,
        session_state: &CdpSessionState,
        client_targets: &mut ClientTargetSessions,
        source: &str,
        audit_recorder: Option<&CdpAuditRecorder>,
    ) -> Result<ClientTextAction, CdpError> {
        let command = CdpCommandDecoder::decode(source)?;
        let outcome = CdpCommandEnforcer::outcome_for_client_state(
            engine,
            context,
            &command,
            session_state,
            Some(client_targets),
        )?;
        CdpAuditRecorder::record_optional(audit_recorder, outcome.audit_record());
        let rule_id = outcome
            .audit_record()
            .and_then(|record| record.final_decision.rule_id())
            .unwrap_or("none");

        match outcome.action() {
            CdpEnforcementAction::Forward => {
                if let Some(protocol_command) = command.protocol_command() {
                    ClientTargetCommandTracker::record(&command, protocol_command, client_targets);
                    session_state.record_provisional_forwarded_command_for_client_session(
                        protocol_command,
                        command.session_id.as_deref(),
                        Some(client_targets),
                    );
                }
                debug!(
                    session_id = %context.session_id.as_str(),
                    method = %command.method,
                    id = ?command.id,
                    "forwarding CDP command"
                );
                Ok(ClientTextAction::Forward {
                    payload: source.to_owned(),
                })
            }
            CdpEnforcementAction::Block { reason } => {
                info!(
                    session_id = %context.session_id.as_str(),
                    method = %command.method,
                    id = ?command.id,
                    reason = %reason,
                    rule_id = %rule_id,
                    "blocking CDP command"
                );
                Ok(ClientTextAction::Reply {
                    payload: CommandErrorResponse::from_command(&command, -32000, reason),
                })
            }
            CdpEnforcementAction::AwaitApproval { reason } => {
                info!(
                    session_id = %context.session_id.as_str(),
                    method = %command.method,
                    id = ?command.id,
                    reason = %reason,
                    rule_id = %rule_id,
                    "holding CDP command for approval"
                );
                Ok(ClientTextAction::HoldForApproval)
            }
        }
    }
}

pub(super) struct BrowserTextObserver;

impl BrowserTextObserver {
    pub(super) fn observe_event(
        context: &CdpSessionContext,
        session_state: &CdpSessionState,
        client_targets: Option<&mut ClientTargetSessions>,
        source: &str,
    ) -> Result<Option<CdpEvent>, CdpError> {
        let event = match CdpEventDecoder::decode(source) {
            Ok(Some(event)) => event,
            Ok(None) | Err(CdpError::InvalidJson { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        session_state.record_browser_event_for_client_session(&event, client_targets);
        let runtime_event = CdpEventObserver::observe(context, &event)?;
        debug!(
            session_id = %context.session_id.as_str(),
            method = %event.method(),
            event_id = %runtime_event.id.as_str(),
            "observed CDP context message"
        );

        Ok(Some(event))
    }

    pub(super) fn observe_response(
        client_targets: &mut ClientTargetSessions,
        source: &str,
    ) -> Result<(), CdpError> {
        let response = match serde_json::from_str::<ClientTargetMethodResponse>(source) {
            Ok(response) => response,
            Err(error) if error.is_data() => return Ok(()),
            Err(error) if error.is_syntax() || error.is_eof() => {
                return Err(CdpError::InvalidJson {
                    source: error,
                    location: Location::default(),
                });
            }
            Err(error) => {
                return Err(CdpError::InvalidProtocol {
                    source: error,
                    location: Location::default(),
                });
            }
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
}

struct ClientTargetCommandTracker;

impl ClientTargetCommandTracker {
    fn record(
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

        client_targets.record_attach_request(command.id, crate::BrowserTargetId::new(target_id));
    }
}

struct CommandErrorResponse;

impl CommandErrorResponse {
    fn from_command(command: &CdpCommand, code: i64, reason: &str) -> Value {
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
