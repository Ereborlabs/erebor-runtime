use erebor_runtime_core::{ApprovalProvider, AuditRecord, AuditSink, LocalEnforcementEngine};
use erebor_runtime_events::{EventId, RiskMetadata, RuntimeEvent};
use erebor_runtime_policy::PolicyEvaluator;
use snafu::ResultExt;

use super::{
    decision::EnforcementDecisionMapper, CdpEnforcementAction, CdpEnforcementOutcome,
    CdpEventObserver, CdpSessionContext,
};
use crate::{
    error::{EnforcementSnafu, UnsupportedMethodSnafu},
    CdpCommand, CdpError, CdpMethodRegistry, CdpSessionState, ClientTargetSessions,
    GovernedCdpCommand,
};

pub struct CdpCommandEnforcer;

impl CdpCommandEnforcer {
    pub fn enforce<E, A, S>(
        engine: &LocalEnforcementEngine<E, A, S>,
        context: &CdpSessionContext,
        command: &CdpCommand,
    ) -> Result<CdpEnforcementAction, CdpError>
    where
        E: PolicyEvaluator,
        A: ApprovalProvider,
        S: AuditSink,
    {
        Self::enforce_for_session_state(engine, context, command, &CdpSessionState::default())
    }

    pub fn enforce_for_session_state<E, A, S>(
        engine: &LocalEnforcementEngine<E, A, S>,
        context: &CdpSessionContext,
        command: &CdpCommand,
        session_state: &CdpSessionState,
    ) -> Result<CdpEnforcementAction, CdpError>
    where
        E: PolicyEvaluator,
        A: ApprovalProvider,
        S: AuditSink,
    {
        Self::enforce_for_client_state(engine, context, command, session_state, None)
    }

    pub fn enforce_for_client_state<E, A, S>(
        engine: &LocalEnforcementEngine<E, A, S>,
        context: &CdpSessionContext,
        command: &CdpCommand,
        session_state: &CdpSessionState,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Result<CdpEnforcementAction, CdpError>
    where
        E: PolicyEvaluator,
        A: ApprovalProvider,
        S: AuditSink,
    {
        Ok(Self::outcome_for_client_state(
            engine,
            context,
            command,
            session_state,
            client_sessions,
        )?
        .action()
        .clone())
    }

    pub fn outcome_for_client_state<E, A, S>(
        engine: &LocalEnforcementEngine<E, A, S>,
        context: &CdpSessionContext,
        command: &CdpCommand,
        session_state: &CdpSessionState,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Result<CdpEnforcementOutcome, CdpError>
    where
        E: PolicyEvaluator,
        A: ApprovalProvider,
        S: AuditSink,
    {
        if command.protocol_command().is_none() {
            return Ok(CdpEnforcementOutcome::unrecorded(
                CdpEnforcementAction::Forward,
            ));
        }

        if Self::browser_level_target_is_ambiguous(command, client_sessions) {
            return Ok(CdpEnforcementOutcome::unrecorded(
                CdpEnforcementAction::Block {
                    reason: String::from("browser target is unknown for CDP session"),
                },
            ));
        }

        let event = Self::normalize_command(context, command, session_state, client_sessions)?;
        let outcome = engine
            .enforce_with_deferred_approval(&event)
            .context(EnforcementSnafu)?;

        let action =
            EnforcementDecisionMapper::action(&outcome.policy_decision, &outcome.final_decision);
        let audit_record = AuditRecord::from_outcome(&outcome);
        Ok(CdpEnforcementOutcome::recorded(action, audit_record))
    }

    fn browser_level_target_is_ambiguous(
        command: &CdpCommand,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> bool {
        let Some(session_id) = command.session_id.as_deref() else {
            return false;
        };
        let Some(protocol_command) = command.protocol_command() else {
            return false;
        };
        if matches!(protocol_command, GovernedCdpCommand::TargetManagement(_)) {
            return false;
        }

        client_sessions.is_none_or(|sessions| !sessions.has_session(session_id))
    }

    fn normalize_command(
        context: &CdpSessionContext,
        command: &CdpCommand,
        session_state: &CdpSessionState,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Result<RuntimeEvent, CdpError> {
        let classification = CdpMethodRegistry::classify(&command.method).ok_or_else(|| {
            UnsupportedMethodSnafu {
                method: command.method.clone(),
            }
            .build()
        })?;
        let protocol_command = command.protocol_command().ok_or_else(|| {
            UnsupportedMethodSnafu {
                method: command.method.clone(),
            }
            .build()
        })?;

        Ok(RuntimeEvent {
            id: EventId::new(command.id.to_string()),
            session_id: context.session_id.clone(),
            actor: context.actor.clone(),
            surface: classification.surface,
            action: classification.action,
            target: session_state.target_for_client_command(
                protocol_command,
                command.session_id.as_deref(),
                client_sessions,
            ),
            payload: CdpEventObserver::command_payload(
                command,
                session_state.command_page_payload_for_client(
                    protocol_command,
                    command.session_id.as_deref(),
                    client_sessions,
                ),
            )?,
            risk: RiskMetadata {
                level: classification.risk_level,
                reasons: vec![format!("governed CDP method `{}`", command.method)],
            },
            timestamp: context.timestamp.clone(),
        })
    }
}
