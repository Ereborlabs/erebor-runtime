use erebor_runtime_events::{EventId, RiskMetadata, RuntimeEvent};
use serde_json::{json, Value};

use super::CdpSessionContext;
use crate::{error::UnsupportedMethodSnafu, CdpError, CdpEvent, CdpMethodRegistry};

pub struct CdpEventObserver;

impl CdpEventObserver {
    pub fn observe(
        context: &CdpSessionContext,
        event: &CdpEvent,
    ) -> Result<RuntimeEvent, CdpError> {
        let classification = CdpMethodRegistry::classify(event.method()).ok_or_else(|| {
            UnsupportedMethodSnafu {
                method: event.method(),
            }
            .build()
        })?;

        Ok(RuntimeEvent {
            id: EventId::new(event.event_id()),
            session_id: context.session_id.clone(),
            actor: context.actor.clone(),
            surface: classification.surface,
            action: classification.action,
            target: event.target(),
            payload: Self::event_payload(event),
            risk: RiskMetadata {
                level: classification.risk_level,
                reasons: vec![format!("inspected CDP method `{}`", event.method())],
            },
            timestamp: context.timestamp.clone(),
        })
    }

    pub(super) fn command_payload(
        command: &crate::CdpCommand,
        page_context: Value,
    ) -> Result<Value, CdpError> {
        let params = command.params().ok_or_else(|| {
            UnsupportedMethodSnafu {
                method: command.method.clone(),
            }
            .build()
        })?;

        Ok(json!({
            "kind": "command",
            "method": command.method,
            "message_id": command.id,
            "cdp_session_id": command.session_id,
            "page": page_context,
            "params": params,
        }))
    }

    fn event_payload(event: &CdpEvent) -> Value {
        json!({
            "kind": "event",
            "method": event.method(),
            "cdp_session_id": event.session_id(),
            "event_id": event.event_id(),
            "params": event.params(),
        })
    }
}
