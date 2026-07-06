use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};

pub(super) struct PolicyEventFixture;

impl PolicyEventFixture {
    pub(super) fn event(
        surface: ExecutionSurface,
        action: ActionKind,
        risk: RiskLevel,
    ) -> RuntimeEvent {
        RuntimeEvent {
            id: EventId::new("evt-1"),
            session_id: SessionId::new("session-1"),
            actor: ActorIdentity {
                id: String::from("agent-1"),
                kind: ActorKind::Agent,
            },
            surface,
            action,
            target: Some(TargetRef {
                label: Some(String::from("Delete")),
                uri: Some(String::from("https://mail.example/message/1")),
            }),
            payload: serde_json::json!({}),
            risk: RiskMetadata {
                level: risk,
                reasons: Vec::new(),
            },
            timestamp: String::from("2026-05-13T00:00:00Z"),
        }
    }

    pub(super) fn event_with_payload(
        surface: ExecutionSurface,
        action: ActionKind,
        risk: RiskLevel,
        payload: serde_json::Value,
    ) -> RuntimeEvent {
        RuntimeEvent {
            payload,
            ..Self::event(surface, action, risk)
        }
    }
}
