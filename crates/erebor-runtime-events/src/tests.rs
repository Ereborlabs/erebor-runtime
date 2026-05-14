use crate::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};

fn fixture(surface: ExecutionSurface, action: ActionKind) -> RuntimeEvent {
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
            label: Some(String::from("fixture target")),
            uri: None,
        }),
        payload: serde_json::json!({ "fixture": true }),
        risk: RiskMetadata {
            level: RiskLevel::Medium,
            reasons: vec![String::from("fixture")],
        },
        timestamp: String::from("2026-05-13T00:00:00Z"),
    }
}

#[test]
fn fixture_events_cover_planned_surfaces() {
    let fixtures = [
        fixture(ExecutionSurface::BrowserCdp, ActionKind::BrowserNavigate),
        fixture(ExecutionSurface::Terminal, ActionKind::ProcessExec),
        fixture(ExecutionSurface::Mcp, ActionKind::ToolInvoke),
        fixture(ExecutionSurface::Network, ActionKind::NetworkRequest),
        fixture(ExecutionSurface::SaaS, ActionKind::SaaSMutation),
        fixture(ExecutionSurface::Desktop, ActionKind::DesktopInput),
        fixture(
            ExecutionSurface::InternalSystem,
            ActionKind::InternalMutation,
        ),
    ];

    assert_eq!(fixtures.len(), 7);
    assert!(fixtures
        .iter()
        .all(|event| event.actor.kind == ActorKind::Agent));
}

#[test]
fn serializes_event_contract() -> Result<(), serde_json::Error> {
    let event = fixture(ExecutionSurface::BrowserCdp, ActionKind::BrowserScriptEval);
    let encoded = serde_json::to_string(&event)?;
    let decoded: RuntimeEvent = serde_json::from_str(&encoded)?;

    assert_eq!(decoded.surface, ExecutionSurface::BrowserCdp);
    assert_eq!(decoded.action, ActionKind::BrowserScriptEval);
    assert_eq!(decoded.risk.level, RiskLevel::Medium);

    Ok(())
}

#[test]
fn risk_order_supports_policy_thresholds() {
    assert!(RiskLevel::High.is_at_least(&RiskLevel::Medium));
    assert!(RiskLevel::Medium.is_at_least(&RiskLevel::Low));
    assert!(!RiskLevel::Low.is_at_least(&RiskLevel::High));
    assert!(!RiskLevel::Unknown.is_at_least(&RiskLevel::Low));
}
