//! Shared event contract for erebor-runtime enforcement surfaces.

use serde::{Deserialize, Serialize};

/// Stable event envelope emitted by every governed execution surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub id: EventId,
    pub session_id: SessionId,
    pub actor: ActorIdentity,
    pub surface: ExecutionSurface,
    pub action: ActionKind,
    pub target: Option<TargetRef>,
    pub payload: serde_json::Value,
    pub risk: RiskMetadata,
    pub timestamp: String,
}

/// RuntimeEvent plus the original substrate payload captured by an interceptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionEnvelope {
    pub event: RuntimeEvent,
    pub raw: serde_json::Value,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EventId(String);

impl EventId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorIdentity {
    pub id: String,
    pub kind: ActorKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Agent,
    User,
    System,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSurface {
    BrowserCdp,
    Mcp,
    Terminal,
    Network,
    SaaS,
    Desktop,
    InternalSystem,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    BrowserNavigate,
    BrowserClick,
    BrowserInput,
    BrowserScriptEval,
    NetworkRequest,
    ProcessExec,
    FileRead,
    FileWrite,
    ToolInvoke,
    SaaSMutation,
    DesktopInput,
    InternalMutation,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetRef {
    pub label: Option<String>,
    pub uri: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RiskMetadata {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}

impl RiskLevel {
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Unknown => 0,
        }
    }

    #[must_use]
    pub fn is_at_least(&self, minimum: &Self) -> bool {
        self.severity() >= minimum.severity()
    }
}

#[cfg(test)]
mod tests {
    use super::{
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
}
