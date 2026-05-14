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
pub enum ActorKind {
    Agent,
    User,
    System,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}
