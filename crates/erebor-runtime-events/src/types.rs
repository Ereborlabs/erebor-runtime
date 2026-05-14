use serde::{Deserialize, Serialize};

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
