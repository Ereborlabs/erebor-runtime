use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NotificationDeliveryKindV1 {
    Finding,
    FailureEscalation,
    AcknowledgementEscalation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NotificationFailureV1 {
    NoRoute,
    SinkUnavailable,
    SinkRejected,
    TransportFailed,
    AuthorizationRevoked,
    DisclosureDenied,
    FindingUnavailable,
    InvalidSinkResult,
    RetryExhausted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NotificationSinkResultV1 {
    Accepted { receipt: String },
    AgentReceived { receipt: String },
    Failed { reason: NotificationFailureV1 },
}

impl NotificationSinkResultV1 {
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Accepted { receipt } | Self::AgentReceived { receipt } => {
                NotificationGrantV1::identifier(receipt, 128)
            }
            Self::Failed { .. } => true,
        }
    }

    pub(crate) fn accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. } | Self::AgentReceived { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAttemptV1 {
    pub number: u64,
    pub kind: NotificationDeliveryKindV1,
    pub finding_revision: u64,
    pub context_revision: u64,
    pub priority: NotificationPriorityV1,
    pub started_utc_ns: u64,
    pub completed_utc_ns: Option<u64>,
    pub result: Option<NotificationSinkResultV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAcknowledgementV1 {
    pub request_id: [u8; 16],
    pub principal_id: [u8; 16],
    pub authorization_revision: u64,
    pub finding_revision: u64,
    pub acknowledged_utc_ns: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAgentReceiptV1 {
    pub request_id: [u8; 16],
    pub principal_id: [u8; 16],
    pub authorization_revision: u64,
    pub received_utc_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAdvisoryV1 {
    pub suggested_priority: NotificationPriorityV1,
    pub model_label: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NotificationSinkHealthV1 {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationDeliveryV1 {
    pub key: NotificationKeyV1,
    pub attempt: u64,
    pub kind: NotificationDeliveryKindV1,
    pub route_id: String,
    pub route_revision: u64,
    pub finding: Option<NotificationFindingV1>,
    pub unconfirmed_concern: Option<UnconfirmedNotificationConcernV1>,
    pub required_action: Option<String>,
    pub priority: NotificationPriorityV1,
    pub deadline_utc_ns: u64,
    pub overdue: bool,
}

/// A sink deduplicates the notification key, delivery kind, and attempt number.
pub trait NotificationSink: Send + Sync {
    fn deliver(&self, delivery: &NotificationDeliveryV1) -> NotificationSinkResultV1;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct NotificationHealthV1 {
    pub routing_available: bool,
    pub configured_routes: usize,
    pub obligations: usize,
    pub unrouted: usize,
    pub failed: usize,
    pub overdue: usize,
    pub acknowledged: usize,
}
