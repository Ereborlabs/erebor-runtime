use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use crate::{ContextSensitivityV1, FindingSeverityV1, GraphRevisionV1, Result};

pub const NOTIFICATION_ROUTE_OWNER: &str = "notification-route-v1";
pub const NOTIFICATION_STATE_OWNER: &str = "notification-state-v1";
/// This value limits one read page or one routing or delivery call.
pub const MAX_NOTIFICATION_STATES: usize = 256;
pub const MAX_NOTIFICATION_ROUTES: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NotificationErrorCodeV1 {
    Invalid,
    Denied,
    Conflict,
    Limit,
    Unavailable,
}

impl NotificationErrorCodeV1 {
    pub(crate) fn require(self, value: bool, field: &'static str) -> Result<()> {
        if value {
            Ok(())
        } else {
            crate::NotificationSnafu { code: self, field }.fail()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NotificationPriorityV1 {
    Info,
    Warning,
    High,
    Critical,
}

impl From<FindingSeverityV1> for NotificationPriorityV1 {
    fn from(value: FindingSeverityV1) -> Self {
        match value {
            FindingSeverityV1::Info => Self::Info,
            FindingSeverityV1::Warning => Self::Warning,
            FindingSeverityV1::High => Self::High,
            FindingSeverityV1::Critical => Self::Critical,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NotificationPrincipalV1 {
    Human,
    Agent,
    Service,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NotificationOperationV1 {
    Configure,
    Read,
    Acknowledge,
    RecordAgent,
    SubmitConcern,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationGrantV1 {
    pub tenant_id: [u8; 16],
    pub principal_id: [u8; 16],
    pub principal: NotificationPrincipalV1,
    pub authorization_revision: u64,
    pub routes: Vec<String>,
    pub operations: Vec<NotificationOperationV1>,
    pub max_sensitivity: ContextSensitivityV1,
    pub expires_utc_ns: u64,
}

impl NotificationGrantV1 {
    pub fn validate(&self) -> Result<()> {
        NotificationErrorCodeV1::Invalid.require(
            self.tenant_id != [0; 16]
                && self.principal_id != [0; 16]
                && self.authorization_revision > 0
                && self.expires_utc_ns > 0
                && (1..=MAX_NOTIFICATION_ROUTES).contains(&self.routes.len())
                && self.routes.iter().all(|route| Self::identifier(route, 64))
                && self.routes.windows(2).all(|pair| pair[0] < pair[1])
                && !self.operations.is_empty()
                && self.operations.windows(2).all(|pair| pair[0] < pair[1]),
            "grant",
        )
    }

    pub fn allows(
        &self,
        tenant: [u8; 16],
        route: &str,
        operation: NotificationOperationV1,
        now: u64,
    ) -> bool {
        self.tenant_id == tenant
            && now > 0
            && now < self.expires_utc_ns
            && self.routes.iter().any(|candidate| candidate == route)
            && self.operations.contains(&operation)
    }

    pub fn sensitivity(allowed: ContextSensitivityV1, requested: ContextSensitivityV1) -> bool {
        matches!(
            (allowed, requested),
            (ContextSensitivityV1::HostRestricted, _)
                | (
                    ContextSensitivityV1::Tenant,
                    ContextSensitivityV1::Public | ContextSensitivityV1::Tenant
                )
                | (ContextSensitivityV1::Public, ContextSensitivityV1::Public)
        )
    }

    pub(crate) fn identifier(value: &str, limit: usize) -> bool {
        !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
    }
}

/// The caller must authenticate the grant principal before an operation.
/// The authority checks the current principal, revision, routes, and permissions.
pub trait NotificationAuthorization: Send + Sync {
    fn check(&self, grant: &NotificationGrantV1, now_utc_ns: u64) -> Result<()>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationPolicyV1 {
    pub tenant_id: [u8; 16],
    pub route_id: String,
    pub revision: u64,
    pub package_ids: Vec<String>,
    pub minimum_priority: NotificationPriorityV1,
    pub acknowledgement_ns: u64,
    pub retry_limit: u16,
    pub retry_delay_ns: u64,
    pub escalation_route_id: String,
    pub max_sensitivity: ContextSensitivityV1,
    #[serde(default)]
    pub allow_concerns: bool,
}

impl NotificationPolicyV1 {
    pub fn validate(&self) -> Result<()> {
        NotificationErrorCodeV1::Invalid.require(
            self.tenant_id != [0; 16]
                && NotificationGrantV1::identifier(&self.route_id, 64)
                && self.revision > 0
                && (1..=16).contains(&self.package_ids.len())
                && self
                    .package_ids
                    .iter()
                    .all(|package| NotificationGrantV1::identifier(package, 64))
                && self.package_ids.windows(2).all(|pair| pair[0] < pair[1])
                && self.acknowledgement_ns > 0
                && (1..=16).contains(&self.retry_limit)
                && self.retry_delay_ns > 0
                && NotificationGrantV1::identifier(&self.escalation_route_id, 64),
            "policy",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedNotificationRouteV1 {
    pub policy: NotificationPolicyV1,
    pub grant: NotificationGrantV1,
    pub approved_utc_ns: u64,
}

impl TryFrom<&crate::AnalysisContextVersionV1> for ApprovedNotificationRouteV1 {
    type Error = crate::Error;

    fn try_from(context: &crate::AnalysisContextVersionV1) -> Result<Self> {
        NotificationErrorCodeV1::Invalid.require(
            context.key.owner_id == NOTIFICATION_ROUTE_OWNER
                && context.key.lifetime_key == b"route"
                && context.sensitivity == ContextSensitivityV1::HostRestricted
                && context.body.len() <= 32 * 1024,
            "route context owner",
        )?;
        let route: Self =
            serde_json::from_slice(&context.body).context(crate::NotificationEncodingSnafu)?;
        route.policy.validate()?;
        route.grant.validate()?;
        NotificationErrorCodeV1::Invalid.require(
            route.policy.tenant_id == context.key.tenant_id
                && route.policy.route_id.as_bytes() == context.key.entity_key
                && route.policy.revision == context.key.owner_revision
                && route.grant.allows(
                    route.policy.tenant_id,
                    &route.policy.route_id,
                    NotificationOperationV1::Configure,
                    route.approved_utc_ns,
                )
                && NotificationGrantV1::sensitivity(
                    route.grant.max_sensitivity,
                    route.policy.max_sensitivity,
                ),
            "route context identity",
        )?;
        Ok(route)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRouteRefV1 {
    pub route_id: String,
    pub revision: u64,
}

impl From<&NotificationPolicyV1> for NotificationRouteRefV1 {
    fn from(policy: &NotificationPolicyV1) -> Self {
        Self {
            route_id: policy.route_id.clone(),
            revision: policy.revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationFindingV1 {
    pub finding_id: String,
    pub revision: GraphRevisionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationFindingRefV1 {
    pub finding_id: String,
    pub result_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnconfirmedNotificationConcernV1 {
    pub concern_id: [u8; 16],
    pub model_label: String,
    pub summary: String,
    pub context: Vec<crate::AnalysisContextKeyV1>,
    pub sensitivity: ContextSensitivityV1,
    pub suggested_priority: NotificationPriorityV1,
}

impl UnconfirmedNotificationConcernV1 {
    pub(crate) fn validate(&self, tenant: [u8; 16]) -> Result<()> {
        NotificationErrorCodeV1::Invalid.require(
            self.concern_id != [0; 16]
                && NotificationGrantV1::identifier(&self.model_label, 128)
                && NotificationGrantV1::identifier(&self.summary, 512)
                && self.context.len() <= 16
                && self.context.windows(2).all(|pair| pair[0] < pair[1])
                && self
                    .context
                    .iter()
                    .all(|key| key.tenant_id == tenant && key.valid()),
            "unconfirmed concern",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationKeyV1 {
    pub tenant_id: [u8; 16],
    pub notification_id: [u8; 16],
}

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
    pub number: u16,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationObligationV1 {
    pub schema_version: u32,
    pub key: NotificationKeyV1,
    pub revision: u64,
    pub finding: Option<NotificationFindingRefV1>,
    pub unconfirmed_concern: Option<UnconfirmedNotificationConcernV1>,
    pub finding_revision: u64,
    pub package_id: String,
    pub required_action: Option<String>,
    pub sensitivity: ContextSensitivityV1,
    pub source_priority: NotificationPriorityV1,
    pub minimum_priority: NotificationPriorityV1,
    pub route: Option<NotificationRouteRefV1>,
    pub escalation: Option<NotificationRouteRefV1>,
    pub first_seen_utc_ns: u64,
    pub deadline_utc_ns: Option<u64>,
    pub overdue_since_utc_ns: Option<u64>,
    pub attempts: Vec<NotificationAttemptV1>,
    pub sink_health: NotificationSinkHealthV1,
    pub failure: Option<NotificationFailureV1>,
    pub human_acknowledgement: Option<NotificationAcknowledgementV1>,
    pub agent_receipt: Option<NotificationAgentReceiptV1>,
    pub advisory: Option<NotificationAdvisoryV1>,
}

impl NotificationObligationV1 {
    #[must_use]
    pub fn priority(&self) -> NotificationPriorityV1 {
        self.minimum_priority.max(self.source_priority).max(
            self.advisory
                .as_ref()
                .map_or(NotificationPriorityV1::Info, |value| {
                    value.suggested_priority
                }),
        )
    }

    #[must_use]
    pub fn overdue(&self, now_utc_ns: u64) -> bool {
        self.human_acknowledgement
            .is_none_or(|ack| ack.finding_revision != self.finding_revision)
            && self
                .deadline_utc_ns
                .is_some_and(|deadline| now_utc_ns >= deadline)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        NotificationErrorCodeV1::Invalid.require(
            self.schema_version == 1
                && self.key.tenant_id != [0; 16]
                && self.key.notification_id != [0; 16]
                && self.revision > 0
                && self.finding.is_some() != self.unconfirmed_concern.is_some()
                && self.finding.as_ref().is_none_or(|finding| {
                    NotificationGrantV1::identifier(&finding.finding_id, 4096)
                        && NotificationGrantV1::identifier(&finding.result_id, 256)
                })
                && NotificationGrantV1::identifier(&self.package_id, 64)
                && self
                    .required_action
                    .as_ref()
                    .is_none_or(|action| NotificationGrantV1::identifier(action, 256))
                && self.finding_revision > 0
                && self.finding_revision <= self.revision
                && self.first_seen_utc_ns > 0
                && self.attempts.len() <= 48
                && self
                    .deadline_utc_ns
                    .is_none_or(|deadline| deadline > self.first_seen_utc_ns)
                && self.attempts.iter().all(|attempt| {
                    attempt.number > 0
                        && attempt.finding_revision > 0
                        && attempt.finding_revision <= self.revision
                        && attempt.context_revision > 0
                        && attempt.context_revision <= self.revision
                        && attempt.started_utc_ns >= self.first_seen_utc_ns
                        && attempt.completed_utc_ns.is_some() == attempt.result.is_some()
                        && attempt
                            .completed_utc_ns
                            .is_none_or(|completed| completed >= attempt.started_utc_ns)
                        && attempt
                            .result
                            .as_ref()
                            .is_none_or(NotificationSinkResultV1::valid)
                }),
            "obligation",
        )?;
        if let Some(concern) = &self.unconfirmed_concern {
            concern.validate(self.key.tenant_id)?;
        }
        Ok(())
    }
}

impl TryFrom<&crate::AnalysisContextVersionV1> for NotificationObligationV1 {
    type Error = crate::Error;

    fn try_from(context: &crate::AnalysisContextVersionV1) -> Result<Self> {
        NotificationErrorCodeV1::Invalid.require(
            context.key.owner_id == NOTIFICATION_STATE_OWNER
                && context.key.lifetime_key == b"obligation"
                && context.body.len() <= 32 * 1024,
            "notification context owner",
        )?;
        let state: Self =
            serde_json::from_slice(&context.body).context(crate::NotificationEncodingSnafu)?;
        state.validate()?;
        NotificationErrorCodeV1::Invalid.require(
            state.key.tenant_id == context.key.tenant_id
                && state.key.notification_id.as_slice() == context.key.entity_key
                && state.revision == context.key.owner_revision
                && state.sensitivity == context.sensitivity,
            "notification context identity",
        )?;
        Ok(state)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationDeliveryV1 {
    pub key: NotificationKeyV1,
    pub attempt: u16,
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
