use serde::{Deserialize, Serialize};

use crate::{ContextSensitivityV1, FindingSeverityV1, GraphRevisionV1, Result};

mod delivery;
mod obligation;
mod route;
mod subject;
pub use delivery::*;
pub use obligation::*;
pub use route::*;
pub use subject::*;

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
