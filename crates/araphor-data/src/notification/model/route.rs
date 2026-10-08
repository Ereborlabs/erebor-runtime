use super::*;
use snafu::ResultExt as _;

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
