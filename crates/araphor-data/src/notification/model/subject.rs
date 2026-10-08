use super::*;

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
