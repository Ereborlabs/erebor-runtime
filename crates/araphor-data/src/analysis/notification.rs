

use snafu::ResultExt as _;


use crate :: { AnalysisContextKeyV1 , AnalysisContextVersionV1 , NotificationGrantV1 , NotificationObligationV1 , Result , NOTIFICATION_STATE_OWNER } ;

#[derive(Clone, Copy)]
pub enum NotificationLookup<'a> {
    Finding(&'a str, Option<&'a str>),
    Concern([u8; 16], &'a str),
}

const VALIDATION_PAGE_ROWS: i64 = 256;

pub(in crate::analysis) struct NotificationKeys {
    pub state: Vec<u8>,
    pub finding: Option<Vec<u8>>,
    pub concern: Option<Vec<u8>>,
}

impl NotificationKeys {
    pub(in crate::analysis) fn state(tenant: [u8; 16], notification: &[u8]) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(tenant, notification)).context(crate::AnalysisKeyEncodeSnafu)
    }

    pub(in crate::analysis) fn lookup(
        tenant: [u8; 16],
        lookup: NotificationLookup<'_>,
    ) -> Result<Vec<u8>> {
        match lookup {
            NotificationLookup::Finding(finding, action) => {
                rmp_serde::to_vec(&(tenant, finding, action)).context(crate::AnalysisKeyEncodeSnafu)
            }
            NotificationLookup::Concern(concern, route) => {
                rmp_serde::to_vec(&(tenant, concern, route)).context(crate::AnalysisKeyEncodeSnafu)
            }
        }
    }

    pub fn from_context(context: &AnalysisContextVersionV1) -> Result<Self> {
        let state = NotificationObligationV1::try_from(context)?;
        let finding = state
            .finding
            .as_ref()
            .map(|finding| {
                Self::lookup(
                    state.key.tenant_id,
                    NotificationLookup::Finding(
                        &finding.finding_id,
                        state.required_action.as_deref(),
                    ),
                )
            })
            .transpose()?;
        let concern = state
            .unconfirmed_concern
            .as_ref()
            .zip(state.route.as_ref())
            .map(|(concern, route)| {
                Self::lookup(
                    state.key.tenant_id,
                    NotificationLookup::Concern(concern.concern_id, &route.route_id),
                )
            })
            .transpose()?;
        Ok(Self {
            state: Self::state(state.key.tenant_id, &state.key.notification_id)?,
            finding,
            concern,
        })
    }
}



#[cfg(test)]
mod tests;

mod prepared;
pub use prepared::PreparedNotificationBatch;
