use duckdb::core::LogicalTypeId::*;
use duckdb::types::Value;
use snafu::IntoError as _;

use super::input::{InputField, InputRow, InputSchema};
use crate::{NotificationObligationV1, Result};

pub(super) const NOTIFICATIONS: InputSchema = InputSchema {
    name: "notifications",
    columns: &[
        InputField("tenant_id", Blob, "16-byte ID", ""),
        InputField("notification_id", Blob, "16-byte obligation lifetime ID", ""),
        InputField("notification_revision", UBigint, "committed notification owner revision", ""),
        InputField("kind", Varchar, "finding or unconfirmed_concern", ""),
        InputField("finding_id", Varchar, "exact full finding key", "An unconfirmed concern has no finding."),
        InputField("finding_result_id", Varchar, "immutable graph result row reference", "An unconfirmed concern has no finding."),
        InputField("finding_revision", Blob, "JSON exact finding input manifest", "The exact finding reference is absent or unresolved."),
        InputField("finding_available", Boolean, "the exact committed finding reference was resolved", ""),
        InputField("package_id", Varchar, "source package ID", ""),
        InputField("required_action", Varchar, "required human action", "The source has no required action."),
        InputField("route_id", Varchar, "approved route ID", "This obligation has no approved route."),
        InputField("route_revision", UBigint, "approved route revision", "This obligation has no approved route."),
        InputField("priority", Varchar, "effective priority at or above the source and route floors", ""),
        InputField("source_priority", Varchar, "source priority floor", ""),
        InputField("minimum_priority", Varchar, "approved route priority floor", ""),
        InputField("first_seen_utc_ns", UBigint, "original obligation UTC nanoseconds", ""),
        InputField("deadline_utc_ns", UBigint, "original human acknowledgement deadline", "This obligation is unrouted."),
        InputField("overdue", Boolean, "human acknowledgement is overdue at query time", ""),
        InputField("overdue_since_utc_ns", UBigint, "persisted overdue deadline", "No overdue deadline was recorded."),
        InputField("sink_health", Varchar, "unknown, healthy, or unhealthy", ""),
        InputField("failure", Varchar, "persisted route or sink failure", "No failure was recorded."),
        InputField("human_acknowledgement", Blob, "JSON authenticated human acknowledgement record", "No human acknowledgement was recorded."),
        InputField("agent_receipt", Blob, "JSON agent receipt; this does not acknowledge the human obligation", "No agent receipt was recorded."),
        InputField("advisory", Blob, "JSON advisory priority and model label", "No advisory was recorded."),
        InputField("unconfirmed_concern", Blob, "JSON unconfirmed model concern; this grants no authority", "This notification came from a finding."),
        InputField("delivery_attempts", Blob, "JSON bounded attempts with exact delivery revisions and sink results", ""),
        InputField("sensitivity", Varchar, "public, tenant, or host_restricted", ""),
        InputField("commit_revision", UBigint, "captured store commit revision", ""),
    ],
    join_keys: "tenant_id,notification_id,notification_revision. finding_id and finding_revision identify the exact finding input. Names and time are not join keys.",
    owner: "araphor-data.NotificationRouter",
    readiness: "conditional",
    description: "Current authorized notification obligations. Original deadlines survive retries and restart. Sink and agent receipts do not prove human acknowledgement. A model concern remains unconfirmed and grants no response authority. Unrouted obligations and delivery failures remain visible.",
};

pub(super) fn notification_row(
    state: &NotificationObligationV1,
    finding: Option<&crate::FindingV1>,
    commit_revision: u64,
    now: u64,
) -> Result<InputRow> {
    state.validate()?;
    if finding.is_some_and(|finding| {
        finding.tenant_id != state.key.tenant_id
            || !state
                .finding
                .as_ref()
                .is_some_and(|reference| reference.finding_id == finding.finding_id)
    }) {
        return crate::QueryDeniedSnafu.fail();
    }
    Ok(InputRow(vec![
        Value::Blob(state.key.tenant_id.to_vec()),
        Value::Blob(state.key.notification_id.to_vec()),
        Value::UBigInt(state.revision),
        Value::Text(
            if state.finding.is_some() {
                "finding"
            } else {
                "unconfirmed_concern"
            }
            .into(),
        ),
        state.finding.as_ref().map_or(Value::Null, |finding| {
            Value::Text(finding.finding_id.clone())
        }),
        state.finding.as_ref().map_or(Value::Null, |finding| {
            Value::Text(finding.result_id.clone())
        }),
        finding
            .map(|finding| json(&finding.revision))
            .transpose()?
            .unwrap_or(Value::Null),
        Value::Boolean(finding.is_some()),
        Value::Text(state.package_id.clone()),
        state
            .required_action
            .clone()
            .map_or(Value::Null, Value::Text),
        state
            .route
            .as_ref()
            .map_or(Value::Null, |route| Value::Text(route.route_id.clone())),
        state
            .route
            .as_ref()
            .map_or(Value::Null, |route| Value::UBigInt(route.revision)),
        Value::Text(format!("{:?}", state.priority())),
        Value::Text(format!("{:?}", state.source_priority)),
        Value::Text(format!("{:?}", state.minimum_priority)),
        Value::UBigInt(state.first_seen_utc_ns),
        state.deadline_utc_ns.map_or(Value::Null, Value::UBigInt),
        Value::Boolean(state.overdue(now)),
        state
            .overdue_since_utc_ns
            .map_or(Value::Null, Value::UBigInt),
        Value::Text(format!("{:?}", state.sink_health).to_ascii_lowercase()),
        state
            .failure
            .map_or(Value::Null, |failure| Value::Text(format!("{failure:?}"))),
        state
            .human_acknowledgement
            .as_ref()
            .map(json)
            .transpose()?
            .unwrap_or(Value::Null),
        state
            .agent_receipt
            .as_ref()
            .map(json)
            .transpose()?
            .unwrap_or(Value::Null),
        state
            .advisory
            .as_ref()
            .map(json)
            .transpose()?
            .unwrap_or(Value::Null),
        state
            .unconfirmed_concern
            .as_ref()
            .map(json)
            .transpose()?
            .unwrap_or(Value::Null),
        json(&state.attempts)?,
        Value::Text(
            match state.sensitivity {
                crate::ContextSensitivityV1::Public => "public",
                crate::ContextSensitivityV1::Tenant => "tenant",
                crate::ContextSensitivityV1::HostRestricted => "host_restricted",
            }
            .into(),
        ),
        Value::UBigInt(commit_revision),
    ]))
}

fn json(value: &impl serde::Serialize) -> Result<Value> {
    serde_json::to_vec(value)
        .map(Value::Blob)
        .map_err(|source| crate::QueryEncodingSnafu.into_error(source))
}
