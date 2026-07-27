use erebor_runtime_ipc::v1::{SessionRecord, SessionStateProjection};
use erebor_runtime_session::DurableSessionRecord;

pub(super) fn session_record(
    record: &DurableSessionRecord,
    retry_guarantee_expires_unix_ms: u64,
) -> SessionRecord {
    SessionRecord {
        session_id: record.spec().session_id().as_str().to_owned(),
        state: record.state().as_str().to_owned(),
        generation: record.generation(),
        owner_uid: record.spec().owner().uid(),
        runner_id: record
            .spec()
            .runner_capability()
            .runner()
            .as_str()
            .to_owned(),
        runner_recovery: record.runner_binding().map_or_else(String::new, |binding| {
            binding.recovery().payload().to_owned()
        }),
        failure: record.failure().unwrap_or_default().to_owned(),
        retry_guarantee_expires_unix_ms,
        retention_hold: record.retention_hold(),
        api_version: record
            .spec()
            .resource_association()
            .map_or_else(String::new, |_| String::from("erebor.dev/v1")),
        kind: record
            .spec()
            .resource_association()
            .map_or_else(String::new, |_| String::from("Session")),
        agent_name: record
            .spec()
            .resource_association()
            .map_or_else(String::new, |association| {
                association.agent_name().to_owned()
            }),
        policy_set_name: record
            .spec()
            .resource_association()
            .map_or_else(String::new, |association| {
                association.policy_set_name().to_owned()
            }),
        surface_names: record
            .spec()
            .resource_association()
            .map_or_else(Vec::new, |association| association.surface_names().to_vec()),
        state_projection: record.spec().private_state_projection().map(|projection| {
            SessionStateProjection {
                target: projection.target().display().to_string(),
                lower_snapshot: projection.lower_snapshot().to_owned(),
                writable_upper: projection.writable_upper().to_owned(),
                refresh: String::from("explicit"),
                retention: String::from("discard-on-session-removal"),
            }
        }),
    }
}
