use erebor_runtime_ipc::v1::SessionRecord;
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
        stable_runner_identity: record
            .runner_binding()
            .map_or_else(String::new, |binding| binding.stable_identity().to_owned()),
        failure: record.failure().unwrap_or_default().to_owned(),
        retry_guarantee_expires_unix_ms,
        retention_hold: record.retention_hold(),
    }
}
