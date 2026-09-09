use super::{fixture_authorization_id, invalid_state, run_authorization_replay_fixture};

#[test]
fn authorization_replay_fixture_persists_exact_rejections_and_fresh_control() -> crate::Result<()> {
    let temporary = tempfile::tempdir().map_err(|error| {
        invalid_state(format!("create authorization fixture directory: {error}"))
    })?;
    let state = temporary.path().join("authorization-replay");

    let (wal_sha256, wal_records) =
        run_authorization_replay_fixture(&state, fixture_authorization_id(90))?;

    assert_eq!(wal_sha256.len(), 64);
    assert_eq!(wal_records, 5);
    Ok(())
}
