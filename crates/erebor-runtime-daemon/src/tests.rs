use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};

use tempfile::TempDir;

use crate::{
    config::DaemonConfig,
    idempotency::{
        DaemonIdempotencyStore, IdempotencyAction, MutationIntent, MutationResponse,
        MutationResponseType,
    },
    paths::DaemonSecurity,
    DaemonPaths,
};

#[test]
fn configured_paths_keep_each_daemon_owner_below_its_explicit_directory() {
    let mut paths = DaemonPaths::system();
    paths.set_config_path("/tmp/erebor-paths/etc/erebord.json");
    paths.set_runtime_dir("/tmp/erebor-paths/run");
    paths.set_log_dir("/tmp/erebor-paths/log");
    paths.set_state_dir("/tmp/erebor-paths/lib");
    assert_eq!(
        paths.config_path(),
        Path::new("/tmp/erebor-paths/etc/erebord.json")
    );
    assert_eq!(
        paths.socket_path(),
        Path::new("/tmp/erebor-paths/run/daemon.sock")
    );
    assert_eq!(
        paths.lock_path(),
        Path::new("/tmp/erebor-paths/run/erebord.lock")
    );
    assert_eq!(
        paths.log_path(),
        Path::new("/tmp/erebor-paths/log/daemon.jsonl")
    );
    assert_eq!(
        paths.idempotency_path(),
        Path::new("/tmp/erebor-paths/lib/daemon/control-idempotency")
    );
}

#[test]
fn idempotency_store_reuses_completed_records_and_resumes_the_original_pending_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let directory = root.path().join("idempotency");
    fs::create_dir(&directory)?;
    let fingerprint = [7_u8; 32];
    let intent = reload_intent(2);
    let store = DaemonIdempotencyStore::new(
        directory.clone(),
        root.path().to_path_buf(),
        2,
        Duration::ZERO,
    );
    assert_eq!(
        store.prepare(1000, "reload", "completed", fingerprint, intent.clone())?,
        IdempotencyAction::Execute(Box::new(intent.clone()))
    );
    store.complete(
        1000,
        "reload",
        "completed",
        fingerprint,
        intent.clone(),
        response(),
    )?;
    assert_eq!(
        store.prepare(1000, "reload", "pending", fingerprint, intent.clone())?,
        IdempotencyAction::Execute(Box::new(intent.clone()))
    );
    drop(store);

    let resumed =
        DaemonIdempotencyStore::new(directory, root.path().to_path_buf(), 2, Duration::ZERO);
    assert_eq!(
        resumed.prepare(1000, "reload", "completed", fingerprint, reload_intent(9))?,
        IdempotencyAction::ReturnCompleted(response())
    );
    assert_eq!(
        resumed.prepare(1000, "reload", "pending", fingerprint, reload_intent(9))?,
        IdempotencyAction::ResumePending(Box::new(intent.clone()))
    );
    assert!(resumed
        .prepare(1000, "reload", "completed", [8_u8; 32], intent)
        .is_err());
    Ok(())
}

#[test]
fn idempotency_store_evicts_completed_records_but_never_pending_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let directory = root.path().join("idempotency");
    fs::create_dir(&directory)?;
    let store =
        DaemonIdempotencyStore::new(directory, root.path().to_path_buf(), 1, Duration::ZERO);
    let intent = reload_intent(2);
    let fingerprint = [7_u8; 32];
    store.prepare(1000, "reload", "pending", fingerprint, intent.clone())?;
    assert!(store
        .prepare(1000, "reload", "next", fingerprint, intent.clone())
        .is_err());
    store.complete(
        1000,
        "reload",
        "pending",
        fingerprint,
        intent.clone(),
        response(),
    )?;
    assert_eq!(
        store.prepare(1000, "reload", "next", fingerprint, intent)?,
        IdempotencyAction::Execute(Box::new(reload_intent(2)))
    );
    Ok(())
}

#[test]
fn idempotency_store_retains_session_mutations_until_tombstone_horizon_and_prune(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let directory = root.path().join("idempotency");
    fs::create_dir(&directory)?;
    let store =
        DaemonIdempotencyStore::new(directory, root.path().to_path_buf(), 1, Duration::ZERO);
    let fingerprint = [7_u8; 32];
    let intent = MutationIntent::SessionStart {
        uid: 1000,
        session_id: String::from("session-retained"),
    };
    store.prepare(1000, "session-start", "first", fingerprint, intent.clone())?;
    store.complete(
        1000,
        "session-start",
        "first",
        fingerprint,
        intent,
        response(),
    )?;
    assert!(store
        .prepare(1000, "reload", "next", fingerprint, reload_intent(2))
        .is_err());

    let session = root.path().join("users/1000/sessions/session-retained");
    fs::create_dir_all(&session)?;
    fs::write(
        session.join("session.json"),
        br#"{"state":"removed","updated_at_unix_ms":1}"#,
    )?;
    assert_eq!(
        store.prepare(1000, "reload", "next", fingerprint, reload_intent(2))?,
        IdempotencyAction::Execute(Box::new(reload_intent(2)))
    );
    Ok(())
}

#[test]
fn typed_idempotency_response_reads_legacy_records_and_writes_typed_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let legacy: MutationResponse = serde_json::from_slice(
        br#"{"message_kind":"erebor.runtime.ipc.v1.DaemonCommandResult","payload":[1,2,3]}"#,
    )?;
    assert_eq!(
        legacy.response_type(),
        MutationResponseType::DaemonCommandResult
    );
    assert_eq!(legacy.into_encoded_message(), [1, 2, 3]);

    let stored = serde_json::to_value(response())?;
    assert_eq!(stored["response_type"], "DaemonCommandResult");
    assert_eq!(
        stored["encoded_message"],
        serde_json::to_value(b"configuration reloaded".as_slice())?
    );
    assert!(stored.get("message_kind").is_none());
    assert!(stored.get("payload").is_none());
    Ok(())
}

#[test]
fn daemon_configuration_rejects_symlinks_before_opening_them(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let paths = DaemonPaths::for_testing(root.path());
    let parent = match paths.config_path().parent() {
        Some(parent) => parent,
        None => return Err("test daemon config path has no parent".into()),
    };
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
    let target = root.path().join("target.json");
    fs::write(&target, fixture_config_source())?;
    std::os::unix::fs::symlink(&target, paths.config_path())?;
    assert!(DaemonConfig::load(&paths, DaemonSecurity::current_process()).is_err());
    Ok(())
}

#[test]
fn daemon_configuration_rejects_group_writable_files() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let paths = DaemonPaths::for_testing(root.path());
    let parent = match paths.config_path().parent() {
        Some(parent) => parent,
        None => return Err("test daemon config path has no parent".into()),
    };
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
    fs::write(paths.config_path(), fixture_config_source())?;
    fs::set_permissions(paths.config_path(), fs::Permissions::from_mode(0o660))?;
    assert!(DaemonConfig::load(&paths, DaemonSecurity::current_process()).is_err());
    Ok(())
}

#[test]
fn daemon_lock_is_private_and_survives_owner_drop() -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let paths = DaemonPaths::for_testing(root.path());
    let security = DaemonSecurity::current_process();
    paths.prepare(security)?;
    let lock = paths.acquire_lock(security)?;
    let metadata = fs::metadata(paths.lock_path())?;
    assert_eq!(metadata.uid(), security.owner_uid);
    assert_eq!(metadata.mode() & 0o077, 0);
    drop(lock);
    assert!(paths.lock_path().is_file());
    Ok(())
}

fn reload_intent(generation: u64) -> MutationIntent {
    MutationIntent::Reload {
        configuration: DaemonConfig {
            socket_group_gid: DaemonSecurity::current_process().socket_gid,
            max_log_bytes: 4096,
            max_log_records: 32,
            max_idempotency_records: 32,
            ..DaemonConfig::default()
        },
        generation,
    }
}

fn response() -> MutationResponse {
    MutationResponse::new(
        crate::idempotency::MutationResponseType::DaemonCommandResult,
        b"configuration reloaded".to_vec(),
    )
}

fn fixture_config_source() -> String {
    format!(
        "{{\"socket_group_gid\":{},\"max_log_bytes\":4096,\"max_log_records\":32,\"max_idempotency_records\":32}}",
        DaemonSecurity::current_process().socket_gid
    )
}
