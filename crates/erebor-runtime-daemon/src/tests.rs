use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use tempfile::TempDir;
use tokio::net::UnixListener;

use erebor_runtime_ipc::{
    v1::{
        DaemonHello, DaemonHelloAck, Envelope, KIND_DAEMON_HELLO, KIND_DAEMON_HELLO_ACK,
        PROTOCOL_VERSION,
    },
    AsyncFrameCodec,
};

use crate::{
    config::DaemonConfig,
    idempotency::{DaemonIdempotencyStore, IdempotencyAction, MutationIntent},
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
    let store = DaemonIdempotencyStore::new(directory.clone(), 2);
    assert_eq!(
        store.prepare(1000, "reload", "completed", fingerprint, intent.clone())?,
        IdempotencyAction::Execute(intent.clone())
    );
    store.complete(
        1000,
        "reload",
        "completed",
        fingerprint,
        intent.clone(),
        String::from("configuration reloaded"),
    )?;
    assert_eq!(
        store.prepare(1000, "reload", "pending", fingerprint, intent.clone())?,
        IdempotencyAction::Execute(intent.clone())
    );
    drop(store);

    let resumed = DaemonIdempotencyStore::new(directory, 2);
    assert_eq!(
        resumed.prepare(1000, "reload", "completed", fingerprint, reload_intent(9))?,
        IdempotencyAction::ReturnCompleted(String::from("configuration reloaded"))
    );
    assert_eq!(
        resumed.prepare(1000, "reload", "pending", fingerprint, reload_intent(9))?,
        IdempotencyAction::ResumePending(intent.clone())
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
    let store = DaemonIdempotencyStore::new(directory, 1);
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
        String::from("configuration reloaded"),
    )?;
    assert_eq!(
        store.prepare(1000, "reload", "next", fingerprint, intent)?,
        IdempotencyAction::Execute(reload_intent(2))
    );
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

#[tokio::test]
#[ignore = "requires host Unix-domain socket I/O"]
async fn stale_socket_recovery_preserves_live_socket_and_persistent_lock(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let root = TempDir::new()?;
    let paths = DaemonPaths::for_testing(root.path());
    let security = DaemonSecurity::current_process();
    paths.prepare(security)?;
    let lock = paths.acquire_lock(security)?;

    let listener = UnixListener::bind(paths.socket_path())?;
    let server = tokio::spawn(async move {
        let (mut stream, _address) = listener.accept().await?;
        let request: Envelope = AsyncFrameCodec::read_frame(&mut stream)
            .await?
            .decode_payload()?;
        assert_eq!(request.message_kind, KIND_DAEMON_HELLO);
        let _hello: DaemonHello = request.decode_typed_payload(KIND_DAEMON_HELLO)?;
        let response = Envelope::wrap_message(
            2,
            request.message_id,
            KIND_DAEMON_HELLO_ACK,
            &DaemonHelloAck {
                protocol_version: PROTOCOL_VERSION,
                daemon_version: String::from("test"),
                capabilities: Vec::new(),
            },
        )?;
        AsyncFrameCodec::write_frame(&mut stream, &response.into_frame()?).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    assert!(paths.remove_stale_socket(&lock, security).await.is_err());
    assert!(paths.socket_path().exists());
    server.await??;

    paths.remove_stale_socket(&lock, security).await?;
    assert!(!paths.socket_path().exists());
    assert!(paths.lock_path().is_file());
    drop(lock);
    Ok(())
}

fn reload_intent(generation: u64) -> MutationIntent {
    MutationIntent::Reload {
        configuration: DaemonConfig {
            socket_group_gid: DaemonSecurity::current_process().socket_gid,
            max_log_bytes: 4096,
            max_log_records: 32,
            max_idempotency_records: 32,
        },
        generation,
    }
}

fn fixture_config_source() -> String {
    format!(
        "{{\"socket_group_gid\":{},\"max_log_bytes\":4096,\"max_log_records\":32,\"max_idempotency_records\":32}}",
        DaemonSecurity::current_process().socket_gid
    )
}
