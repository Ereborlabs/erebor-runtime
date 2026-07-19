use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use tempfile::TempDir;

use crate::{
    config::DaemonConfig,
    idempotency::{DaemonIdempotencyStore, IdempotencyAction},
    paths::DaemonSecurity,
    DaemonPaths,
};

#[test]
fn idempotency_store_reuses_matching_mutation_and_rejects_conflicts(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let directory = root.path().join("idempotency");
    fs::create_dir(&directory)?;
    let store = DaemonIdempotencyStore::new(directory.clone());
    let fingerprint = [7_u8; 32];
    assert_eq!(
        store.prepare(1000, "reload", "key", fingerprint)?,
        IdempotencyAction::Execute
    );
    store.complete(
        1000,
        "reload",
        "key",
        fingerprint,
        String::from("configuration reloaded"),
    )?;
    drop(store);
    let resumed = DaemonIdempotencyStore::new(directory);
    assert_eq!(
        resumed.prepare(1000, "reload", "key", fingerprint)?,
        IdempotencyAction::ReturnCompleted(String::from("configuration reloaded"))
    );
    assert!(resumed.prepare(1000, "reload", "key", [8_u8; 32]).is_err());
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

#[test]
#[ignore = "requires host Unix-domain socket I/O"]
fn stale_socket_recovery_preserves_live_socket_and_persistent_lock(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = TempDir::new()?;
    let paths = DaemonPaths::for_testing(root.path());
    let security = DaemonSecurity::current_process();
    paths.prepare(security)?;
    let lock = paths.acquire_lock(security)?;

    let listener = std::os::unix::net::UnixListener::bind(paths.socket_path())?;
    assert!(paths.remove_stale_socket().is_err());
    assert!(paths.socket_path().exists());
    drop(listener);

    paths.remove_stale_socket()?;
    assert!(!paths.socket_path().exists());
    assert!(paths.lock_path().is_file());
    drop(lock);
    Ok(())
}

fn fixture_config_source() -> String {
    format!(
        "{{\"socket_group_gid\":{},\"max_log_bytes\":4096,\"max_log_records\":32}}",
        DaemonSecurity::current_process().socket_gid
    )
}
