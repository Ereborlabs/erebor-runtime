use std::{fs, path::Path, process::Command};

use crate::{FilesystemError, FilesystemVolumeMode};

use super::{prepare_with_initializer, FilesystemSessionStorage, FilesystemVolumeStorageRequest};

#[test]
fn prepare_creates_expected_layout_without_copying_host_tree(
) -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = test_dir("layout")?;
    let host = test_dir.join("host/project");
    let session_path = test_dir.join("session/project");
    fs::create_dir_all(&host)?;
    fs::create_dir_all(&session_path)?;
    fs::write(host.join("settings.json"), "phase4-host-sentinel\n")?;

    let request = FilesystemVolumeStorageRequest::new(
        "project",
        &host,
        &session_path,
        FilesystemVolumeMode::Writable,
    )?;
    let storage =
        prepare_with_initializer(&test_dir.join("session-record"), vec![request], |_| Ok(()))?;

    assert_eq!(
        storage.root(),
        test_dir.join("session-record/filesystem").as_path()
    );
    assert_eq!(
        storage.repo_path(),
        test_dir.join("session-record/filesystem/repo").as_path()
    );
    assert_eq!(storage.volumes().len(), 1);

    let volume = &storage.volumes()[0];
    assert_eq!(volume.id(), "project");
    assert_eq!(
        volume.lower_ro_path(),
        test_dir
            .join("session-record/filesystem/work/volumes/project/lower-ro")
            .as_path()
    );
    assert!(volume.lower_ro_path().is_dir());
    assert!(volume.overlay().upper_path().is_dir());
    assert!(volume.overlay().workdir_path().is_dir());
    assert!(volume.overlay().merged_path().is_dir());
    assert!(!storage_tree_contains_file_named(
        storage.root(),
        "settings.json"
    )?);

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

#[test]
fn rejects_invalid_volume_ids_and_paths() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        FilesystemVolumeStorageRequest::new(
            "bad/id",
            "/tmp/host",
            "/tmp/session",
            FilesystemVolumeMode::Writable
        ),
        Err(FilesystemError::InvalidVolumeId { .. })
    ));
    assert!(matches!(
        FilesystemVolumeStorageRequest::new(
            "workspace",
            "relative-host",
            "/tmp/session",
            FilesystemVolumeMode::Writable
        ),
        Err(FilesystemError::InvalidVolumePath {
            field: "host_path",
            ..
        })
    ));
    assert!(matches!(
        FilesystemVolumeStorageRequest::new(
            "workspace",
            "/tmp/host",
            "relative-session",
            FilesystemVolumeMode::Writable
        ),
        Err(FilesystemError::InvalidVolumePath {
            field: "session_path",
            ..
        })
    ));
    Ok(())
}

#[test]
fn dropping_storage_handle_preserves_repo_directory() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = test_dir("drop")?;
    let request = FilesystemVolumeStorageRequest::new(
        "workspace",
        "/tmp/host",
        "/tmp/session",
        FilesystemVolumeMode::Writable,
    )?;
    let storage = prepare_with_initializer(&test_dir, vec![request], |_| Ok(()))?;
    let repo_path = storage.repo_path().to_path_buf();
    drop(storage);

    assert!(repo_path.is_dir());

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

#[test]
fn prepare_initializes_empty_ostree_repo_when_available() -> Result<(), Box<dyn std::error::Error>>
{
    if !ostree_available() {
        return Ok(());
    }

    let test_dir = test_dir("ostree")?;
    let request = FilesystemVolumeStorageRequest::new(
        "workspace",
        "/tmp/host",
        "/tmp/session",
        FilesystemVolumeMode::Writable,
    )?;
    let storage = FilesystemSessionStorage::prepare(&test_dir, vec![request])?;
    let refs = Command::new("ostree")
        .arg(format!("--repo={}", storage.repo_path().display()))
        .arg("refs")
        .arg("--list")
        .output()?;

    assert!(refs.status.success());
    assert!(String::from_utf8_lossy(&refs.stdout).trim().is_empty());

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

fn storage_tree_contains_file_named(root: &Path, file_name: &str) -> Result<bool, std::io::Error> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() && storage_tree_contains_file_named(&path, file_name)? {
            return Ok(true);
        }
        if path.file_name().is_some_and(|current| current == file_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ostree_available() -> bool {
    Command::new("ostree")
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
}

fn test_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = std::env::temp_dir().join(format!(
        "erebor-filesystem-storage-{name}-{}",
        std::process::id()
    ));
    let _result = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}
