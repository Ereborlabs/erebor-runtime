use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    storage::FilesystemStoragePreparer, FilesystemError, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest, LinuxOverlaySessionView,
};

#[test]
fn prepare_creates_private_executable_wrapper() -> Result<(), Box<dyn std::error::Error>> {
    if !required_commands_available() {
        return Ok(());
    }

    let test_dir = test_dir("wrapper")?;
    let host = test_dir.join("host/project");
    let session_path = test_dir.join("session/project");
    fs::create_dir_all(&host)?;
    let storage = storage_for(&test_dir, &host, &session_path)?;

    let view = LinuxOverlaySessionView::prepare(&storage)?;

    assert!(view.wrapper_path().is_file());
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(view.wrapper_path())?.permissions().mode() & 0o777,
        0o700
    );

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

#[test]
fn rejects_host_and_session_path_overlap() -> Result<(), Box<dyn std::error::Error>> {
    if !required_commands_available() {
        return Ok(());
    }

    let test_dir = test_dir("overlap")?;
    let host = test_dir.join("host");
    let session_path = host.join("session");
    fs::create_dir_all(&host)?;
    let storage = storage_for(&test_dir, &host, &session_path)?;

    let error = match LinuxOverlaySessionView::prepare(&storage) {
        Ok(_) => {
            return Err(std::io::Error::other("overlap must be rejected").into());
        }
        Err(error) => error,
    };

    assert!(matches!(
        error,
        FilesystemError::InvalidOverlaySessionView { .. }
    ));

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

#[test]
fn rejects_host_path_overlapping_storage_root() -> Result<(), Box<dyn std::error::Error>> {
    if !required_commands_available() {
        return Ok(());
    }

    let test_dir = test_dir("storage-overlap")?;
    let host = test_dir.join("session-record");
    let session_path = test_dir.join("session/project");
    fs::create_dir_all(&host)?;
    let storage = storage_for(&test_dir, &host, &session_path)?;

    let error = match LinuxOverlaySessionView::prepare(&storage) {
        Ok(_) => {
            return Err(std::io::Error::other("storage overlap must be rejected").into());
        }
        Err(error) => error,
    };

    assert!(matches!(
        error,
        FilesystemError::InvalidOverlaySessionView { .. }
    ));

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

fn storage_for(
    test_dir: &Path,
    host: &Path,
    session_path: &Path,
) -> Result<crate::FilesystemSessionStorage, FilesystemError> {
    let request = FilesystemVolumeStorageRequest::new(
        "project",
        host,
        session_path,
        FilesystemVolumeMode::Writable,
    )?;
    FilesystemStoragePreparer::new(&test_dir.join("session-record"), vec![request])
        .prepare(|_| Ok(()))
}

fn required_commands_available() -> bool {
    ["unshare", "mount", "umount"].into_iter().all(|command| {
        std::process::Command::new(command)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

fn test_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = std::env::temp_dir().join(format!(
        "erebor-filesystem-overlay-{name}-{}",
        std::process::id()
    ));
    let _result = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}
