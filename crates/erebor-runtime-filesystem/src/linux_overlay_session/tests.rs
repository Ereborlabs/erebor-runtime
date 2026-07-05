use std::{fs, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    storage::prepare_with_initializer, FilesystemError, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest, LinuxOverlaySessionView,
};

#[test]
fn prepare_writes_executable_mount_namespace_wrapper() -> Result<(), Box<dyn std::error::Error>> {
    if !required_commands_available() {
        return Ok(());
    }

    let test_dir = test_dir("wrapper")?;
    let host = test_dir.join("host/project");
    let session_path = test_dir.join("session/project");
    fs::create_dir_all(&host)?;
    let storage = storage_for(&test_dir, &host, &session_path)?;

    let view = LinuxOverlaySessionView::prepare(&storage)?;
    let script = fs::read_to_string(view.wrapper_path())?;

    assert!(view.wrapper_path().is_file());
    assert!(script.contains("unshare -U --map-current-user --keep-caps -m"));
    assert!(script.contains("unshare -m --propagation private"));
    assert!(script.contains("mount --bind"));
    assert!(script.contains("mount -t overlay overlay"));
    assert!(script.contains("lowerdir="));
    assert!(script.contains("umount"));
    assert!(script.contains("--erebor-overlay-child"));
    assert!(script.contains("setpriv --reuid"));
    assert!(script.contains("refused to run the session command as root"));
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
    prepare_with_initializer(&test_dir.join("session-record"), vec![request], |_| Ok(()))
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
