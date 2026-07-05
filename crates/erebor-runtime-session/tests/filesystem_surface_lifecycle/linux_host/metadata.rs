use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::Path,
};

use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_filesystem::{
    rollback_promotion, FilesystemSessionStorage, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest,
};
use erebor_runtime_session::SessionExecutionService;
use rustix::{
    fs::{
        lgetxattr, lsetxattr, utimensat, AtFlags, Timespec, Timestamps, XattrFlags, CWD, UTIME_OMIT,
    },
    io::Errno,
};

use super::support;

const ORIGINAL_MTIME: i64 = 1_700_001_000;
const PROMOTED_MTIME: i64 = 1_700_001_300;

#[test]
fn linux_host_overlay_metadata_promotes_and_rolls_back() -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle("linux_host_overlay_metadata_promotes_and_rolls_back")? {
        return Ok(());
    }

    let test_dir = support::test_dir("overlay-metadata")?;
    let workspace = test_dir.join("workspace");
    let host_project = test_dir.join("host/project");
    let session_project = workspace.join("project");
    fs::create_dir_all(&host_project)?;
    fs::create_dir_all(&session_project)?;
    fs::write(host_project.join("settings.txt"), "original\n")?;
    fs::write(host_project.join("old-target.txt"), "old target\n")?;
    symlink("old-target.txt", host_project.join("shortcut"))?;
    set_metadata(&host_project.join("settings.txt"), 0o640, ORIGINAL_MTIME)?;
    let xattrs = set_user_xattr(&host_project.join("settings.txt"), b"before")?;
    let policy_path = support::write_empty_policy(&test_dir)?;

    let session_id = "session-filesystem-metadata";
    let command =
        "ostree --repo=\"$EREBOR_FILESYSTEM_REPO\" config set core.min-free-space-percent 0 && \
        cd project && \
        printf 'changed\\n' > settings.txt && \
        chmod 600 settings.txt && \
        touch -m -d @1700001300 settings.txt && \
        rm shortcut && ln -s settings.txt shortcut";
    let config = support::overlay_promoting_config(
        &policy_path,
        &workspace,
        &host_project,
        &session_project,
        "overlay-metadata",
        command,
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "overlay-metadata",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    assert_eq!(
        fs::read_to_string(host_project.join("settings.txt"))?,
        "changed\n"
    );
    assert_metadata(&host_project.join("settings.txt"), 0o600, PROMOTED_MTIME)?;
    assert_eq!(
        fs::read_link(host_project.join("shortcut"))?,
        Path::new("settings.txt")
    );

    let storage = reopen_storage(&workspace, session_id, &host_project, &session_project)?;
    rollback_promotion(&storage, session_id)?;

    assert_eq!(
        fs::read_to_string(host_project.join("settings.txt"))?,
        "original\n"
    );
    assert_metadata(&host_project.join("settings.txt"), 0o640, ORIGINAL_MTIME)?;
    assert_eq!(
        fs::read_link(host_project.join("shortcut"))?,
        Path::new("old-target.txt")
    );
    if xattrs {
        assert_user_xattr(&host_project.join("settings.txt"), b"before")?;
    }
    support::cleanup_overlay_test_dir(&test_dir, &workspace, session_id)?;
    Ok(())
}

fn reopen_storage(
    workspace: &Path,
    session_id: &str,
    host_project: &Path,
    session_project: &Path,
) -> Result<FilesystemSessionStorage, Box<dyn std::error::Error>> {
    let request = FilesystemVolumeStorageRequest::new(
        "project",
        host_project,
        session_project,
        FilesystemVolumeMode::Writable,
    )?;
    Ok(FilesystemSessionStorage::open_existing(
        workspace.join(".erebor/sessions").join(session_id),
        vec![request],
    )?)
}

fn set_metadata(path: &Path, mode: u32, mtime_sec: i64) -> Result<(), Box<dyn std::error::Error>> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    set_mtime(path, mtime_sec)
}

fn set_mtime(path: &Path, mtime_sec: i64) -> Result<(), Box<dyn std::error::Error>> {
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: mtime_sec,
            tv_nsec: 0,
        },
    };
    utimensat(CWD, path, &times, AtFlags::SYMLINK_NOFOLLOW).map_err(std::io::Error::from)?;
    Ok(())
}

fn set_user_xattr(path: &Path, value: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    match lsetxattr(path, "user.erebor_probe", value, XattrFlags::empty()) {
        Ok(()) => Ok(true),
        Err(Errno::NOTSUP | Errno::PERM)
            if std::env::var("EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE").as_deref() != Ok("1") =>
        {
            Ok(false)
        }
        Err(Errno::NOTSUP | Errno::PERM) => Err(std::io::Error::other(
            "required filesystem lifecycle metadata probe needs user xattr support",
        )
        .into()),
        Err(source) => Err(std::io::Error::from(source).into()),
    }
}

fn assert_user_xattr(path: &Path, expected: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0_u8; 64];
    let len = lgetxattr(path, "user.erebor_probe", &mut buffer).map_err(std::io::Error::from)?;
    assert_eq!(&buffer[..len], expected);
    Ok(())
}

fn assert_metadata(
    path: &Path,
    mode: u32,
    mtime_sec: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    assert_eq!(metadata.mode() & 0o7777, mode);
    assert_eq!(metadata.mtime(), mtime_sec);
    assert_eq!(metadata.mtime_nsec(), 0);
    Ok(())
}
