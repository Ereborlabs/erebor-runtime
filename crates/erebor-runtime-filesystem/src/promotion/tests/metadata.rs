use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{
        lgetxattr, lsetxattr, utimensat, AtFlags, Timespec, Timestamps, XattrFlags, CWD, UTIME_OMIT,
    },
    io::Errno,
};

use crate::{
    promotion::{FilesystemPromotionOptions, FilesystemRollback, PromotionHook},
    FilesystemError,
};

use super::{
    support::{
        commit_checkpoint, fixture, FakeOstreeRepository, PromotionTestWorkflow, TestResult,
    },
    NoopHook,
};

const OLD_MTIME: i64 = 1_700_000_000;
const NEW_MTIME: i64 = 1_700_000_300;

#[test]
fn promotion_and_rollback_restore_supported_metadata() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.txt", "original\n")?;
    fs::create_dir_all(fixture.host().join("docs"))?;
    fs::write(fixture.host().join("docs/readme.txt"), "old docs\n")?;
    symlink("settings.txt", fixture.host().join("shortcut"))?;
    set_metadata(&fixture.host().join("settings.txt"), 0o640, OLD_MTIME)?;
    set_metadata(&fixture.host().join("docs"), 0o750, OLD_MTIME)?;
    set_metadata(&fixture.host().join("docs/readme.txt"), 0o640, OLD_MTIME)?;
    let xattrs = set_user_xattr(&fixture.host().join("settings.txt"), b"before")?;

    fs::write(fixture.upper().join("settings.txt"), "changed\n")?;
    fs::create_dir_all(fixture.upper().join("docs"))?;
    fs::write(fixture.upper().join("docs/readme.txt"), "new docs\n")?;
    fs::write(fixture.upper().join("docs/new.txt"), "new\n")?;
    symlink("docs/new.txt", fixture.upper().join("shortcut"))?;
    set_metadata(&fixture.upper().join("settings.txt"), 0o600, NEW_MTIME)?;
    set_metadata(&fixture.upper().join("docs/readme.txt"), 0o600, NEW_MTIME)?;
    set_metadata(&fixture.upper().join("docs/new.txt"), 0o600, NEW_MTIME)?;
    set_metadata(&fixture.upper().join("docs"), 0o700, NEW_MTIME)?;
    if xattrs {
        set_user_xattr(&fixture.upper().join("settings.txt"), b"after")?;
    }

    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;
    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )
    .promote()?;

    assert_file_metadata(&fixture.host().join("settings.txt"), 0o600, NEW_MTIME)?;
    assert_file_metadata(&fixture.host().join("docs/readme.txt"), 0o600, NEW_MTIME)?;
    assert_file_metadata(&fixture.host().join("docs/new.txt"), 0o600, NEW_MTIME)?;
    assert_dir_metadata(&fixture.host().join("docs"), 0o700, NEW_MTIME)?;
    assert_eq!(
        fs::read_link(fixture.host().join("shortcut"))?,
        PathBuf::from("docs/new.txt")
    );
    if xattrs {
        assert_user_xattr(&fixture.host().join("settings.txt"), b"after")?;
    }

    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;

    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.txt"))?,
        "original\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host().join("docs/readme.txt"))?,
        "old docs\n"
    );
    assert!(!fixture.host().join("docs/new.txt").exists());
    assert_file_metadata(&fixture.host().join("settings.txt"), 0o640, OLD_MTIME)?;
    assert_file_metadata(&fixture.host().join("docs/readme.txt"), 0o640, OLD_MTIME)?;
    assert_dir_metadata(&fixture.host().join("docs"), 0o750, OLD_MTIME)?;
    assert_eq!(
        fs::read_link(fixture.host().join("shortcut"))?,
        PathBuf::from("settings.txt")
    );
    if xattrs {
        assert_user_xattr(&fixture.host().join("settings.txt"), b"before")?;
    }
    Ok(())
}

#[test]
fn xattr_drift_blocks_before_promotion_apply() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("settings.txt", "original\n")?;
    if !set_user_xattr(&fixture.host().join("settings.txt"), b"before")? {
        return Ok(());
    }
    fs::write(fixture.upper().join("settings.txt"), "changed\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;
    let hook = XattrDriftHook {
        path: fixture.host().join("settings.txt"),
    };

    let result = PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &hook,
    )
    .promote();

    assert!(matches!(
        result,
        Err(FilesystemError::PromotionHostDrift { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("settings.txt"))?,
        "original\n"
    );
    assert_user_xattr(&fixture.host().join("settings.txt"), b"drift")?;
    Ok(())
}

struct XattrDriftHook {
    path: PathBuf,
}

impl PromotionHook for XattrDriftHook {
    fn before_apply(&self) -> crate::Result<()> {
        lsetxattr(
            &self.path,
            "user.erebor_test",
            b"drift",
            XattrFlags::empty(),
        )
        .map_err(std::io::Error::from)
        .map_err(|source| FilesystemError::PromotionIo {
            action: "write xattr drift hook",
            path: self.path.clone(),
            source,
            location: snafu::Location::default(),
        })
    }
}

fn set_metadata(path: &Path, mode: u32, mtime_sec: i64) -> TestResult {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    set_mtime(path, mtime_sec)
}

fn set_mtime(path: &Path, mtime_sec: i64) -> TestResult {
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
    match lsetxattr(path, "user.erebor_test", value, XattrFlags::empty()) {
        Ok(()) => Ok(true),
        Err(Errno::NOTSUP | Errno::PERM) => Ok(false),
        Err(source) => Err(std::io::Error::from(source).into()),
    }
}

fn assert_user_xattr(path: &Path, expected: &[u8]) -> TestResult {
    let mut buffer = [0_u8; 64];
    let len = lgetxattr(path, "user.erebor_test", &mut buffer).map_err(std::io::Error::from)?;
    assert_eq!(&buffer[..len], expected);
    Ok(())
}

fn assert_file_metadata(path: &Path, mode: u32, mtime_sec: i64) -> TestResult {
    let metadata = fs::symlink_metadata(path)?;
    assert_eq!(metadata.mode() & 0o7777, mode);
    assert_eq!(metadata.mtime(), mtime_sec);
    assert_eq!(metadata.mtime_nsec(), 0);
    Ok(())
}

fn assert_dir_metadata(path: &Path, mode: u32, mtime_sec: i64) -> TestResult {
    assert_file_metadata(path, mode, mtime_sec)
}
