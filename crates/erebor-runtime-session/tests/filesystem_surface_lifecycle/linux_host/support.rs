use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{self, Command},
};

use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{ActionKind, ExecutionSurface};

pub(super) fn test_dir(name: &str) -> Result<PathBuf, io::Error> {
    let path = std::env::temp_dir().join(format!(
        "erebor-filesystem-lifecycle-{name}-{}",
        process::id()
    ));
    let _result = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}

pub(super) fn write_policy_source(
    test_dir: &Path,
    file_name: &str,
    source: &str,
) -> Result<PathBuf, io::Error> {
    let policy_path = test_dir.join(file_name);
    fs::write(&policy_path, source)?;
    Ok(policy_path)
}

pub(super) fn write_empty_policy(test_dir: &Path) -> Result<PathBuf, io::Error> {
    write_policy_source(test_dir, "empty-policy.json", r#"{ "rules": [] }"#)
}

pub(super) fn session_audit_path(test_dir: &Path, session_id: &str) -> PathBuf {
    test_dir
        .join(".erebor/sessions")
        .join(session_id)
        .join("audit.jsonl")
}

pub(super) fn session_filesystem_path(workspace: &Path, session_id: &str) -> PathBuf {
    workspace
        .join(".erebor/sessions")
        .join(session_id)
        .join("filesystem")
}

pub(super) fn filesystem_audit_record<'a>(
    records: &'a [AuditRecord],
    action: ActionKind,
    rule_id: &str,
) -> Result<&'a AuditRecord, io::Error> {
    records
        .iter()
        .find(|record| {
            record.event.surface == ExecutionSurface::Filesystem
                && record.event.action == action
                && record.final_decision.rule_id() == Some(rule_id)
        })
        .ok_or_else(|| io::Error::other("missing denied filesystem audit record"))
}

pub(super) fn assert_storage_layout(filesystem: &Path, volume_id: &str) -> Result<(), io::Error> {
    let volume = filesystem.join("work/volumes").join(volume_id);
    for path in [
        filesystem.join("repo"),
        volume.join("lower-ro"),
        volume.join("overlay/upper"),
        volume.join("overlay/workdir"),
        volume.join("overlay/merged"),
    ] {
        assert!(
            path.is_dir(),
            "missing storage directory {}",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn assert_empty_ostree_repo(repo: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let refs = Command::new("ostree")
        .arg(format!("--repo={}", repo.display()))
        .arg("refs")
        .arg("--list")
        .output()?;
    assert!(refs.status.success());
    let refs = String::from_utf8_lossy(&refs.stdout);
    assert!(refs.trim().is_empty());
    assert!(!refs.contains("base"));
    Ok(())
}

pub(super) fn storage_tree_contains_file_named(
    root: &Path,
    file_name: &str,
) -> Result<bool, io::Error> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
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

pub(super) fn require_ostree(test_name: &str) -> Result<bool, io::Error> {
    if ostree_available() {
        return Ok(true);
    }

    let message = format!("skipping {test_name}: ostree CLI is not available in PATH");
    if std::env::var("EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE").as_deref() == Ok("1") {
        return Err(io::Error::other(message));
    }
    eprintln!("{message}");
    Ok(false)
}

fn ostree_available() -> bool {
    Command::new("ostree")
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
}
