use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use erebor_runtime_core::AuditRecord;
use erebor_runtime_core::RuntimeConfig;
use erebor_runtime_events::{ActionKind, ExecutionSurface};

pub(super) fn test_dir(name: &str) -> Result<PathBuf, io::Error> {
    let path = std::env::temp_dir().join(format!(
        "erebor-filesystem-lifecycle-{name}-{}-{}",
        process::id(),
        nonce()
    ));
    let _result = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
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

pub(super) fn project_upper_path(workspace: &Path, session_id: &str) -> PathBuf {
    session_filesystem_path(workspace, session_id).join("work/volumes/project/overlay/upper")
}

pub(super) fn project_layer_manifest_path(workspace: &Path, session_id: &str) -> PathBuf {
    session_filesystem_path(workspace, session_id).join("work/volumes/project/erebor-layer.json")
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

pub(super) fn require_overlay_lifecycle(test_name: &str) -> Result<bool, io::Error> {
    if std::env::var("EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE").as_deref() != Ok("1") {
        let message = format!(
            "skipping {test_name}: set EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 to run mount lifecycle checks"
        );
        if std::env::var("EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE").as_deref() == Ok("1") {
            return Err(io::Error::other(message));
        }
        eprintln!("{message}");
        return Ok(false);
    }

    for command in ["ostree", "unshare", "mount", "umount", "findmnt"] {
        require_command(test_name, command)?;
    }
    Ok(true)
}

pub(super) fn assert_not_mountpoint(path: &Path) -> Result<(), io::Error> {
    let status = Command::new("findmnt")
        .arg("--mountpoint")
        .arg(path)
        .status()?;
    assert!(
        !status.success(),
        "{} is still a mountpoint after the session",
        path.display()
    );
    Ok(())
}

pub(super) fn overlay_config(
    policy_path: &Path,
    workspace: &Path,
    host_project: &Path,
    session_project: &Path,
    diagnostic_name: &str,
    shell_command: &str,
    empty_policy_only: bool,
) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    let interception = if empty_policy_only {
        r#""operations": ["process_exec", "file_open", "file_read", "file_mutation"]"#
    } else {
        r#""operations": ["process_exec", "file_mutation"]"#
    };
    Ok(RuntimeConfig::from_json_str(&format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [
              {{
                "name": "{}",
                "command": ["sh", "-lc", "{}"]
              }}
            ],
            "runner": {{ "kind": "linux_host" }},
            "interception": {{
              "enabled": true,
              "backend": "linux_ptrace",
              {}
            }}
          }},
          "surfaces": {{
            "terminal": {{ "enabled": true }},
            "filesystem": {{
              "enabled": true,
              "backend": {{ "kind": "linux_ostree_overlay" }},
              "volumes": [
                {{
                  "id": "project",
                  "host_path": "{}",
                  "session_path": "{}",
                  "mode": "writable"
                }}
              ]
            }}
          }}
        }}"#,
        policy_path.display(),
        workspace.display(),
        diagnostic_name,
        json_escape(shell_command),
        interception,
        host_project.display(),
        session_project.display()
    ))?)
}

pub(super) fn cleanup_overlay_test_dir(
    test_dir: &Path,
    workspace: &Path,
    session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let private_work = session_filesystem_path(workspace, session_id)
            .join("work/volumes/project/overlay/workdir/work");
        if private_work.exists() {
            fs::set_permissions(&private_work, fs::Permissions::from_mode(0o700))?;
        }
    }
    fs::remove_dir_all(test_dir)?;
    Ok(())
}

fn ostree_available() -> bool {
    Command::new("ostree")
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn require_command(test_name: &str, command: &str) -> Result<(), io::Error> {
    if command_available(command) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{test_name} requires `{command}` in PATH"
        )))
    }
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
