use std::{fs, path::Path, process, process::Command};

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::{ActionKind, ExecutionSurface, SessionId};
use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};

#[test]
fn linux_host_cat_secret_is_denied_by_filesystem_policy() -> Result<(), Box<dyn std::error::Error>>
{
    if !ostree_available() {
        return Ok(());
    }

    let test_dir = test_dir("cat-secret")?;
    fs::write(test_dir.join("secret.txt"), "secret\n")?;
    let policy_path = write_policy(&test_dir)?;
    let session_id = "session-filesystem-linux-deny";
    let config = RuntimeConfig::from_json_str(&format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [
              {{
                "name": "cat-secret",
                "command": ["cat", "secret.txt"]
              }}
            ],
            "runner": {{ "kind": "linux_host" }},
            "interception": {{
              "enabled": true,
              "backend": "linux_ptrace",
              "operations": ["process_exec", "file_open", "file_read", "file_mutation"]
            }}
          }},
          "surfaces": {{
            "terminal": {{ "enabled": true }},
            "filesystem": {{
              "enabled": true,
              "backend": {{ "kind": "linux_ostree_overlay" }},
              "volumes": [
                {{
                  "id": "workspace",
                  "host_path": "{}",
                  "session_path": "{}",
                  "mode": "writable"
                }}
              ]
            }}
          }}
        }}"#,
        policy_path.display(),
        test_dir.display(),
        test_dir.display(),
        test_dir.display()
    ))?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "cat-secret",
    )?;

    let error = SessionExecutionService::run_diagnostic(&config, &plan);

    assert!(
        matches!(error, Err(SessionExecutionError::DiagnosticFailed { .. })),
        "expected cat secret.txt to fail through filesystem policy, got {error:?}"
    );
    let records = read_audit_records(session_audit_path(&test_dir, session_id))?;
    let record = records
        .iter()
        .find(|record| {
            record.event.surface == ExecutionSurface::Filesystem
                && record.event.action == ActionKind::FileRead
                && record.final_decision.rule_id() == Some("deny-secret-read")
        })
        .ok_or_else(|| std::io::Error::other("missing denied filesystem audit record"))?;

    assert!(record.event.payload["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("secret.txt")));
    assert!(record.event.payload["resolved_identity"]["device"]
        .as_u64()
        .is_some());
    assert!(record.event.payload["resolved_identity"]["inode"]
        .as_u64()
        .is_some());

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

#[test]
fn linux_host_filesystem_storage_layout_is_prepared_without_host_copy(
) -> Result<(), Box<dyn std::error::Error>> {
    if !ostree_available() {
        return Ok(());
    }

    let test_dir = test_dir("storage-layout")?;
    let workspace = test_dir.join("workspace");
    let host_project = test_dir.join("host/project");
    let session_project = workspace.join("project");
    fs::create_dir_all(&host_project)?;
    fs::create_dir_all(&session_project)?;
    fs::write(host_project.join("settings.json"), "phase4-host-sentinel\n")?;
    let policy_path = write_empty_policy(&test_dir)?;

    let session_id = "session-filesystem-storage-layout";
    let config = RuntimeConfig::from_json_str(&format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [
              {{
                "name": "storage-layout",
                "command": [
                  "sh",
                  "-lc",
                  "test -d \"$EREBOR_FILESYSTEM_SESSION_DIR\" && test -d \"$EREBOR_FILESYSTEM_REPO\""
                ]
              }}
            ],
            "runner": {{ "kind": "linux_host" }}
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
        host_project.display(),
        session_project.display()
    ))?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "storage-layout",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    let filesystem = session_filesystem_path(&workspace, session_id);
    assert_storage_layout(&filesystem, "project")?;
    assert_empty_ostree_repo(&filesystem.join("repo"))?;
    assert!(!storage_tree_contains_file_named(
        &filesystem,
        "settings.json"
    )?);
    assert_eq!(
        fs::read_to_string(host_project.join("settings.json"))?,
        "phase4-host-sentinel\n"
    );

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

fn test_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = std::env::temp_dir().join(format!(
        "erebor-filesystem-lifecycle-{name}-{}",
        process::id()
    ));
    let _result = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn write_policy(test_dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    let policy_path = test_dir.join("policy.json");
    fs::write(
        &policy_path,
        r#"
        {
          "rules": [
            {
              "id": "deny-secret-read",
              "match": {
                "surface": "filesystem",
                "action": "file_read",
                "target_contains": "secret.txt"
              },
              "decision": "deny",
              "reason": "secret file reads are denied"
            }
          ]
        }
        "#,
    )?;
    Ok(policy_path)
}

fn write_empty_policy(test_dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    let policy_path = test_dir.join("empty-policy.json");
    fs::write(&policy_path, r#"{ "rules": [] }"#)?;
    Ok(policy_path)
}

fn session_audit_path(test_dir: &Path, session_id: &str) -> std::path::PathBuf {
    test_dir
        .join(".erebor/sessions")
        .join(session_id)
        .join("audit.jsonl")
}

fn session_filesystem_path(workspace: &Path, session_id: &str) -> std::path::PathBuf {
    workspace
        .join(".erebor/sessions")
        .join(session_id)
        .join("filesystem")
}

fn assert_storage_layout(filesystem: &Path, volume_id: &str) -> Result<(), std::io::Error> {
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

fn assert_empty_ostree_repo(repo: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
