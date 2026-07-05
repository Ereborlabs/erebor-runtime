use std::fs;

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::{ActionKind, SessionId};
use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};

#[path = "linux_host/support.rs"]
mod support;

#[test]
fn linux_host_cat_secret_is_denied_by_filesystem_policy() -> Result<(), Box<dyn std::error::Error>>
{
    let test_dir = support::test_dir("cat-secret")?;
    fs::write(test_dir.join("secret.txt"), "secret\n")?;
    let policy_path = support::write_policy_source(
        &test_dir,
        "secret-read-policy.json",
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
              "backend": {{ "kind": "linux_ostree_overlay" }}
            }}
          }}
        }}"#,
        policy_path.display(),
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
    let records = read_audit_records(support::session_audit_path(&test_dir, session_id))?;
    let record =
        support::filesystem_audit_record(&records, ActionKind::FileRead, "deny-secret-read")?;

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
fn linux_host_settings_mutation_is_denied_by_filesystem_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = support::test_dir("settings-mutation")?;
    let settings = test_dir.join("settings.json");
    fs::write(&settings, "original-settings\n")?;
    let policy_path = support::write_policy_source(
        &test_dir,
        "settings-mutation-policy.json",
        r#"
        {
          "rules": [
            {
              "id": "deny-settings-mutation",
              "match": {
                "surface": "filesystem",
                "action": "file_mutation",
                "target_contains": "settings.json"
              },
              "decision": "deny",
              "reason": "settings edits are denied"
            }
          ]
        }
        "#,
    )?;
    let session_id = "session-filesystem-linux-mutation-deny";
    let config = RuntimeConfig::from_json_str(&format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [
              {{
                "name": "edit-settings",
                "command": [
                  "sh",
                  "-lc",
                  "printf changed > settings.json"
                ]
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
              "backend": {{ "kind": "linux_ostree_overlay" }}
            }}
          }}
        }}"#,
        policy_path.display(),
        test_dir.display()
    ))?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "edit-settings",
    )?;

    let error = SessionExecutionService::run_diagnostic(&config, &plan);

    assert!(
        matches!(error, Err(SessionExecutionError::DiagnosticFailed { .. })),
        "expected settings mutation to fail through filesystem policy, got {error:?}"
    );
    assert_eq!(fs::read_to_string(&settings)?, "original-settings\n");
    let records = read_audit_records(support::session_audit_path(&test_dir, session_id))?;
    let record = support::filesystem_audit_record(
        &records,
        ActionKind::FileMutation,
        "deny-settings-mutation",
    )?;

    assert!(record.event.payload["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("settings.json")));
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
    if !support::require_ostree(
        "linux_host_filesystem_storage_layout_is_prepared_without_host_copy",
    )? {
        return Ok(());
    }

    let test_dir = support::test_dir("storage-layout")?;
    let workspace = test_dir.join("workspace");
    let host_project = test_dir.join("host/project");
    let session_project = workspace.join("project");
    fs::create_dir_all(&host_project)?;
    fs::create_dir_all(&session_project)?;
    fs::write(host_project.join("settings.json"), "phase4-host-sentinel\n")?;
    let policy_path = support::write_empty_policy(&test_dir)?;

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

    let filesystem = support::session_filesystem_path(&workspace, session_id);
    support::assert_storage_layout(&filesystem, "project")?;
    support::assert_empty_ostree_repo(&filesystem.join("repo"))?;
    assert!(!support::storage_tree_contains_file_named(
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
