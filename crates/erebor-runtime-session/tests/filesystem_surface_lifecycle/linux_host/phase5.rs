use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::{ActionKind, SessionId};
use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};

use super::support;

#[test]
fn linux_host_overlay_session_view_writes_through_upperdir_without_host_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_overlay_session_view_writes_through_upperdir_without_host_mutation",
    )? {
        return Ok(());
    }

    let test_dir = support::test_dir("overlay-session-view")?;
    let workspace = test_dir.join("workspace");
    let host_project = test_dir.join("host/project");
    let session_project = workspace.join("project");
    fs::create_dir_all(&host_project)?;
    fs::create_dir_all(&session_project)?;
    fs::write(
        host_project.join("settings.json"),
        "{\"theme\":\"light\"}\n",
    )?;
    fs::write(host_project.join("old-cache.txt"), "old cache\n")?;
    let policy_path = support::write_empty_policy(&test_dir)?;

    let session_id = "session-filesystem-overlay-view";
    let command = format!(
        "test \"$(id -u)\" != 0 && cd project && rg '\"theme\":\"light\"' settings.json && \
         printf '{{\"theme\":\"dark\"}}\\n' > settings.json && rm old-cache.txt && \
         mkdir -p generated && printf 'token\\n' > generated/token.txt && \
         if printf bypass > '{}/settings.json'; then exit 72; fi",
        host_project.display()
    );
    let config = overlay_config(
        &policy_path,
        &workspace,
        &host_project,
        &session_project,
        "overlay-write",
        &command,
        true,
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "overlay-write",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    let upper = project_upper_path(&workspace, session_id);
    assert_eq!(
        fs::read_to_string(upper.join("settings.json"))?,
        "{\"theme\":\"dark\"}\n"
    );
    assert_eq!(
        fs::read_to_string(upper.join("generated/token.txt"))?,
        "token\n"
    );
    assert_eq!(
        fs::read_to_string(host_project.join("settings.json"))?,
        "{\"theme\":\"light\"}\n"
    );
    assert_eq!(
        fs::read_to_string(host_project.join("old-cache.txt"))?,
        "old cache\n"
    );
    assert!(!host_project.join("generated/token.txt").exists());
    support::assert_not_mountpoint(&session_project)?;
    support::assert_not_mountpoint(&host_project)?;

    cleanup_overlay_test_dir(&test_dir, &workspace, session_id)?;
    Ok(())
}

#[test]
fn linux_host_denied_overlay_mutation_does_not_create_upperdir_change(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_denied_overlay_mutation_does_not_create_upperdir_change",
    )? {
        return Ok(());
    }

    let test_dir = support::test_dir("overlay-denied-mutation")?;
    let workspace = test_dir.join("workspace");
    let host_project = test_dir.join("host/project");
    let session_project = workspace.join("project");
    fs::create_dir_all(&host_project)?;
    fs::create_dir_all(&session_project)?;
    fs::write(host_project.join("settings.json"), "original-settings\n")?;
    let policy_path = support::write_policy_source(
        &test_dir,
        "deny-settings-mutation-policy.json",
        r#"
        {
          "rules": [
            {
              "id": "deny-overlay-settings-mutation",
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

    let session_id = "session-filesystem-overlay-deny";
    let config = overlay_config(
        &policy_path,
        &workspace,
        &host_project,
        &session_project,
        "overlay-denied-mutation",
        "printf changed > project/settings.json",
        false,
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "overlay-denied-mutation",
    )?;

    let error = SessionExecutionService::run_diagnostic(&config, &plan);

    assert!(
        matches!(error, Err(SessionExecutionError::DiagnosticFailed { .. })),
        "expected overlay mutation denial, got {error:?}"
    );
    assert_eq!(
        fs::read_to_string(host_project.join("settings.json"))?,
        "original-settings\n"
    );
    let records = read_audit_records(support::session_audit_path(&workspace, session_id))?;
    support::filesystem_audit_record(
        &records,
        ActionKind::FileMutation,
        "deny-overlay-settings-mutation",
    )?;
    let upper = project_upper_path(&workspace, session_id);
    assert!(!support::storage_tree_contains_file_named(
        &upper,
        "settings.json"
    )?);
    support::assert_not_mountpoint(&session_project)?;
    support::assert_not_mountpoint(&host_project)?;

    cleanup_overlay_test_dir(&test_dir, &workspace, session_id)?;
    Ok(())
}

fn overlay_config(
    policy_path: &std::path::Path,
    workspace: &std::path::Path,
    host_project: &std::path::Path,
    session_project: &std::path::Path,
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

fn project_upper_path(workspace: &std::path::Path, session_id: &str) -> std::path::PathBuf {
    support::session_filesystem_path(workspace, session_id)
        .join("work/volumes/project/overlay/upper")
}

fn cleanup_overlay_test_dir(
    test_dir: &std::path::Path,
    workspace: &std::path::Path,
    session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let private_work = support::session_filesystem_path(workspace, session_id)
            .join("work/volumes/project/overlay/workdir/work");
        if private_work.exists() {
            fs::set_permissions(&private_work, fs::Permissions::from_mode(0o700))?;
        }
    }
    fs::remove_dir_all(test_dir)?;
    Ok(())
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
