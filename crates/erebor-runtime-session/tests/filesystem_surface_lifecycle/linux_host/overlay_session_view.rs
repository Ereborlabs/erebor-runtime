use std::fs;

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
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
    let config = support::overlay_config(
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

    let upper = support::project_upper_path(&workspace, session_id);
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

    support::cleanup_overlay_test_dir(&test_dir, &workspace, session_id)?;
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
    let config = support::overlay_config(
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
    let upper = support::project_upper_path(&workspace, session_id);
    assert!(!support::storage_tree_contains_file_named(
        &upper,
        "settings.json"
    )?);
    support::assert_not_mountpoint(&session_project)?;
    support::assert_not_mountpoint(&host_project)?;

    support::cleanup_overlay_test_dir(&test_dir, &workspace, session_id)?;
    Ok(())
}
