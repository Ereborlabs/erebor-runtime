use std::{fs, path::Path};

use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_session::SessionExecutionService;
use serde_json::Value;

use super::{support, transaction_catalog_cli as cli};

#[test]
fn linux_host_session_work_transactions_autocommit_and_cli_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_session_work_transactions_autocommit_and_cli_commit",
    )? {
        return Ok(());
    }

    let root = support::test_dir("session-work-transaction")?;
    let workspace = root.join("workspace");
    let host_project = root.join("host/project");
    let session_project = workspace.join("project");
    fs::create_dir_all(&host_project)?;
    fs::create_dir_all(&session_project)?;
    fs::write(host_project.join("settings.txt"), "light\n")?;
    let policy_path = support::write_empty_policy(&root)?;
    let session_id = "session-filesystem-work-transaction";
    let config_path = root.join("session-work-config.json");
    let config_source = config_source(
        &root,
        &workspace,
        &host_project,
        &session_project,
        &policy_path,
    );
    fs::write(&config_path, &config_source)?;
    let config = RuntimeConfig::from_json_str(&config_source)?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "session-work",
    )?;
    let mut plan = plan;
    plan.set_config_path(config_path);

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    assert_eq!(
        fs::read_to_string(host_project.join("settings.txt"))?,
        "light\n"
    );
    let filesystem = support::session_filesystem_path(&workspace, session_id);
    let repo = filesystem.join("repo");
    let auto_manifest_ref =
        format!("erebor/session-work/{session_id}/{session_id}.work-000001/manifest");
    let refs = support::ostree_refs(&repo)?;
    assert!(refs.lines().any(|line| line == auto_manifest_ref));
    assert!(refs
        .lines()
        .any(|line| line == format!("erebor/checkpoints/{session_id}.work-000001/manifest")));
    let manifest = support::ostree_output(
        &repo,
        &["cat", &auto_manifest_ref, "/erebor-session-work.json"],
    )?;
    let manifest: Value = serde_json::from_str(&manifest)?;
    assert_eq!(manifest["source"], "autocommit");
    assert_eq!(manifest["autocommit_rule_id"], "session-finish");
    assert_eq!(manifest["parent_transaction_id"], Value::Null);

    let registry = workspace.join(".erebor/sessions");
    let binary = cli::erebor_runtime_binary()?;
    let list = cli::run(
        &binary,
        &root,
        &cli::transaction_args(&registry, session_id, ["list"]),
    )?;
    assert!(list.contains("work@{0}"));
    assert!(list.contains("autocommit"));
    let show = cli::run(
        &binary,
        &root,
        &cli::transaction_args(&registry, session_id, ["show", "work@{0}"]),
    )?;
    assert!(show.contains("settings.txt"));
    assert!(show.contains("generated/token.txt"));

    let upper = support::project_upper_path(&workspace, session_id);
    fs::write(upper.join("settings.txt"), "manual\n")?;
    fs::write(upper.join("manual.txt"), "operator\n")?;
    let commit = cli::run(
        &binary,
        &root,
        &cli::transaction_args(&registry, session_id, ["commit", "--name", "manual work"]),
    )?;
    assert!(commit.contains("committed"));
    assert!(commit.contains("work@{0}"));
    let committed = cli::run(
        &binary,
        &root,
        &cli::transaction_args(&registry, session_id, ["show", "manual work"]),
    )?;
    assert!(committed.contains("manual.txt"));

    let writer = fs::File::create(upper.join("live-writer.txt"))?;
    let failure = cli::run_failure(
        &binary,
        &root,
        &cli::transaction_args(&registry, session_id, ["commit"]),
    )?;
    assert!(failure.contains("cannot normalize layer while pid"));
    drop(writer);

    let rollback = cli::run(
        &binary,
        &root,
        &cli::transaction_args(&registry, session_id, ["rollback", "work@{1}"]),
    )?;
    assert!(rollback.contains("overlay_restored"));
    assert_eq!(fs::read_to_string(upper.join("settings.txt"))?, "dark");
    assert!(upper.join("generated/token.txt").is_file());
    assert!(!upper.join("manual.txt").exists());

    support::assert_not_mountpoint(&session_project)?;
    support::assert_not_mountpoint(&host_project)?;
    support::cleanup_overlay_test_dir(&root, &workspace, session_id)?;
    Ok(())
}

fn config_source(
    root: &Path,
    workspace: &Path,
    host_project: &Path,
    session_project: &Path,
    policy_path: &Path,
) -> String {
    format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [
              {{
                "name": "session-work",
                "command": ["sh", "-lc", "{}"]
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
                  "id": "project",
                  "host_path": "{}",
                  "session_path": "{}",
                  "mode": "writable"
                }}
              ],
              "revert": {{
                "promote_on_session_finish": false,
                "retain_layers": true,
                "preimage_size_limit_bytes": 104857600,
                "preimage_backend": "ostree_bytes",
                "autocommit": {{
                  "enabled": true,
                  "rules": [
                    {{ "id": "session-finish", "boundary": "session_finish" }}
                  ]
                }}
              }}
            }}
          }}
        }}"#,
        policy_path.display(),
        workspace.display(),
        command(root),
        host_project.display(),
        session_project.display()
    )
}

fn command(root: &Path) -> String {
    let command = format!(
        "cd project && rg light settings.txt && \
         printf dark > settings.txt && mkdir -p generated && \
         printf token > generated/token.txt && \
         test -d \"$EREBOR_FILESYSTEM_SESSION_DIR\" && \
         test -d \"$EREBOR_FILESYSTEM_REPO\" && \
         test ! -e '{}'",
        root.join("host/project/generated/token.txt").display()
    );
    command.replace('\\', "\\\\").replace('"', "\\\"")
}
