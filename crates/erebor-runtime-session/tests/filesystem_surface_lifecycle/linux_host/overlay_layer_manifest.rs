use std::fs;

use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_session::SessionExecutionService;
use serde_json::Value;

use super::support;

#[test]
fn linux_host_overlay_session_writes_layer_manifest() -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle("linux_host_overlay_session_writes_layer_manifest")? {
        return Ok(());
    }

    let test_dir = support::test_dir("overlay-layer-manifest")?;
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

    let session_id = "session-filesystem-overlay-manifest";
    let command = "cd project && rg '\"theme\":\"light\"' settings.json && \
         printf '{\"theme\":\"dark\"}\\n' > settings.json && rm old-cache.txt && \
         mkdir -p generated && printf 'token\\n' > generated/token.txt";
    let config = support::overlay_config(
        &policy_path,
        &workspace,
        &host_project,
        &session_project,
        "overlay-layer-manifest",
        command,
        true,
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "overlay-layer-manifest",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    let manifest_path = support::project_layer_manifest_path(&workspace, session_id);
    let manifest: Value = serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
    assert_eq!(manifest["kind"], "erebor.filesystem.layer");
    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["volume_id"], "project");
    assert_eq!(manifest["promotable"], true);
    assert_operation(&manifest, "replace", "settings.json");
    assert_operation(&manifest, "create", "generated");
    assert_operation(&manifest, "create", "generated/token.txt");
    assert_operation(&manifest, "delete", "old-cache.txt");
    assert!(!operation_path_contains(&manifest, ".wh."));
    assert_eq!(
        fs::read_to_string(host_project.join("settings.json"))?,
        "{\"theme\":\"light\"}\n"
    );
    assert_eq!(
        fs::read_to_string(host_project.join("old-cache.txt"))?,
        "old cache\n"
    );
    support::assert_not_mountpoint(&session_project)?;
    support::assert_not_mountpoint(&host_project)?;

    support::cleanup_overlay_test_dir(&test_dir, &workspace, session_id)?;
    Ok(())
}

fn assert_operation(manifest: &Value, expected_op: &str, expected_path: &str) {
    assert!(
        manifest["operations"].as_array().is_some_and(|operations| {
            operations.iter().any(|operation| {
                operation["op"] == expected_op && operation["path"] == expected_path
            })
        }),
        "missing {expected_op} operation for {expected_path}: {manifest:#}"
    );
}

fn operation_path_contains(manifest: &Value, needle: &str) -> bool {
    manifest["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|operation| {
            operation["path"]
                .as_str()
                .is_some_and(|path| path.contains(needle))
        })
}
