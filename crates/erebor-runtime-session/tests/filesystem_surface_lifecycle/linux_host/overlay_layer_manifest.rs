use std::{fs, path::Path, process::Command};

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
    let repo = support::session_filesystem_path(&workspace, session_id).join("repo");
    let layer_ref = format!("erebor/checkpoints/{session_id}/volumes/project/layer");
    let checkpoint_ref = format!("erebor/checkpoints/{session_id}/manifest");
    let refs = ostree_output(&repo, &["refs", "--list"])?;
    assert!(refs.lines().any(|line| line == layer_ref));
    assert!(refs.lines().any(|line| line == checkpoint_ref));
    assert!(!refs.lines().any(|line| line.ends_with("/base")));
    let layer_root = ostree_output(&repo, &["ls", &layer_ref, "/"])?;
    assert!(layer_root.contains("erebor-layer.json"));
    assert!(layer_root.contains("files"));
    let settings = ostree_output(&repo, &["cat", &layer_ref, "/files/settings.json"])?;
    assert_eq!(settings, "{\"theme\":\"dark\"}\n");
    let checkpoint = ostree_output(&repo, &["cat", &checkpoint_ref, "/erebor-checkpoint.json"])?;
    let checkpoint: Value = serde_json::from_str(&checkpoint)?;
    assert_eq!(checkpoint["kind"], "erebor.filesystem.checkpoint");
    assert_eq!(checkpoint["checkpoint_id"], session_id);
    assert_eq!(checkpoint["volumes"][0]["layer_ref"], layer_ref);
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

fn ostree_output(repo: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("ostree")
        .arg(format!("--repo={}", repo.display()))
        .args(args)
        .output()?;
    assert!(
        output.status.success(),
        "ostree {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
