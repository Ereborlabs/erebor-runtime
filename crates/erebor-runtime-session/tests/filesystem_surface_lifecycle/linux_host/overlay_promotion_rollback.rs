use std::{fs, path::Path, process::Command};

use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_filesystem::{
    rollback_promotion, FilesystemSessionStorage, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest,
};
use erebor_runtime_session::SessionExecutionService;
use serde_json::Value;

use super::support;

#[test]
fn linux_host_overlay_promotion_and_rollback_restore_host() -> Result<(), Box<dyn std::error::Error>>
{
    if !support::require_overlay_lifecycle(
        "linux_host_overlay_promotion_and_rollback_restore_host",
    )? {
        return Ok(());
    }

    let test_dir = support::test_dir("overlay-promotion-rollback")?;
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

    let session_id = "session-filesystem-promotion-rollback";
    let command = "cd project && rg '\"theme\":\"light\"' settings.json && \
         printf '{\"theme\":\"dark\"}\\n' > settings.json && rm old-cache.txt && \
         mkdir -p generated && printf 'token\\n' > generated/token.txt";
    let config = support::overlay_promoting_config(
        &policy_path,
        &workspace,
        &host_project,
        &session_project,
        "overlay-promotion-rollback",
        command,
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "overlay-promotion-rollback",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    assert_eq!(
        fs::read_to_string(host_project.join("settings.json"))?,
        "{\"theme\":\"dark\"}\n"
    );
    assert!(!host_project.join("old-cache.txt").exists());
    assert_eq!(
        fs::read_to_string(host_project.join("generated/token.txt"))?,
        "token\n"
    );
    let repo = support::session_filesystem_path(&workspace, session_id).join("repo");
    let preimage_ref = format!("erebor/promotions/{session_id}/volumes/project/preimage");
    let promotion_ref = format!("erebor/promotions/{session_id}/manifest");
    let refs = ostree_output(&repo, &["refs", "--list"])?;
    assert!(refs.lines().any(|line| line == preimage_ref));
    assert!(refs.lines().any(|line| line == promotion_ref));
    let promotion = ostree_output(&repo, &["cat", &promotion_ref, "/erebor-promotion.json"])?;
    let promotion: Value = serde_json::from_str(&promotion)?;
    assert_eq!(promotion["kind"], "erebor.filesystem.promotion");
    assert_eq!(promotion["state"], "applied");

    let storage = reopen_storage(&workspace, session_id, &host_project, &session_project)?;
    fs::remove_dir_all(storage.work_path().join("promotions").join(session_id))?;
    rollback_promotion(&storage, session_id)?;

    assert_eq!(
        fs::read_to_string(host_project.join("settings.json"))?,
        "{\"theme\":\"light\"}\n"
    );
    assert_eq!(
        fs::read_to_string(host_project.join("old-cache.txt"))?,
        "old cache\n"
    );
    assert!(!host_project.join("generated").exists());
    support::assert_not_mountpoint(&session_project)?;
    support::assert_not_mountpoint(&host_project)?;

    support::cleanup_overlay_test_dir(&test_dir, &workspace, session_id)?;
    Ok(())
}

fn reopen_storage(
    workspace: &Path,
    session_id: &str,
    host_project: &Path,
    session_project: &Path,
) -> Result<FilesystemSessionStorage, Box<dyn std::error::Error>> {
    let request = FilesystemVolumeStorageRequest::new(
        "project",
        host_project,
        session_project,
        FilesystemVolumeMode::Writable,
    )?;
    Ok(FilesystemSessionStorage::open_existing(
        workspace.join(".erebor/sessions").join(session_id),
        vec![request],
    )?)
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
