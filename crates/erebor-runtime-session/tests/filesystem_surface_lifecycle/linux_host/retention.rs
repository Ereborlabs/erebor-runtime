use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_session::SessionExecutionService;

use super::{
    overlay_multivolume_support::{assert_promoted, assert_restored, LifecycleFixture},
    support, transaction_catalog_cli as cli,
};

#[test]
fn linux_host_retention_cli_prunes_restored_session_without_breaking_protected_rollback(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_retention_cli_prunes_restored_session_without_breaking_protected_rollback",
    )? {
        return Ok(());
    }

    let root = support::test_dir("retention")?;
    let workspace = root.join("workspace");
    let restored_fixture = retention_fixture(&root, &workspace, "restored")?;
    let protected_fixture = retention_fixture(&root, &workspace, "protected")?;
    restored_fixture.seed()?;
    protected_fixture.seed()?;
    let policy_path = support::write_empty_policy(&root)?;
    let restored_session = "session-filesystem-retention-restored";
    let protected_session = "session-filesystem-retention-protected";
    let command =
        "ostree --repo=\"$EREBOR_FILESYSTEM_REPO\" config set core.min-free-space-percent 0 && \
        cd project && printf dark > settings.txt && rm old-cache.txt && \
        mkdir -p generated && printf token > generated/token.txt && \
        cd ../cache && printf warm > cache.txt && rm stale.bin && \
        mkdir -p warmed && printf index > warmed/index.txt";

    run_promoted_session(
        &restored_fixture,
        &policy_path,
        restored_session,
        "retention-restored",
        command,
    )?;
    run_promoted_session(
        &protected_fixture,
        &policy_path,
        protected_session,
        "retention-protected",
        command,
    )?;
    assert_promoted(&restored_fixture)?;
    assert_promoted(&protected_fixture)?;

    let binary = cli::erebor_runtime_binary()?;
    let registry = workspace.join(".erebor/sessions");
    let restored_repo = support::session_filesystem_path(&workspace, restored_session).join("repo");
    let protected_repo =
        support::session_filesystem_path(&workspace, protected_session).join("repo");
    let restored_before = support::ostree_refs(&restored_repo)?;
    let protected_before = support::ostree_refs(&protected_repo)?;
    let _prune_probe_before = support::ostree_output(&restored_repo, &["prune", "--no-prune"])?;
    assert_session_refs(&restored_before, restored_session);
    assert_session_refs(&protected_before, protected_session);

    let list = cli::run(
        &binary,
        &root,
        &cli::retention_args(&registry, protected_session, ["list"]),
    )?;
    assert!(list.contains("HANDLE"));
    assert!(list.contains("checkpoint_layer"));
    assert!(list.contains("promotion_preimage"));
    assert!(list.contains("yes"));

    let protected_failure = cli::run_failure(
        &binary,
        &root,
        &cli::retention_args(&registry, protected_session, ["prune", "tx@{0}"]),
    )?;
    assert!(protected_failure.contains("protected"));
    let protected_after_failure = support::ostree_refs(&protected_repo)?;
    assert_session_refs(&protected_after_failure, protected_session);

    cli::run(
        &binary,
        &root,
        &cli::transaction_args(&registry, restored_session, ["rollback", "tx@{0}"]),
    )?;
    assert_restored(&restored_fixture)?;
    let prune = cli::run(
        &binary,
        &root,
        &cli::retention_args(&registry, restored_session, ["prune", "tx@{0}"]),
    )?;
    assert!(prune.contains("pruned"));
    let restored_after = support::ostree_refs(&restored_repo)?;
    assert!(!restored_after.contains(restored_session));
    let _prune_probe_after = support::ostree_output(&restored_repo, &["prune", "--no-prune"])?;
    let retention_journal = fs::read_to_string(
        support::session_filesystem_path(&workspace, restored_session)
            .join("retention/erebor-retention.jsonl"),
    )?;
    assert!(retention_journal.contains("\"event\":\"prune\""));
    assert!(retention_journal.contains("\"outcome\":\"success\""));

    cli::run(
        &binary,
        &root,
        &cli::transaction_args(&registry, protected_session, ["rollback", "tx@{0}"]),
    )?;
    assert_restored(&protected_fixture)?;

    restored_fixture.assert_unmounted()?;
    protected_fixture.assert_unmounted()?;
    cleanup_retention_root(&root, &workspace, [restored_session, protected_session])?;
    Ok(())
}

fn run_promoted_session(
    fixture: &LifecycleFixture,
    policy_path: &Path,
    session_id: &str,
    diagnostic_name: &str,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = fixture.root.join(format!("{diagnostic_name}.json"));
    fs::write(
        &config_path,
        cli::config_source(fixture, policy_path, diagnostic_name, command),
    )?;
    let config = RuntimeConfig::from_json_str(&fs::read_to_string(&config_path)?)?;
    let mut plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        diagnostic_name,
    )?;
    plan.set_config_path(config_path);
    SessionExecutionService::run_diagnostic(&config, &plan)?;
    Ok(())
}

fn retention_fixture(
    root: &Path,
    workspace: &Path,
    label: &str,
) -> Result<LifecycleFixture, Box<dyn std::error::Error>> {
    let host_project = root.join(format!("host/{label}/project"));
    let host_cache = root.join(format!("host/{label}/cache"));
    let session_project = workspace.join("project");
    let session_cache = workspace.join("cache");
    for path in [&host_project, &host_cache, &session_project, &session_cache] {
        fs::create_dir_all(path)?;
    }
    Ok(LifecycleFixture {
        root: root.to_path_buf(),
        workspace: workspace.to_path_buf(),
        host_project,
        host_cache,
        session_project,
        session_cache,
    })
}

fn assert_session_refs(refs: &str, session_id: &str) {
    for reference in [
        format!("erebor/checkpoints/{session_id}/manifest"),
        format!("erebor/checkpoints/{session_id}/volumes/project/layer"),
        format!("erebor/checkpoints/{session_id}/volumes/cache/layer"),
        format!("erebor/promotions/{session_id}/manifest"),
        format!("erebor/promotions/{session_id}/volumes/project/preimage"),
        format!("erebor/promotions/{session_id}/volumes/cache/preimage"),
    ] {
        assert!(
            refs.lines().any(|line| line == reference),
            "missing retained ref {reference} in {refs}"
        );
    }
}

fn cleanup_retention_root<const N: usize>(
    root: &Path,
    workspace: &Path,
    sessions: [&str; N],
) -> Result<(), Box<dyn std::error::Error>> {
    for session_id in sessions {
        let filesystem = support::session_filesystem_path(workspace, session_id);
        for volume_id in ["project", "cache"] {
            let private_work =
                filesystem.join(format!("work/volumes/{volume_id}/overlay/workdir/work"));
            if private_work.exists() {
                fs::set_permissions(&private_work, fs::Permissions::from_mode(0o700))?;
            }
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
