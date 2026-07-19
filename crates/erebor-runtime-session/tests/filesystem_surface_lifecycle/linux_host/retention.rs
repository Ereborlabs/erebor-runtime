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

    RetentionLifecycleScenario::new()?.run()
}

struct RetentionLifecycleScenario {
    root: std::path::PathBuf,
    workspace: std::path::PathBuf,
    restored_fixture: LifecycleFixture,
    protected_fixture: LifecycleFixture,
    restored_session: &'static str,
    protected_session: &'static str,
}

impl RetentionLifecycleScenario {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = support::test_dir("retention")?;
        let workspace = root.join("workspace");
        Ok(Self {
            restored_fixture: Self::fixture(&root, &workspace, "restored")?,
            protected_fixture: Self::fixture(&root, &workspace, "protected")?,
            root,
            workspace,
            restored_session: "session-filesystem-retention-restored",
            protected_session: "session-filesystem-retention-protected",
        })
    }

    fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.seed()?;
        let policy_path = support::write_empty_policy(&self.root)?;
        self.run_promoted_session(
            &self.restored_fixture,
            &policy_path,
            self.restored_session,
            "retention-restored",
        )?;
        self.run_promoted_session(
            &self.protected_fixture,
            &policy_path,
            self.protected_session,
            "retention-protected",
        )?;
        assert_promoted(&self.restored_fixture)?;
        assert_promoted(&self.protected_fixture)?;

        let binary = cli::erebor_binary()?;
        let registry = self.registry();
        let restored_repo = self.repo(self.restored_session);
        let protected_repo = self.repo(self.protected_session);
        let restored_before = support::ostree_refs(&restored_repo)?;
        let protected_before = support::ostree_refs(&protected_repo)?;
        let _prune_probe_before = support::ostree_output(&restored_repo, &["prune", "--no-prune"])?;
        Self::assert_session_refs(&restored_before, self.restored_session);
        Self::assert_session_refs(&protected_before, self.protected_session);

        let list = cli::run(
            &binary,
            &self.root,
            &cli::retention_args(&registry, self.protected_session, ["list"]),
        )?;
        assert!(list.contains("HANDLE"));
        assert!(list.contains("checkpoint_layer"));
        assert!(list.contains("promotion_preimage"));
        assert!(list.contains("yes"));

        let protected_failure = cli::run_failure(
            &binary,
            &self.root,
            &cli::retention_args(&registry, self.protected_session, ["prune", "tx@{0}"]),
        )?;
        assert!(protected_failure.contains("protected"));
        let protected_after_failure = support::ostree_refs(&protected_repo)?;
        Self::assert_session_refs(&protected_after_failure, self.protected_session);

        cli::run(
            &binary,
            &self.root,
            &cli::transaction_args(&registry, self.restored_session, ["rollback", "tx@{0}"]),
        )?;
        assert_restored(&self.restored_fixture)?;
        let prune = cli::run(
            &binary,
            &self.root,
            &cli::retention_args(&registry, self.restored_session, ["prune", "tx@{0}"]),
        )?;
        assert!(prune.contains("pruned"));
        let restored_after = support::ostree_refs(&restored_repo)?;
        assert!(!restored_after.contains(self.restored_session));
        let _prune_probe_after = support::ostree_output(&restored_repo, &["prune", "--no-prune"])?;
        self.assert_retention_journal()?;

        cli::run(
            &binary,
            &self.root,
            &cli::transaction_args(&registry, self.protected_session, ["rollback", "tx@{0}"]),
        )?;
        assert_restored(&self.protected_fixture)?;

        self.restored_fixture.assert_unmounted()?;
        self.protected_fixture.assert_unmounted()?;
        self.cleanup()
    }

    fn seed(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.restored_fixture.seed()?;
        self.protected_fixture.seed()
    }

    fn run_promoted_session(
        &self,
        fixture: &LifecycleFixture,
        policy_path: &Path,
        session_id: &str,
        diagnostic_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = fixture.root.join(format!("{diagnostic_name}.json"));
        fs::write(
            &config_path,
            cli::config_source(fixture, policy_path, diagnostic_name, Self::COMMAND),
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

    fn fixture(
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

    fn registry(&self) -> std::path::PathBuf {
        self.workspace.join(".erebor/sessions")
    }

    fn repo(&self, session_id: &str) -> std::path::PathBuf {
        support::session_filesystem_path(&self.workspace, session_id).join("repo")
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

    fn assert_retention_journal(&self) -> Result<(), Box<dyn std::error::Error>> {
        let retention_journal = fs::read_to_string(
            support::session_filesystem_path(&self.workspace, self.restored_session)
                .join("retention/erebor-retention.jsonl"),
        )?;
        assert!(retention_journal.contains("\"event\":\"prune\""));
        assert!(retention_journal.contains("\"outcome\":\"success\""));
        Ok(())
    }

    fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        for session_id in [self.restored_session, self.protected_session] {
            let filesystem = support::session_filesystem_path(&self.workspace, session_id);
            for volume_id in ["project", "cache"] {
                let private_work =
                    filesystem.join(format!("work/volumes/{volume_id}/overlay/workdir/work"));
                if private_work.exists() {
                    fs::set_permissions(&private_work, fs::Permissions::from_mode(0o700))?;
                }
            }
        }
        fs::remove_dir_all(&self.root)?;
        Ok(())
    }

    const COMMAND: &str =
        "ostree --repo=\"$EREBOR_FILESYSTEM_REPO\" config set core.min-free-space-percent 0 && \
        cd project && printf dark > settings.txt && rm old-cache.txt && \
        mkdir -p generated && printf token > generated/token.txt && \
        cd ../cache && printf warm > cache.txt && rm stale.bin && \
        mkdir -p warmed && printf index > warmed/index.txt";
}
