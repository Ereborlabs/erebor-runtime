use std::{
    fs,
    fs::{File, OpenOptions},
    path::Path,
    process::Command,
};

use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_filesystem::{
    FilesystemRollback, FilesystemSessionStorage, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest,
};
use erebor_runtime_session::SessionExecutionService;
use serde_json::Value;

use super::support;

#[test]
fn linux_host_large_file_without_reflink_blocks_promotion_before_host_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_large_file_without_reflink_blocks_promotion_before_host_mutation",
    )? {
        return Ok(());
    }

    let fixture = LargeFileLifecycle::new("large-file-byte-block")?;
    fixture.seed_original()?;
    let policy_path = support::write_empty_policy(&fixture.test_dir)?;
    let session_id = "session-filesystem-large-byte-block";
    let config = support::overlay_promoting_config_with_revert(
        support::OverlayPromotingRevertConfigRequest {
            policy_path: &policy_path,
            workspace: &fixture.workspace,
            host_project: &fixture.host_project,
            session_project: &fixture.session_project,
            diagnostic_name: "large-file-byte-block",
            shell_command: "cd project && test -s large.bin && printf changed > large.bin",
            preimage_size_limit_bytes: 16,
            preimage_backend: "ostree_bytes",
        },
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "large-file-byte-block",
    )?;

    let result = SessionExecutionService::run_diagnostic(&config, &plan);

    assert!(result.is_err(), "large byte preimage unexpectedly promoted");
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("large.bin"))?,
        original_large()
    );
    support::assert_not_mountpoint(&fixture.session_project)?;
    support::cleanup_overlay_test_dir(&fixture.test_dir, &fixture.workspace, session_id)?;
    Ok(())
}

#[test]
fn linux_host_large_file_reflink_promotion_and_rollback() -> Result<(), Box<dyn std::error::Error>>
{
    if !support::require_overlay_lifecycle("linux_host_large_file_reflink_promotion_and_rollback")?
    {
        return Ok(());
    }

    let fixture = LargeFileLifecycle::new("large-file-reflink")?;
    if !ReflinkProbe::new(&fixture.test_dir).supported()? {
        println!(
            "reflink capability on {}: unsupported",
            fixture.test_dir.display()
        );
        return Ok(());
    }
    println!(
        "reflink capability on {}: supported",
        fixture.test_dir.display()
    );
    fixture.seed_original()?;
    let policy_path = support::write_empty_policy(&fixture.test_dir)?;
    let session_id = "session-filesystem-large-reflink";
    let config = support::overlay_promoting_config_with_revert(
        support::OverlayPromotingRevertConfigRequest {
            policy_path: &policy_path,
            workspace: &fixture.workspace,
            host_project: &fixture.host_project,
            session_project: &fixture.session_project,
            diagnostic_name: "large-file-reflink",
            shell_command: "cd project && test -s large.bin && printf changed > large.bin",
            preimage_size_limit_bytes: 16,
            preimage_backend: "linux_reflink",
        },
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "large-file-reflink",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    assert_eq!(
        fs::read_to_string(fixture.host_project.join("large.bin"))?,
        "changed"
    );
    let filesystem = support::session_filesystem_path(&fixture.workspace, session_id);
    let repo = filesystem.join("repo");
    let preimage_ref = format!("erebor/promotions/{session_id}/volumes/project/preimage");
    let preimage = support::ostree_output(&repo, &["cat", &preimage_ref, "/erebor-preimage.json"])?;
    let preimage: Value = serde_json::from_str(&preimage)?;
    assert_eq!(preimage["total_bytes"], 0);
    let artifact = reflink_artifact(&preimage, "large.bin")?;
    assert!(filesystem.join("work").join(artifact).is_file());
    assert!(!ostree_path_exists(
        &repo,
        &preimage_ref,
        "/files/large.bin"
    )?);

    let storage = fixture.reopen_storage(session_id)?;
    fs::remove_dir_all(storage.work_path().join("promotions").join(session_id))?;
    FilesystemRollback::rollback_promotion(&storage, session_id)?;
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("large.bin"))?,
        original_large()
    );
    support::assert_not_mountpoint(&fixture.session_project)?;
    support::cleanup_overlay_test_dir(&fixture.test_dir, &fixture.workspace, session_id)?;
    Ok(())
}

#[test]
fn linux_host_large_file_reflink_artifact_drift_blocks_rollback(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_large_file_reflink_artifact_drift_blocks_rollback",
    )? {
        return Ok(());
    }

    let fixture = LargeFileLifecycle::new("large-file-reflink-drift")?;
    if !ReflinkProbe::new(&fixture.test_dir).supported()? {
        println!(
            "reflink capability on {}: unsupported",
            fixture.test_dir.display()
        );
        return Ok(());
    }
    println!(
        "reflink capability on {}: supported",
        fixture.test_dir.display()
    );
    fixture.seed_original()?;
    let policy_path = support::write_empty_policy(&fixture.test_dir)?;
    let session_id = "session-filesystem-large-reflink-drift";
    let config = support::overlay_promoting_config_with_revert(
        support::OverlayPromotingRevertConfigRequest {
            policy_path: &policy_path,
            workspace: &fixture.workspace,
            host_project: &fixture.host_project,
            session_project: &fixture.session_project,
            diagnostic_name: "large-file-reflink-drift",
            shell_command: "cd project && test -s large.bin && printf changed > large.bin",
            preimage_size_limit_bytes: 16,
            preimage_backend: "linux_reflink",
        },
    )?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "large-file-reflink-drift",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;
    let filesystem = support::session_filesystem_path(&fixture.workspace, session_id);
    let repo = filesystem.join("repo");
    let preimage_ref = format!("erebor/promotions/{session_id}/volumes/project/preimage");
    let preimage = support::ostree_output(&repo, &["cat", &preimage_ref, "/erebor-preimage.json"])?;
    let preimage: Value = serde_json::from_str(&preimage)?;
    let artifact = filesystem
        .join("work")
        .join(reflink_artifact(&preimage, "large.bin")?);
    fs::write(&artifact, "drifted")?;
    let storage = fixture.reopen_storage(session_id)?;

    let result = FilesystemRollback::rollback_promotion(&storage, session_id);

    assert!(result.is_err(), "rollback ignored reflink artifact drift");
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("large.bin"))?,
        "changed"
    );
    support::assert_not_mountpoint(&fixture.session_project)?;
    support::cleanup_overlay_test_dir(&fixture.test_dir, &fixture.workspace, session_id)?;
    Ok(())
}

fn reflink_artifact<'a>(
    preimage: &'a Value,
    path: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let entries = preimage["entries"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("preimage entries is not an array"))?;
    let entry = entries
        .iter()
        .find(|entry| entry["path"] == path)
        .ok_or_else(|| std::io::Error::other("missing large file preimage entry"))?;
    assert_eq!(entry["state"], "present");
    assert_eq!(entry["entry_type"]["entry_type"], "regular");
    assert_eq!(
        entry["entry_type"]["preimage"]["preimage_backend"],
        "linux_reflink"
    );
    entry["entry_type"]["preimage"]["artifact"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing reflink artifact").into())
}

fn ostree_path_exists(repo: &Path, ref_name: &str, path: &str) -> Result<bool, std::io::Error> {
    let status = Command::new("ostree")
        .arg(format!("--repo={}", repo.display()))
        .arg("cat")
        .arg(ref_name)
        .arg(path)
        .status()?;
    Ok(status.success())
}

fn original_large() -> String {
    format!("original:{}\n", "0123456789abcdef".repeat(256))
}

struct LargeFileLifecycle {
    test_dir: std::path::PathBuf,
    workspace: std::path::PathBuf,
    host_project: std::path::PathBuf,
    session_project: std::path::PathBuf,
}

impl LargeFileLifecycle {
    fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let test_dir = support::test_dir(name)?;
        let workspace = test_dir.join("workspace");
        let host_project = test_dir.join("host/project");
        let session_project = workspace.join("project");
        fs::create_dir_all(&host_project)?;
        fs::create_dir_all(&session_project)?;
        Ok(Self {
            test_dir,
            workspace,
            host_project,
            session_project,
        })
    }

    fn seed_original(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(self.host_project.join("large.bin"), original_large())?;
        Ok(())
    }

    fn reopen_storage(
        &self,
        session_id: &str,
    ) -> Result<FilesystemSessionStorage, Box<dyn std::error::Error>> {
        let request = FilesystemVolumeStorageRequest::new(
            "project",
            &self.host_project,
            &self.session_project,
            FilesystemVolumeMode::Writable,
        )?;
        Ok(FilesystemSessionStorage::open_existing(
            self.workspace.join(".erebor/sessions").join(session_id),
            vec![request],
        )?)
    }
}

struct ReflinkProbe<'a> {
    root: &'a Path,
}

impl<'a> ReflinkProbe<'a> {
    const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    fn supported(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let source = self.root.join("reflink-probe-source");
        let target = self.root.join("reflink-probe-target");
        let _result = fs::remove_file(&source);
        let _result = fs::remove_file(&target);
        fs::write(&source, b"probe")?;
        let source_file = File::open(&source)?;
        let target_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        let supported = rustix::fs::ioctl_ficlone(&target_file, &source_file).is_ok();
        let _result = fs::remove_file(&source);
        let _result = fs::remove_file(&target);
        Ok(supported)
    }
}
