use std::{fs, os::unix::net::UnixListener};

use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};

use super::{
    overlay_multivolume_support::{cleanup, multivolume_config, ostree_output, LifecycleFixture},
    support,
};

#[test]
fn linux_host_overlay_multivolume_preimage_failure_blocks_host_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_overlay_multivolume_preimage_failure_blocks_host_mutation",
    )? {
        return Ok(());
    }

    let fixture = LifecycleFixture::new("multivolume-failure")?;
    fixture.seed()?;
    let socket = fixture.host_cache.join("stale.sock");
    let listener = UnixListener::bind(&socket)?;
    let policy_path = support::write_empty_policy(&fixture.root)?;
    let session_id = "session-filesystem-multivolume-failure";
    let command = "cd project && printf dark > settings.txt && cd ../cache && rm stale.sock";
    let config = multivolume_config(&fixture, &policy_path, "multivolume-failure", command, true)?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "multivolume-failure",
    )?;

    let result = SessionExecutionService::run_diagnostic(&config, &plan);

    assert!(
        matches!(result, Err(SessionExecutionError::FilesystemSurface { .. })),
        "expected filesystem promotion failure, got {result:?}"
    );
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("settings.txt"))?,
        "light\n"
    );
    assert!(socket.exists());
    drop(listener);
    let repo = support::session_filesystem_path(&fixture.workspace, session_id).join("repo");
    let refs = ostree_output(&repo, &["refs", "--list"])?;
    assert!(!refs.contains(&format!("erebor/promotions/{session_id}/manifest")));
    fixture.assert_unmounted()?;
    cleanup(&fixture, session_id)?;
    Ok(())
}
