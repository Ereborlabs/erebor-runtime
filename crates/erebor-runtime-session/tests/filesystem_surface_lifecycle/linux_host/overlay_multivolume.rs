use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::{ActionKind, SessionId};
use erebor_runtime_filesystem::rollback_promotion;
use erebor_runtime_session::SessionExecutionService;

use super::{
    overlay_multivolume_support::{
        assert_promoted, assert_refs, assert_restored, cleanup, multivolume_config, reopen_storage,
        sorted, LifecycleFixture,
    },
    support,
};

#[test]
fn linux_host_overlay_multivolume_promotes_and_rolls_back() -> Result<(), Box<dyn std::error::Error>>
{
    if !support::require_overlay_lifecycle(
        "linux_host_overlay_multivolume_promotes_and_rolls_back",
    )? {
        return Ok(());
    }

    let fixture = LifecycleFixture::new("multivolume-success")?;
    fixture.seed()?;
    let policy_path = support::write_policy_source(
        &fixture.root,
        "deny-blocked.json",
        r#"{
          "rules": [{
            "id": "deny-blocked-project",
            "match": {
              "surface": "filesystem",
              "action": "file_mutation",
              "target_contains": "blocked.txt"
            },
            "decision": "deny",
            "reason": "blocked project writes are denied"
          }]
        }"#,
    )?;
    let session_id = "session-filesystem-multivolume-success";
    let command = "cd project && rg light settings.txt && \
        if printf blocked > blocked.txt; then exit 41; fi; \
        printf dark > settings.txt && rm old-cache.txt && \
        mkdir -p generated && printf token > generated/token.txt && \
        cd ../cache && rg cold cache.txt && printf warm > cache.txt && \
        rm stale.bin && mkdir -p warmed && printf index > warmed/index.txt";
    let config = multivolume_config(&fixture, &policy_path, "multivolume-success", command, true)?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "multivolume-success",
    )?;

    SessionExecutionService::run_diagnostic(&config, &plan)?;

    assert_promoted(&fixture)?;
    let records = read_audit_records(support::session_audit_path(&fixture.workspace, session_id))?;
    support::filesystem_audit_record(&records, ActionKind::FileMutation, "deny-blocked-project")?;
    assert_refs(&fixture, session_id)?;
    let storage = reopen_storage(&fixture, session_id)?;
    std::fs::remove_dir_all(storage.work_path().join("promotions").join(session_id))?;
    let rollback = rollback_promotion(&storage, session_id)?;
    assert_eq!(sorted(rollback.restored_volumes()), ["cache", "project"]);
    assert_restored(&fixture)?;
    fixture.assert_unmounted()?;
    cleanup(&fixture, session_id)?;
    Ok(())
}
