use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::{ActionKind, SessionId};
use erebor_runtime_filesystem::FilesystemRollback;
use erebor_runtime_session::SessionExecutionService;
use serde_json::Value;

use super::{
    overlay_multivolume_support::{
        assert_promoted, assert_refs, assert_restored, cleanup, multivolume_config, ostree_output,
        reopen_storage, sorted, LifecycleFixture,
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
    let record = support::filesystem_audit_record(
        &records,
        ActionKind::FileMutation,
        "deny-blocked-project",
    )?;
    assert!(record.event.payload["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("blocked.txt")));
    assert_refs(&fixture, session_id)?;
    assert_committed_artifacts(&fixture, session_id)?;
    let storage = reopen_storage(&fixture, session_id)?;
    std::fs::remove_dir_all(storage.work_path().join("promotions").join(session_id))?;
    let rollback = FilesystemRollback::rollback_promotion(&storage, session_id)?;
    assert_eq!(sorted(rollback.restored_volumes()), ["cache", "project"]);
    assert_restored(&fixture)?;
    fixture.assert_unmounted()?;
    cleanup(&fixture, session_id)?;
    Ok(())
}

fn assert_committed_artifacts(
    fixture: &LifecycleFixture,
    session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let repo = support::session_filesystem_path(&fixture.workspace, session_id).join("repo");
    let checkpoint_ref = format!("erebor/checkpoints/{session_id}/manifest");
    let project_layer = format!("erebor/checkpoints/{session_id}/volumes/project/layer");
    let cache_layer = format!("erebor/checkpoints/{session_id}/volumes/cache/layer");
    let promotion_ref = format!("erebor/promotions/{session_id}/manifest");
    let project_preimage = format!("erebor/promotions/{session_id}/volumes/project/preimage");
    let cache_preimage = format!("erebor/promotions/{session_id}/volumes/cache/preimage");

    let checkpoint = ref_json(&repo, &checkpoint_ref, "/erebor-checkpoint.json")?;
    assert_eq!(volume_ids(&checkpoint)?, ["cache", "project"]);

    let promotion = ref_json(&repo, &promotion_ref, "/erebor-promotion.json")?;
    assert_eq!(promotion["state"], "applied");
    assert_eq!(volume_ids(&promotion)?, ["cache", "project"]);
    assert_volume_ref(&promotion, "project", "preimage_ref", &project_preimage)?;
    assert_volume_ref(&promotion, "cache", "preimage_ref", &cache_preimage)?;

    let project = ref_json(&repo, &project_layer, "/erebor-layer.json")?;
    assert_operation(&project, "replace", "settings.txt")?;
    assert_operation(&project, "delete", "old-cache.txt")?;
    assert_operation(&project, "create", "generated/token.txt")?;
    assert_ref_text(&repo, &project_layer, "/files/settings.txt", "dark")?;
    assert_ref_text(&repo, &project_layer, "/files/generated/token.txt", "token")?;

    let cache = ref_json(&repo, &cache_layer, "/erebor-layer.json")?;
    assert_operation(&cache, "replace", "cache.txt")?;
    assert_operation(&cache, "delete", "stale.bin")?;
    assert_operation(&cache, "create", "warmed/index.txt")?;
    assert_ref_text(&repo, &cache_layer, "/files/cache.txt", "warm")?;
    assert_ref_text(&repo, &cache_layer, "/files/warmed/index.txt", "index")?;

    let project_preimage = ref_json(&repo, &project_preimage, "/erebor-preimage.json")?;
    assert_preimage_state(&project_preimage, "settings.txt", "present")?;
    assert_preimage_state(&project_preimage, "old-cache.txt", "present")?;
    assert_preimage_state(&project_preimage, "generated/token.txt", "absent")?;

    let cache_preimage = ref_json(&repo, &cache_preimage, "/erebor-preimage.json")?;
    assert_preimage_state(&cache_preimage, "cache.txt", "present")?;
    assert_preimage_state(&cache_preimage, "stale.bin", "present")?;
    assert_preimage_state(&cache_preimage, "warmed/index.txt", "absent")?;
    Ok(())
}

fn ref_json(
    repo: &std::path::Path,
    reference: &str,
    path: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&ostree_output(
        repo,
        &["cat", reference, path],
    )?)?)
}

fn assert_ref_text(
    repo: &std::path::Path,
    reference: &str,
    path: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(ostree_output(repo, &["cat", reference, path])?, expected);
    Ok(())
}

fn volume_ids(manifest: &Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let volumes = manifest["volumes"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("manifest volumes must be an array"))?;
    let mut ids = Vec::new();
    for volume in volumes {
        ids.push(json_string(volume, "volume_id")?);
    }
    ids.sort();
    Ok(ids)
}

fn assert_volume_ref(
    manifest: &Value,
    volume_id: &str,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let volume = manifest["volumes"]
        .as_array()
        .and_then(|volumes| {
            volumes
                .iter()
                .find(|volume| volume["volume_id"].as_str() == Some(volume_id))
        })
        .ok_or_else(|| std::io::Error::other("missing manifest volume"))?;
    assert_eq!(json_string(volume, field)?, expected);
    Ok(())
}

fn assert_operation(
    manifest: &Value,
    op: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let operations = manifest["operations"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("layer operations must be an array"))?;
    assert!(operations
        .iter()
        .any(|entry| entry["op"].as_str() == Some(op) && entry["path"].as_str() == Some(path)));
    Ok(())
}

fn assert_preimage_state(
    manifest: &Value,
    path: &str,
    state: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = manifest["entries"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("preimage entries must be an array"))?;
    let entry = entries
        .iter()
        .find(|entry| entry["path"].as_str() == Some(path))
        .ok_or_else(|| std::io::Error::other("missing preimage entry"))?;
    assert_eq!(entry["state"].as_str(), Some(state));
    Ok(())
}

fn json_string(value: &Value, field: &str) -> Result<String, Box<dyn std::error::Error>> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| std::io::Error::other(format!("missing string field `{field}`")).into())
}
