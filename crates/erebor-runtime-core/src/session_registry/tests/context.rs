use std::{fs, io, path::Path};

use super::temp_dir;
use crate::{
    RuntimeConfig, SessionRegistry, SessionRegistryError, SessionRegistryFinish, SessionRunOutcome,
    SessionRunPlan, SessionRunnerKind,
};
use erebor_runtime_context::{ScopeRef, Snapshot, TreeEdit};
use erebor_runtime_events::SessionId;

fn runtime_config(root: &Path) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    let policy = root.join("policy.json");
    fs::write(&policy, r#"{"rules":[]}"#)?;
    Ok(RuntimeConfig::from_json_str(&format!(
        r#"{{
            "policies": ["{}"],
            "session": {{
                "enabled": true,
                "workspace": "{}",
                "runner": {{ "kind": "linux_host" }}
            }},
            "surfaces": {{ "terminal": {{ "enabled": true }} }}
        }}"#,
        policy.display(),
        root.display()
    ))?)
}

fn plan(
    config: &RuntimeConfig,
    session_id: &str,
) -> Result<SessionRunPlan, Box<dyn std::error::Error>> {
    Ok(SessionRunPlan::from_config(
        config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        vec![String::from("true")],
    )?)
}

#[test]
fn new_session_records_and_reopens_its_isolated_context_repository(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_dir("context-artifact")?;
    let config = runtime_config(&root)?;
    let plan = plan(&config, "session-context")?;
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());

    let started = registry.start_session(&config, &plan)?;
    let artifact = started
        .record()
        .context_artifact
        .as_ref()
        .ok_or_else(|| io::Error::other("new session did not record its context artifact"))?;
    assert_eq!(started.record().schema_version, 2);
    assert_eq!(artifact.path(), Path::new("context"));
    assert_eq!(artifact.repository_kind(), "bare");
    assert_eq!(artifact.object_format(), "sha256");
    assert_eq!(
        started.context_repository().path(),
        started.record().session_dir.join("context")
    );

    let root_commit = started.context_repository().initialize_root(
        "session-context",
        Snapshot::new(vec![TreeEdit::blob("payload", b"root")?])?,
        "Initialize context root",
    )?;
    registry.finish_session(
        plan.session_id(),
        SessionRegistryFinish::succeeded(&SessionRunOutcome::new(
            SessionRunnerKind::LinuxHost,
            Some(0),
        )),
    )?;
    drop(started);

    let reopened = registry
        .open_context_repository(plan.session_id().as_str())?
        .ok_or_else(|| io::Error::other("new session did not reopen its context repository"))?;
    assert_eq!(
        reopened.scope_head(&ScopeRef::root("session-context")?)?,
        root_commit
    );
    assert_eq!(reopened.scope_refs()?.len(), 1);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn colliding_normalized_ids_never_open_another_sessions_record_or_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_dir("context-collision")?;
    let config = runtime_config(&root)?;
    let first = plan(&config, "a@b")?;
    let second = plan(&config, "a_b")?;
    let registry = SessionRegistry::new(first.registry_path().to_path_buf());

    registry.start_session(&config, &first)?;
    assert!(matches!(
        registry.start_session(&config, &second),
        Err(SessionRegistryError::SessionDirectoryCollision {
            requested_session_id,
            stored_session_id,
            ..
        }) if requested_session_id == "a_b" && stored_session_id.as_str() == "a@b"
    ));
    assert!(matches!(
        registry.load_session("a_b"),
        Err(SessionRegistryError::SessionIdMismatch { .. })
    ));
    assert!(matches!(
        registry.open_context_repository("a_b"),
        Err(SessionRegistryError::SessionIdMismatch { .. })
    ));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_records_remain_readable_without_a_context_repository(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_dir("legacy-context")?;
    let registry_root = root.join("registry");
    let session_id = "legacy-session";
    let session_dir = registry_root.join(session_id);
    fs::create_dir_all(&session_dir)?;
    fs::write(
        session_dir.join("session.json"),
        serde_json::json!({
            "schema_version": 1,
            "session_id": session_id,
            "status": "succeeded",
            "actor_id": "agent",
            "actor_kind": "agent",
            "runner": "linux_host",
            "surfaces": ["terminal"],
            "workspace": null,
            "command": ["true"],
            "diagnostic": null,
            "registry_path": registry_root.clone(),
            "session_dir": session_dir.clone(),
            "audit_path": session_dir.join("audit.jsonl"),
            "config_artifact_path": null,
            "source_config_path": null,
            "policy_artifact_paths": [],
            "source_policy_paths": [],
            "started_at_unix_ms": 1,
            "ended_at_unix_ms": 2,
            "exit_code": 0,
            "failure": null
        })
        .to_string(),
    )?;
    let registry = SessionRegistry::new(&registry_root);

    let record = registry.load_session(session_id)?;
    assert_eq!(record.schema_version, 1);
    assert!(record.context_artifact.is_none());
    assert_eq!(registry.list_sessions()?.len(), 1);
    assert!(registry.open_context_repository(session_id)?.is_none());

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn rejects_context_metadata_that_escapes_or_does_not_describe_the_session_repository(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_dir("context-path-validation")?;
    let config = runtime_config(&root)?;
    let plan = plan(&config, "path-session")?;
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
    let started = registry.start_session(&config, &plan)?;
    let record_path = started.record().session_dir.join("session.json");
    drop(started);

    for (path, expected) in [
        (serde_json::json!("../other"), "parent"),
        (serde_json::json!("/tmp/other"), "relative"),
    ] {
        let mut record: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&record_path)?)?;
        record["context_artifact"]["path"] = path;
        fs::write(&record_path, serde_json::to_string(&record)?)?;
        let error = registry
            .open_context_repository(plan.session_id().as_str())
            .err()
            .ok_or_else(|| io::Error::other("invalid context path unexpectedly opened"))?;
        assert!(matches!(
            error,
            SessionRegistryError::InvalidContextArtifactPath { reason, .. }
                if reason.contains(expected)
        ));
    }

    let mut record: serde_json::Value = serde_json::from_str(&fs::read_to_string(&record_path)?)?;
    record["context_artifact"]["path"] = serde_json::json!("context");
    record["context_artifact"]["object_format"] = serde_json::json!("sha1");
    fs::write(&record_path, serde_json::to_string(&record)?)?;
    assert!(matches!(
        registry.open_context_repository(plan.session_id().as_str()),
        Err(SessionRegistryError::InvalidContextArtifactMetadata { field, .. })
            if field == "object format"
    ));

    let mut record: serde_json::Value = serde_json::from_str(&fs::read_to_string(&record_path)?)?;
    record["context_artifact"]["object_format"] = serde_json::json!("sha256");
    record["session_dir"] = serde_json::json!(root.join("other-session"));
    fs::write(&record_path, serde_json::to_string(&record)?)?;
    assert!(matches!(
        registry.open_context_repository(plan.session_id().as_str()),
        Err(SessionRegistryError::SessionDirectoryMismatch { .. })
    ));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_a_symlinked_context_root_and_a_missing_context_artifact(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let root = temp_dir("context-symlink")?;
    let config = runtime_config(&root)?;
    let plan = plan(&config, "symlink-session")?;
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
    let started = registry.start_session(&config, &plan)?;
    let context_path = started.record().session_dir.join("context");
    let replacement = root.join("replacement-context");
    drop(started);
    fs::remove_dir_all(&context_path)?;
    fs::create_dir_all(&replacement)?;
    symlink(&replacement, &context_path)?;
    assert!(matches!(
        registry.open_context_repository(plan.session_id().as_str()),
        Err(SessionRegistryError::ContextArtifactSymlink { .. })
    ));
    fs::remove_file(&context_path)?;
    assert!(matches!(
        registry.open_context_repository(plan.session_id().as_str()),
        Err(SessionRegistryError::MissingContextArtifact { .. })
    ));

    fs::remove_dir_all(root)?;
    Ok(())
}
