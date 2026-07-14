use std::fs;

use erebor_runtime_core::{
    RuntimeConfig, SessionRegistry, SessionRegistryFinish, SessionRunOutcome, SessionRunPlan,
    SessionRunnerKind,
};
use erebor_runtime_events::SessionId;
use erebor_runtime_policy::Decision;

use crate::session_review::{
    test_support::{process_record, temp_dir},
    SessionReviewOutputFormat, SessionReviewSource,
};

#[test]
fn source_renderers_resolve_registry_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_dir("registry-source")?;
    let policy = root.join("policy.json");
    let config = root.join("config.json");
    fs::write(&policy, r#"{"rules":[]}"#)?;
    fs::write(
        &config,
        format!(
            r#"{{
                "policies": ["{}"],
                "session": {{
                    "enabled": true,
                    "workspace": "{}",
                    "actor": {{ "id": "test-agent", "kind": "agent" }},
                    "runner": {{ "kind": "linux_host" }}
                }},
                "surfaces": {{
                    "terminal": {{ "enabled": true }}
                }}
            }}"#,
            policy.display(),
            root.display(),
        ),
    )?;
    let runtime_config = RuntimeConfig::from_json_str(&fs::read_to_string(&config)?)?;
    let mut plan = SessionRunPlan::from_config(
        &runtime_config,
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-registry-source"),
        vec![String::from("sh")],
    )?;
    plan.set_config_path(config.clone());
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
    let started = registry.start_session(&runtime_config, &plan)?;
    let record = process_record(
        "session-registry-source",
        "deny-process",
        "sh --remote-debugging-port=9222",
        Decision::Deny {
            reason: String::from("raw CDP process launch is denied"),
            rule_id: Some(String::from("deny-raw-cdp")),
        },
        "2026-06-21T18:00:01Z",
    );
    fs::write(
        started.record().audit_path(),
        format!("{}\n", serde_json::to_string(&record)?),
    )?;
    registry.finish_session(
        plan.session_id(),
        SessionRegistryFinish::succeeded(&SessionRunOutcome::new(
            SessionRunnerKind::LinuxHost,
            Some(0),
        )),
    )?;
    let record_path = started.record().session_dir.join("session.json");
    let mut legacy_record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record_path)?)?;
    legacy_record["schema_version"] = serde_json::json!(1);
    legacy_record
        .as_object_mut()
        .ok_or("session record must be a JSON object")?
        .remove("context_artifact");
    fs::write(&record_path, serde_json::to_string(&legacy_record)?)?;

    let source = SessionReviewSource::new(registry.root().to_path_buf());
    let list = source.render_list(SessionReviewOutputFormat::Text)?;
    let show = source.render_show("session-registry-source", SessionReviewOutputFormat::Text)?;
    let describe =
        source.render_describe("session-registry-source", SessionReviewOutputFormat::Json)?;

    assert!(list.contains("session-registry-source"));
    assert!(list.contains("succeeded"));
    assert!(show.contains("deny-raw-cdp"));
    assert!(show.contains("Policy sha256:"));
    assert!(describe.contains(r#""session_id": "session-registry-source""#));
    assert!(describe.contains(r#""controlled_path_backend": "linux_ptrace_process_guard""#));

    fs::remove_dir_all(root)?;
    Ok(())
}
