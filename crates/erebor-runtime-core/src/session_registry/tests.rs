use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    RuntimeConfig, SessionRegistry, SessionRegistryFinish, SessionRegistryStatus,
    SessionRunOutcome, SessionRunPlan, SessionRunnerKind,
};
use erebor_runtime_events::SessionId;

mod context;

#[test]
fn registry_creates_session_record_and_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_dir("registry")?;
    let policy = root.join("policy.json");
    let config_path = root.join("runtime.json");
    fs::write(&policy, r#"{"rules":[]}"#)?;
    fs::write(
        &config_path,
        format!(
            r#"{{
                    "policies": ["{}"],
                    "session": {{
                        "enabled": true,
                        "workspace": "{}",
                        "runner": {{ "kind": "linux_host" }}
                    }},
                    "surfaces": {{
                        "terminal": {{ "enabled": true }}
                    }}
                }}"#,
            policy.display(),
            root.display()
        ),
    )?;
    let config = RuntimeConfig::from_json_str(&fs::read_to_string(&config_path)?)?;
    let mut plan = SessionRunPlan::from_config(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-registry-test"),
        vec![String::from("true")],
    )?;
    plan.set_config_path(config_path.clone());
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());

    let started = registry.start_session(&config, &plan)?;

    assert_eq!(started.record().status, SessionRegistryStatus::Running);
    assert!(started.record().session_dir.join("session.json").exists());
    assert!(started
        .record()
        .config_artifact_path()
        .is_some_and(Path::exists));
    assert_eq!(started.record().policy_artifact_paths.len(), 1);
    assert_eq!(started.audit_path(), started.record().audit_path());

    let finished = registry.finish_session(
        plan.session_id(),
        SessionRegistryFinish::succeeded(&SessionRunOutcome::new(
            SessionRunnerKind::LinuxHost,
            Some(0),
        )),
    )?;

    assert_eq!(finished.status, SessionRegistryStatus::Succeeded);
    assert_eq!(finished.exit_code, Some(0));
    assert!(finished.ended_at_unix_ms.is_some());
    assert_eq!(registry.list_sessions()?.len(), 1);

    fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn temp_dir(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = std::env::temp_dir().join(format!(
        "erebor-session-registry-{name}-{nanos}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}
