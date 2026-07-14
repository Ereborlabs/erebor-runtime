use std::{fs, io, path::Path};

use erebor_runtime_context::{ScopeRef, Snapshot, TreeEdit};
use erebor_runtime_core::{
    RuntimeConfig, SessionRegistry, SessionRegistryFinish, SessionRunOutcome, SessionRunPlan,
    SessionRunnerKind,
};
use erebor_runtime_events::SessionId;

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn runtime_config(root: &Path) -> TestResult<RuntimeConfig> {
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

fn plan(config: &RuntimeConfig, session_id: &str) -> TestResult<SessionRunPlan> {
    Ok(SessionRunPlan::from_config(
        config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        vec![String::from("true")],
    )?)
}

#[test]
fn context_repositories_are_session_isolated_and_survive_session_completion() -> TestResult<()> {
    let root = tempfile::tempdir()?;
    let config = runtime_config(root.path())?;
    let first_plan = plan(&config, "session-one")?;
    let second_plan = plan(&config, "session-two")?;
    let registry = SessionRegistry::new(first_plan.registry_path().to_path_buf());

    let first = registry.start_session(&config, &first_plan)?;
    let second = registry.start_session(&config, &second_plan)?;
    let first_commit = first.context_repository().initialize_root(
        "session-one",
        Snapshot::new(vec![TreeEdit::blob("result", b"first")?])?,
        "Initialize first context",
    )?;
    let second_commit = second.context_repository().initialize_root(
        "session-two",
        Snapshot::new(vec![TreeEdit::blob("result", b"second")?])?,
        "Initialize second context",
    )?;
    assert_ne!(first_commit, second_commit);
    assert_ne!(
        first.context_repository().path(),
        second.context_repository().path()
    );

    for plan in [&first_plan, &second_plan] {
        registry.finish_session(
            plan.session_id(),
            SessionRegistryFinish::succeeded(&SessionRunOutcome::new(
                SessionRunnerKind::LinuxHost,
                Some(0),
            )),
        )?;
    }
    drop(first);
    drop(second);

    let reopened_first = registry
        .open_context_repository("session-one")?
        .ok_or_else(|| io::Error::other("first context artifact was not recorded"))?;
    let reopened_second = registry
        .open_context_repository("session-two")?
        .ok_or_else(|| io::Error::other("second context artifact was not recorded"))?;
    assert_eq!(
        reopened_first.scope_head(&ScopeRef::root("session-one")?)?,
        first_commit
    );
    assert_eq!(
        reopened_second.scope_head(&ScopeRef::root("session-two")?)?,
        second_commit
    );
    assert_eq!(reopened_first.scope_refs()?.len(), 1);
    assert_eq!(reopened_second.scope_refs()?.len(), 1);
    assert_eq!(registry.list_sessions()?.len(), 2);
    Ok(())
}
