use std::{cell::Cell, fs, rc::Rc};

use erebor_runtime_audit::{
    read_audit_records, JsonlAuditSink, SessionReviewOutputFormat, SessionReviewSource,
};
use erebor_runtime_context::{ContextPinSelection, ScopeRef, ScopeStart, Snapshot, TreeEdit};
use erebor_runtime_core::{
    AuditError, AuditRecord, AuditSink, DenyApprovalProvider, DurableAuditSink,
    LocalEnforcementEngine, RuntimeConfig, RuntimeError, SessionRegistry, SessionRegistryFinish,
    SessionRunOutcome, SessionRunPlan, SessionRunnerKind,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId,
};
use erebor_runtime_policy::{Decision, PolicyEvaluator};
use snafu::Location;

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn runtime_config(root: &std::path::Path) -> TestResult<(RuntimeConfig, std::path::PathBuf)> {
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
                    "runner": {{ "kind": "linux_host" }}
                }},
                "surfaces": {{ "terminal": {{ "enabled": true }} }}
            }}"#,
            policy.display(),
            root.display()
        ),
    )?;
    Ok((
        RuntimeConfig::from_json_str(&fs::read_to_string(&config)?)?,
        config,
    ))
}

fn plan(config: &RuntimeConfig, config_path: std::path::PathBuf) -> TestResult<SessionRunPlan> {
    let mut plan = SessionRunPlan::from_config(
        config,
        SessionRunnerKind::LinuxHost,
        SessionId::new("session-pin"),
        vec![String::from("true")],
    )?;
    plan.set_config_path(config_path);
    Ok(plan)
}

fn event() -> RuntimeEvent {
    RuntimeEvent {
        id: EventId::new("evt-pinned"),
        session_id: SessionId::new("session-pin"),
        actor: ActorIdentity {
            id: String::from("agent"),
            kind: ActorKind::Agent,
        },
        surface: ExecutionSurface::Terminal,
        action: ActionKind::ProcessExec,
        target: None,
        payload: serde_json::json!({ "command": ["true"] }),
        risk: RiskMetadata {
            level: RiskLevel::Low,
            reasons: vec![String::from("fixture")],
        },
        timestamp: String::from("2026-07-14T00:00:00Z"),
    }
}

#[test]
fn decision_pin_remains_immutable_through_later_commits_merges_and_session_restart(
) -> TestResult<()> {
    let root = tempfile::tempdir()?;
    let (config, config_path) = runtime_config(root.path())?;
    let plan = plan(&config, config_path)?;
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
    let started = registry.start_session(&config, &plan)?;
    let repository = started.context_repository();
    let parent = ScopeRef::root("session-pin")?;
    let root_commit = repository.initialize_root(
        "session-pin",
        Snapshot::new(vec![
            TreeEdit::blob("results/value", b"early")?,
            TreeEdit::blob("unselected/private", b"not policy input")?,
        ])?,
        "Initialize context",
    )?;
    let pinned = repository.pin_scope_head(
        parent.clone(),
        &[ContextPinSelection::blob("results/value")],
    )?;
    assert_eq!(pinned.selected_blobs()[0].bytes(), b"early");

    let later_parent = repository.append_snapshot(
        parent.clone(),
        root_commit,
        Snapshot::new(vec![TreeEdit::blob("results/value", b"parent later")?])?,
        "Parent later result",
    )?;
    let child = ScopeRef::scope("session-pin", "child")?;
    repository.create_scope(child.clone(), ScopeStart::existing_commit(root_commit))?;
    let child_commit = repository.append_snapshot(
        child,
        root_commit,
        Snapshot::new(vec![TreeEdit::blob("results/value", b"child source")?])?,
        "Child produced result",
    )?;
    let selected_merge_tree = repository.create_tree(Snapshot::new(vec![TreeEdit::blob(
        "results/value",
        b"merge selected",
    )?])?)?;
    let merge = repository.append_pinned_merge(
        parent.clone(),
        later_parent,
        child_commit,
        selected_merge_tree,
        "Consume selected child result",
    )?;
    let merge_facts = repository.read_commit(merge)?;
    assert_eq!(merge_facts.parents(), [later_parent, child_commit]);
    assert_eq!(pinned.selected_blobs()[0].bytes(), b"early");

    let policy = CountingAllowPolicy::default();
    let sink = JsonlAuditSink::new(started.audit_path());
    let engine = LocalEnforcementEngine::with_hooks(policy.clone(), DenyApprovalProvider, sink);
    let outcome = engine.enforce_with_context(&event(), &pinned)?;
    assert!(matches!(outcome.final_decision, Decision::Allow { .. }));
    assert_eq!(policy.calls(), 1);
    assert_eq!(outcome.context_pin.as_ref(), Some(pinned.pin()));

    let invalid = repository.pin_scope_head(parent, &[ContextPinSelection::blob("missing")]);
    assert!(invalid.is_err());
    assert_eq!(policy.calls(), 1);

    registry.finish_session(
        plan.session_id(),
        SessionRegistryFinish::succeeded(&SessionRunOutcome::new(
            SessionRunnerKind::LinuxHost,
            Some(0),
        )),
    )?;
    let audit_path = started.audit_path().to_path_buf();
    drop(started);

    let audit_records = read_audit_records(&audit_path)?;
    assert_eq!(audit_records.len(), 1);
    let recorded_pin = audit_records[0]
        .context_pin
        .as_ref()
        .ok_or("durable audit record has no context pin")?;
    let reopened = registry
        .open_context_repository("session-pin")?
        .ok_or("session has no context repository")?;
    reopened.validate_pin(recorded_pin)?;
    let review = SessionReviewSource::new(registry.root().to_path_buf())
        .render_describe("session-pin", SessionReviewOutputFormat::Text)?;
    assert!(review.contains("Scope ref: refs/scopes/session-pin/root"));
    assert!(review.contains(&format!("Commit: {}", pinned.pin().commit_id())));
    assert!(review.contains("Selected paths: results/value"));
    Ok(())
}

#[test]
fn failed_durable_audit_returns_no_allow_outcome_to_the_action_boundary() -> TestResult<()> {
    let root = tempfile::tempdir()?;
    let (config, config_path) = runtime_config(root.path())?;
    let plan = plan(&config, config_path)?;
    let registry = SessionRegistry::new(plan.registry_path().to_path_buf());
    let started = registry.start_session(&config, &plan)?;
    let repository = started.context_repository();
    repository.initialize_root(
        "session-pin",
        Snapshot::new(vec![TreeEdit::blob("result", b"selected")?])?,
        "Initialize context",
    )?;
    let pinned = repository.pin_scope_head(
        ScopeRef::root("session-pin")?,
        &[ContextPinSelection::blob("result")],
    )?;
    let policy = CountingAllowPolicy::default();
    let engine = LocalEnforcementEngine::with_hooks(
        policy.clone(),
        DenyApprovalProvider,
        FailingDurableAuditSink,
    );

    let action_boundary_received_allow = match engine.enforce_with_context(&event(), &pinned) {
        Ok(outcome) => matches!(outcome.final_decision, Decision::Allow { .. }),
        Err(RuntimeError::DurableAudit { .. }) => false,
        Err(error) => return Err(error.into()),
    };

    assert!(!action_boundary_received_allow);
    assert_eq!(policy.calls(), 1);
    Ok(())
}

#[derive(Clone, Default)]
struct CountingAllowPolicy {
    calls: Rc<Cell<usize>>,
}

impl CountingAllowPolicy {
    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl PolicyEvaluator for CountingAllowPolicy {
    fn evaluate(&self, _event: &RuntimeEvent) -> erebor_runtime_policy::Result<Decision> {
        self.calls.set(self.calls.get() + 1);
        Ok(Decision::Allow { rule_id: None })
    }
}

struct FailingDurableAuditSink;

impl AuditSink for FailingDurableAuditSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::SinkUnavailable {
            reason: String::from("durable disk failure"),
            location: Location::default(),
        })
    }
}

impl DurableAuditSink for FailingDurableAuditSink {
    fn record_durable(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.record(record)
    }
}
