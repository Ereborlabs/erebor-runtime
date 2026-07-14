use std::cell::RefCell;

use erebor_runtime_core::{
    AuditCommandLogLevel, AuditError, AuditRecord, AuditSink, DurableAuditSink, RuntimeAuditConfig,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};
use erebor_runtime_policy::Decision;

use super::{AuditFilter, FilteredAuditSink};

#[test]
fn default_filter_suppresses_allowed_terminal_sleep() {
    let record = audit_record_with_command(
        "evt-sleep",
        Decision::Allow { rule_id: None },
        "/usr/bin/sleep",
        vec!["sleep", "0.25"],
    );

    assert!(!AuditFilter::new(&RuntimeAuditConfig::default()).should_record(&record));
}

#[test]
fn all_level_logs_debug_terminal_commands() {
    let mut audit = RuntimeAuditConfig::default();
    audit.surfaces.terminal.level = AuditCommandLogLevel::All;
    let record = audit_record_with_command(
        "evt-sleep",
        Decision::Allow { rule_id: None },
        "/usr/bin/sleep",
        vec!["sleep", "0.25"],
    );

    assert!(AuditFilter::new(&audit).should_record(&record));
}

#[test]
fn debug_command_denials_still_log() {
    let record = audit_record_with_command(
        "evt-sleep-denied",
        Decision::Deny {
            reason: String::from("sleep denied for test"),
            rule_id: Some(String::from("deny-sleep")),
        },
        "/usr/bin/sleep",
        vec!["sleep", "0.25"],
    );

    assert!(AuditFilter::new(&RuntimeAuditConfig::default()).should_record(&record));
}

#[test]
fn filtered_sink_wraps_any_audit_sink() -> Result<(), Box<dyn std::error::Error>> {
    let sink = RecordingAuditSink::default();
    let filtered = FilteredAuditSink::new(sink, RuntimeAuditConfig::default());
    let sleep = audit_record_with_command(
        "evt-sleep",
        Decision::Allow { rule_id: None },
        "/usr/bin/sleep",
        vec!["sleep", "0.25"],
    );
    let echo = audit_record_with_command(
        "evt-echo",
        Decision::Allow { rule_id: None },
        "/usr/bin/echo",
        vec!["echo", "hello"],
    );

    filtered.record(&sleep)?;
    filtered.record(&echo)?;

    assert_eq!(filtered.inner().records(), vec![echo]);
    Ok(())
}

#[test]
fn pinned_records_bypass_legacy_filtering_at_the_durable_sink_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let sink = RecordingAuditSink::default();
    let filtered = FilteredAuditSink::new(sink, RuntimeAuditConfig::default());
    let mut sleep = audit_record_with_command(
        "evt-pinned-sleep",
        Decision::Allow { rule_id: None },
        "/usr/bin/sleep",
        vec!["sleep", "0.25"],
    );
    sleep.context_pin = Some(test_pin()?);

    filtered.record_durable(&sleep)?;

    assert_eq!(filtered.inner().records(), vec![sleep]);
    Ok(())
}

#[test]
fn browser_cdp_debug_methods_are_filtered_per_surface() {
    let mut audit = RuntimeAuditConfig::default();
    audit.surfaces.browser_cdp.level = AuditCommandLogLevel::Signal;
    audit.surfaces.browser_cdp.debug_methods = vec![String::from("Runtime.evaluate")];
    let record = audit_record_for_surface(
        "evt-browser-eval",
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserScriptEval,
        serde_json::json!({ "method": "Runtime.evaluate" }),
        Decision::Allow { rule_id: None },
        None,
    );

    assert!(!AuditFilter::new(&audit).should_record(&record));
}

#[test]
fn network_debug_operations_are_filtered_per_surface() {
    let mut audit = RuntimeAuditConfig::default();
    audit.surfaces.network.level = AuditCommandLogLevel::Signal;
    audit.surfaces.network.debug_operations = vec![String::from("GET")];
    let record = audit_record_for_surface(
        "evt-network-get",
        ExecutionSurface::Network,
        ActionKind::NetworkRequest,
        serde_json::json!({ "operation": "GET" }),
        Decision::Allow { rule_id: None },
        None,
    );

    assert!(!AuditFilter::new(&audit).should_record(&record));
}

#[derive(Default)]
struct RecordingAuditSink {
    records: RefCell<Vec<AuditRecord>>,
}

impl RecordingAuditSink {
    fn records(&self) -> Vec<AuditRecord> {
        self.records.borrow().clone()
    }
}

impl AuditSink for RecordingAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.records.borrow_mut().push(record.clone());
        Ok(())
    }
}

impl DurableAuditSink for RecordingAuditSink {
    fn record_durable(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.record(record)
    }
}

fn test_pin() -> Result<erebor_runtime_context::ContextPin, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "scope_ref": "refs/scopes/session-1/root",
        "commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "used_paths": ["result"],
        "used_blob_ids": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    }))
}

fn audit_record_with_command(
    event_id: &str,
    final_decision: Decision,
    target: &str,
    command: Vec<&str>,
) -> AuditRecord {
    let command = command.into_iter().map(String::from).collect::<Vec<_>>();
    let argv_summary = command.join(" ");
    audit_record_for_surface(
        event_id,
        ExecutionSurface::Terminal,
        ActionKind::ProcessExec,
        serde_json::json!({
            "command": command,
            "argv_summary": argv_summary,
        }),
        final_decision,
        Some(target),
    )
}

fn audit_record_for_surface(
    event_id: &str,
    surface: ExecutionSurface,
    action: ActionKind,
    payload: serde_json::Value,
    final_decision: Decision,
    target: Option<&str>,
) -> AuditRecord {
    AuditRecord {
        event: RuntimeEvent {
            id: EventId::new(event_id),
            session_id: SessionId::new("session-1"),
            actor: ActorIdentity {
                id: String::from("agent-1"),
                kind: ActorKind::Agent,
            },
            surface,
            action,
            target: target.map(|label| TargetRef {
                label: Some(label.to_owned()),
                uri: None,
            }),
            payload,
            risk: RiskMetadata {
                level: RiskLevel::High,
                reasons: vec![String::from("commit changes")],
            },
            timestamp: String::from("2026-05-13T00:00:00Z"),
        },
        policy_decision: final_decision.clone(),
        final_decision,
        context_pin: None,
    }
}
