use std::{
    cell::RefCell,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{
    AuditCommandLogLevel, AuditError, AuditRecord, AuditSink, RuntimeAuditConfig,
};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId,
};
use erebor_runtime_policy::Decision;

use crate::{
    append_audit_record, read_audit_records, should_record_audit_record, AuditLogError,
    FilteredAuditSink, JsonlAuditSink,
};

#[test]
fn writes_and_reads_jsonl_audit_records() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_audit_path()?;
    let sink = JsonlAuditSink::new(&path);
    let record = audit_record("evt-1", Decision::Allow { rule_id: None });

    sink.record(&record)?;

    let records = read_audit_records(&path)?;

    assert_eq!(records, vec![record]);
    let _result = fs::remove_file(path);
    Ok(())
}

#[test]
fn appends_multiple_records() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_audit_path()?;
    let first = audit_record("evt-1", Decision::Allow { rule_id: None });
    let second = audit_record(
        "evt-2",
        Decision::Deny {
            reason: String::from("denied"),
            rule_id: Some(String::from("rule-1")),
        },
    );

    append_audit_record(&path, &first)?;
    append_audit_record(&path, &second)?;

    let records = read_audit_records(&path)?;

    assert_eq!(records, vec![first, second]);
    let _result = fs::remove_file(path);
    Ok(())
}

#[test]
fn reports_invalid_jsonl_line() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_audit_path()?;
    fs::write(&path, "{not-json}\n")?;

    let error = read_audit_records(&path);

    assert!(matches!(
        error,
        Err(AuditLogError::InvalidRecord { line: 1, .. })
    ));
    let _result = fs::remove_file(path);
    Ok(())
}

#[test]
fn default_filter_suppresses_allowed_terminal_sleep() {
    let record = audit_record_with_command(
        "evt-sleep",
        Decision::Allow { rule_id: None },
        "/usr/bin/sleep",
        vec!["sleep", "0.25"],
    );

    assert!(!should_record_audit_record(
        &record,
        &RuntimeAuditConfig::default()
    ));
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

    assert!(should_record_audit_record(&record, &audit));
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

    assert!(should_record_audit_record(
        &record,
        &RuntimeAuditConfig::default()
    ));
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
fn browser_cdp_debug_methods_are_filtered_per_surface() {
    let mut audit = RuntimeAuditConfig::default();
    audit.surfaces.browser_cdp.level = AuditCommandLogLevel::Signal;
    audit.surfaces.browser_cdp.debug_methods = vec![String::from("Runtime.evaluate")];
    let record = audit_record_for_surface(
        "evt-browser-eval",
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserScriptEval,
        serde_json::json!({
            "method": "Runtime.evaluate",
        }),
        Decision::Allow { rule_id: None },
    );

    assert!(!should_record_audit_record(&record, &audit));
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
        serde_json::json!({
            "operation": "GET",
        }),
        Decision::Allow { rule_id: None },
    );

    assert!(!should_record_audit_record(&record, &audit));
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

fn audit_record(event_id: &str, final_decision: Decision) -> AuditRecord {
    audit_record_with_command(
        event_id,
        final_decision,
        "/usr/bin/git",
        vec!["git", "commit"],
    )
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
    )
    .with_target_label(target)
}

fn temp_audit_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "erebor-runtime-audit-{nanos}-{}.jsonl",
        std::process::id()
    )))
}

fn audit_record_for_surface(
    event_id: &str,
    surface: ExecutionSurface,
    action: ActionKind,
    payload: serde_json::Value,
    final_decision: Decision,
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
            target: None,
            payload,
            risk: RiskMetadata {
                level: RiskLevel::High,
                reasons: vec![String::from("commit changes")],
            },
            timestamp: String::from("2026-05-13T00:00:00Z"),
        },
        policy_decision: final_decision.clone(),
        final_decision,
    }
}

trait AuditRecordExt {
    fn with_target_label(self, label: &str) -> Self;
}

impl AuditRecordExt for AuditRecord {
    fn with_target_label(mut self, label: &str) -> Self {
        self.event.target = Some(erebor_runtime_events::TargetRef {
            label: Some(label.to_owned()),
            uri: None,
        });
        self
    }
}
