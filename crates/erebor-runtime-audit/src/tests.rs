use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{AuditRecord, AuditSink, DurableAuditSink};
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId,
};
use erebor_runtime_policy::Decision;

use crate::{append_audit_record, read_audit_records, AuditLogError, JsonlAuditSink};

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
fn durable_pinned_records_round_trip_without_copying_selected_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_audit_path()?;
    let sink = JsonlAuditSink::new(&path);
    let mut record = audit_record("evt-pinned", Decision::Allow { rule_id: None });
    record.context_pin = Some(test_pin()?);

    sink.record_durable(&record)?;

    let serialized = fs::read_to_string(&path)?;
    assert!(serialized.contains(r#""context_pin""#));
    assert!(!serialized.contains("selected context bytes"));
    assert_eq!(read_audit_records(&path)?, vec![record]);
    let _result = fs::remove_file(path);
    Ok(())
}

#[test]
fn old_jsonl_records_without_pins_remain_readable() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_audit_path()?;
    let record = audit_record("evt-legacy", Decision::Allow { rule_id: None });
    let serialized = serde_json::to_string(&record)?;
    assert!(!serialized.contains("context_pin"));
    fs::write(&path, format!("{serialized}\n"))?;

    let records = read_audit_records(&path)?;

    assert_eq!(records[0].context_pin, None);
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

pub(crate) fn audit_record(event_id: &str, final_decision: Decision) -> AuditRecord {
    AuditRecord {
        event: RuntimeEvent {
            id: EventId::new(event_id),
            session_id: SessionId::new("session-1"),
            actor: ActorIdentity {
                id: String::from("agent-1"),
                kind: ActorKind::Agent,
            },
            surface: ExecutionSurface::Terminal,
            action: ActionKind::ProcessExec,
            target: None,
            payload: serde_json::json!({ "command": ["git", "commit"] }),
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

fn temp_audit_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "erebor-runtime-audit-{nanos}-{}.jsonl",
        std::process::id()
    )))
}

fn test_pin() -> Result<erebor_runtime_context::ContextPin, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "scope_ref": "refs/scopes/session-1/root",
        "commit_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "used_paths": ["result"],
        "used_blob_ids": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    }))
}
