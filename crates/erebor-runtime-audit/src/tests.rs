use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{AuditRecord, AuditSink};
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

fn audit_record(event_id: &str, final_decision: Decision) -> AuditRecord {
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
            payload: serde_json::json!({ "command": "git commit" }),
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

fn temp_audit_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "erebor-runtime-audit-{nanos}-{}.jsonl",
        std::process::id()
    )))
}
