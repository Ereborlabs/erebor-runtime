use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};
use erebor_runtime_policy::Decision;
use serde_json::json;

pub(crate) struct RecordFixture<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) id: &'a str,
    pub(crate) surface: ExecutionSurface,
    pub(crate) action: ActionKind,
    pub(crate) target: &'a str,
    pub(crate) risk: RiskLevel,
    pub(crate) final_decision: Decision,
    pub(crate) timestamp: &'a str,
}

pub(crate) fn browser_record(
    session_id: &str,
    id: &str,
    action: ActionKind,
    target: &str,
    final_decision: Decision,
    timestamp: &str,
) -> AuditRecord {
    record(RecordFixture {
        session_id,
        id,
        surface: ExecutionSurface::BrowserCdp,
        action,
        target,
        risk: risk_for_decision(&final_decision),
        final_decision,
        timestamp,
    })
}

pub(crate) fn process_record(
    session_id: &str,
    id: &str,
    target: &str,
    final_decision: Decision,
    timestamp: &str,
) -> AuditRecord {
    record(RecordFixture {
        session_id,
        id,
        surface: ExecutionSurface::Terminal,
        action: ActionKind::ProcessExec,
        target,
        risk: risk_for_decision(&final_decision),
        final_decision,
        timestamp,
    })
}

pub(crate) fn temp_file(name: &str, content: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = temp_path(name)?;
    fs::write(&path, content)?;
    Ok(path)
}

pub(crate) fn temp_dir(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = temp_path(name)?;
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn record(fixture: RecordFixture<'_>) -> AuditRecord {
    let payload = if matches!(&fixture.surface, ExecutionSurface::Terminal) {
        json!({
            "kind": "process_interception",
            "command": fixture.target.split_whitespace().collect::<Vec<_>>()
        })
    } else {
        json!({ "target": fixture.target })
    };

    AuditRecord {
        event: RuntimeEvent {
            id: EventId::new(fixture.id),
            session_id: SessionId::new(fixture.session_id),
            actor: ActorIdentity {
                id: String::from("test-agent"),
                kind: ActorKind::Agent,
            },
            surface: fixture.surface,
            action: fixture.action,
            target: Some(TargetRef {
                label: Some(fixture.target.to_owned()),
                uri: None,
            }),
            payload,
            risk: RiskMetadata {
                level: fixture.risk,
                reasons: vec![String::from("test")],
            },
            timestamp: fixture.timestamp.to_owned(),
        },
        policy_decision: fixture.final_decision.clone(),
        final_decision: fixture.final_decision,
    }
}

fn risk_for_decision(decision: &Decision) -> RiskLevel {
    match decision {
        Decision::Allow { .. } => RiskLevel::Low,
        Decision::Deny { .. } | Decision::RequireApproval { .. } | Decision::Mediate { .. } => {
            RiskLevel::High
        }
    }
}

fn temp_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "erebor-session-review-{nanos}-{}-{name}",
        std::process::id()
    )))
}
