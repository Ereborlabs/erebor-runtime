use std::{fs, path::PathBuf};

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::RuntimeAuditConfig;
use erebor_runtime_events::{ActorIdentity, ActorKind, ExecutionSurface, SessionId};
use erebor_runtime_ipc::v1::{
    DecisionKind, FileOperation, FileOperationKind, GuardHello, InterceptionOperation,
    InterceptionRequest, InterceptionSource, PROTOCOL_VERSION,
};
use erebor_runtime_policy::{LocalPolicy, PolicySet};
use erebor_runtime_session::{
    FilesystemFileOperationHandler, FilesystemSessionContext, InterceptionBrokerClient,
    RuntimeInterceptionBroker, SessionInterceptionRouter,
};

#[test]
fn synthetic_file_operations_route_to_filesystem_handler_and_audit(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("filesystem-policy");
    let audit_path = temp_path("filesystem-lifecycle-audit");
    let handler = filesystem_handler(
        &session_id,
        r#"
        {
          "rules": [
            {
              "id": "allow-public-open",
              "match": {
                "surface": "filesystem",
                "action": "file_open",
                "target_contains": "public.txt"
              },
              "decision": "allow"
            },
            {
              "id": "deny-secret-read",
              "match": {
                "surface": "filesystem",
                "action": "file_read",
                "target_contains": "secret.txt"
              },
              "decision": "deny",
              "reason": "secret reads are denied"
            },
            {
              "id": "approve-settings-write",
              "match": {
                "surface": "filesystem",
                "action": "file_mutation",
                "target_contains": "settings.json"
              },
              "decision": "require_approval",
              "reason": "settings writes need approval"
            },
            {
              "id": "mediate-open",
              "match": {
                "surface": "filesystem",
                "action": "file_open",
                "target_contains": "unsafe.txt"
              },
              "decision": "mediate",
              "reason": "rewrite unsafe open",
              "mediation": {
                "kind": "filesystem_path_rewrite",
                "replacement_surface": "filesystem",
                "endpoint": "file:///safe.txt",
                "lease_id": "rewrite-lease",
                "keepalive": true
              }
            }
          ]
        }
        "#,
    )?
    .with_audit_jsonl(&audit_path, RuntimeAuditConfig::default());
    let router = SessionInterceptionRouter::new().with_file_operation_handler(handler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;

    let allow = request_decision(
        broker.endpoint(),
        &session_id,
        FileOperationKind::Open,
        "/workspace/public.txt",
    )?;
    let deny = request_decision(
        broker.endpoint(),
        &session_id,
        FileOperationKind::Read,
        "/workspace/secret.txt",
    )?;
    let approval = request_decision(
        broker.endpoint(),
        &session_id,
        FileOperationKind::Mutation,
        "/workspace/settings.json",
    )?;
    let mediate = request_decision(
        broker.endpoint(),
        &session_id,
        FileOperationKind::Open,
        "/workspace/unsafe.txt",
    )?;

    assert_eq!(allow.decision, DecisionKind::Allow as i32);
    assert_eq!(allow.rule_id, "allow-public-open");
    assert_eq!(deny.decision, DecisionKind::Deny as i32);
    assert_eq!(deny.rule_id, "deny-secret-read");
    assert_eq!(approval.decision, DecisionKind::RequireApproval as i32);
    assert_eq!(approval.rule_id, "approve-settings-write");
    assert_eq!(mediate.decision, DecisionKind::Mediate as i32);
    assert_eq!(mediate.rule_id, "mediate-open");
    assert_mediation(mediate.mediate.as_ref())?;

    let records = read_audit_records(&audit_path)?;
    assert_eq!(records.len(), 4);
    assert!(records
        .iter()
        .all(|record| record.event.surface == ExecutionSurface::Filesystem));
    assert!(records
        .iter()
        .any(|record| record.final_decision.rule_id() == Some("deny-secret-read")));

    fs::remove_file(audit_path)?;
    Ok(())
}

#[test]
fn synthetic_file_operation_fails_closed_without_filesystem_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("filesystem-missing-handler");
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;

    let decision = request_decision(
        broker.endpoint(),
        &session_id,
        FileOperationKind::Read,
        "/workspace/secret.txt",
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-unrouted-operation"
    );
    assert!(decision.reason.contains("file_read"));
    Ok(())
}

fn filesystem_handler(
    session_id: &str,
    policy_source: &str,
) -> Result<FilesystemFileOperationHandler, erebor_runtime_policy::PolicyError> {
    let policy = LocalPolicy::from_json_str(policy_source)?;
    Ok(FilesystemFileOperationHandler::new(
        PolicySet::from_policies(vec![policy]),
        FilesystemSessionContext::new(
            SessionId::new(session_id.to_owned()),
            ActorIdentity {
                id: String::from("openclaw"),
                kind: ActorKind::Agent,
            },
        ),
    ))
}

fn request_decision(
    endpoint: &erebor_runtime_session::RuntimeInterceptionEndpoint,
    session_id: &str,
    kind: FileOperationKind,
    path: &str,
) -> Result<
    erebor_runtime_ipc::v1::InterceptionDecision,
    erebor_runtime_session::RuntimeInterceptionBrokerError,
> {
    InterceptionBrokerClient::request_interception_decision(
        endpoint,
        hello(session_id),
        file_request(kind, path),
    )
}

fn hello(session_id: &str) -> GuardHello {
    GuardHello {
        protocol_version: PROTOCOL_VERSION,
        session_id: session_id.to_owned(),
        actor_id: String::from("openclaw"),
        guard_pid: 42,
        runner_kind: String::from("linux_host"),
        platform: String::from("linux-x86_64"),
        capabilities: vec![String::from("interception_request")],
    }
}

fn file_request(kind: FileOperationKind, path: &str) -> InterceptionRequest {
    InterceptionRequest {
        request_id: 11,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Ptrace as i32,
        pid: 100,
        ppid: 99,
        executable: String::new(),
        argv: Vec::new(),
        cwd: String::from("/workspace"),
        selected_env: Vec::new(),
        requested_endpoint: None,
        matched_handler_id: String::new(),
        timestamp: String::from("unix:1"),
        operation: operation_for_kind(kind) as i32,
        process_exec: None,
        file: Some(FileOperation {
            kind: kind as i32,
            path: path.to_owned(),
            resolved_identity: None,
        }),
        socket: None,
    }
}

fn operation_for_kind(kind: FileOperationKind) -> InterceptionOperation {
    match kind {
        FileOperationKind::Open => InterceptionOperation::FileOpen,
        FileOperationKind::Read => InterceptionOperation::FileRead,
        FileOperationKind::Mutation => InterceptionOperation::FileMutation,
        FileOperationKind::Unspecified => InterceptionOperation::Unspecified,
    }
}

fn assert_mediation(
    mediation: Option<&erebor_runtime_ipc::v1::MediateDecision>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mediation = mediation.ok_or_else(|| std::io::Error::other("missing mediation decision"))?;
    assert_eq!(mediation.kind, "filesystem_path_rewrite");
    assert_eq!(mediation.replacement_surface, "filesystem");
    assert_eq!(mediation.endpoint, "file:///safe.txt");
    assert_eq!(mediation.lease_id, "rewrite-lease");
    assert!(mediation.keepalive);
    Ok(())
}

fn session_id(name: &str) -> String {
    format!("session-test-{name}-{}", std::process::id())
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "erebor-{name}-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "filesystem_surface_lifecycle/linux_host.rs"]
mod linux_host;
