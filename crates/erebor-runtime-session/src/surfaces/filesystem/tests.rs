use std::{fs, path::PathBuf};

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{
    FileInterceptionOperationKind, FileInterceptionRequest, FileOperationSurfaceHandler,
    FileResolvedIdentity, RuntimeAuditConfig, SessionInterceptionDecision,
};
use erebor_runtime_events::{ActionKind, ActorIdentity, ActorKind, ExecutionSurface, SessionId};
use erebor_runtime_policy::{LocalPolicy, PolicySet};

use super::{
    path::normalize_request_path, FilesystemFileOperationHandler, FilesystemSessionContext,
};

#[test]
fn filesystem_handler_allows_denies_and_requires_approval() -> Result<(), Box<dyn std::error::Error>>
{
    let handler = handler_from_policy(
        r#"
        {
          "rules": [
            {
              "id": "allow-public-read",
              "match": {
                "surface": "filesystem",
                "action": "file_read",
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
              "id": "approve-mutation",
              "match": {
                "surface": "filesystem",
                "action": "file_mutation",
                "target_contains": "settings.json"
              },
              "decision": "require_approval",
              "reason": "settings writes need approval"
            }
          ]
        }
        "#,
    )?;

    let allow = decide(&handler, FileInterceptionOperationKind::Read, "public.txt");
    let deny = decide(&handler, FileInterceptionOperationKind::Read, "secret.txt");
    let approval = decide(
        &handler,
        FileInterceptionOperationKind::Mutation,
        "settings.json",
    );

    assert_eq!(allow.0, SessionInterceptionDecision::Allow);
    assert_eq!(allow.1, "allow-public-read");
    assert_eq!(deny.0, SessionInterceptionDecision::Deny);
    assert_eq!(deny.1, "deny-secret-read");
    assert_eq!(deny.2, "secret reads are denied");
    assert_eq!(approval.0, SessionInterceptionDecision::RequireApproval);
    assert_eq!(approval.1, "approve-mutation");
    Ok(())
}

#[test]
fn filesystem_handler_mediates_from_policy_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let handler = handler_from_policy(
        r#"
        {
          "rules": [
            {
              "id": "mediate-open",
              "match": {
                "surface": "filesystem",
                "action": "file_open",
                "target_contains": "unsafe.txt"
              },
              "decision": "mediate",
              "reason": "open replacement file",
              "mediation": {
                "kind": "filesystem_path_rewrite",
                "replacement_surface": "filesystem",
                "endpoint": "file:///safe.txt",
                "lease_id": "rewrite-1",
                "print_line": "opening safe.txt",
                "keepalive": true
              }
            }
          ]
        }
        "#,
    )?;

    let decision = decide(&handler, FileInterceptionOperationKind::Open, "unsafe.txt");
    let mediation = decision
        .3
        .ok_or_else(|| std::io::Error::other("missing mediation decision"))?;
    let (kind, surface, endpoint, lease_id, print_line, keepalive) = mediation.into_parts();

    assert_eq!(decision.0, SessionInterceptionDecision::Mediate);
    assert_eq!(decision.1, "mediate-open");
    assert_eq!(kind, "filesystem_path_rewrite");
    assert_eq!(surface, "filesystem");
    assert_eq!(endpoint, "file:///safe.txt");
    assert_eq!(lease_id, "rewrite-1");
    assert_eq!(print_line, "opening safe.txt");
    assert!(keepalive);
    Ok(())
}

#[test]
fn filesystem_handler_writes_audit_records() -> Result<(), Box<dyn std::error::Error>> {
    let audit_path = temp_path("filesystem-audit");
    let handler = handler_from_policy(
        r#"
        {
          "rules": [
            {
              "id": "deny-secret-read",
              "match": {
                "surface": "filesystem",
                "action": "file_read",
                "target_contains": "secret.txt"
              },
              "decision": "deny",
              "reason": "secret reads are denied"
            }
          ]
        }
        "#,
    )?
    .with_audit_jsonl(&audit_path, RuntimeAuditConfig::default());

    let _allow = decide(&handler, FileInterceptionOperationKind::Read, "public.txt");
    let _deny = decide(&handler, FileInterceptionOperationKind::Read, "secret.txt");
    let records = read_audit_records(&audit_path)?;

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].event.surface, ExecutionSurface::Filesystem);
    assert_eq!(records[0].event.action, ActionKind::FileRead);
    assert_eq!(
        records[1].final_decision.rule_id(),
        Some("deny-secret-read")
    );

    fs::remove_file(audit_path)?;
    Ok(())
}

#[test]
fn filesystem_handler_audits_resolved_identity() -> Result<(), Box<dyn std::error::Error>> {
    let audit_path = temp_path("filesystem-identity-audit");
    let handler = handler_from_policy(r#"{"rules":[]}"#)?
        .with_audit_jsonl(&audit_path, RuntimeAuditConfig::default());
    let request = FileInterceptionRequest::new(
        FileInterceptionOperationKind::Read,
        "secret.txt",
        "/workspace",
        100,
        99,
    )
    .with_resolved_identity(FileResolvedIdentity::new(12, 34));

    let _decision = handler.decide_file_operation(&request);
    let records = read_audit_records(&audit_path)?;
    let identity = &records[0].event.payload["resolved_identity"];

    assert_eq!(identity["device"], 12);
    assert_eq!(identity["inode"], 34);

    fs::remove_file(audit_path)?;
    Ok(())
}

#[test]
fn path_normalization_is_lexical() {
    assert_eq!(
        normalize_request_path("/workspace/project", "../secret.txt"),
        "/workspace/secret.txt"
    );
    assert_eq!(
        normalize_request_path("/workspace", "missing-link/../target.txt"),
        "/workspace/target.txt"
    );
    assert_eq!(
        normalize_request_path("", "../relative.txt"),
        "../relative.txt"
    );
}

fn handler_from_policy(
    source: &str,
) -> Result<FilesystemFileOperationHandler, erebor_runtime_policy::PolicyError> {
    let policy = LocalPolicy::from_json_str(source)?;
    Ok(FilesystemFileOperationHandler::new(
        PolicySet::from_policies(vec![policy]),
        FilesystemSessionContext::new(
            SessionId::new("session-filesystem-test"),
            ActorIdentity {
                id: String::from("agent"),
                kind: ActorKind::Agent,
            },
        ),
    ))
}

fn decide(
    handler: &FilesystemFileOperationHandler,
    operation: FileInterceptionOperationKind,
    path: &str,
) -> (
    SessionInterceptionDecision,
    String,
    String,
    Option<erebor_runtime_core::SurfaceMediationDecision>,
) {
    let request = FileInterceptionRequest::new(operation, path, "/workspace/project", 100, 99);
    handler.decide_file_operation(&request).into_parts()
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
