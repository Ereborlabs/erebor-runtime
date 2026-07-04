use std::{fs, path::Path, process};

use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::{ActionKind, ExecutionSurface, SessionId};
use erebor_runtime_session::{SessionExecutionError, SessionExecutionService};

#[test]
fn linux_host_cat_secret_is_denied_by_filesystem_policy() -> Result<(), Box<dyn std::error::Error>>
{
    let test_dir = test_dir("cat-secret")?;
    fs::write(test_dir.join("secret.txt"), "secret\n")?;
    let policy_path = write_policy(&test_dir)?;
    let session_id = "session-filesystem-linux-deny";
    let config = RuntimeConfig::from_json_str(&format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [
              {{
                "name": "cat-secret",
                "command": ["cat", "secret.txt"]
              }}
            ],
            "runner": {{ "kind": "linux_host" }},
            "interception": {{
              "enabled": true,
              "backend": "linux_ptrace",
              "operations": ["process_exec", "file_open", "file_read", "file_mutation"]
            }}
          }},
          "surfaces": {{
            "terminal": {{ "enabled": true }},
            "filesystem": {{
              "enabled": true,
              "backend": {{ "kind": "linux_ostree_overlay" }},
              "volumes": [
                {{
                  "id": "workspace",
                  "host_path": "{}",
                  "session_path": "{}",
                  "mode": "writable"
                }}
              ]
            }}
          }}
        }}"#,
        policy_path.display(),
        test_dir.display(),
        test_dir.display(),
        test_dir.display()
    ))?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "cat-secret",
    )?;

    let error = SessionExecutionService::run_diagnostic(&config, &plan);

    assert!(
        matches!(error, Err(SessionExecutionError::DiagnosticFailed { .. })),
        "expected cat secret.txt to fail through filesystem policy, got {error:?}"
    );
    let records = read_audit_records(session_audit_path(&test_dir, session_id))?;
    let record = records
        .iter()
        .find(|record| {
            record.event.surface == ExecutionSurface::Filesystem
                && record.event.action == ActionKind::FileRead
                && record.final_decision.rule_id() == Some("deny-secret-read")
        })
        .ok_or_else(|| std::io::Error::other("missing denied filesystem audit record"))?;

    assert!(record.event.payload["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("secret.txt")));
    assert!(record.event.payload["resolved_identity"]["device"]
        .as_u64()
        .is_some());
    assert!(record.event.payload["resolved_identity"]["inode"]
        .as_u64()
        .is_some());

    fs::remove_dir_all(test_dir)?;
    Ok(())
}

fn test_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = std::env::temp_dir().join(format!(
        "erebor-filesystem-lifecycle-{name}-{}",
        process::id()
    ));
    let _result = fs::remove_dir_all(&path);
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn write_policy(test_dir: &Path) -> Result<std::path::PathBuf, std::io::Error> {
    let policy_path = test_dir.join("policy.json");
    fs::write(
        &policy_path,
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
              "reason": "secret file reads are denied"
            }
          ]
        }
        "#,
    )?;
    Ok(policy_path)
}

fn session_audit_path(test_dir: &Path, session_id: &str) -> std::path::PathBuf {
    test_dir
        .join(".erebor/sessions")
        .join(session_id)
        .join("audit.jsonl")
}
