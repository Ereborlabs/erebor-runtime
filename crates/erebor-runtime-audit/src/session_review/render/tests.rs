use std::fs;

use erebor_runtime_events::ActionKind;
use erebor_runtime_policy::Decision;

use crate::session_review::{
    test_support::{browser_record, process_record, temp_file},
    SessionReviewArtifacts, SessionReviewOutputFormat, SessionReviewRenderer,
    SessionSummaryBuilder,
};

#[test]
fn renderers_include_decision_context_and_hashes() -> Result<(), Box<dyn std::error::Error>> {
    let policy = temp_file("policy.json", r#"{"rules":[]}"#)?;
    let config = temp_file(
        "config.json",
        &format!(
            r#"{{
                "policies": ["{}"],
                "session": {{
                    "enabled": true,
                    "runner": {{ "kind": "linux_host" }}
                }},
                "surfaces": {{
                    "terminal": {{ "enabled": true }}
                }}
            }}"#,
            policy.display()
        ),
    )?;
    let artifacts =
        SessionReviewArtifacts::from_paths(Some(String::from("linux-host")), &policy, &config)?;
    let records = vec![process_record(
        "session-1",
        "deny-process",
        "sh --remote-debugging-port=9222",
        Decision::Deny {
            reason: String::from("raw CDP process launch is denied"),
            rule_id: Some(String::from("deny-raw-cdp")),
        },
        "2026-06-21T18:00:01Z",
    )];
    let audit = temp_file(
        "audit.jsonl",
        &format!("{}\n", serde_json::to_string(&records[0])?),
    )?;

    let renderer = SessionReviewRenderer::new(&records, &artifacts);
    let list = SessionSummaryBuilder::new(&records, &artifacts).build_all()?;
    let show = renderer.render_show("session-1")?;
    let describe = renderer.render_describe("session-1")?;
    let review = renderer.review("session-1")?;
    let path_json = SessionReviewRenderer::render_show_from_paths(
        &audit,
        &policy,
        &config,
        "session-1",
        SessionReviewOutputFormat::Json,
    )?;

    assert_eq!(list[0].session_id, "session-1");
    assert!(show.contains("deny-raw-cdp"));
    assert!(show.contains("Policy sha256:"));
    assert!(describe.contains("Denied Event"));
    assert!(describe.contains("linux_ptrace_process_guard"));
    assert!(describe.contains("exec_denied_before_child_gained_authority"));
    assert!(describe.contains("Raw payload sha256:"));
    assert_eq!(review.summary.session_id, "session-1");
    assert_eq!(review.important_decisions.len(), 1);
    assert_eq!(
        review.important_decisions[0].controlled_path_backend,
        "linux_ptrace_process_guard"
    );
    assert_eq!(review.timeline.len(), 1);
    assert!(review.policy_sha256.is_some());
    assert!(review.config_sha256.is_some());
    assert!(path_json.contains(r#""controlled_path_backend": "linux_ptrace_process_guard""#));

    let _result = fs::remove_file(policy);
    let _result = fs::remove_file(config);
    let _result = fs::remove_file(audit);
    Ok(())
}

#[test]
fn show_redacts_sensitive_query_values() -> Result<(), Box<dyn std::error::Error>> {
    let records = vec![browser_record(
        "session-1",
        "deny-callback",
        ActionKind::NetworkRequest,
        "http://127.0.0.1:5105/oauth/callback?code=secret&state=secret",
        Decision::Deny {
            reason: String::from("callback denied"),
            rule_id: Some(String::from("deny-oauth-callback-network-request")),
        },
        "2026-06-21T18:00:01Z",
    )];

    let artifacts = SessionReviewArtifacts::default();
    let show = SessionReviewRenderer::new(&records, &artifacts).render_show("session-1")?;

    assert!(show.contains("code=redacted"));
    assert!(show.contains("state=redacted"));
    assert!(!show.contains("code=secret"));
    Ok(())
}
