use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

use crate::{Decision, LocalPolicy, PolicyError, PolicyEvaluator};

use super::fixtures::PolicyEventFixture;

#[test]
fn require_verification_alias_maps_to_approval_decision() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "verify-git-push",
                "match": {
                  "surface": "terminal",
                  "action": "process_exec",
                  "command_contains": "git push"
                },
              "decision": "require_verification",
              "reason": "git push needs operator verification"
            }
          ]
        }
        "#,
    )?;

    let decision = policy.evaluate(&PolicyEventFixture::event_with_payload(
        ExecutionSurface::Terminal,
        ActionKind::ProcessExec,
        RiskLevel::High,
        serde_json::json!({ "command": "git push origin main" }),
    ))?;

    assert_eq!(decision.rule_id(), Some("verify-git-push"));

    Ok(())
}

#[test]
fn mediate_decision_preserves_mediation_metadata() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "mediate-managed-browser-launch",
              "match": {
                "surface": "terminal",
                "action": "process_exec",
                "command_contains": "--remote-debugging-port"
              },
              "decision": "mediate",
              "mediation": {
                "kind": "managed_browser_cdp",
                "return_endpoint": "requested_port"
              },
              "reason": "convert raw browser CDP launches to Erebor-owned governed CDP"
            }
          ]
        }
        "#,
    )?;

    let decision = policy.evaluate(&PolicyEventFixture::event_with_payload(
        ExecutionSurface::Terminal,
        ActionKind::ProcessExec,
        RiskLevel::High,
        serde_json::json!({ "command": "google-chrome --remote-debugging-port=9222" }),
    ))?;

    assert_eq!(
        decision,
        Decision::Mediate {
            reason: String::from("convert raw browser CDP launches to Erebor-owned governed CDP"),
            rule_id: Some(String::from("mediate-managed-browser-launch")),
            mediation: Some(serde_json::json!({
                "kind": "managed_browser_cdp",
                "return_endpoint": "requested_port"
            })),
        }
    );

    Ok(())
}
