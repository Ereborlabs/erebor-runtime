use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

use crate::{Decision, LocalPolicy, PolicyError, PolicyEvaluator};

use super::fixtures::PolicyEventFixture;

#[test]
fn payload_matcher_can_target_specific_protocol_params() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "deny-specific-script",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_script_eval",
                "payload_contains": "owned-denied"
              },
              "decision": "deny",
              "reason": "script payload denied"
            }
          ]
        }
        "#,
    )?;
    let decision = policy.evaluate(&PolicyEventFixture::event_with_payload(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserScriptEval,
        RiskLevel::High,
        serde_json::json!({
            "kind": "command",
            "method": "Runtime.evaluate",
            "params": {
                "expression": "window.__erebor = 'owned-denied'"
            }
        }),
    ))?;

    assert_eq!(
        decision,
        Decision::Deny {
            reason: String::from("script payload denied"),
            rule_id: Some(String::from("deny-specific-script"))
        }
    );

    Ok(())
}
