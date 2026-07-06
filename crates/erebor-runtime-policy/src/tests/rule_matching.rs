use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

use crate::{Decision, LocalPolicy, PolicyError, PolicyEvaluator};

use super::fixtures::PolicyEventFixture;

#[test]
fn evaluates_first_matching_rule() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "allow-navigation",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_navigate"
              },
              "decision": "allow"
            },
            {
              "id": "approve-script-eval",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_script_eval"
              },
              "decision": "require_approval",
              "reason": "script evaluation requires approval"
            }
          ]
        }
        "#,
    )?;

    let decision = policy.evaluate(&PolicyEventFixture::event(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserScriptEval,
        RiskLevel::High,
    ))?;

    assert_eq!(
        decision,
        Decision::RequireApproval {
            reason: String::from("script evaluation requires approval"),
            rule_id: Some(String::from("approve-script-eval")),
            approval_id: None,
        }
    );

    Ok(())
}

#[test]
fn unmatched_events_allow_by_default() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "deny-terminal-exec",
              "match": {
                "surface": "terminal",
                "action": "process_exec"
              },
              "decision": "deny"
            }
          ]
        }
        "#,
    )?;

    let decision = policy.evaluate(&PolicyEventFixture::event(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserNavigate,
        RiskLevel::Low,
    ))?;

    assert_eq!(decision, Decision::Allow { rule_id: None });

    Ok(())
}

#[test]
fn target_and_risk_matchers_work_together() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "approve-delete-clicks",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_click",
                "target_contains": "Delete",
                "risk_at_least": "medium"
              },
              "decision": "require_approval"
            }
          ]
        }
        "#,
    )?;

    let decision = policy.evaluate(&PolicyEventFixture::event(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserClick,
        RiskLevel::Medium,
    ))?;

    assert_eq!(decision.rule_id(), Some("approve-delete-clicks"));

    Ok(())
}
