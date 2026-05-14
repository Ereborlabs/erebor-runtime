use erebor_runtime_events::{
    ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
    RuntimeEvent, SessionId, TargetRef,
};

use crate::{Decision, LocalPolicy, PolicyError, PolicyEvaluator, PolicySet};

fn event(surface: ExecutionSurface, action: ActionKind, risk: RiskLevel) -> RuntimeEvent {
    RuntimeEvent {
        id: EventId::new("evt-1"),
        session_id: SessionId::new("session-1"),
        actor: ActorIdentity {
            id: String::from("agent-1"),
            kind: ActorKind::Agent,
        },
        surface,
        action,
        target: Some(TargetRef {
            label: Some(String::from("Delete")),
            uri: Some(String::from("https://mail.example/message/1")),
        }),
        payload: serde_json::json!({}),
        risk: RiskMetadata {
            level: risk,
            reasons: Vec::new(),
        },
        timestamp: String::from("2026-05-13T00:00:00Z"),
    }
}

fn event_with_payload(
    surface: ExecutionSurface,
    action: ActionKind,
    risk: RiskLevel,
    payload: serde_json::Value,
) -> RuntimeEvent {
    RuntimeEvent {
        payload,
        ..event(surface, action, risk)
    }
}

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

    let decision = policy.evaluate(&event(
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

    let decision = policy.evaluate(&event(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserNavigate,
        RiskLevel::Low,
    ))?;

    assert_eq!(decision, Decision::Allow { rule_id: None });

    Ok(())
}

#[test]
fn policy_set_uses_first_matching_policy_across_files() -> Result<(), PolicyError> {
    let first = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "allow-nav",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_navigate"
              },
              "decision": "allow"
            }
          ]
        }
        "#,
    )?;
    let second = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "deny-nav",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_navigate"
              },
              "decision": "deny",
              "reason": "deny later"
            }
          ]
        }
        "#,
    )?;
    let policies = PolicySet::from_policies(vec![first, second]);

    let decision = policies.evaluate(&event(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserNavigate,
        RiskLevel::Low,
    ))?;

    assert_eq!(
        decision,
        Decision::Allow {
            rule_id: Some(String::from("allow-nav"))
        }
    );
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

    let decision = policy.evaluate(&event(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserClick,
        RiskLevel::Medium,
    ))?;

    assert_eq!(decision.rule_id(), Some("approve-delete-clicks"));

    Ok(())
}

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
    let decision = policy.evaluate(&event_with_payload(
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

#[test]
fn duplicate_rules_are_rejected() {
    let error = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "duplicate",
              "match": { "surface": "terminal" },
              "decision": "deny"
            },
            {
              "id": "duplicate",
              "match": { "surface": "mcp" },
              "decision": "deny"
            }
          ]
        }
        "#,
    );

    assert!(matches!(
        error,
        Err(PolicyError::DuplicateRule { rule_id, .. }) if rule_id == "duplicate"
    ));
}
