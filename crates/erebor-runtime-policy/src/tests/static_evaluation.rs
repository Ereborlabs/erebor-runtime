use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

use crate::{
    Decision, LayerEvaluation, LayeredDecision, LayeredPolicySet, LocalPolicy, PolicyError,
    PolicyLayer, PolicyLayerEvaluator,
};

use super::fixtures::PolicyEventFixture;

fn terminal_event(risk: RiskLevel) -> erebor_runtime_events::RuntimeEvent {
    PolicyEventFixture::event(ExecutionSurface::Terminal, ActionKind::ProcessExec, risk)
}

#[test]
fn static_evaluation_returns_exact_allow_and_deny_decisions() -> Result<(), PolicyError> {
    let allow = LocalPolicy::from_json_str(
        r#"{"rules":[{"id":"allow-low","match":{"surface":"terminal","action":"process_exec"},"decision":"allow"}]}"#,
    )?;
    let deny = LocalPolicy::from_json_str(
        r#"{"rules":[{"id":"deny-high","match":{"surface":"terminal","action":"process_exec","risk_at_least":"high"},"decision":"deny","reason":"high-risk execution"}]}"#,
    )?;

    assert_eq!(
        allow.evaluate_static_layer(&terminal_event(RiskLevel::Low))?,
        LayerEvaluation::Decision(Decision::Allow {
            rule_id: Some(String::from("allow-low")),
        })
    );
    assert_eq!(
        deny.evaluate_static_layer(&terminal_event(RiskLevel::High))?,
        LayerEvaluation::Decision(Decision::Deny {
            reason: String::from("high-risk execution"),
            rule_id: Some(String::from("deny-high")),
        })
    );
    Ok(())
}

#[test]
fn static_evaluation_rejects_dynamic_matchers() -> Result<(), PolicyError> {
    for field in ["target_contains", "payload_contains", "command_contains"] {
        let source = format!(
            r#"{{"rules":[{{"id":"dynamic","match":{{"surface":"terminal","action":"process_exec","{field}":"needle"}},"decision":"deny"}}]}}"#
        );
        let policy = LocalPolicy::from_json_str(&source)?;

        assert!(matches!(
            policy.evaluate_static_layer(&terminal_event(RiskLevel::Low)),
            Err(PolicyError::StaticEvaluationUnsupported { rule_id, reason, .. })
                if rule_id == "dynamic" && reason.contains(field)
        ));
    }
    Ok(())
}

#[test]
fn wildcard_dynamic_rule_is_potentially_applicable() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"{"rules":[{"id":"wildcard","match":{"target_contains":"secret"},"decision":"deny"}]}"#,
    )?;

    assert!(matches!(
        policy.evaluate_static_layer(&terminal_event(RiskLevel::Low)),
        Err(PolicyError::StaticEvaluationUnsupported { rule_id, .. }) if rule_id == "wildcard"
    ));
    Ok(())
}

#[test]
fn dynamic_rule_for_another_operation_is_irrelevant() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"{"rules":[
            {"id":"browser-target","match":{"surface":"browser_cdp","action":"browser_click","target_contains":"Delete"},"decision":"deny"},
            {"id":"terminal-allow","match":{"surface":"terminal","action":"process_exec"},"decision":"allow"}
        ]}"#,
    )?;

    assert_eq!(
        policy.evaluate_static_layer(&terminal_event(RiskLevel::Low))?,
        LayerEvaluation::Decision(Decision::Allow {
            rule_id: Some(String::from("terminal-allow")),
        })
    );
    Ok(())
}

#[test]
fn earlier_static_match_keeps_first_match_semantics() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"{"rules":[
            {"id":"terminal-allow","match":{"surface":"terminal","action":"process_exec"},"decision":"allow"},
            {"id":"unreachable-target","match":{"surface":"terminal","target_contains":"secret"},"decision":"deny"}
        ]}"#,
    )?;

    assert_eq!(
        policy.evaluate_static_layer(&terminal_event(RiskLevel::Low))?,
        LayerEvaluation::Decision(Decision::Allow {
            rule_id: Some(String::from("terminal-allow")),
        })
    );
    Ok(())
}

#[test]
fn layered_static_evaluation_keeps_mandatory_ordering() -> Result<(), PolicyError> {
    let policies = LayeredPolicySet::new(vec![
        PolicyLayer::mandatory(
            "root",
            LocalPolicy::from_json_str(
                r#"{"rules":[{"id":"root-allow","match":{"surface":"terminal","action":"process_exec"},"decision":"allow"}]}"#,
            )?,
        ),
        PolicyLayer::mandatory(
            "package",
            LocalPolicy::from_json_str(
                r#"{"rules":[{"id":"package-deny","match":{"surface":"terminal","action":"process_exec"},"decision":"deny","reason":"package minimum"}]}"#,
            )?,
        ),
    ]);

    assert_eq!(
        policies.evaluate_static(&terminal_event(RiskLevel::Low))?,
        LayeredDecision::Deny {
            reason: String::from("package minimum"),
            rule_id: Some(String::from("package-deny")),
        }
    );
    Ok(())
}
