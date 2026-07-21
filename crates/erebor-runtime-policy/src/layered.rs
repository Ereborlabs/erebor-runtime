use crate::{
    error::{IncompatibleMediationSnafu, MissingMandatoryCoverageSnafu},
    Decision, Result,
};
use erebor_runtime_events::RuntimeEvent;

/// The result of evaluating one immutable policy layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LayerEvaluation {
    NotApplicable,
    Decision(Decision),
}

/// An evaluator that can distinguish a deliberate allow from no matching rule.
pub trait PolicyLayerEvaluator {
    fn evaluate_layer(&self, event: &RuntimeEvent) -> Result<LayerEvaluation>;
}

/// One named immutable policy revision in a composed policy set.
pub struct PolicyLayer {
    name: String,
    mandatory: bool,
    evaluator: Box<dyn PolicyLayerEvaluator + Send + Sync>,
}

impl PolicyLayer {
    #[must_use]
    pub fn mandatory(
        name: impl Into<String>,
        evaluator: impl PolicyLayerEvaluator + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            mandatory: true,
            evaluator: Box::new(evaluator),
        }
    }

    #[must_use]
    pub fn optional(
        name: impl Into<String>,
        evaluator: impl PolicyLayerEvaluator + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            mandatory: false,
            evaluator: Box::new(evaluator),
        }
    }
}

/// A lossless result for the policy-composition seam.
///
/// The existing `Decision` model cannot represent both a mediation requirement
/// and a subsequent approval requirement. Keeping that pair explicit prevents
/// approval resolution from accidentally erasing mediation before a runtime
/// guard has consumed the composed constraints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LayeredDecision {
    Allow,
    Deny {
        reason: String,
        rule_id: Option<String>,
    },
    RequireApproval {
        reason: String,
        rule_ids: Vec<String>,
        mediation: Option<serde_json::Value>,
    },
    Mediate {
        reason: String,
        rule_ids: Vec<String>,
        mediation: Option<serde_json::Value>,
    },
}

/// Evaluates every configured policy layer without allowing an allow in one
/// revision to short-circuit the host or package minimums.
pub struct LayeredPolicySet {
    layers: Vec<PolicyLayer>,
}

impl LayeredPolicySet {
    #[must_use]
    pub fn new(layers: Vec<PolicyLayer>) -> Self {
        Self { layers }
    }

    pub fn evaluate(&self, event: &RuntimeEvent) -> Result<LayeredDecision> {
        let mut approvals = Vec::new();
        let mut mediation: Option<(String, serde_json::Value)> = None;
        let mut mediation_rule_ids = Vec::new();

        for layer in &self.layers {
            match layer.evaluator.evaluate_layer(event)? {
                LayerEvaluation::NotApplicable if layer.mandatory => {
                    return MissingMandatoryCoverageSnafu {
                        layer: layer.name.clone(),
                    }
                    .fail()
                }
                LayerEvaluation::NotApplicable => {}
                LayerEvaluation::Decision(Decision::Deny { reason, rule_id }) => {
                    return Ok(LayeredDecision::Deny { reason, rule_id })
                }
                LayerEvaluation::Decision(Decision::RequireApproval {
                    reason, rule_id, ..
                }) => approvals.push((layer.name.clone(), reason, rule_id)),
                LayerEvaluation::Decision(Decision::Mediate {
                    reason: _,
                    rule_id,
                    mediation: value,
                }) => {
                    let value = value.unwrap_or(serde_json::Value::Null);
                    if let Some((first_layer, first_value)) = &mediation {
                        if first_value != &value {
                            return IncompatibleMediationSnafu {
                                first_layer: first_layer.clone(),
                                second_layer: layer.name.clone(),
                            }
                            .fail();
                        }
                    } else {
                        mediation = Some((layer.name.clone(), value));
                    }
                    if let Some(rule_id) = rule_id {
                        mediation_rule_ids.push(rule_id);
                    }
                }
                LayerEvaluation::Decision(Decision::Allow { .. }) => {}
            }
        }

        let mediation = mediation.map(|(_, value)| value);
        if !approvals.is_empty() {
            let reasons = approvals
                .iter()
                .map(|(_, reason, _)| reason.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            let rule_ids = approvals
                .into_iter()
                .filter_map(|(_, _, rule_id)| rule_id)
                .collect();
            return Ok(LayeredDecision::RequireApproval {
                reason: reasons,
                rule_ids,
                mediation,
            });
        }
        if mediation.is_some() {
            return Ok(LayeredDecision::Mediate {
                reason: String::from("one or more policy layers require mediation"),
                rule_ids: mediation_rule_ids,
                mediation,
            });
        }
        Ok(LayeredDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

    use crate::{LocalPolicy, PolicyError};

    use super::{LayeredDecision, LayeredPolicySet, PolicyLayer};
    use crate::tests::fixtures::PolicyEventFixture;

    fn policy(source: &str) -> Result<LocalPolicy, PolicyError> {
        LocalPolicy::from_json_str(source)
    }

    #[test]
    fn allow_never_short_circuits_a_later_mandatory_deny() -> Result<(), PolicyError> {
        let policies = LayeredPolicySet::new(vec![
            PolicyLayer::mandatory(
                "root",
                policy(
                    r#"{"rules":[{"id":"root-allow","match":{"surface":"terminal"},"decision":"allow"}]}"#,
                )?,
            ),
            PolicyLayer::mandatory(
                "package",
                policy(
                    r#"{"rules":[{"id":"package-deny","match":{"surface":"terminal"},"decision":"deny","reason":"package minimum"}]}"#,
                )?,
            ),
        ]);

        assert_eq!(
            policies.evaluate(&PolicyEventFixture::event(
                ExecutionSurface::Terminal,
                ActionKind::ProcessExec,
                RiskLevel::Low,
            ))?,
            LayeredDecision::Deny {
                reason: String::from("package minimum"),
                rule_id: Some(String::from("package-deny")),
            }
        );
        Ok(())
    }

    #[test]
    fn mandatory_layers_require_explicit_coverage() -> Result<(), PolicyError> {
        let policies = LayeredPolicySet::new(vec![PolicyLayer::mandatory(
            "root",
            policy(
                r#"{"rules":[{"id":"other","match":{"surface":"browser_cdp"},"decision":"allow"}]}"#,
            )?,
        )]);

        assert!(matches!(
            policies.evaluate(&PolicyEventFixture::event(
                ExecutionSurface::Terminal,
                ActionKind::ProcessExec,
                RiskLevel::Low,
            )),
            Err(PolicyError::MissingMandatoryCoverage { .. })
        ));
        Ok(())
    }

    #[test]
    fn approval_preserves_an_already_composed_mediation_requirement() -> Result<(), PolicyError> {
        let policies = LayeredPolicySet::new(vec![
            PolicyLayer::mandatory(
                "root",
                policy(
                    r#"{"rules":[{"id":"mediate","match":{"surface":"terminal"},"decision":"mediate","mediation":{"kind":"managed"}}]}"#,
                )?,
            ),
            PolicyLayer::mandatory(
                "user",
                policy(
                    r#"{"rules":[{"id":"approve","match":{"surface":"terminal"},"decision":"require_approval","reason":"operator review"}]}"#,
                )?,
            ),
        ]);

        let decision = policies.evaluate(&PolicyEventFixture::event(
            ExecutionSurface::Terminal,
            ActionKind::ProcessExec,
            RiskLevel::Low,
        ))?;
        assert!(matches!(
            decision,
            LayeredDecision::RequireApproval {
                mediation: Some(_),
                ..
            }
        ));
        Ok(())
    }
}
