use std::collections::HashSet;

use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel, RuntimeEvent};
use serde::Deserialize;

use crate::{Decision, PolicyError};

pub trait PolicyEvaluator {
    fn evaluate(&self, event: &RuntimeEvent) -> Result<Decision, PolicyError>;
}

#[derive(Clone, Debug, Default)]
pub struct AllowAllPolicy;

impl PolicyEvaluator for AllowAllPolicy {
    fn evaluate(&self, _event: &RuntimeEvent) -> Result<Decision, PolicyError> {
        Ok(Decision::Allow { rule_id: None })
    }
}

#[derive(Clone, Debug, Default)]
pub struct PolicySet {
    policies: Vec<LocalPolicy>,
}

impl PolicySet {
    #[must_use]
    pub fn from_policies(policies: Vec<LocalPolicy>) -> Self {
        Self { policies }
    }

    #[must_use]
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

impl PolicyEvaluator for PolicySet {
    fn evaluate(&self, event: &RuntimeEvent) -> Result<Decision, PolicyError> {
        for policy in &self.policies {
            let decision = policy.evaluate(event)?;
            if decision.rule_id().is_some() {
                return Ok(decision);
            }
        }

        Ok(Decision::Allow { rule_id: None })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPolicy {
    rules: Vec<PolicyRule>,
}

impl LocalPolicy {
    pub fn from_json_str(source: &str) -> Result<Self, PolicyError> {
        if source.trim().is_empty() {
            return Err(PolicyError::empty_policy());
        }

        let document: PolicyDocument =
            serde_json::from_str(source).map_err(PolicyError::invalid_policy_syntax)?;

        Self::from_document(document)
    }

    fn from_document(document: PolicyDocument) -> Result<Self, PolicyError> {
        let mut seen = HashSet::new();

        for rule in &document.rules {
            if rule.id.trim().is_empty() {
                return Err(PolicyError::invalid_rule(
                    rule.id.clone(),
                    "rule id cannot be empty",
                ));
            }

            if !seen.insert(rule.id.clone()) {
                return Err(PolicyError::duplicate_rule(rule.id.clone()));
            }

            if rule.matcher.is_empty() {
                return Err(PolicyError::invalid_rule(
                    rule.id.clone(),
                    "rule must declare at least one match criterion",
                ));
            }
        }

        Ok(Self {
            rules: document.rules,
        })
    }
}

impl PolicyEvaluator for LocalPolicy {
    fn evaluate(&self, event: &RuntimeEvent) -> Result<Decision, PolicyError> {
        let decision = self
            .rules
            .iter()
            .find(|rule| rule.matcher.matches(event))
            .map_or(Decision::Allow { rule_id: None }, PolicyRule::to_decision);

        Ok(decision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct PolicyDocument {
    rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct PolicyRule {
    id: String,
    #[serde(rename = "match")]
    matcher: EventMatcher,
    decision: RuleDecision,
    reason: Option<String>,
}

impl PolicyRule {
    fn to_decision(&self) -> Decision {
        let reason = self
            .reason
            .clone()
            .unwrap_or_else(|| format!("matched policy rule `{}`", self.id));
        let rule_id = Some(self.id.clone());

        match self.decision {
            RuleDecision::Allow => Decision::Allow { rule_id },
            RuleDecision::Deny => Decision::Deny { reason, rule_id },
            RuleDecision::RequireApproval => Decision::RequireApproval {
                reason,
                rule_id,
                approval_id: None,
            },
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
struct EventMatcher {
    surface: Option<ExecutionSurface>,
    action: Option<ActionKind>,
    target_contains: Option<String>,
    payload_contains: Option<String>,
    command_contains: Option<String>,
    risk_at_least: Option<RiskLevel>,
}

impl EventMatcher {
    fn is_empty(&self) -> bool {
        self.surface.is_none()
            && self.action.is_none()
            && self.target_contains.is_none()
            && self.payload_contains.is_none()
            && self.command_contains.is_none()
            && self.risk_at_least.is_none()
    }

    fn matches(&self, event: &RuntimeEvent) -> bool {
        self.surface
            .as_ref()
            .is_none_or(|surface| surface == &event.surface)
            && self
                .action
                .as_ref()
                .is_none_or(|action| action == &event.action)
            && self
                .target_contains
                .as_ref()
                .is_none_or(|needle| target_contains(event, needle))
            && self
                .payload_contains
                .as_ref()
                .is_none_or(|needle| payload_contains(event, needle))
            && self
                .command_contains
                .as_ref()
                .is_none_or(|needle| command_contains(event, needle))
            && self
                .risk_at_least
                .as_ref()
                .is_none_or(|minimum| event.risk.level.is_at_least(minimum))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RuleDecision {
    Allow,
    Deny,
    #[serde(alias = "require_verification")]
    RequireApproval,
}

fn target_contains(event: &RuntimeEvent, needle: &str) -> bool {
    event.target.as_ref().is_some_and(|target| {
        target
            .label
            .as_ref()
            .is_some_and(|label| label.contains(needle))
            || target.uri.as_ref().is_some_and(|uri| uri.contains(needle))
    })
}

fn payload_contains(event: &RuntimeEvent, needle: &str) -> bool {
    event.payload.to_string().contains(needle)
}

fn command_contains(event: &RuntimeEvent, needle: &str) -> bool {
    event
        .payload
        .get("command")
        .is_some_and(|command| value_contains(command, needle))
        || event
            .payload
            .get("argv_summary")
            .is_some_and(|summary| value_contains(summary, needle))
}

fn value_contains(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::String(text) => text.contains(needle),
        serde_json::Value::Array(values) => {
            values.iter().any(|value| value_contains(value, needle))
        }
        _ => value.to_string().contains(needle),
    }
}
