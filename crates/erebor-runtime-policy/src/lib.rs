//! Policy evaluation contracts for erebor-runtime.

use std::collections::HashSet;

use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel, RuntimeEvent};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Decision {
    Allow {
        rule_id: Option<String>,
    },
    Deny {
        reason: String,
        rule_id: Option<String>,
    },
    RequireApproval {
        reason: String,
        rule_id: Option<String>,
        approval_id: Option<String>,
    },
}

impl Decision {
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::Allow { rule_id }
            | Self::Deny { rule_id, .. }
            | Self::RequireApproval { rule_id, .. } => rule_id.as_deref(),
        }
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPolicy {
    rules: Vec<PolicyRule>,
}

impl LocalPolicy {
    pub fn from_json_str(source: &str) -> Result<Self, PolicyError> {
        if source.trim().is_empty() {
            return Err(PolicyError::EmptyPolicy);
        }

        let document: PolicyDocument =
            serde_json::from_str(source).map_err(|error| PolicyError::InvalidPolicySyntax {
                reason: error.to_string(),
            })?;

        Self::from_document(document)
    }

    fn from_document(document: PolicyDocument) -> Result<Self, PolicyError> {
        let mut seen = HashSet::new();

        for rule in &document.rules {
            if rule.id.trim().is_empty() {
                return Err(PolicyError::InvalidRule {
                    rule_id: rule.id.clone(),
                    reason: String::from("rule id cannot be empty"),
                });
            }

            if !seen.insert(rule.id.clone()) {
                return Err(PolicyError::DuplicateRule {
                    rule_id: rule.id.clone(),
                });
            }

            if rule.matcher.is_empty() {
                return Err(PolicyError::InvalidRule {
                    rule_id: rule.id.clone(),
                    reason: String::from("rule must declare at least one match criterion"),
                });
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
            .map_or(Decision::Allow { rule_id: None }, |rule| rule.to_decision());

        Ok(decision)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    #[error("policy source is empty")]
    EmptyPolicy,
    #[error("policy syntax is invalid: {reason}")]
    InvalidPolicySyntax { reason: String },
    #[error("policy rule `{rule_id}` is invalid: {reason}")]
    InvalidRule { rule_id: String, reason: String },
    #[error("policy rule `{rule_id}` is duplicated")]
    DuplicateRule { rule_id: String },
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
    risk_at_least: Option<RiskLevel>,
}

impl EventMatcher {
    fn is_empty(&self) -> bool {
        self.surface.is_none()
            && self.action.is_none()
            && self.target_contains.is_none()
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

#[cfg(test)]
mod tests {
    use erebor_runtime_events::{
        ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata,
        RuntimeEvent, SessionId, TargetRef,
    };

    use super::{Decision, LocalPolicy, PolicyError, PolicyEvaluator};

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

        assert_eq!(
            error,
            Err(PolicyError::DuplicateRule {
                rule_id: String::from("duplicate")
            })
        );
    }
}
