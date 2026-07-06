use std::{fmt, fs, path::Path};

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SurfaceInterceptionDecision,
    TerminalSurfaceConfig,
};
use erebor_runtime_policy::LocalPolicy;
use snafu::{OptionExt, ResultExt};

use crate::{
    error,
    guard_rules::{
        TerminalProcessGuardDecision, TerminalProcessGuardRule, TerminalProcessGuardRules,
    },
    mediation::{TerminalProcessMediationCapability, TerminalProcessMediationPolicy},
    TerminalSurfaceResult,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProcessPolicy {
    rules: TerminalProcessGuardRules,
}

impl TerminalProcessPolicy {
    pub fn from_config(config: &TerminalSurfaceConfig) -> TerminalSurfaceResult<Self> {
        Ok(Self {
            rules: TerminalProcessGuardRuleCompiler::new(config).compile()?,
        })
    }

    #[must_use]
    pub fn rules(&self) -> &TerminalProcessGuardRules {
        &self.rules
    }

    #[must_use]
    pub fn decide_process_exec(
        &self,
        executable: &str,
        argv: &[String],
    ) -> Option<TerminalProcessPolicyDecision> {
        let text = TerminalProcessCommand::new(executable, argv).to_string();
        self.rules
            .rules()
            .iter()
            .find(|rule| text.contains(rule.match_token()))
            .map(|rule| {
                TerminalProcessPolicyDecision::new(rule.rule_id(), rule.reason(), rule.decision())
            })
    }
}

pub struct TerminalProcessExecValidator {
    policy: TerminalProcessPolicy,
    mediation: TerminalProcessMediationPolicy,
}

impl TerminalProcessExecValidator {
    pub fn from_config(config: &TerminalSurfaceConfig) -> TerminalSurfaceResult<Self> {
        Ok(Self {
            policy: TerminalProcessPolicy::from_config(config)?,
            mediation: TerminalProcessMediationPolicy::from_config(config),
        })
    }

    pub fn set_process_mediation_capability(
        &mut self,
        capability: impl TerminalProcessMediationCapability + 'static,
    ) {
        self.mediation.set_capability(capability);
    }
}

impl ProcessExecSurfaceHandler for TerminalProcessExecValidator {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        if !request.matched_handler_id().is_empty() {
            return self.mediation.decide_process_exec(request);
        }

        self.policy
            .decide_process_exec(request.executable(), request.argv())
            .map(Into::into)
            .unwrap_or_else(|| {
                SurfaceInterceptionDecision::allow(
                    "terminal-process-exec-default-allow",
                    "process execution allowed by terminal policy",
                )
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProcessPolicyDecision {
    rule_id: String,
    reason: String,
    decision: TerminalProcessGuardDecision,
}

impl From<TerminalProcessPolicyDecision> for SurfaceInterceptionDecision {
    fn from(decision: TerminalProcessPolicyDecision) -> Self {
        match decision.decision() {
            TerminalProcessGuardDecision::Allow => {
                Self::allow(decision.rule_id(), decision.reason())
            }
            TerminalProcessGuardDecision::Deny => Self::deny(decision.rule_id(), decision.reason()),
            TerminalProcessGuardDecision::RequireApproval => {
                Self::require_approval(decision.rule_id(), decision.reason())
            }
        }
    }
}

impl TerminalProcessPolicyDecision {
    #[must_use]
    pub fn new(
        rule_id: impl Into<String>,
        reason: impl Into<String>,
        decision: TerminalProcessGuardDecision,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            reason: reason.into(),
            decision,
        }
    }

    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub const fn decision(&self) -> TerminalProcessGuardDecision {
        self.decision
    }
}

struct TerminalProcessGuardRuleCompiler<'a> {
    config: &'a TerminalSurfaceConfig,
}

impl<'a> TerminalProcessGuardRuleCompiler<'a> {
    const fn new(config: &'a TerminalSurfaceConfig) -> Self {
        Self { config }
    }

    fn compile(&self) -> TerminalSurfaceResult<TerminalProcessGuardRules> {
        let mut rules = Vec::new();

        for path in self.config.policies() {
            let document = TerminalPolicyDocument::read(path)?;
            for rule in document.rules()? {
                if let Ok(rule) = TerminalPolicyRule::try_from(rule) {
                    rules.push(rule.into());
                }
            }
        }

        Ok(TerminalProcessGuardRules::new(rules))
    }
}

struct TerminalPolicyDocument {
    value: serde_json::Value,
}

impl TerminalPolicyDocument {
    fn read(path: &Path) -> TerminalSurfaceResult<Self> {
        let source = fs::read_to_string(path).context(error::ReadPolicySnafu {
            path: path.to_path_buf(),
        })?;
        let _policy = LocalPolicy::from_json_str(&source).context(error::InvalidPolicySnafu)?;
        let value = serde_json::from_str(&source).context(error::PolicyJsonSnafu)?;

        Ok(Self { value })
    }

    fn rules(&self) -> TerminalSurfaceResult<&[serde_json::Value]> {
        self.value
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .context(error::InvalidGuardConfigSnafu {
                reason: String::from("policy JSON must contain rules array"),
            })
    }
}

struct TerminalPolicyRule<'a> {
    match_token: &'a str,
    reason: &'a str,
    rule_id: &'a str,
    decision: TerminalProcessGuardDecision,
}

impl<'a> TryFrom<&'a serde_json::Value> for TerminalPolicyRule<'a> {
    type Error = ();

    fn try_from(rule: &'a serde_json::Value) -> Result<Self, Self::Error> {
        if !TerminalPolicyRuleMatcher::matches_terminal_process_exec(rule) {
            return Err(());
        }

        let match_token = rule
            .get("match")
            .and_then(|matcher| {
                matcher
                    .get("command_contains")
                    .or_else(|| matcher.get("payload_contains"))
            })
            .and_then(serde_json::Value::as_str)
            .ok_or(())?;
        let rule_id = rule
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("erebor-terminal-process-deny");
        let reason = rule
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("process execution denied by Erebor policy");
        let decision = rule
            .get("decision")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .try_into()?;

        Ok(Self {
            match_token,
            reason,
            rule_id,
            decision,
        })
    }
}

impl From<TerminalPolicyRule<'_>> for TerminalProcessGuardRule {
    fn from(rule: TerminalPolicyRule<'_>) -> Self {
        Self::new(rule.match_token, rule.reason, rule.rule_id, rule.decision)
    }
}

struct TerminalPolicyRuleMatcher;

impl TerminalPolicyRuleMatcher {
    fn matches_terminal_process_exec(rule: &serde_json::Value) -> bool {
        let matcher = rule.get("match");
        matcher
            .and_then(|matcher| matcher.get("surface"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|surface| surface == "terminal")
            && matcher
                .and_then(|matcher| matcher.get("action"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|action| action == "process_exec")
    }
}

struct TerminalProcessCommand<'a> {
    executable: &'a str,
    argv: &'a [String],
}

impl<'a> TerminalProcessCommand<'a> {
    fn new(executable: &'a str, argv: &'a [String]) -> Self {
        Self { executable, argv }
    }
}

impl fmt::Display for TerminalProcessCommand<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.executable)?;
        for argument in self.argv {
            formatter.write_str(" ")?;
            formatter.write_str(argument)?;
        }

        Ok(())
    }
}
