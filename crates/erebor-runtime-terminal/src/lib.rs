use std::{
    fs, io,
    path::{Path, PathBuf},
};

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, SurfaceInterceptionDecision,
    TerminalSurfaceConfig,
};
use erebor_runtime_policy::{LocalPolicy, PolicyError};
use thiserror::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalProcessGuardRules {
    rules: Vec<TerminalProcessGuardRule>,
}

impl TerminalProcessGuardRules {
    #[must_use]
    pub fn new(rules: Vec<TerminalProcessGuardRule>) -> Self {
        Self { rules }
    }

    #[must_use]
    pub fn rules(&self) -> &[TerminalProcessGuardRule] {
        &self.rules
    }

    pub fn prepend(&mut self, mut rules: Vec<TerminalProcessGuardRule>) {
        rules.append(&mut self.rules);
        self.rules = rules;
    }

    #[must_use]
    pub fn to_env_value(&self) -> String {
        self.rules
            .iter()
            .map(|rule| {
                format!(
                    "{}\t{}\t{}\t{}",
                    guard_env_field(rule.match_token()),
                    guard_env_field(rule.reason()),
                    guard_env_field(rule.rule_id()),
                    guard_env_field(rule.decision().as_guard_env())
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[must_use]
    pub fn to_docker_env_value(&self) -> String {
        self.to_env_value()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProcessPolicy {
    rules: TerminalProcessGuardRules,
}

impl TerminalProcessPolicy {
    pub fn from_config(config: &TerminalSurfaceConfig) -> Result<Self, TerminalSurfaceError> {
        Ok(Self {
            rules: compile_terminal_process_guard_rules(config)?,
        })
    }

    #[must_use]
    pub fn decide_process_exec(
        &self,
        executable: &str,
        argv: &[String],
    ) -> Option<TerminalProcessPolicyDecision> {
        let text = terminal_process_command_text(executable, argv);
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
}

impl TerminalProcessExecValidator {
    pub fn from_config(config: &TerminalSurfaceConfig) -> Result<Self, TerminalSurfaceError> {
        Ok(Self {
            policy: TerminalProcessPolicy::from_config(config)?,
        })
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
        self.policy
            .decide_process_exec(request.executable(), request.argv())
            .map_or_else(default_allow_process_exec, surface_decision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProcessPolicyDecision {
    rule_id: String,
    reason: String,
    decision: TerminalProcessGuardDecision,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProcessGuardRule {
    match_token: String,
    reason: String,
    rule_id: String,
    decision: TerminalProcessGuardDecision,
}

impl TerminalProcessGuardRule {
    #[must_use]
    pub fn new(
        match_token: impl Into<String>,
        reason: impl Into<String>,
        rule_id: impl Into<String>,
        decision: TerminalProcessGuardDecision,
    ) -> Self {
        Self {
            match_token: match_token.into(),
            reason: reason.into(),
            rule_id: rule_id.into(),
            decision,
        }
    }

    #[must_use]
    pub fn match_token(&self) -> &str {
        &self.match_token
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    #[must_use]
    pub const fn decision(&self) -> TerminalProcessGuardDecision {
        self.decision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalProcessGuardDecision {
    Allow,
    Deny,
    RequireApproval,
}

fn surface_decision(decision: TerminalProcessPolicyDecision) -> SurfaceInterceptionDecision {
    match decision.decision() {
        TerminalProcessGuardDecision::Allow => {
            SurfaceInterceptionDecision::allow(decision.rule_id(), decision.reason())
        }
        TerminalProcessGuardDecision::Deny => {
            SurfaceInterceptionDecision::deny(decision.rule_id(), decision.reason())
        }
        TerminalProcessGuardDecision::RequireApproval => {
            SurfaceInterceptionDecision::require_approval(decision.rule_id(), decision.reason())
        }
    }
}

fn default_allow_process_exec() -> SurfaceInterceptionDecision {
    SurfaceInterceptionDecision::allow(
        "terminal-process-exec-default-allow",
        "process execution allowed by terminal policy",
    )
}

impl TerminalProcessGuardDecision {
    #[must_use]
    pub const fn as_guard_env(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
        }
    }
}

pub fn compile_terminal_process_guard_rules(
    config: &TerminalSurfaceConfig,
) -> Result<TerminalProcessGuardRules, TerminalSurfaceError> {
    let mut rules = Vec::new();

    for path in config.policies() {
        let source = read_policy_source(path)?;
        let _policy =
            LocalPolicy::from_json_str(&source).map_err(TerminalSurfaceError::invalid_policy)?;
        let document: serde_json::Value =
            serde_json::from_str(&source).map_err(TerminalSurfaceError::policy_json)?;
        let policy_rules = document
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                TerminalSurfaceError::invalid_guard_config("policy JSON must contain rules array")
            })?;

        for rule in policy_rules {
            let Some(decision) = terminal_process_guard_decision(rule) else {
                continue;
            };

            let Some(match_token) = rule
                .get("match")
                .and_then(|matcher| {
                    matcher
                        .get("command_contains")
                        .or_else(|| matcher.get("payload_contains"))
                })
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };

            let rule_id = rule
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("erebor-terminal-process-deny");
            let reason = rule
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("process execution denied by Erebor policy");

            rules.push(TerminalProcessGuardRule::new(
                match_token,
                reason,
                rule_id,
                decision,
            ));
        }
    }

    Ok(TerminalProcessGuardRules::new(rules))
}

#[derive(Debug, Error)]
pub enum TerminalSurfaceError {
    #[error("failed to read terminal policy `{}`: {source}", path.display())]
    ReadPolicy { path: PathBuf, source: io::Error },
    #[error("{source}")]
    InvalidPolicy { source: PolicyError },
    #[error("failed to parse terminal policy JSON: {source}")]
    PolicyJson { source: serde_json::Error },
    #[error("terminal process guard config is invalid: {reason}")]
    InvalidGuardConfig { reason: String },
}

impl TerminalSurfaceError {
    fn invalid_policy(source: PolicyError) -> Self {
        Self::InvalidPolicy { source }
    }

    fn policy_json(source: serde_json::Error) -> Self {
        Self::PolicyJson { source }
    }

    fn invalid_guard_config(reason: impl Into<String>) -> Self {
        Self::InvalidGuardConfig {
            reason: reason.into(),
        }
    }
}

fn read_policy_source(path: &Path) -> Result<String, TerminalSurfaceError> {
    fs::read_to_string(path).map_err(|error| TerminalSurfaceError::ReadPolicy {
        path: path.to_path_buf(),
        source: error,
    })
}

fn terminal_process_command_text(executable: &str, argv: &[String]) -> String {
    let mut text = String::new();
    text.push_str(executable);
    for argument in argv {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(argument);
    }
    text
}

fn terminal_process_guard_decision(
    rule: &serde_json::Value,
) -> Option<TerminalProcessGuardDecision> {
    let matcher = rule.get("match");
    let terminal_process_exec = matcher
        .and_then(|matcher| matcher.get("surface"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|surface| surface == "terminal")
        && matcher
            .and_then(|matcher| matcher.get("action"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|action| action == "process_exec");

    if !terminal_process_exec {
        return None;
    }

    match rule
        .get("decision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
    {
        "allow" => Some(TerminalProcessGuardDecision::Allow),
        "deny" => Some(TerminalProcessGuardDecision::Deny),
        "require_approval" | "require_verification" => {
            Some(TerminalProcessGuardDecision::RequireApproval)
        }
        _ => None,
    }
}

fn guard_env_field(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use erebor_runtime_core::{
        ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, RuntimeConfig,
        SessionInterceptionDecision,
    };

    use super::{
        compile_terminal_process_guard_rules, TerminalProcessExecValidator,
        TerminalProcessGuardDecision, TerminalProcessGuardRule, TerminalProcessGuardRules,
        TerminalProcessPolicy,
    };

    #[test]
    fn guard_rules_serialize_for_docker_environment() {
        let rules = TerminalProcessGuardRules::new(vec![
            TerminalProcessGuardRule::new(
                "/tmp/erebor/shims/google-chrome",
                "managed shim launch",
                "allow-mediated-browser",
                TerminalProcessGuardDecision::Allow,
            ),
            TerminalProcessGuardRule::new(
                "remote-debugging-port",
                "raw CDP\nis denied",
                "deny\tcdp",
                TerminalProcessGuardDecision::Deny,
            ),
        ]);

        assert_eq!(
            rules.to_docker_env_value(),
            "/tmp/erebor/shims/google-chrome\tmanaged shim launch\tallow-mediated-browser\tallow\nremote-debugging-port\traw CDP is denied\tdeny cdp\tdeny"
        );
    }

    #[test]
    fn terminal_policy_compiles_deny_rules_for_process_guard(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy_path = std::env::temp_dir().join(format!(
            "erebor-terminal-policy-{}.json",
            std::process::id()
        ));
        fs::write(
            &policy_path,
            r#"
            {
              "rules": [
                {
                  "id": "deny-raw-cdp",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "remote-debugging-port"
                  },
                  "decision": "deny",
                  "reason": "raw CDP is denied"
                },
                {
                  "id": "approve-git-push",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "git push"
                  },
                  "decision": "require_approval",
                  "reason": "git push needs operator verification"
                },
                {
                  "id": "allow-ls",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "payload_contains": "ls -la"
                  },
                  "decision": "allow"
                }
              ]
            }
            "#,
        )?;

        let runtime = RuntimeConfig::from_json_str(&format!(
            r#"{{
              "policies": ["{}"],
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
            policy_path.display()
        ))?;
        let start_plan = runtime.surface_start_plan()?;
        let terminal = start_plan
            .terminal()
            .ok_or_else(|| io::Error::other("expected terminal surface config"))?;
        let rules = compile_terminal_process_guard_rules(terminal)?;

        assert_eq!(rules.rules().len(), 3);
        assert_eq!(rules.rules()[0].match_token(), "remote-debugging-port");
        assert_eq!(rules.rules()[0].reason(), "raw CDP is denied");
        assert_eq!(rules.rules()[0].rule_id(), "deny-raw-cdp");
        assert_eq!(
            rules.rules()[0].decision(),
            TerminalProcessGuardDecision::Deny
        );
        assert_eq!(rules.rules()[1].match_token(), "git push");
        assert_eq!(
            rules.rules()[1].reason(),
            "git push needs operator verification"
        );
        assert_eq!(rules.rules()[1].rule_id(), "approve-git-push");
        assert_eq!(
            rules.rules()[1].decision(),
            TerminalProcessGuardDecision::RequireApproval
        );
        assert_eq!(rules.rules()[2].match_token(), "ls -la");
        assert_eq!(
            rules.rules()[2].decision(),
            TerminalProcessGuardDecision::Allow
        );

        let policy = TerminalProcessPolicy::from_config(terminal)?;
        let decision = policy
            .decide_process_exec(
                "google-chrome",
                &[String::from("--remote-debugging-port=9222")],
            )
            .ok_or_else(|| io::Error::other("expected terminal process decision"))?;
        assert_eq!(decision.rule_id(), "deny-raw-cdp");
        assert_eq!(decision.reason(), "raw CDP is denied");
        assert_eq!(decision.decision(), TerminalProcessGuardDecision::Deny);

        let validator = TerminalProcessExecValidator::from_config(terminal)?;
        let argv = vec![String::from("--remote-debugging-port=9222")];
        let request = ProcessExecInterceptionRequest::new("google-chrome", &argv, "");
        let (decision, rule_id, reason, mediation) =
            validator.decide_process_exec(&request).into_parts();
        assert_eq!(decision, SessionInterceptionDecision::Deny);
        assert_eq!(rule_id, "deny-raw-cdp");
        assert_eq!(reason, "raw CDP is denied");
        assert_eq!(mediation, None);

        fs::remove_file(policy_path)?;
        Ok(())
    }

    #[test]
    fn guard_rules_can_prepend_generated_allow_rules() {
        let mut rules = TerminalProcessGuardRules::new(vec![TerminalProcessGuardRule::new(
            "remote-debugging-port",
            "raw CDP is denied",
            "deny-raw-cdp",
            TerminalProcessGuardDecision::Deny,
        )]);

        rules.prepend(vec![TerminalProcessGuardRule::new(
            "/tmp/erebor/shims/google-chrome",
            "managed browser launch shim",
            "allow-managed-browser-cdp-shim",
            TerminalProcessGuardDecision::Allow,
        )]);

        assert_eq!(rules.rules().len(), 2);
        assert_eq!(
            rules.rules()[0].decision(),
            TerminalProcessGuardDecision::Allow
        );
        assert_eq!(
            rules.rules()[1].decision(),
            TerminalProcessGuardDecision::Deny
        );
    }
}
