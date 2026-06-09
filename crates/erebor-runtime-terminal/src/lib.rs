use std::{
    fs, io,
    path::{Path, PathBuf},
};

use erebor_runtime_core::TerminalSurfaceConfig;
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

    #[must_use]
    pub fn to_docker_env_value(&self) -> String {
        self.rules
            .iter()
            .map(|rule| {
                format!(
                    "{}\t{}\t{}",
                    guard_env_field(rule.match_token()),
                    guard_env_field(rule.reason()),
                    guard_env_field(rule.rule_id())
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalProcessGuardRule {
    match_token: String,
    reason: String,
    rule_id: String,
}

impl TerminalProcessGuardRule {
    #[must_use]
    pub fn new(
        match_token: impl Into<String>,
        reason: impl Into<String>,
        rule_id: impl Into<String>,
    ) -> Self {
        Self {
            match_token: match_token.into(),
            reason: reason.into(),
            rule_id: rule_id.into(),
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
            if !terminal_process_deny_rule(rule) {
                continue;
            }

            let Some(match_token) = rule
                .get("match")
                .and_then(|matcher| matcher.get("payload_contains"))
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

            rules.push(TerminalProcessGuardRule::new(match_token, reason, rule_id));
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

fn terminal_process_deny_rule(rule: &serde_json::Value) -> bool {
    let matcher = rule.get("match");
    rule.get("decision")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|decision| decision == "deny")
        && matcher
            .and_then(|matcher| matcher.get("surface"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|surface| surface == "terminal")
        && matcher
            .and_then(|matcher| matcher.get("action"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|action| action == "process_exec")
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

    use erebor_runtime_core::RuntimeConfig;

    use super::{
        compile_terminal_process_guard_rules, TerminalProcessGuardRule, TerminalProcessGuardRules,
    };

    #[test]
    fn guard_rules_serialize_for_docker_environment() {
        let rules = TerminalProcessGuardRules::new(vec![TerminalProcessGuardRule::new(
            "remote-debugging-port",
            "raw CDP\nis denied",
            "deny\tcdp",
        )]);

        assert_eq!(
            rules.to_docker_env_value(),
            "remote-debugging-port\traw CDP is denied\tdeny cdp"
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
                    "payload_contains": "remote-debugging-port"
                  },
                  "decision": "deny",
                  "reason": "raw CDP is denied"
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
                "terminal": {{ "enabled": true }}
              }}
            }}"#,
            policy_path.display()
        ))?;
        let start_plan = runtime.surface_start_plan()?;
        let terminal = start_plan
            .terminal()
            .ok_or_else(|| io::Error::other("expected terminal surface config"))?;
        let rules = compile_terminal_process_guard_rules(terminal)?;

        assert_eq!(rules.rules().len(), 1);
        assert_eq!(rules.rules()[0].match_token(), "remote-debugging-port");
        assert_eq!(rules.rules()[0].reason(), "raw CDP is denied");
        assert_eq!(rules.rules()[0].rule_id(), "deny-raw-cdp");

        fs::remove_file(policy_path)?;
        Ok(())
    }
}
