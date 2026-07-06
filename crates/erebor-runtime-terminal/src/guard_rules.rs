use crate::env::guard_env_field;

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

impl TryFrom<&str> for TerminalProcessGuardDecision {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "require_approval" | "require_verification" => Ok(Self::RequireApproval),
            _ => Err(()),
        }
    }
}
