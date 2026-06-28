#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionInterceptionDecision {
    Allow,
    Deny,
    RequireApproval,
    Mediate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceInterceptionDecision {
    decision: SessionInterceptionDecision,
    rule_id: String,
    reason: String,
}

impl SurfaceInterceptionDecision {
    #[must_use]
    pub fn allow(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: SessionInterceptionDecision::Allow,
            rule_id: rule_id.into(),
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn deny(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: SessionInterceptionDecision::Deny,
            rule_id: rule_id.into(),
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn require_approval(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: SessionInterceptionDecision::RequireApproval,
            rule_id: rule_id.into(),
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn into_parts(self) -> (SessionInterceptionDecision, String, String) {
        (self.decision, self.rule_id, self.reason)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProcessExecInterceptionRequest<'a> {
    executable: &'a str,
    argv: &'a [String],
}

impl<'a> ProcessExecInterceptionRequest<'a> {
    #[must_use]
    pub const fn new(executable: &'a str, argv: &'a [String]) -> Self {
        Self { executable, argv }
    }

    #[must_use]
    pub const fn executable(&self) -> &'a str {
        self.executable
    }

    #[must_use]
    pub const fn argv(&self) -> &'a [String] {
        self.argv
    }
}

pub trait ProcessExecSurfaceHandler: Send + Sync {
    fn surface(&self) -> &str;
    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision;
}
