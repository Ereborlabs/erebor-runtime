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
    mediation: Option<SurfaceMediationDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceMediationDecision {
    kind: String,
    replacement_surface: String,
    endpoint: String,
    lease_id: String,
    print_line: String,
    keepalive: bool,
}

impl SurfaceMediationDecision {
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        replacement_surface: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            replacement_surface: replacement_surface.into(),
            endpoint: endpoint.into(),
            lease_id: String::new(),
            print_line: String::new(),
            keepalive: false,
        }
    }

    #[must_use]
    pub fn from_parts(
        kind: impl Into<String>,
        replacement_surface: impl Into<String>,
        endpoint: impl Into<String>,
        lease_id: impl Into<String>,
        print_line: impl Into<String>,
        keepalive: bool,
    ) -> Self {
        Self {
            kind: kind.into(),
            replacement_surface: replacement_surface.into(),
            endpoint: endpoint.into(),
            lease_id: lease_id.into(),
            print_line: print_line.into(),
            keepalive,
        }
    }

    #[must_use]
    pub fn with_lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = lease_id.into();
        self
    }

    #[must_use]
    pub fn with_print_line(mut self, print_line: impl Into<String>) -> Self {
        self.print_line = print_line.into();
        self
    }

    #[must_use]
    pub const fn with_keepalive(mut self, keepalive: bool) -> Self {
        self.keepalive = keepalive;
        self
    }

    #[must_use]
    pub fn into_parts(self) -> (String, String, String, String, String, bool) {
        (
            self.kind,
            self.replacement_surface,
            self.endpoint,
            self.lease_id,
            self.print_line,
            self.keepalive,
        )
    }
}

impl SurfaceInterceptionDecision {
    #[must_use]
    pub fn allow(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: SessionInterceptionDecision::Allow,
            rule_id: rule_id.into(),
            reason: reason.into(),
            mediation: None,
        }
    }

    #[must_use]
    pub fn deny(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: SessionInterceptionDecision::Deny,
            rule_id: rule_id.into(),
            reason: reason.into(),
            mediation: None,
        }
    }

    #[must_use]
    pub fn require_approval(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: SessionInterceptionDecision::RequireApproval,
            rule_id: rule_id.into(),
            reason: reason.into(),
            mediation: None,
        }
    }

    #[must_use]
    pub fn mediate(
        rule_id: impl Into<String>,
        reason: impl Into<String>,
        mediation: SurfaceMediationDecision,
    ) -> Self {
        Self {
            decision: SessionInterceptionDecision::Mediate,
            rule_id: rule_id.into(),
            reason: reason.into(),
            mediation: Some(mediation),
        }
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        SessionInterceptionDecision,
        String,
        String,
        Option<SurfaceMediationDecision>,
    ) {
        (self.decision, self.rule_id, self.reason, self.mediation)
    }
}
