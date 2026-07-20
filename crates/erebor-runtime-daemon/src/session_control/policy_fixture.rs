use erebor_runtime_core::{
    ImmutableIdentity, ProcessExecInterceptionRequest, ProcessExecSurfaceHandler,
    SurfaceInterceptionDecision,
};

/// Temporary Phase 2 decision owner for operator-admitted immutable policy fixtures.
///
/// Admission and start both require the root daemon configuration to recognize
/// the pinned identity. Phase 3 replaces this owner with the resolved policy
/// store; arbitrary client-supplied policy digests never reach this handler.
pub(super) struct PhaseTwoProcessExecPolicy {
    identity: ImmutableIdentity,
}

impl PhaseTwoProcessExecPolicy {
    const DENIED_ARGUMENT: &'static str = "erebor-phase-two-denied";

    pub(super) const fn new(identity: ImmutableIdentity) -> Self {
        Self { identity }
    }
}

impl ProcessExecSurfaceHandler for PhaseTwoProcessExecPolicy {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        if request
            .argv()
            .iter()
            .any(|argument| argument == Self::DENIED_ARGUMENT)
        {
            return SurfaceInterceptionDecision::deny(
                "phase-two-policy-fixture-denied-argument",
                "process execution denied by the pinned operator-admitted Phase 2 policy fixture",
            );
        }
        SurfaceInterceptionDecision::allow(
            format!("phase-two-policy-fixture-{}", self.identity.sha256()),
            "process execution allowed by the pinned operator-admitted Phase 2 policy fixture",
        )
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_core::{
        ImmutableIdentity, ProcessExecInterceptionRequest, ProcessExecSurfaceHandler,
        SessionInterceptionDecision,
    };

    use super::PhaseTwoProcessExecPolicy;

    fn policy() -> Result<PhaseTwoProcessExecPolicy, Box<dyn std::error::Error>> {
        Ok(PhaseTwoProcessExecPolicy::new(ImmutableIdentity::new(
            "policy-set",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )?))
    }

    #[test]
    fn operator_admitted_fixture_allows_normal_exec_and_denies_its_explicit_rule(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = policy()?;
        let allowed_argv = vec![String::from("/usr/bin/id")];
        let denied_argv = vec![
            String::from("/usr/bin/dash"),
            String::from("erebor-phase-two-denied"),
        ];

        let (allowed, _, _, _) = policy
            .decide_process_exec(&ProcessExecInterceptionRequest::new(
                "/usr/bin/id",
                &allowed_argv,
                "",
            ))
            .into_parts();
        let (denied, rule_id, _, _) = policy
            .decide_process_exec(&ProcessExecInterceptionRequest::new(
                "/usr/bin/dash",
                &denied_argv,
                "",
            ))
            .into_parts();

        assert_eq!(allowed, SessionInterceptionDecision::Allow);
        assert_eq!(denied, SessionInterceptionDecision::Deny);
        assert_eq!(rule_id, "phase-two-policy-fixture-denied-argument");
        Ok(())
    }
}
