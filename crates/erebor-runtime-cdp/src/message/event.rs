use erebor_runtime_core::{ApprovalProvider, AuditRecord, AuditSink, LocalEnforcementEngine};
use erebor_runtime_policy::PolicyEvaluator;
use snafu::ResultExt;

use super::{
    decision::EnforcementDecisionMapper, CdpEnforcementAction, CdpEnforcementOutcome,
    CdpEventObserver, CdpSessionContext,
};
use crate::{error::EnforcementSnafu, CdpError, CdpEvent};

pub struct CdpEventEnforcer;

impl CdpEventEnforcer {
    pub fn enforce<E, A, S>(
        engine: &LocalEnforcementEngine<E, A, S>,
        context: &CdpSessionContext,
        event: &CdpEvent,
    ) -> Result<CdpEnforcementAction, CdpError>
    where
        E: PolicyEvaluator,
        A: ApprovalProvider,
        S: AuditSink,
    {
        Ok(Self::outcome(engine, context, event)?.action().clone())
    }

    pub fn outcome<E, A, S>(
        engine: &LocalEnforcementEngine<E, A, S>,
        context: &CdpSessionContext,
        event: &CdpEvent,
    ) -> Result<CdpEnforcementOutcome, CdpError>
    where
        E: PolicyEvaluator,
        A: ApprovalProvider,
        S: AuditSink,
    {
        let runtime_event = CdpEventObserver::observe(context, event)?;
        let outcome = engine
            .enforce_with_deferred_approval(&runtime_event)
            .context(EnforcementSnafu)?;

        let action =
            EnforcementDecisionMapper::action(&outcome.policy_decision, &outcome.final_decision);
        let audit_record = AuditRecord::from_outcome(&outcome);
        Ok(CdpEnforcementOutcome::recorded(action, audit_record))
    }
}
