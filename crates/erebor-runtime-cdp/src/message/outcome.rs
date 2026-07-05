use erebor_runtime_core::AuditRecord;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CdpEnforcementAction {
    Forward,
    Block { reason: String },
    AwaitApproval { reason: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CdpEnforcementOutcome {
    action: CdpEnforcementAction,
    audit_record: Option<AuditRecord>,
}

impl CdpEnforcementOutcome {
    #[must_use]
    pub const fn action(&self) -> &CdpEnforcementAction {
        &self.action
    }

    #[must_use]
    pub const fn audit_record(&self) -> Option<&AuditRecord> {
        self.audit_record.as_ref()
    }

    pub(super) fn unrecorded(action: CdpEnforcementAction) -> Self {
        Self {
            action,
            audit_record: None,
        }
    }

    pub(super) fn recorded(action: CdpEnforcementAction, audit_record: AuditRecord) -> Self {
        Self {
            action,
            audit_record: Some(audit_record),
        }
    }
}
