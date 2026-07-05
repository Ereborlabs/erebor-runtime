use std::{cell::RefCell, rc::Rc};

use erebor_runtime_core::{ApprovalProvider, ApprovalRequest, ApprovalResponse};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};

use crate::CdpSessionContext;

pub(super) fn context() -> CdpSessionContext {
    CdpSessionContext {
        session_id: SessionId::new("session-1"),
        actor: ActorIdentity {
            id: String::from("agent-1"),
            kind: ActorKind::Agent,
        },
        timestamp: String::from("2026-05-13T00:00:00Z"),
    }
}

#[derive(Clone, Debug)]
pub(super) struct ApproveAll;

impl ApprovalProvider for ApproveAll {
    fn request_approval(
        &self,
        _request: &ApprovalRequest,
    ) -> Result<ApprovalResponse, erebor_runtime_core::ApprovalError> {
        Ok(ApprovalResponse::Approved)
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct RecordingAuditSink {
    records: Rc<RefCell<Vec<erebor_runtime_core::AuditRecord>>>,
}

impl RecordingAuditSink {
    pub(super) fn records(&self) -> Vec<erebor_runtime_core::AuditRecord> {
        self.records.borrow().clone()
    }
}

impl erebor_runtime_core::AuditSink for RecordingAuditSink {
    fn record(
        &self,
        record: &erebor_runtime_core::AuditRecord,
    ) -> Result<(), erebor_runtime_core::AuditError> {
        self.records.borrow_mut().push(record.clone());
        Ok(())
    }
}
