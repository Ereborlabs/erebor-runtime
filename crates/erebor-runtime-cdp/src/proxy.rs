use erebor_runtime_core::{ApprovalProvider, AuditSink, LocalEnforcementEngine};
use erebor_runtime_policy::PolicyEvaluator;
use serde_json::Value;

use crate::{CdpCommand, CdpCommandEnforcer, CdpEnforcementAction, CdpError, CdpSessionContext};

#[derive(Clone, Debug, PartialEq)]
pub struct CdpBackendResponse {
    pub payload: Value,
}

pub trait CdpBackend {
    fn forward(&self, command: &CdpCommand) -> Result<CdpBackendResponse, CdpError>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum CdpProxyAction {
    Forwarded { response: CdpBackendResponse },
    Block { reason: String },
    AwaitApproval { reason: String },
}

pub struct CdpMessageProxy;

impl CdpMessageProxy {
    pub fn proxy<E, A, S, B>(
        engine: &LocalEnforcementEngine<E, A, S>,
        context: &CdpSessionContext,
        backend: &B,
        command: &CdpCommand,
    ) -> Result<CdpProxyAction, CdpError>
    where
        E: PolicyEvaluator,
        A: ApprovalProvider,
        S: AuditSink,
        B: CdpBackend,
    {
        match CdpCommandEnforcer::enforce(engine, context, command)? {
            CdpEnforcementAction::Forward => {
                let response = backend.forward(command)?;
                Ok(CdpProxyAction::Forwarded { response })
            }
            CdpEnforcementAction::Block { reason } => Ok(CdpProxyAction::Block { reason }),
            CdpEnforcementAction::AwaitApproval { reason } => {
                Ok(CdpProxyAction::AwaitApproval { reason })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use erebor_runtime_core::{ApprovalProvider, ApprovalRequest, ApprovalResponse};
    use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
    use erebor_runtime_policy::LocalPolicy;
    use serde_json::json;

    use super::{
        CdpBackend, CdpBackendResponse, CdpCommand, CdpMessageProxy, CdpProxyAction,
        CdpSessionContext,
    };
    use crate::CdpCommandDecoder;

    fn context() -> CdpSessionContext {
        CdpSessionContext {
            session_id: SessionId::new("session-1"),
            actor: ActorIdentity {
                id: String::from("agent-1"),
                kind: ActorKind::Agent,
            },
            timestamp: String::from("2026-05-13T00:00:00Z"),
        }
    }

    #[test]
    fn forwards_only_after_enforcement_allows() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
        let backend = RecordingBackend::default();
        let command = CdpCommandDecoder::decode(r#"{ "id": 1, "method": "Browser.getVersion" }"#)?;

        let action = CdpMessageProxy::proxy(&engine, &context(), &backend, &command)?;

        assert_eq!(backend.forwarded.get(), 1);
        assert_eq!(
            action,
            CdpProxyAction::Forwarded {
                response: CdpBackendResponse {
                    payload: json!({ "forwarded_method": "Browser.getVersion" })
                }
            }
        );
        Ok(())
    }

    #[test]
    fn does_not_forward_denied_messages() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "deny",
                  "reason": "script evaluation denied"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
        let backend = RecordingBackend::default();
        let command = CdpCommandDecoder::decode(
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = CdpMessageProxy::proxy(&engine, &context(), &backend, &command)?;

        assert_eq!(backend.forwarded.get(), 0);
        assert_eq!(
            action,
            CdpProxyAction::Block {
                reason: String::from("script evaluation denied")
            }
        );
        Ok(())
    }

    #[test]
    fn does_not_forward_approval_required_messages() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "approve-script-eval",
                  "match": {
                    "surface": "browser_cdp",
                    "action": "browser_script_eval"
                  },
                  "decision": "require_approval",
                  "reason": "script evaluation requires approval"
                }
              ]
            }
            "#,
        )?;
        let engine = erebor_runtime_core::LocalEnforcementEngine::with_hooks(
            policy,
            ApproveAll,
            erebor_runtime_core::NoopAuditSink,
        );
        let backend = RecordingBackend::default();
        let command = CdpCommandDecoder::decode(
            r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
        )?;

        let action = CdpMessageProxy::proxy(&engine, &context(), &backend, &command)?;

        assert_eq!(backend.forwarded.get(), 0);
        assert_eq!(
            action,
            CdpProxyAction::AwaitApproval {
                reason: String::from("script evaluation requires approval")
            }
        );
        Ok(())
    }

    #[derive(Clone, Debug)]
    struct ApproveAll;

    impl ApprovalProvider for ApproveAll {
        fn request_approval(
            &self,
            _request: &ApprovalRequest,
        ) -> Result<ApprovalResponse, erebor_runtime_core::ApprovalError> {
            Ok(ApprovalResponse::Approved)
        }
    }

    #[derive(Debug, Default)]
    struct RecordingBackend {
        forwarded: Cell<usize>,
    }

    impl CdpBackend for RecordingBackend {
        fn forward(&self, command: &CdpCommand) -> Result<CdpBackendResponse, crate::CdpError> {
            self.forwarded.set(self.forwarded.get() + 1);

            Ok(CdpBackendResponse {
                payload: json!({ "forwarded_method": command.method }),
            })
        }
    }
}
