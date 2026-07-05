use erebor_runtime_policy::Decision;

use super::CdpEnforcementAction;

pub(super) struct EnforcementDecisionMapper;

impl EnforcementDecisionMapper {
    pub(super) fn action(
        policy_decision: &Decision,
        final_decision: &Decision,
    ) -> CdpEnforcementAction {
        match policy_decision {
            Decision::RequireApproval { reason, .. } => CdpEnforcementAction::AwaitApproval {
                reason: reason.clone(),
            },
            _ => match final_decision {
                Decision::Allow { .. } => CdpEnforcementAction::Forward,
                Decision::Deny { reason, .. } => CdpEnforcementAction::Block {
                    reason: reason.clone(),
                },
                Decision::RequireApproval { reason, .. } => CdpEnforcementAction::AwaitApproval {
                    reason: reason.clone(),
                },
                Decision::Mediate { reason, .. } => CdpEnforcementAction::Block {
                    reason: reason.clone(),
                },
            },
        }
    }
}
