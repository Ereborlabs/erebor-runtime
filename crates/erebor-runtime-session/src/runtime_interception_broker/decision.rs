use erebor_runtime_core::{SessionInterceptionDecision, SurfaceInterceptionDecision};
use erebor_runtime_ipc::v1::{AllowDecision, DecisionKind, DenyDecision, InterceptionDecision};

use super::constants::DEFAULT_TIMEOUT_MS;

pub(super) fn deny_decision(
    request_id: u64,
    rule_id: impl Into<String>,
    reason: impl Into<String>,
) -> InterceptionDecision {
    InterceptionDecision {
        request_id,
        decision: DecisionKind::Deny as i32,
        rule_id: rule_id.into(),
        reason: reason.into(),
        timeout_ms: DEFAULT_TIMEOUT_MS as u32,
        allow: None,
        deny: Some(DenyDecision { exit_code: 126 }),
        mediate: None,
    }
}

pub(super) fn surface_decision(
    request_id: u64,
    decision: SurfaceInterceptionDecision,
) -> InterceptionDecision {
    let (decision, rule_id, reason) = decision.into_parts();
    match decision {
        SessionInterceptionDecision::Allow => InterceptionDecision {
            request_id,
            decision: DecisionKind::Allow as i32,
            rule_id,
            reason,
            timeout_ms: DEFAULT_TIMEOUT_MS as u32,
            allow: Some(AllowDecision {
                exec_target: String::new(),
            }),
            deny: None,
            mediate: None,
        },
        SessionInterceptionDecision::Deny => deny_decision(request_id, rule_id, reason),
        SessionInterceptionDecision::RequireApproval => InterceptionDecision {
            request_id,
            decision: DecisionKind::RequireApproval as i32,
            rule_id,
            reason,
            timeout_ms: DEFAULT_TIMEOUT_MS as u32,
            allow: None,
            deny: None,
            mediate: None,
        },
        SessionInterceptionDecision::Mediate => deny_decision(
            request_id,
            rule_id,
            "surface route returned unsupported mediate decision for direct interception",
        ),
    }
}
