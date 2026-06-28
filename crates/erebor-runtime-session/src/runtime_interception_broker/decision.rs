use erebor_runtime_core::{SessionInterceptionDecision, SurfaceInterceptionDecision};
use erebor_runtime_ipc::v1::{
    AllowDecision, DecisionKind, DenyDecision, InterceptionDecision, MediateDecision,
};

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
    let (decision, rule_id, reason, mediation) = decision.into_parts();
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
        SessionInterceptionDecision::Mediate => {
            let Some(mediation) = mediation else {
                return deny_decision(
                    request_id,
                    rule_id,
                    "surface route returned mediate decision without mediation details",
                );
            };
            let (kind, replacement_surface, endpoint, lease_id, print_line, keepalive) =
                mediation.into_parts();
            InterceptionDecision {
                request_id,
                decision: DecisionKind::Mediate as i32,
                rule_id,
                reason,
                timeout_ms: DEFAULT_TIMEOUT_MS as u32,
                allow: None,
                deny: None,
                mediate: Some(MediateDecision {
                    kind,
                    replacement_surface,
                    endpoint,
                    lease_id,
                    print_line,
                    keepalive,
                }),
            }
        }
    }
}
