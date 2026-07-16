#[path = "interception/broker.rs"]
mod broker;
#[path = "interception/executable.rs"]
mod executable;
#[path = "interception/handlers.rs"]
mod handlers;

use std::{
    env, os::unix::process::CommandExt, path::PathBuf, process::Command, thread, time::Duration,
};

use broker::InterceptionBrokerClient;
use executable::RealExecutableResolver;
use handlers::{InterceptionHandler, InterceptionHandlers};

use super::ipc;

pub(super) struct ShimInterception;

impl ShimInterception {
    pub(super) fn try_handle_configured_interception() -> Option<i32> {
        let args = env::args().collect::<Vec<_>>();
        let invoked = args
            .first()
            .and_then(|arg| RealExecutableResolver::executable_name(arg))
            .unwrap_or_else(|| String::from("unknown"));
        let handlers = InterceptionHandlers::from_environment();
        let handler = handlers.matching(&invoked)?;

        Some(Self::handle_interception(handler, &invoked, &args))
    }

    fn handle_interception(handler: &InterceptionHandler, invoked: &str, args: &[String]) -> i32 {
        let client = InterceptionBrokerClient::new(handler, invoked, args);
        match client.request_decision() {
            Ok(decision) => Self::apply_broker_decision(handler, invoked, args, &decision),
            Err(reason) => Self::fail_closed(&reason, handler, invoked, args, None),
        }
    }

    fn apply_broker_decision(
        handler: &InterceptionHandler,
        invoked: &str,
        args: &[String],
        decision: &ipc::InterceptionDecision,
    ) -> i32 {
        match decision.kind {
            ipc::InterceptionDecisionKind::Allow => {
                Self::handle_allow(handler, invoked, args, decision)
            }
            ipc::InterceptionDecisionKind::Deny => Self::fail_closed(
                &decision.reason,
                handler,
                invoked,
                args,
                decision.deny_exit_code,
            ),
            ipc::InterceptionDecisionKind::RequireApproval => Self::fail_closed(
                &format!(
                    "{}; approval leases are not available to this guard yet",
                    decision.reason
                ),
                handler,
                invoked,
                args,
                Some(126),
            ),
            ipc::InterceptionDecisionKind::Mediate => {
                Self::handle_mediation(handler, invoked, args, decision)
            }
            ipc::InterceptionDecisionKind::Unknown => Self::fail_closed(
                "broker returned an unknown process interception decision",
                handler,
                invoked,
                args,
                Some(126),
            ),
        }
    }

    fn handle_allow(
        handler: &InterceptionHandler,
        invoked: &str,
        args: &[String],
        decision: &ipc::InterceptionDecision,
    ) -> i32 {
        let target = decision
            .allow_exec_target
            .as_deref()
            .filter(|target| !target.is_empty())
            .map(PathBuf::from)
            .or_else(|| RealExecutableResolver::from_environment(invoked));
        let Some(target) = target else {
            return Self::fail_closed(
                "broker allowed launch, but no real executable was found after the Erebor shim",
                handler,
                invoked,
                args,
                Some(126),
            );
        };

        let error = Command::new(&target).args(&args[1..]).exec();
        Self::fail_closed(
            &format!("allowed process exec failed: {error}"),
            handler,
            invoked,
            args,
            Some(126),
        )
    }

    fn handle_mediation(
        handler: &InterceptionHandler,
        invoked: &str,
        args: &[String],
        decision: &ipc::InterceptionDecision,
    ) -> i32 {
        let Some(mediation) = decision.mediate.as_ref() else {
            return Self::fail_closed(
                "broker returned a mediate decision without mediation details",
                handler,
                invoked,
                args,
                Some(126),
            );
        };
        if !mediation.print_line.is_empty() {
            eprintln!("{}", mediation.print_line);
        }

        if mediation.keepalive {
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }

        0
    }

    fn fail_closed(
        reason: &str,
        _handler: &InterceptionHandler,
        _invoked: &str,
        _args: &[String],
        exit_code: Option<i32>,
    ) -> i32 {
        eprintln!("erebor linux process guard interception: {reason}");
        exit_code.unwrap_or(126)
    }
}

#[cfg(test)]
mod tests {
    use super::{ipc, InterceptionHandler, ShimInterception};

    #[test]
    fn applies_generic_broker_mediation_without_browser_specific_kind_check() {
        let handler =
            InterceptionHandler::new(String::from("api-mediator"), vec![String::from("tool")]);
        let decision = ipc::InterceptionDecision {
            request_id: 1,
            kind: ipc::InterceptionDecisionKind::Mediate,
            rule_id: String::from("mediate-api"),
            reason: String::from("route launch to mediated surface"),
            allow_exec_target: None,
            deny_exit_code: None,
            mediate: Some(ipc::MediateDecision {
                kind: String::from("future_api"),
                replacement_surface: String::from("api"),
                endpoint: String::from("local://api"),
                lease_id: String::from("lease"),
                print_line: String::new(),
                keepalive: false,
            }),
        };

        let status = ShimInterception::apply_broker_decision(
            &handler,
            "tool",
            &[String::from("tool")],
            &decision,
        );

        assert_eq!(status, 0);
    }
}
