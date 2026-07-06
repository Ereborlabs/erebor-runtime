use erebor_runtime_ipc::v1::DecisionKind;

use super::{
    super::SessionInterceptionRouter,
    fixtures::{
        BrokerFixture, InterceptionRequestFixture, MatchedHandlerProcessExecHandler,
        TestProcessExecDecisionHandler, TestProcessExecHandler, TestProcessExecMediationHandler,
    },
};

#[test]
fn broker_returns_interception_decisions_after_guard_hello(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("decisions");
    let router =
        SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecDecisionHandler);
    let broker = fixture.register(router)?;

    let allow =
        fixture.request_decision(&broker, InterceptionRequestFixture::process("allow-tool"))?;
    let deny =
        fixture.request_decision(&broker, InterceptionRequestFixture::process("deny-tool"))?;
    let approval =
        fixture.request_decision(&broker, InterceptionRequestFixture::process("approve-tool"))?;
    let mediate =
        fixture.request_decision(&broker, InterceptionRequestFixture::process("mediate-tool"))?;

    assert_eq!(allow.decision, DecisionKind::Allow as i32);
    assert_eq!(deny.decision, DecisionKind::Deny as i32);
    assert_eq!(approval.decision, DecisionKind::RequireApproval as i32);
    assert_eq!(mediate.decision, DecisionKind::Mediate as i32);
    assert_eq!(
        mediate
            .mediate
            .as_ref()
            .map(|decision| decision.replacement_surface.as_str()),
        Some("browser_cdp")
    );
    Ok(())
}

#[test]
fn broker_routes_process_exec_requests_without_handler_id() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = BrokerFixture::new("routes-process-exec");
    let router = SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecHandler);
    let broker = fixture.register(router)?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process_with_argv("", &[String::from("danger-tool")]),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "test-process-exec-deny");
    assert_eq!(decision.reason, "dangerous process execution");
    Ok(())
}

#[test]
fn broker_routes_process_exec_mediation_from_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("routes-process-exec-mediate");
    let router =
        SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecMediationHandler);
    let broker = fixture.register(router)?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process_with_argv("", &[String::from("google-chrome")]),
    )?;

    let mediation = decision
        .mediate
        .as_ref()
        .ok_or_else(|| std::io::Error::other("expected process-exec mediation decision"))?;
    assert_eq!(decision.decision, DecisionKind::Mediate as i32);
    assert_eq!(decision.rule_id, "test-process-exec-mediate");
    assert_eq!(
        decision.reason,
        "process execution mediated by surface handler"
    );
    assert_eq!(mediation.kind, "managed_browser_cdp");
    assert_eq!(mediation.replacement_surface, "browser_cdp");
    assert_eq!(mediation.endpoint, "ws://127.0.0.1:9222/");
    assert_eq!(mediation.lease_id, "surface-lease");
    assert_eq!(
        mediation.print_line,
        "DevTools listening on ws://127.0.0.1:9222/devtools/browser/surface"
    );
    assert!(mediation.keepalive);
    Ok(())
}

#[test]
fn broker_routes_process_exec_requests_with_handler_id_to_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("routes-matched-process-exec");
    let router = SessionInterceptionRouter::new()
        .with_process_exec_handler(MatchedHandlerProcessExecHandler);
    let broker = fixture.register(router)?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process_with_argv(
            "managed-browser-cdp",
            &[String::from("google-chrome")],
        ),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "matched-handler-id-visible");
    assert_eq!(decision.reason, "managed-browser-cdp");
    assert_eq!(decision.mediate, None);
    Ok(())
}

#[test]
fn broker_fails_closed_for_unrouted_process_exec() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("unrouted-process-exec");
    let broker = fixture.register(SessionInterceptionRouter::new())?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process("missing-handler"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-unrouted-process-exec"
    );
    Ok(())
}
