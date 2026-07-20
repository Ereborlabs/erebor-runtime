use erebor_runtime_audit::read_audit_records;
use erebor_runtime_core::RuntimeAuditConfig;
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_ipc::v1::DecisionKind;
use erebor_runtime_policy::Decision;

use super::{
    super::{ProcessExecAuditRecorder, SessionInterceptionRouter},
    fixtures::{
        BrokerFixture, InterceptionRequestFixture, MatchedHandlerProcessExecHandler,
        TempDirectoryFixture, TestProcessExecDecisionHandler, TestProcessExecHandler,
        TestProcessExecMediationHandler,
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
fn broker_audits_mediated_process_exec_with_the_handler_and_endpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("audits-process-exec-mediate");
    let directory = TempDirectoryFixture::new("audits-process-exec-mediate")?;
    let audit_path = directory.path().join("audit.jsonl");
    let audit = ProcessExecAuditRecorder::new(
        &audit_path,
        SessionId::new(fixture.session_id()),
        ActorIdentity {
            id: String::from("openclaw"),
            kind: ActorKind::Agent,
        },
        RuntimeAuditConfig::default(),
    );
    let router = SessionInterceptionRouter::new()
        .with_process_exec_handler(TestProcessExecMediationHandler)
        .with_process_exec_audit(audit);
    let broker = fixture.register(router)?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process_with_argv(
            "managed-browser-cdp",
            &[
                String::from("google-chrome"),
                String::from("--remote-debugging-port=9222"),
            ],
        ),
    )?;

    assert_eq!(decision.decision, DecisionKind::Mediate as i32);
    let records = read_audit_records(&audit_path)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event.payload["kind"], "process_interception");
    assert_eq!(
        records[0].event.payload["handler_id"],
        "managed-browser-cdp"
    );
    let Decision::Mediate {
        rule_id, mediation, ..
    } = &records[0].policy_decision
    else {
        return Err("expected a mediated process-exec audit decision".into());
    };
    assert_eq!(
        rule_id.as_deref(),
        Some("erebor-process-interception-managed-browser-cdp")
    );
    assert_eq!(
        mediation
            .as_ref()
            .and_then(|value| value["endpoint"].as_str()),
        Some("ws://127.0.0.1:9222/")
    );
    Ok(())
}

#[test]
fn broker_audits_approval_required_process_exec_as_fail_closed_denial(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("audits-process-exec-approval");
    let directory = TempDirectoryFixture::new("audits-process-exec-approval")?;
    let audit_path = directory.path().join("audit.jsonl");
    let audit = ProcessExecAuditRecorder::new(
        &audit_path,
        SessionId::new(fixture.session_id()),
        ActorIdentity {
            id: String::from("openclaw"),
            kind: ActorKind::Agent,
        },
        RuntimeAuditConfig::default(),
    );
    let router = SessionInterceptionRouter::new()
        .with_process_exec_handler(TestProcessExecDecisionHandler)
        .with_process_exec_audit(audit);
    let broker = fixture.register(router)?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process_with_argv(
            "approve-tool",
            &[String::from("git"), String::from("push")],
        ),
    )?;

    assert_eq!(decision.decision, DecisionKind::RequireApproval as i32);
    let records = read_audit_records(&audit_path)?;
    assert_eq!(records.len(), 1);
    assert!(matches!(
        &records[0].policy_decision,
        Decision::RequireApproval { rule_id, .. } if rule_id.as_deref() == Some("approve-tool")
    ));
    assert!(matches!(
        &records[0].final_decision,
        Decision::Deny { rule_id, .. } if rule_id.as_deref() == Some("approve-tool")
    ));
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
