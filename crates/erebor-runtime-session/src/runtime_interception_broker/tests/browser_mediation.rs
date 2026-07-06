use erebor_runtime_cdp::CdpSessionContext;
use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler,
    ProcessMediationPrivateEndpointLayerConfig, ProcessMediationPrivatePortStrategy,
    RuntimeAuditConfig, SessionInterceptionDecision,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_ipc::v1::DecisionKind;
use erebor_runtime_policy::PolicySet;
use erebor_runtime_terminal::{TerminalProcessExecValidator, TerminalProcessMediationCapability};

use super::{
    super::SessionInterceptionRouter,
    fixtures::{
        BrokerFixture, InterceptionRequestFixture, TcpPortFixture, TerminalMediationFixture,
    },
};
use crate::surfaces::terminal::browser_cdp_process_mediation::{
    BrowserCdpProcessMediationCapability, PrivateRemoteDebuggingPort,
};

#[test]
fn browser_cdp_process_mediation_capability_owns_endpoint_and_port_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("browser-cdp-mediator");
    let terminal = TerminalMediationFixture::terminal_config()?;
    let mut validator = TerminalProcessExecValidator::from_config(&terminal)?;
    validator.set_process_mediation_capability(BrowserCdpProcessMediationCapability::new(
        "ws://127.0.0.1:9222/",
    ));
    let broker =
        fixture.register(SessionInterceptionRouter::new().with_process_exec_handler(validator))?;

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

    let mediation = decision
        .mediate
        .as_ref()
        .ok_or_else(|| std::io::Error::other("expected browser_cdp mediation decision"))?;
    assert_eq!(decision.decision, DecisionKind::Mediate as i32);
    assert_eq!(mediation.replacement_surface, "browser_cdp");
    assert_eq!(mediation.endpoint, "ws://127.0.0.1:9222/");
    assert_eq!(mediation.lease_id, "managed-browser-cdp-lease");
    assert!(mediation
        .print_line
        .contains("ws://127.0.0.1:9222/devtools/browser/erebor-managed-browser"));
    assert!(mediation.keepalive);

    let denied = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process_with_argv(
            "managed-browser-cdp",
            &[
                String::from("google-chrome"),
                String::from("--remote-debugging-port=9333"),
            ],
        ),
    )?;

    assert_eq!(denied.decision, DecisionKind::Deny as i32);
    assert!(denied
        .reason
        .contains("requested remote debugging port 9333 is not allowed"));
    Ok(())
}

#[test]
fn browser_cdp_lazy_mediation_starts_surface_on_requested_port(
) -> Result<(), Box<dyn std::error::Error>> {
    let requested_port = TcpPortFixture::free_local()?;
    let config = TerminalMediationFixture::runtime_config("127.0.0.1:0")?;
    let browser_cdp = config
        .surface_start_plan()?
        .browser_cdp()
        .ok_or_else(|| std::io::Error::other("missing browser CDP config"))?
        .clone();
    let terminal = config
        .surface_start_plan()?
        .terminal()
        .ok_or_else(|| std::io::Error::other("missing terminal config"))?
        .clone();
    let process_handler = terminal
        .process_interception()
        .handlers()
        .first()
        .ok_or_else(|| std::io::Error::other("missing process mediation handler"))?;
    let handler = BrowserCdpProcessMediationCapability::lazy(
        browser_cdp,
        PolicySet::default(),
        CdpSessionContext {
            session_id: SessionId::new("session-lazy-browser"),
            actor: ActorIdentity {
                id: String::from("openclaw"),
                kind: ActorKind::Agent,
            },
            timestamp: String::from("unix:1"),
        },
        None,
        RuntimeAuditConfig::default(),
    )?;

    let argv = vec![
        String::from("google-chrome"),
        format!("--remote-debugging-port={requested_port}"),
    ];
    let request =
        ProcessExecInterceptionRequest::new("google-chrome", &argv, "managed-browser-cdp");
    let outcome = handler.mediate_process_exec(&request, process_handler)?;
    let (_kind, _surface, endpoint, _lease_id, print_line, _keepalive) = outcome.into_parts();

    assert_eq!(endpoint, format!("ws://127.0.0.1:{requested_port}/"));
    assert!(print_line.contains(&format!(
        "ws://127.0.0.1:{requested_port}/devtools/browser/"
    )));
    Ok(())
}

#[test]
fn terminal_process_surface_fails_closed_for_missing_browser_cdp_capability(
) -> Result<(), Box<dyn std::error::Error>> {
    let terminal = TerminalMediationFixture::terminal_config()?;
    let validator = TerminalProcessExecValidator::from_config(&terminal)?;

    let argv = vec![
        String::from("google-chrome"),
        String::from("--remote-debugging-port=9222"),
    ];
    let request =
        ProcessExecInterceptionRequest::new("google-chrome", &argv, "managed-browser-cdp");
    let (decision, rule_id, reason, mediation) =
        validator.decide_process_exec(&request).into_parts();

    assert_eq!(decision, SessionInterceptionDecision::Deny);
    assert_eq!(rule_id, "managed-browser-cdp");
    assert_eq!(
        reason,
        "browser_cdp process mediation capability is unavailable"
    );
    assert_eq!(mediation, None);
    Ok(())
}

#[test]
fn private_browser_port_can_follow_requested_port_plus_offset() -> Result<(), String> {
    let private_endpoint = ProcessMediationPrivateEndpointLayerConfig {
        port_strategy: ProcessMediationPrivatePortStrategy::RequestedPlusOffset,
        port_offset: 1,
    }
    .into();

    let private_port = PrivateRemoteDebuggingPort::new(&private_endpoint);
    assert_eq!(private_port.for_requested_port(1000)?, Some(1001));
    let overflow = private_port.for_requested_port(u16::MAX);
    let Err(error) = overflow else {
        return Err(String::from("overflow should fail closed"));
    };
    assert!(error.contains("exceeds u16"));

    Ok(())
}

#[test]
fn terminal_process_surface_fails_closed_for_unknown_matched_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = BrokerFixture::new("unknown-handler");
    let terminal = TerminalMediationFixture::terminal_config()?;
    let validator = TerminalProcessExecValidator::from_config(&terminal)?;
    let broker =
        fixture.register(SessionInterceptionRouter::new().with_process_exec_handler(validator))?;

    let decision = fixture.request_decision(
        &broker,
        InterceptionRequestFixture::process("missing-handler"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "terminal-process-exec-unknown-interception-handler"
    );
    Ok(())
}
