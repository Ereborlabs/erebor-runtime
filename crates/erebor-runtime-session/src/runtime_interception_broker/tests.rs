use std::{fs, net::TcpListener, path::PathBuf};

use erebor_runtime_cdp::CdpSessionContext;
use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler,
    ProcessMediationPrivateEndpointLayerConfig, ProcessMediationPrivatePortStrategy,
    RuntimeAuditConfig, RuntimeConfig, SurfaceInterceptionDecision, SurfaceMediationDecision,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_ipc::v1::{
    DecisionKind, GuardHello, InterceptionRequest, InterceptionSource, PROTOCOL_VERSION,
};
use erebor_runtime_policy::PolicySet;

use super::{
    browser_cdp_mediation::private_remote_debugging_port_for_request, BrowserCdpMediationHandler,
    InterceptionBrokerClient, RuntimeInterceptionBroker, RuntimeInterceptionBrokerError,
    RuntimeInterceptionEndpoint, SessionInterceptionHandler, SessionInterceptionRouter,
    SessionMediationIntent, SessionMediationRegistry, SurfaceMediationHandler,
    SurfaceMediationOutcome,
};

#[test]
fn broker_accepts_guard_hello_with_interception_token() -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("accepts-hello");
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", Vec::new())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(broker.endpoint().directory())?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(broker.endpoint().path())?.permissions().mode() & 0o777,
            0o600
        );
    }

    let ack = InterceptionBrokerClient::send_hello(broker.endpoint(), hello(&session_id))?;

    assert!(ack.accepted);
    assert_eq!(ack.protocol_version, PROTOCOL_VERSION);
    assert!(ack.broker_id.contains(&session_id));

    Ok(())
}

#[test]
fn broker_rejects_guard_hello_with_bad_interception_token() -> Result<(), Box<dyn std::error::Error>>
{
    let session_id = session_id("rejects-token");
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", Vec::new())?;
    let bad_endpoint = broker.endpoint().with_path(broker.endpoint().path());
    let bad_endpoint = RuntimeInterceptionEndpoint::unix(bad_endpoint.path(), "wrong-token", 25);

    let ack = InterceptionBrokerClient::send_hello(&bad_endpoint, hello(&session_id))?;

    assert!(!ack.accepted);
    assert_eq!(ack.reason, "invalid interception token");

    Ok(())
}

#[test]
fn broker_accepts_multiple_sessions_on_one_server() -> Result<(), Box<dyn std::error::Error>> {
    let first_session = session_id("first");
    let second_session = session_id("second");
    let first =
        RuntimeInterceptionBroker::register_session(&first_session, "openclaw", Vec::new())?;
    let second = RuntimeInterceptionBroker::register_session(&second_session, "codex", Vec::new())?;

    assert_eq!(first.endpoint().path(), second.endpoint().path());
    assert_ne!(first.endpoint().token(), second.endpoint().token());

    let first_ack = InterceptionBrokerClient::send_hello(first.endpoint(), hello(&first_session))?;
    let second_ack =
        InterceptionBrokerClient::send_hello(second.endpoint(), hello(&second_session))?;
    let crossed_endpoint =
        RuntimeInterceptionEndpoint::unix(first.endpoint().path(), second.endpoint().token(), 25);
    let crossed_ack =
        InterceptionBrokerClient::send_hello(&crossed_endpoint, hello(&first_session))?;

    assert!(first_ack.accepted);
    assert!(second_ack.accepted);
    assert!(!crossed_ack.accepted);
    assert_eq!(crossed_ack.reason, "invalid interception token");
    Ok(())
}

#[test]
fn broker_unregisters_session_when_registration_drops() -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("drop-unregisters");
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", Vec::new())?;
    let endpoint = broker.endpoint().clone();
    drop(broker);

    let ack = InterceptionBrokerClient::send_hello(&endpoint, hello(&session_id))?;

    assert!(!ack.accepted);
    assert_eq!(ack.reason, "unknown session");
    Ok(())
}

#[test]
fn broker_rejects_duplicate_session_registration() -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("duplicate");
    let _broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", Vec::new())?;
    let error = match RuntimeInterceptionBroker::register_session(&session_id, "codex", Vec::new())
    {
        Ok(_registration) => return Err("duplicate session id should be rejected".into()),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RuntimeInterceptionBrokerError::SessionAlreadyRegistered { .. }
    ));
    Ok(())
}

#[test]
fn broker_returns_interception_decisions_after_guard_hello(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("decisions");
    let broker = RuntimeInterceptionBroker::register_session_with_mediators(
        &session_id,
        "openclaw",
        vec![
            SessionInterceptionHandler::allow("allow-tool", "safe tool"),
            SessionInterceptionHandler::deny("deny-tool", "dangerous tool"),
            SessionInterceptionHandler::require_approval("approve-tool", "needs approval"),
            SessionInterceptionHandler::mediate(
                "mediate-tool",
                "route to replacement surface",
                SessionMediationIntent::new("future_api", "api")
                    .with_lease_id("api-lease")
                    .with_keepalive(false),
            ),
        ],
        SessionMediationRegistry::new().with_handler(TestMediationHandler {
            surface: String::from("api"),
            endpoint: String::from("local://replacement"),
        }),
    )?;

    let allow = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("allow-tool"),
    )?;
    let deny = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("deny-tool"),
    )?;
    let approval = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("approve-tool"),
    )?;
    let mediate = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("mediate-tool"),
    )?;

    assert_eq!(allow.decision, DecisionKind::Allow as i32);
    assert_eq!(deny.decision, DecisionKind::Deny as i32);
    assert_eq!(approval.decision, DecisionKind::RequireApproval as i32);
    assert_eq!(mediate.decision, DecisionKind::Mediate as i32);
    assert_eq!(
        mediate
            .mediate
            .as_ref()
            .map(|decision| decision.replacement_surface.as_str()),
        Some("api")
    );
    Ok(())
}

#[test]
fn broker_routes_process_exec_requests_without_handler_id() -> Result<(), Box<dyn std::error::Error>>
{
    let session_id = session_id("routes-process-exec");
    let router = SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecHandler);
    let broker = RuntimeInterceptionBroker::register_session_with_router_and_mediators(
        &session_id,
        "openclaw",
        Vec::new(),
        router,
        SessionMediationRegistry::new(),
    )?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request_with_argv("", &[String::from("danger-tool")]),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "test-process-exec-deny");
    assert_eq!(decision.reason, "dangerous process execution");
    Ok(())
}

#[test]
fn broker_routes_process_exec_mediation_without_session_mediation_registry(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("routes-process-exec-mediate");
    let router =
        SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecMediationHandler);
    let broker = RuntimeInterceptionBroker::register_session_with_router_and_mediators(
        &session_id,
        "openclaw",
        Vec::new(),
        router,
        SessionMediationRegistry::new(),
    )?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request_with_argv("", &[String::from("google-chrome")]),
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
fn process_exec_router_passes_matched_handler_id_to_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = SessionInterceptionRouter::new()
        .with_process_exec_handler(MatchedHandlerProcessExecHandler);

    let Some(decision) = router.decide_process_exec(&request_with_argv(
        "managed-browser-cdp",
        &[String::from("google-chrome")],
    )) else {
        return Err("process exec route should be registered".into());
    };
    let (decision, rule_id, reason, mediation) = decision.into_parts();

    assert_eq!(
        decision,
        erebor_runtime_core::SessionInterceptionDecision::Deny
    );
    assert_eq!(rule_id, "matched-handler-id-visible");
    assert_eq!(reason, "managed-browser-cdp");
    assert_eq!(mediation, None);
    Ok(())
}

#[test]
fn broker_fails_closed_when_mediation_surface_is_not_registered(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("missing-mediator");
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        vec![SessionInterceptionHandler::mediate(
            "mediate-tool",
            "route to replacement surface",
            SessionMediationIntent::new("future_api", "api"),
        )],
    )?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("mediate-tool"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert!(decision
        .reason
        .contains("no mediation handler is registered for replacement surface `api`"));
    Ok(())
}

#[test]
fn browser_cdp_mediation_handler_owns_endpoint_and_port_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("browser-cdp-mediator");
    let broker = RuntimeInterceptionBroker::register_session_with_mediators(
        &session_id,
        "openclaw",
        vec![SessionInterceptionHandler::mediate(
            "managed-browser-cdp",
            "route browser launch to governed CDP",
            SessionMediationIntent::new("managed_browser_cdp", "browser_cdp")
                .with_allowed_ports(vec![9222])
                .with_lease_id("browser-lease")
                .with_compatibility_line(true)
                .with_keepalive(true),
        )],
        SessionMediationRegistry::new()
            .with_handler(BrowserCdpMediationHandler::new("ws://127.0.0.1:9222/")),
    )?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request_with_argv(
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
    assert_eq!(mediation.lease_id, "browser-lease");
    assert!(mediation
        .print_line
        .contains("ws://127.0.0.1:9222/devtools/browser/erebor-managed-browser"));
    assert!(mediation.keepalive);

    let denied = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request_with_argv(
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
    let requested_port = free_tcp_port()?;
    let config = RuntimeConfig::from_json_str(
        r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:0",
                  "browser_url": "ws://127.0.0.1:9/devtools/browser/fake"
                }
              }
            }
            "#,
    )?;
    let browser_cdp = config
        .surface_start_plan()?
        .browser_cdp()
        .ok_or_else(|| std::io::Error::other("missing browser CDP config"))?
        .clone();
    let handler = BrowserCdpMediationHandler::lazy(
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

    let outcome = handler.mediate(
        &request_with_argv(
            "managed-browser-cdp",
            &[
                String::from("google-chrome"),
                format!("--remote-debugging-port={requested_port}"),
            ],
        ),
        &SessionMediationIntent::new("managed_browser_cdp", "browser_cdp")
            .with_lease_id("browser-lease")
            .with_compatibility_line(true)
            .with_keepalive(true),
    )?;

    assert_eq!(
        outcome.endpoint,
        format!("ws://127.0.0.1:{requested_port}/")
    );
    assert!(outcome.print_line.contains(&format!(
        "ws://127.0.0.1:{requested_port}/devtools/browser/"
    )));
    Ok(())
}

#[test]
fn private_browser_port_can_follow_requested_port_plus_offset() -> Result<(), String> {
    let intent = SessionMediationIntent::new("managed_browser_cdp", "browser_cdp")
        .with_private_endpoint(
            ProcessMediationPrivateEndpointLayerConfig {
                port_strategy: ProcessMediationPrivatePortStrategy::RequestedPlusOffset,
                port_offset: 1,
            }
            .into(),
        );

    assert_eq!(
        private_remote_debugging_port_for_request(&intent, 1000)?,
        Some(1001)
    );
    let overflow = private_remote_debugging_port_for_request(&intent, u16::MAX);
    let Err(error) = overflow else {
        return Err(String::from("overflow should fail closed"));
    };
    assert!(error.contains("exceeds u16"));

    Ok(())
}

#[test]
fn broker_fails_closed_for_unknown_interception_handler() -> Result<(), Box<dyn std::error::Error>>
{
    let session_id = session_id("unknown-handler");
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", Vec::new())?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("missing-handler"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-unknown-handler"
    );
    Ok(())
}

#[test]
fn client_fails_closed_when_broker_is_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let directory = test_dir("unavailable")?;
    let endpoint = RuntimeInterceptionEndpoint::unix(directory.join("missing.sock"), "token", 25);

    let error = InterceptionBrokerClient::send_hello(&endpoint, hello("missing-session"));

    assert!(error.is_err());

    fs::remove_dir_all(directory)?;
    Ok(())
}

fn hello(session_id: &str) -> GuardHello {
    GuardHello {
        protocol_version: PROTOCOL_VERSION,
        session_id: session_id.to_owned(),
        actor_id: String::from("openclaw"),
        guard_pid: 42,
        runner_kind: String::from("linux_host"),
        platform: String::from("linux-x86_64"),
        capabilities: vec![String::from("interception_request")],
    }
}

fn request(handler_id: &str) -> InterceptionRequest {
    request_with_argv(handler_id, &[String::from("tool")])
}

fn request_with_argv(handler_id: &str, argv: &[String]) -> InterceptionRequest {
    InterceptionRequest {
        request_id: 7,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Shim as i32,
        pid: 100,
        ppid: 99,
        executable: argv
            .first()
            .cloned()
            .unwrap_or_else(|| String::from("tool")),
        argv: argv.to_vec(),
        cwd: String::from("/workspace"),
        selected_env: Vec::new(),
        requested_endpoint: None,
        matched_handler_id: handler_id.to_owned(),
        timestamp: String::from("unix:1"),
    }
}

struct TestMediationHandler {
    surface: String,
    endpoint: String,
}

struct TestProcessExecHandler;

struct TestProcessExecMediationHandler;

struct MatchedHandlerProcessExecHandler;

impl ProcessExecSurfaceHandler for TestProcessExecHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        _request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny("test-process-exec-deny", "dangerous process execution")
    }
}

impl ProcessExecSurfaceHandler for TestProcessExecMediationHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        _request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::mediate(
            "test-process-exec-mediate",
            "process execution mediated by surface handler",
            SurfaceMediationDecision::new(
                "managed_browser_cdp",
                "browser_cdp",
                "ws://127.0.0.1:9222/",
            )
            .with_lease_id("surface-lease")
            .with_print_line("DevTools listening on ws://127.0.0.1:9222/devtools/browser/surface")
            .with_keepalive(true),
        )
    }
}

impl ProcessExecSurfaceHandler for MatchedHandlerProcessExecHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny(
            "matched-handler-id-visible",
            request.matched_handler_id(),
        )
    }
}

impl SurfaceMediationHandler for TestMediationHandler {
    fn surface(&self) -> &str {
        &self.surface
    }

    fn mediate(
        &self,
        _request: &InterceptionRequest,
        intent: &SessionMediationIntent,
    ) -> Result<SurfaceMediationOutcome, String> {
        Ok(SurfaceMediationOutcome::new(
            intent.kind(),
            intent.replacement_surface(),
            &self.endpoint,
        )
        .with_lease_id(intent.lease_id())
        .with_keepalive(intent.keepalive()))
    }
}

fn session_id(name: &str) -> String {
    format!("session-test-{name}-{}", std::process::id())
}

fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
    let directory = std::env::temp_dir().join(format!(
        "erebor-runtime-interception-broker-{name}-{}",
        std::process::id()
    ));
    let _result = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory)?;
    Ok(directory)
}

fn free_tcp_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}
