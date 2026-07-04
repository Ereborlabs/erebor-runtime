use std::{fs, net::TcpListener, path::PathBuf};

use erebor_runtime_cdp::CdpSessionContext;
use erebor_runtime_core::{
    FileInterceptionRequest, FileOperationSurfaceHandler, ProcessExecInterceptionRequest,
    ProcessExecSurfaceHandler, ProcessMediationPrivateEndpointLayerConfig,
    ProcessMediationPrivatePortStrategy, RuntimeAuditConfig, RuntimeConfig,
    SessionInterceptionDecision, SocketConnectInterceptionRequest, SocketConnectSurfaceHandler,
    SurfaceInterceptionDecision, SurfaceMediationDecision, TerminalSurfaceConfig,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use erebor_runtime_ipc::v1::{
    DecisionKind, FileOperation, FileOperationKind, GuardHello, InterceptionOperation,
    InterceptionRequest, InterceptionSource, ProcessExecOperation, SocketOperation,
    SocketOperationKind, PROTOCOL_VERSION,
};
use erebor_runtime_policy::PolicySet;
use erebor_runtime_terminal::{TerminalProcessExecValidator, TerminalProcessMediationCapability};

use super::{
    InterceptionBrokerClient, RuntimeInterceptionBroker, RuntimeInterceptionBrokerError,
    RuntimeInterceptionEndpoint, SessionInterceptionRouter,
};
use crate::surfaces::terminal::browser_cdp_process_mediation::{
    private_remote_debugging_port_for_request, BrowserCdpProcessMediationCapability,
};

#[test]
fn broker_accepts_guard_hello_with_interception_token() -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("accepts-hello");
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;

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
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;
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
    let first = RuntimeInterceptionBroker::register_session(
        &first_session,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;
    let second = RuntimeInterceptionBroker::register_session(
        &second_session,
        "codex",
        SessionInterceptionRouter::new(),
    )?;

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
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;
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
    let _broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;
    let error = match RuntimeInterceptionBroker::register_session(
        &session_id,
        "codex",
        SessionInterceptionRouter::new(),
    ) {
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
    let router =
        SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecDecisionHandler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;

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
        Some("browser_cdp")
    );
    Ok(())
}

#[test]
fn broker_routes_process_exec_requests_without_handler_id() -> Result<(), Box<dyn std::error::Error>>
{
    let session_id = session_id("routes-process-exec");
    let router = SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecHandler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;

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
fn broker_routes_process_exec_mediation_from_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("routes-process-exec-mediate");
    let router =
        SessionInterceptionRouter::new().with_process_exec_handler(TestProcessExecMediationHandler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;

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
fn broker_routes_process_exec_requests_with_handler_id_to_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("routes-matched-process-exec");
    let router = SessionInterceptionRouter::new()
        .with_process_exec_handler(MatchedHandlerProcessExecHandler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request_with_argv("managed-browser-cdp", &[String::from("google-chrome")]),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "matched-handler-id-visible");
    assert_eq!(decision.reason, "managed-browser-cdp");
    assert_eq!(decision.mediate, None);
    Ok(())
}

#[test]
fn broker_fails_closed_for_unrouted_process_exec() -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("unrouted-process-exec");
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("missing-handler"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-unrouted-process-exec"
    );
    Ok(())
}

#[test]
fn broker_routes_file_operation_to_registered_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("routes-file-operation");
    let router = SessionInterceptionRouter::new().with_file_operation_handler(TestFileHandler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        file_request(FileOperationKind::Read, "/workspace/secret.txt"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "filesystem-file-read-visible");
    assert_eq!(decision.reason, "/workspace/secret.txt@/workspace:100");
    Ok(())
}

#[test]
fn broker_fails_closed_for_mismatched_file_operation_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("mismatched-file-operation");
    let router = SessionInterceptionRouter::new().with_file_operation_handler(TestFileHandler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;
    let mut request = file_request(FileOperationKind::Read, "/workspace/secret.txt");
    request.operation = InterceptionOperation::FileOpen as i32;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request,
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-invalid-operation-payload"
    );
    assert!(decision.reason.contains("file.kind"));
    Ok(())
}

#[test]
fn broker_fails_closed_for_unrouted_socket_connect() -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("unrouted-socket-connect");
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new(),
    )?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        socket_connect_request("api.example.test", 443),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "erebor-runtime-interception-broker-unrouted-operation"
    );
    assert!(decision.reason.contains("socket_connect"));
    Ok(())
}

#[test]
fn broker_routes_socket_connect_to_registered_surface_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("routes-socket-connect");
    let router =
        SessionInterceptionRouter::new().with_socket_connect_handler(TestSocketConnectHandler);
    let broker = RuntimeInterceptionBroker::register_session(&session_id, "openclaw", router)?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        socket_connect_request("api.example.test", 443),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decision.rule_id, "network-socket-connect-visible");
    assert_eq!(decision.reason, "tcp://api.example.test:443");
    Ok(())
}

#[test]
fn browser_cdp_process_mediation_capability_owns_endpoint_and_port_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("browser-cdp-mediator");
    let terminal = terminal_process_mediation_config()?;
    let validator = TerminalProcessExecValidator::from_config(&terminal)?
        .with_process_mediation_capability(BrowserCdpProcessMediationCapability::new(
            "ws://127.0.0.1:9222/",
        ));
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new().with_process_exec_handler(validator),
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
    assert_eq!(mediation.lease_id, "managed-browser-cdp-lease");
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
    let config = terminal_process_mediation_runtime_config("127.0.0.1:0")?;
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
    let terminal = terminal_process_mediation_config()?;
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

    assert_eq!(
        private_remote_debugging_port_for_request(&private_endpoint, 1000)?,
        Some(1001)
    );
    let overflow = private_remote_debugging_port_for_request(&private_endpoint, u16::MAX);
    let Err(error) = overflow else {
        return Err(String::from("overflow should fail closed"));
    };
    assert!(error.contains("exceeds u16"));

    Ok(())
}

#[test]
fn terminal_process_surface_fails_closed_for_unknown_matched_handler(
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = session_id("unknown-handler");
    let terminal = terminal_process_mediation_config()?;
    let validator = TerminalProcessExecValidator::from_config(&terminal)?;
    let broker = RuntimeInterceptionBroker::register_session(
        &session_id,
        "openclaw",
        SessionInterceptionRouter::new().with_process_exec_handler(validator),
    )?;

    let decision = InterceptionBrokerClient::request_interception_decision(
        broker.endpoint(),
        hello(&session_id),
        request("missing-handler"),
    )?;

    assert_eq!(decision.decision, DecisionKind::Deny as i32);
    assert_eq!(
        decision.rule_id,
        "terminal-process-exec-unknown-interception-handler"
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
        operation: InterceptionOperation::ProcessExec as i32,
        process_exec: Some(ProcessExecOperation {
            executable: argv
                .first()
                .cloned()
                .unwrap_or_else(|| String::from("tool")),
            argv: argv.to_vec(),
            requested_endpoint: None,
            matched_handler_id: handler_id.to_owned(),
        }),
        file: None,
        socket: None,
    }
}

fn file_request(kind: FileOperationKind, path: &str) -> InterceptionRequest {
    InterceptionRequest {
        request_id: 11,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Ptrace as i32,
        pid: 100,
        ppid: 99,
        executable: String::new(),
        argv: Vec::new(),
        cwd: String::from("/workspace"),
        selected_env: Vec::new(),
        requested_endpoint: None,
        matched_handler_id: String::new(),
        timestamp: String::from("unix:1"),
        operation: match kind {
            FileOperationKind::Open => InterceptionOperation::FileOpen,
            FileOperationKind::Read => InterceptionOperation::FileRead,
            FileOperationKind::Mutation => InterceptionOperation::FileMutation,
            FileOperationKind::Unspecified => InterceptionOperation::Unspecified,
        } as i32,
        process_exec: None,
        file: Some(FileOperation {
            kind: kind as i32,
            path: path.to_owned(),
        }),
        socket: None,
    }
}

fn socket_connect_request(host: &str, port: u32) -> InterceptionRequest {
    InterceptionRequest {
        request_id: 12,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Ptrace as i32,
        pid: 100,
        ppid: 99,
        executable: String::new(),
        argv: Vec::new(),
        cwd: String::from("/workspace"),
        selected_env: Vec::new(),
        requested_endpoint: None,
        matched_handler_id: String::new(),
        timestamp: String::from("unix:1"),
        operation: InterceptionOperation::SocketConnect as i32,
        process_exec: None,
        file: None,
        socket: Some(SocketOperation {
            kind: SocketOperationKind::Connect as i32,
            scheme: String::from("tcp"),
            host: host.to_owned(),
            port,
            path: String::new(),
        }),
    }
}

fn terminal_process_mediation_config() -> Result<TerminalSurfaceConfig, Box<dyn std::error::Error>>
{
    let config = terminal_process_mediation_runtime_config_with_allowed_ports(
        "127.0.0.1:9222",
        r#",
                          "allowed_ports": [9222]"#,
    )?;
    Ok(config
        .surface_start_plan()?
        .terminal()
        .ok_or_else(|| std::io::Error::other("missing terminal config"))?
        .clone())
}

fn terminal_process_mediation_runtime_config(
    browser_cdp_listen: &str,
) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    terminal_process_mediation_runtime_config_with_allowed_ports(browser_cdp_listen, "")
}

fn terminal_process_mediation_runtime_config_with_allowed_ports(
    browser_cdp_listen: &str,
    allowed_ports_fragment: &str,
) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    let policy_path = std::env::temp_dir().join(format!(
        "erebor-broker-mediation-policy-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::write(&policy_path, r#"{"rules":[]}"#)?;

    Ok(RuntimeConfig::from_json_str(&format!(
        r#"
            {{
              "policies": ["{}"],
              "session": {{
                "interception": {{
                  "enabled": true
                }}
              }},
              "surfaces": {{
                "terminal": {{
                  "enabled": true,
                  "process_interception": {{
                    "enabled": true,
                    "handlers": [
                      {{
                        "id": "managed-browser-cdp",
                        "decision": "mediate",
                        "kind": "managed_browser_cdp",
                        "match": {{
                          "executables": ["google-chrome"],
                          "required_args": ["--remote-debugging-port"],
                          "require_remote_debugging_port": true
                        }},
                        "requested_endpoint": {{
                          "source": "remote_debugging_port",
                          "bind": "127.0.0.1"{allowed_ports_fragment}
                        }},
                        "replacement": {{
                          "surface": "browser_cdp",
                          "private_endpoint": {{
                            "port_strategy": "requested_plus_offset",
                            "port_offset": 1
                          }}
                        }},
                        "compatibility": {{
                          "print_devtools_listening_line": true,
                          "keepalive": true
                        }}
                      }}
                    ]
                  }}
                }},
                "browser_cdp": {{
                  "enabled": true,
                  "listen": "{browser_cdp_listen}",
                  "browser_url": "ws://127.0.0.1:9/devtools/browser/fake"
                }}
              }}
            }}
            "#,
        policy_path.display(),
    ))?)
}

struct TestProcessExecHandler;

struct TestProcessExecDecisionHandler;

struct TestProcessExecMediationHandler;

struct MatchedHandlerProcessExecHandler;

struct TestFileHandler;

struct TestSocketConnectHandler;

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

impl ProcessExecSurfaceHandler for TestProcessExecDecisionHandler {
    fn surface(&self) -> &str {
        "terminal"
    }

    fn decide_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        match request.matched_handler_id() {
            "allow-tool" => SurfaceInterceptionDecision::allow("allow-tool", "safe tool"),
            "deny-tool" => SurfaceInterceptionDecision::deny("deny-tool", "dangerous tool"),
            "approve-tool" => {
                SurfaceInterceptionDecision::require_approval("approve-tool", "needs approval")
            }
            "mediate-tool" => SurfaceInterceptionDecision::mediate(
                "mediate-tool",
                "route to replacement surface",
                SurfaceMediationDecision::new("future_api", "browser_cdp", "local://replacement"),
            ),
            handler_id => SurfaceInterceptionDecision::deny(
                "test-process-exec-unknown-handler",
                format!("unexpected handler id `{handler_id}`"),
            ),
        }
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

impl FileOperationSurfaceHandler for TestFileHandler {
    fn surface(&self) -> &str {
        "filesystem"
    }

    fn decide_file_operation(
        &self,
        request: &FileInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny(
            "filesystem-file-read-visible",
            format!("{}@{}:{}", request.path(), request.cwd(), request.pid()),
        )
    }
}

impl SocketConnectSurfaceHandler for TestSocketConnectHandler {
    fn surface(&self) -> &str {
        "network"
    }

    fn decide_socket_connect(
        &self,
        request: &SocketConnectInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision {
        SurfaceInterceptionDecision::deny(
            "network-socket-connect-visible",
            format!(
                "{}://{}:{}",
                request.scheme(),
                request.host(),
                request.port()
            ),
        )
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
