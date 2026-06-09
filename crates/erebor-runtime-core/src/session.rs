use std::{
    path::Path,
    process::Command as ProcessCommand,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_events::{
    ActionKind, ActorIdentity, EventId, ExecutionSurface, RiskLevel, RiskMetadata, RuntimeEvent,
    SessionId, TargetRef,
};
use erebor_runtime_policy::{Decision, PolicyEvaluator};
use serde_json::json;
use tracing::info;

use crate::{
    ApprovalProvider, AuditSink, DockerSessionCommandPlan, LocalEnforcementEngine, RuntimeError,
    SessionRunPlan, SessionRunnerKind,
};

pub trait SessionRunner {
    fn kind(&self) -> SessionRunnerKind;

    fn run(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRunOutcome {
    runner: SessionRunnerKind,
    exit_code: Option<i32>,
}

impl SessionRunOutcome {
    #[must_use]
    pub const fn new(runner: SessionRunnerKind, exit_code: Option<i32>) -> Self {
        Self { runner, exit_code }
    }

    #[must_use]
    pub const fn runner(&self) -> SessionRunnerKind {
        self.runner
    }

    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

pub struct SessionRunnerLauncher;

impl SessionRunnerLauncher {
    pub fn run(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError> {
        match plan.runner().kind() {
            SessionRunnerKind::Docker => DockerSessionRunner.run(plan, environment),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TerminalSessionSurface<E, A, S> {
    engine: LocalEnforcementEngine<E, A, S>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalSessionAuthorization {
    session_id: SessionId,
}

impl TerminalSessionAuthorization {
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

impl<E, A, S> TerminalSessionSurface<E, A, S> {
    #[must_use]
    pub fn new(engine: LocalEnforcementEngine<E, A, S>) -> Self {
        Self { engine }
    }
}

impl<E, A, S> TerminalSessionSurface<E, A, S>
where
    E: PolicyEvaluator,
    A: ApprovalProvider,
    S: AuditSink,
{
    pub fn authorize(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<TerminalSessionAuthorization, RuntimeError> {
        let event = terminal_process_event(plan, environment);
        let outcome = self.engine.enforce(&event)?;

        match outcome.final_decision {
            Decision::Allow { .. } => Ok(TerminalSessionAuthorization {
                session_id: plan.session_id().clone(),
            }),
            Decision::Deny { reason, .. } | Decision::RequireApproval { reason, .. } => {
                Err(RuntimeError::terminal_command_denied(reason))
            }
        }
    }

    pub fn execute_authorized(
        &self,
        _authorization: TerminalSessionAuthorization,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError> {
        SessionRunnerLauncher::run(plan, environment)
    }

    pub fn execute(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError> {
        let authorization = self.authorize(plan, environment)?;
        self.execute_authorized(authorization, plan, environment)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DockerSessionRunner;

impl SessionRunner for DockerSessionRunner {
    fn kind(&self) -> SessionRunnerKind {
        SessionRunnerKind::Docker
    }

    fn run(
        &self,
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Result<SessionRunOutcome, RuntimeError> {
        let launch =
            DockerSessionCommandPlan::from_session_run_plan_with_environment(plan, environment);
        let capabilities = docker_session_runner_capabilities(plan, environment);
        info!(
            session = %plan.session_id().as_str(),
            actor = %plan.actor().id,
            image = %plan.runner().docker().image(),
            tty = plan.tty(),
            capabilities = ?capabilities,
            "launching Docker/OCI session runner"
        );

        let status = ProcessCommand::new(launch.program())
            .args(launch.args())
            .status()
            .map_err(|source| {
                RuntimeError::session_runner_launch(
                    self.kind().as_str(),
                    launch.program().to_owned(),
                    source,
                )
            })?;

        if status.success() {
            Ok(SessionRunOutcome::new(self.kind(), status.code()))
        } else {
            Err(RuntimeError::session_runner_exit(
                self.kind().as_str(),
                status.code(),
            ))
        }
    }
}

impl SessionRunnerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
        }
    }
}

#[must_use]
pub fn terminal_process_event(
    plan: &SessionRunPlan,
    environment: &[(String, String)],
) -> RuntimeEvent {
    let command = plan.command();
    let command_name = command.first().cloned().unwrap_or_default();
    let (risk_level, risk_reasons) = terminal_command_risk(plan);

    RuntimeEvent {
        id: EventId::new(format!(
            "{}-terminal-process-exec",
            plan.session_id().as_str()
        )),
        session_id: plan.session_id().clone(),
        actor: ActorIdentity {
            id: plan.actor().id.clone(),
            kind: plan.actor().kind.clone(),
        },
        surface: ExecutionSurface::Terminal,
        action: ActionKind::ProcessExec,
        target: Some(TargetRef {
            label: Some(command_name),
            uri: None,
        }),
        payload: json!({
            "kind": "session_terminal_exec",
            "session_runner": plan.runner().kind().as_str(),
            "terminal": {
                "surface": "terminal",
                "tty": plan.tty(),
            },
            "runner_capabilities": docker_session_runner_capabilities(plan, environment),
            "docker": {
                "image": plan.runner().docker().image(),
                "network": plan.runner().docker().network(),
                "workdir": path_display(plan.runner().docker().workdir()),
            },
            "workspace": plan.workspace().map(path_display),
            "diagnostic": plan.diagnostic(),
            "argv_summary": argv_summary(command),
            "command": command,
        }),
        risk: RiskMetadata {
            level: risk_level,
            reasons: risk_reasons,
        },
        timestamp: runtime_timestamp(),
    }
}

fn terminal_command_risk(plan: &SessionRunPlan) -> (RiskLevel, Vec<String>) {
    let command_text = plan.command().join(" ");
    let mut reasons = Vec::new();

    if plan.diagnostic().is_some() {
        reasons.push(String::from(
            "named bounded diagnostic declared in session config",
        ));
        return (RiskLevel::Low, reasons);
    }

    for risky_token in [
        "--remote-debugging-port",
        "chromium",
        "google-chrome",
        "rm -rf",
        "/var/run/docker.sock",
    ] {
        if command_text.contains(risky_token) {
            reasons.push(format!("command contains high-risk token `{risky_token}`"));
        }
    }

    if reasons.is_empty() {
        reasons.push(String::from(
            "root command for Docker/OCI governed session terminal surface",
        ));
        (RiskLevel::Medium, reasons)
    } else {
        (RiskLevel::High, reasons)
    }
}

fn docker_session_runner_capabilities(
    plan: &SessionRunPlan,
    environment: &[(String, String)],
) -> serde_json::Value {
    let docker = plan.runner().docker();
    let has_browser_endpoint = environment
        .iter()
        .any(|(key, _value)| key == "EREBOR_BROWSER_CDP_URL");

    json!({
        "process_tree_containment": {
            "status": "enforced",
            "detail": "session root command starts inside a Docker/OCI container process tree"
        },
        "filesystem_mount_scope": {
            "status": if plan.workspace().is_some() { "enforced" } else { "not_configured" },
            "detail": plan.workspace().map(|path| {
                format!(
                    "{} mounted read-write at {}",
                    path.display(),
                    docker.workdir().display()
                )
            }).unwrap_or_else(|| String::from("no workspace mount configured"))
        },
        "network_namespace": {
            "status": docker_network_status(docker.network()),
            "detail": docker_network_detail(docker.network())
        },
        "loopback_private_cdp_exposure": {
            "status": if has_browser_endpoint { "governed_endpoint_injected" } else { "not_applicable" },
            "detail": if has_browser_endpoint {
                "session environment contains only Erebor's governed browser CDP endpoint"
            } else {
                "browser CDP surface is not active for this session command"
            }
        },
        "shell_command_enforcement": {
            "status": "root_command_enforced",
            "detail": "the session root command is policy-checked before Docker/OCI launch"
        },
        "child_process_interception": {
            "status": "not_enforced",
            "detail": "child-process interception inside the container is a future Docker/OCI runner phase"
        },
        "cleanup": {
            "status": "requested",
            "detail": "Docker --rm is requested and side resources are dropped when the session command exits"
        },
        "tty": {
            "status": if plan.tty() { "allocated" } else { "not_allocated" },
            "detail": if plan.tty() {
                "Docker is launched with interactive TTY flags for agent attachment"
            } else {
                "Docker is launched without interactive TTY flags"
            }
        }
    })
}

fn docker_network_status(network: &str) -> &'static str {
    if network.eq_ignore_ascii_case("none") {
        "egress_disabled"
    } else if network.eq_ignore_ascii_case("host") {
        "shared_host_network"
    } else {
        "docker_network_namespace"
    }
}

fn docker_network_detail(network: &str) -> String {
    if network.eq_ignore_ascii_case("none") {
        String::from("container network is disabled by Docker")
    } else if network.eq_ignore_ascii_case("host") {
        String::from("container shares the host network namespace")
    } else {
        format!("container uses Docker network `{network}`")
    }
}

fn argv_summary(command: &[String]) -> String {
    command
        .iter()
        .take(4)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
}

fn path_display(path: &Path) -> String {
    path.display().to_string()
}

fn runtime_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    format!("unix:{seconds}")
}

#[cfg(test)]
mod tests {
    use erebor_runtime_events::{ActionKind, ExecutionSurface, SessionId};
    use erebor_runtime_policy::{LocalPolicy, PolicySet};

    use crate::{
        LocalEnforcementEngine, RuntimeConfig, RuntimeError, SessionRunPlan, SessionRunnerKind,
    };

    use super::{terminal_process_event, TerminalSessionSurface};

    #[test]
    fn terminal_process_event_reports_session_runner_capabilities(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/pilot.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "bridge",
                    "workdir": "/workspace"
                  }
                }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            vec![String::from("openclaw")],
        )?
        .with_tty(true);

        let event = terminal_process_event(
            &plan,
            &[(
                String::from("EREBOR_BROWSER_CDP_URL"),
                String::from("ws://host.docker.internal:3738/"),
            )],
        );

        assert_eq!(event.surface, ExecutionSurface::Terminal);
        assert_eq!(event.action, ActionKind::ProcessExec);
        assert_eq!(event.payload["terminal"]["tty"], serde_json::json!(true));
        assert_eq!(
            event.payload["runner_capabilities"]["loopback_private_cdp_exposure"]["status"],
            serde_json::json!("governed_endpoint_injected")
        );
        assert_eq!(
            event.payload["runner_capabilities"]["child_process_interception"]["status"],
            serde_json::json!("not_enforced")
        );
        Ok(())
    }

    #[test]
    fn terminal_surface_denies_before_docker_launch() -> Result<(), Box<dyn std::error::Error>> {
        let policy = LocalPolicy::from_json_str(
            r#"
            {
              "rules": [
                {
                  "id": "deny-raw-cdp-browser",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "payload_contains": "remote-debugging-port"
                  },
                  "decision": "deny",
                  "reason": "raw browser CDP launch is denied"
                }
              ]
            }
            "#,
        )?;
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/pilot.json"],
              "session": {
                "enabled": true,
                "runner": { "docker": { "image": "alpine:3.20" } }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            vec![
                String::from("google-chrome"),
                String::from("--remote-debugging-port=9222"),
            ],
        )?;
        let engine = LocalEnforcementEngine::new(PolicySet::from_policies(vec![policy]));
        let terminal = TerminalSessionSurface::new(engine);

        match terminal.execute(&plan, &[]) {
            Err(RuntimeError::TerminalCommandDenied { reason, .. }) => {
                assert_eq!(reason, "raw browser CDP launch is denied");
            }
            Ok(_) => {
                return Err(
                    std::io::Error::other("denied terminal command unexpectedly launched").into(),
                );
            }
            Err(error) => return Err(error.into()),
        }

        Ok(())
    }
}
