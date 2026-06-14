use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use erebor_runtime_events::{ActorKind, SessionId};
use serde::Deserialize;

use crate::RuntimeConfigError;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct RuntimeConfig {
    pub policies: Vec<PathBuf>,
    #[serde(default)]
    pub audit: RuntimeAuditConfig,
    #[serde(default)]
    pub session: SessionLayerConfig,
    #[serde(default, alias = "surfaces")]
    pub surfaces: SessionSurfaceLayers,
}

impl RuntimeConfig {
    pub fn from_json_str(source: &str) -> Result<Self, RuntimeConfigError> {
        if source.trim().is_empty() {
            return Err(RuntimeConfigError::empty_config());
        }

        let config: Self =
            serde_json::from_str(source).map_err(RuntimeConfigError::invalid_json)?;
        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.policies.is_empty() {
            return Err(RuntimeConfigError::missing_policy());
        }

        if self
            .policies
            .iter()
            .any(|policy| policy.as_os_str().is_empty())
            || self
                .surfaces
                .browser_cdp
                .policies
                .iter()
                .any(|policy| policy.as_os_str().is_empty())
            || self
                .surfaces
                .terminal
                .policies
                .iter()
                .any(|policy| policy.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::empty_policy_path());
        }

        if self
            .audit
            .jsonl
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::empty_audit_jsonl_path());
        }

        if self.session.enabled {
            self.session.validate()?;
        }

        if self.surfaces.enabled_surfaces().is_empty() && !self.session.enabled {
            return Err(RuntimeConfigError::no_session_surfaces());
        }

        if self.surfaces.browser_cdp.enabled {
            if let Some(browser_url) = self.surfaces.browser_cdp.browser_url.as_deref() {
                if !browser_url.starts_with("ws://") {
                    return Err(RuntimeConfigError::browser_cdp_invalid_browser_url());
                }
            }
        }

        self.surfaces.terminal.process_mediation.validate(
            self.surfaces.terminal.enabled,
            self.surfaces.terminal.process_guard.enabled,
            &self.surfaces.browser_cdp,
        )?;

        Ok(())
    }

    #[must_use]
    pub fn enabled_surfaces(&self) -> Vec<SessionSurfaceKind> {
        self.surfaces.enabled_surfaces()
    }

    pub fn surface_start_plan(&self) -> Result<SessionSurfaceStartPlan, RuntimeConfigError> {
        SessionSurfaceStartPlan::from_config(self)
    }

    pub fn surface_start_plan_for_session(
        &self,
        session: &SessionRunPlan,
    ) -> Result<SessionSurfaceStartPlan, RuntimeConfigError> {
        SessionSurfaceStartPlan::from_config_for_session(self, session)
    }

    pub fn surface_start_plan_for_runner_kind(
        &self,
        runner_kind: SessionRunnerKind,
    ) -> Result<SessionSurfaceStartPlan, RuntimeConfigError> {
        SessionSurfaceStartPlan::from_config_for_runner_kind(self, runner_kind)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSurfaceStartPlan {
    policies: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    surfaces: Vec<SessionSurfaceKind>,
    browser_cdp: Option<BrowserCdpSurfaceConfig>,
    terminal: Option<TerminalSurfaceConfig>,
}

impl SessionSurfaceStartPlan {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            audit: config.audit.clone(),
            surfaces: config.enabled_surfaces(),
            browser_cdp: config.surfaces.browser_cdp.enabled.then(|| {
                BrowserCdpSurfaceConfig::from_layer(
                    &config.surfaces.browser_cdp,
                    config.policies.clone(),
                )
            }),
            terminal: config.surfaces.terminal.enabled.then(|| {
                TerminalSurfaceConfig::from_layer(
                    &config.surfaces.terminal,
                    config.policies.clone(),
                )
            }),
        })
    }

    pub fn from_config_for_session(
        config: &RuntimeConfig,
        session: &SessionRunPlan,
    ) -> Result<Self, RuntimeConfigError> {
        let mut plan = Self::from_config(config)?;

        if let Some(browser_cdp) = plan.browser_cdp.as_mut() {
            if session.runner().kind() == SessionRunnerKind::Docker
                && session.runner().docker().needs_host_reachable_endpoints()
                && browser_cdp.listen.ip().is_loopback()
            {
                browser_cdp.listen =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), browser_cdp.listen.port());
            }
        }

        Ok(plan)
    }

    pub fn from_config_for_runner_kind(
        config: &RuntimeConfig,
        runner_kind: SessionRunnerKind,
    ) -> Result<Self, RuntimeConfigError> {
        let mut plan = Self::from_config(config)?;

        if let Some(browser_cdp) = plan.browser_cdp.as_mut() {
            if runner_kind == SessionRunnerKind::Docker && browser_cdp.listen.ip().is_loopback() {
                browser_cdp.listen =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), browser_cdp.listen.port());
            }
        }

        Ok(plan)
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub fn surfaces(&self) -> &[SessionSurfaceKind] {
        &self.surfaces
    }

    #[must_use]
    pub fn contains_surface(&self, surface: SessionSurfaceKind) -> bool {
        self.surfaces.contains(&surface)
    }

    #[must_use]
    pub fn browser_cdp(&self) -> Option<&BrowserCdpSurfaceConfig> {
        self.browser_cdp.as_ref()
    }

    #[must_use]
    pub fn terminal(&self) -> Option<&TerminalSurfaceConfig> {
        self.terminal.as_ref()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct RuntimeAuditConfig {
    #[serde(default)]
    pub jsonl: Option<PathBuf>,
}

impl RuntimeAuditConfig {
    #[must_use]
    pub fn jsonl(&self) -> Option<&Path> {
        self.jsonl.as_deref()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct SessionLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub actor: SessionActorLayerConfig,
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    #[serde(default)]
    pub diagnostics: Vec<SessionDiagnosticLayerConfig>,
    #[serde(default, alias = "runner")]
    pub runner: SessionRunnerLayerConfig,
}

impl SessionLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.actor.id.trim().is_empty() {
            return Err(RuntimeConfigError::empty_session_actor_id());
        }

        if self
            .workspace
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::empty_session_workspace());
        }

        let mut diagnostics = HashSet::new();
        for diagnostic in &self.diagnostics {
            diagnostic.validate()?;
            if !diagnostics.insert(diagnostic.name.clone()) {
                return Err(RuntimeConfigError::duplicate_session_diagnostic_name(
                    diagnostic.name.clone(),
                ));
            }
        }

        self.runner.validate()
    }

    fn diagnostic(&self, name: &str) -> Option<&SessionDiagnosticLayerConfig> {
        self.diagnostics
            .iter()
            .find(|diagnostic| diagnostic.name == name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct SessionActorLayerConfig {
    #[serde(default = "default_session_actor_id")]
    pub id: String,
    #[serde(default = "default_session_actor_kind")]
    pub kind: ActorKind,
}

impl Default for SessionActorLayerConfig {
    fn default() -> Self {
        Self {
            id: default_session_actor_id(),
            kind: default_session_actor_kind(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct SessionDiagnosticLayerConfig {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub command: Vec<String>,
}

impl SessionDiagnosticLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.name.trim().is_empty() {
            return Err(RuntimeConfigError::empty_session_diagnostic_name());
        }

        if self.command.is_empty()
            || self
                .command
                .iter()
                .any(|argument| argument.trim().is_empty())
        {
            return Err(RuntimeConfigError::empty_session_diagnostic_command(
                self.name.clone(),
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct SessionRunnerLayerConfig {
    #[serde(default = "default_session_runner_kind")]
    pub kind: SessionRunnerKind,
    #[serde(default)]
    pub docker: DockerSessionRunnerLayerConfig,
    #[serde(default)]
    pub linux_host: LinuxHostSessionRunnerLayerConfig,
}

impl Default for SessionRunnerLayerConfig {
    fn default() -> Self {
        Self {
            kind: default_session_runner_kind(),
            docker: DockerSessionRunnerLayerConfig::default(),
            linux_host: LinuxHostSessionRunnerLayerConfig::default(),
        }
    }
}

impl SessionRunnerLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        match self.kind {
            SessionRunnerKind::Docker => self.docker.validate(),
            SessionRunnerKind::LinuxHost => self.linux_host.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRunnerKind {
    Docker,
    #[serde(alias = "linux-host")]
    LinuxHost,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct LinuxHostSessionRunnerLayerConfig {}

impl LinuxHostSessionRunnerLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct DockerSessionRunnerLayerConfig {
    #[serde(default = "default_docker_session_image")]
    pub image: String,
    #[serde(default = "default_docker_session_network")]
    pub network: String,
    #[serde(default = "default_docker_session_workdir")]
    pub workdir: PathBuf,
}

impl Default for DockerSessionRunnerLayerConfig {
    fn default() -> Self {
        Self {
            image: default_docker_session_image(),
            network: default_docker_session_network(),
            workdir: default_docker_session_workdir(),
        }
    }
}

impl DockerSessionRunnerLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.image.trim().is_empty() {
            return Err(RuntimeConfigError::empty_docker_session_image());
        }

        if self.network.trim().is_empty() {
            return Err(RuntimeConfigError::empty_docker_session_network());
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRunPlan {
    policies: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    session_id: SessionId,
    actor: SessionActorLayerConfig,
    workspace: Option<PathBuf>,
    runner: SessionRunnerConfig,
    command: Vec<String>,
    diagnostic: Option<String>,
    terminal: TerminalSurfaceConfig,
}

impl SessionRunPlan {
    pub fn from_config(
        config: &RuntimeConfig,
        runtime_kind: SessionRunnerKind,
        session_id: SessionId,
        command: Vec<String>,
    ) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        if command.is_empty() {
            return Err(RuntimeConfigError::empty_session_command());
        }

        let mut runner = config.session.runner.clone();
        runner.kind = runtime_kind;
        runner.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            audit: config.audit.clone(),
            session_id,
            actor: config.session.actor.clone(),
            workspace: config.session.workspace.clone(),
            runner: runner.into(),
            command,
            diagnostic: None,
            terminal: TerminalSurfaceConfig::from_layer(
                &config.surfaces.terminal,
                config.policies.clone(),
            ),
        })
    }

    pub fn from_diagnostic(
        config: &RuntimeConfig,
        runtime_kind: SessionRunnerKind,
        session_id: SessionId,
        diagnostic_name: &str,
    ) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        let diagnostic = config
            .session
            .diagnostic(diagnostic_name)
            .ok_or_else(|| RuntimeConfigError::unknown_session_diagnostic(diagnostic_name))?;
        let mut plan =
            Self::from_config(config, runtime_kind, session_id, diagnostic.command.clone())?;
        plan.diagnostic = Some(diagnostic.name.clone());

        Ok(plan)
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn actor(&self) -> &SessionActorLayerConfig {
        &self.actor
    }

    #[must_use]
    pub fn workspace(&self) -> Option<&Path> {
        self.workspace.as_deref()
    }

    #[must_use]
    pub const fn runner(&self) -> &SessionRunnerConfig {
        &self.runner
    }

    #[must_use]
    pub fn command(&self) -> &[String] {
        &self.command
    }

    #[must_use]
    pub fn diagnostic(&self) -> Option<&str> {
        self.diagnostic.as_deref()
    }

    #[must_use]
    pub const fn terminal(&self) -> &TerminalSurfaceConfig {
        &self.terminal
    }

    #[must_use]
    pub const fn tty(&self) -> bool {
        self.terminal.tty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAdoptPlan {
    policies: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    session_id: SessionId,
    actor: SessionActorLayerConfig,
    workspace: Option<PathBuf>,
    runner: SessionRunnerConfig,
    pid: i32,
    terminal: TerminalSurfaceConfig,
}

impl SessionAdoptPlan {
    pub fn from_config(
        config: &RuntimeConfig,
        runtime_kind: SessionRunnerKind,
        session_id: SessionId,
        pid: i32,
    ) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        if pid <= 0 {
            return Err(RuntimeConfigError::invalid_session_adopt_pid());
        }

        let mut runner = config.session.runner.clone();
        runner.kind = runtime_kind;
        runner.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            audit: config.audit.clone(),
            session_id,
            actor: config.session.actor.clone(),
            workspace: config.session.workspace.clone(),
            runner: runner.into(),
            pid,
            terminal: TerminalSurfaceConfig::from_layer(
                &config.surfaces.terminal,
                config.policies.clone(),
            ),
        })
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn actor(&self) -> &SessionActorLayerConfig {
        &self.actor
    }

    #[must_use]
    pub fn workspace(&self) -> Option<&Path> {
        self.workspace.as_deref()
    }

    #[must_use]
    pub const fn runner(&self) -> &SessionRunnerConfig {
        &self.runner
    }

    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    #[must_use]
    pub const fn terminal(&self) -> &TerminalSurfaceConfig {
        &self.terminal
    }

    #[must_use]
    pub const fn tty(&self) -> bool {
        self.terminal.tty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRunnerConfig {
    kind: SessionRunnerKind,
    docker: DockerSessionRunnerConfig,
    linux_host: LinuxHostSessionRunnerConfig,
}

impl SessionRunnerConfig {
    #[must_use]
    pub const fn kind(&self) -> SessionRunnerKind {
        self.kind
    }

    #[must_use]
    pub const fn docker(&self) -> &DockerSessionRunnerConfig {
        &self.docker
    }

    #[must_use]
    pub const fn linux_host(&self) -> &LinuxHostSessionRunnerConfig {
        &self.linux_host
    }
}

impl From<SessionRunnerLayerConfig> for SessionRunnerConfig {
    fn from(config: SessionRunnerLayerConfig) -> Self {
        Self {
            kind: config.kind,
            docker: config.docker.into(),
            linux_host: config.linux_host.into(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinuxHostSessionRunnerConfig {}

impl From<LinuxHostSessionRunnerLayerConfig> for LinuxHostSessionRunnerConfig {
    fn from(_config: LinuxHostSessionRunnerLayerConfig) -> Self {
        Self {}
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionRunnerConfig {
    image: String,
    network: String,
    workdir: PathBuf,
}

impl DockerSessionRunnerConfig {
    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    #[must_use]
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    #[must_use]
    pub fn needs_host_reachable_endpoints(&self) -> bool {
        !self.network.eq_ignore_ascii_case("host") && !self.network.eq_ignore_ascii_case("none")
    }
}

impl From<DockerSessionRunnerLayerConfig> for DockerSessionRunnerConfig {
    fn from(config: DockerSessionRunnerLayerConfig) -> Self {
        Self {
            image: config.image,
            network: config.network,
            workdir: config.workdir,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DockerSessionEnvironment {
    variables: Vec<(String, String)>,
    requires_host_gateway: bool,
}

fn docker_environment_for_session(
    docker: &DockerSessionRunnerConfig,
    environment: &[(String, String)],
) -> DockerSessionEnvironment {
    let mut requires_host_gateway = false;
    let variables = environment
        .iter()
        .map(|(key, value)| {
            let value = if let Some(rewritten) = docker_reachable_endpoint_value(docker, value) {
                requires_host_gateway = true;
                rewritten
            } else {
                value.clone()
            };
            (key.clone(), value)
        })
        .collect();

    DockerSessionEnvironment {
        variables,
        requires_host_gateway,
    }
}

fn docker_reachable_endpoint_value(
    docker: &DockerSessionRunnerConfig,
    value: &str,
) -> Option<String> {
    if !docker.needs_host_reachable_endpoints() {
        return None;
    }

    for host in ["127.0.0.1", "localhost", "0.0.0.0"] {
        for scheme in ["ws", "http"] {
            let prefix = format!("{scheme}://{host}");
            if let Some(suffix) = value.strip_prefix(&prefix) {
                return Some(format!("{scheme}://host.docker.internal{suffix}"));
            }
        }
    }

    None
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionCommandPlan {
    program: String,
    args: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DockerSessionCommandOptions {
    extra_environment: Vec<(String, String)>,
    mounts: Vec<DockerSessionMount>,
    entrypoint: Option<String>,
}

impl DockerSessionCommandOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_environment.push((key.into(), value.into()));
        self
    }

    #[must_use]
    pub fn with_mount(mut self, mount: DockerSessionMount) -> Self {
        self.mounts.push(mount);
        self
    }

    #[must_use]
    pub fn with_entrypoint(mut self, entrypoint: impl Into<String>) -> Self {
        self.entrypoint = Some(entrypoint.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionMount {
    host_path: PathBuf,
    container_path: PathBuf,
    read_only: bool,
}

impl DockerSessionMount {
    #[must_use]
    pub fn new(host_path: impl Into<PathBuf>, container_path: impl Into<PathBuf>) -> Self {
        Self {
            host_path: host_path.into(),
            container_path: container_path.into(),
            read_only: false,
        }
    }

    #[must_use]
    pub const fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }
}

impl DockerSessionCommandPlan {
    #[must_use]
    pub fn from_session_run_plan(plan: &SessionRunPlan) -> Self {
        Self::from_session_run_plan_with_environment(plan, &[])
    }

    #[must_use]
    pub fn from_session_run_plan_with_environment(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Self {
        Self::from_session_run_plan_with_environment_and_options(
            plan,
            environment,
            &DockerSessionCommandOptions::default(),
        )
    }

    #[must_use]
    pub fn from_session_run_plan_with_environment_and_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &DockerSessionCommandOptions,
    ) -> Self {
        Self::from_session_run_plan_with_command_and_environment(
            plan,
            environment,
            plan.command(),
            false,
            options,
        )
    }

    #[must_use]
    pub fn detached_from_session_run_plan_with_command_and_environment(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        command: &[String],
    ) -> Self {
        Self::from_session_run_plan_with_command_and_environment(
            plan,
            environment,
            command,
            true,
            &DockerSessionCommandOptions::default(),
        )
    }

    fn from_session_run_plan_with_command_and_environment(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        command: &[String],
        detached: bool,
        options: &DockerSessionCommandOptions,
    ) -> Self {
        let docker = plan.runner().docker();
        let mut combined_environment = environment.to_vec();
        combined_environment.extend(options.extra_environment.iter().cloned());
        let environment = docker_environment_for_session(docker, &combined_environment);
        let mut args = vec![
            String::from("run"),
            String::from("--rm"),
            String::from("--name"),
            docker_container_name_for_session(plan.session_id()),
            String::from("--label"),
            format!("dev.erebor.session_id={}", plan.session_id().as_str()),
            String::from("--label"),
            format!("dev.erebor.actor_id={}", plan.actor().id),
            String::from("--network"),
            docker.network().to_owned(),
            String::from("-e"),
            format!("EREBOR_SESSION_ID={}", plan.session_id().as_str()),
            String::from("-e"),
            format!("EREBOR_ACTOR_ID={}", plan.actor().id),
            String::from("-e"),
            String::from("EREBOR_SESSION_RUNNER=docker"),
        ];

        if detached {
            args.push(String::from("-d"));
        }

        if plan.tty() {
            args.push(String::from("-i"));
            args.push(String::from("-t"));
        }

        if environment.requires_host_gateway {
            args.push(String::from("--add-host"));
            args.push(String::from("host.docker.internal:host-gateway"));
        }

        for (key, value) in environment.variables {
            args.push(String::from("-e"));
            args.push(format!("{key}={value}"));
        }

        for mount in &options.mounts {
            args.push(String::from("-v"));
            let mut spec = format!(
                "{}:{}",
                mount.host_path.display(),
                mount.container_path.display()
            );
            if mount.read_only {
                spec.push_str(":ro");
            }
            args.push(spec);
        }

        if let Some(workspace) = plan.workspace() {
            args.push(String::from("-v"));
            args.push(format!(
                "{}:{}",
                workspace.display(),
                docker.workdir().display()
            ));
            args.push(String::from("-w"));
            args.push(docker.workdir().display().to_string());
        }

        if let Some(entrypoint) = options.entrypoint.as_deref() {
            args.push(String::from("--entrypoint"));
            args.push(entrypoint.to_owned());
        }

        args.push(docker.image().to_owned());
        args.extend(command.iter().cloned());

        Self {
            program: String::from("docker"),
            args,
        }
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHostSessionCommandPlan {
    program: String,
    args: Vec<String>,
    environment: Vec<(String, String)>,
    current_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinuxHostSessionCommandOptions {
    extra_environment: Vec<(String, String)>,
    wrapper_program: Option<PathBuf>,
    adopt_pid: Option<i32>,
}

impl LinuxHostSessionCommandOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_environment.push((key.into(), value.into()));
        self
    }

    #[must_use]
    pub fn with_wrapper_program(mut self, wrapper: impl Into<PathBuf>) -> Self {
        self.wrapper_program = Some(wrapper.into());
        self
    }

    #[must_use]
    pub const fn with_adopt_pid(mut self, pid: i32) -> Self {
        self.adopt_pid = Some(pid);
        self
    }
}

impl LinuxHostSessionCommandPlan {
    #[must_use]
    pub fn from_session_run_plan(plan: &SessionRunPlan) -> Self {
        Self::from_session_run_plan_with_environment(plan, &[])
    }

    #[must_use]
    pub fn from_session_run_plan_with_environment(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Self {
        Self::from_session_run_plan_with_environment_and_options(
            plan,
            environment,
            &LinuxHostSessionCommandOptions::default(),
        )
    }

    #[must_use]
    pub fn from_session_run_plan_with_environment_and_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Self {
        let mut combined_environment =
            linux_host_base_environment(plan.session_id(), &plan.actor().id);
        combined_environment.extend(environment.iter().cloned());
        combined_environment.extend(options.extra_environment.iter().cloned());

        let (program, args) = if let Some(wrapper) = options.wrapper_program.as_ref() {
            (
                wrapper.display().to_string(),
                plan.command().iter().map(ToOwned::to_owned).collect(),
            )
        } else {
            let command = plan.command();
            (
                command[0].clone(),
                command.iter().skip(1).map(ToOwned::to_owned).collect(),
            )
        };

        Self {
            program,
            args,
            environment: combined_environment,
            current_dir: plan.workspace().map(Path::to_path_buf),
        }
    }

    #[must_use]
    pub fn from_session_adopt_plan_with_environment_and_options(
        plan: &SessionAdoptPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Self {
        let mut combined_environment =
            linux_host_base_environment(plan.session_id(), &plan.actor().id);
        combined_environment.extend(environment.iter().cloned());
        combined_environment.extend(options.extra_environment.iter().cloned());
        combined_environment.push((
            String::from("EREBOR_GUARD_ADOPT_PID"),
            options.adopt_pid.unwrap_or_else(|| plan.pid()).to_string(),
        ));

        let program = options
            .wrapper_program
            .as_ref()
            .map_or_else(String::new, |wrapper| wrapper.display().to_string());

        Self {
            program,
            args: Vec::new(),
            environment: combined_environment,
            current_dir: plan.workspace().map(Path::to_path_buf),
        }
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    #[must_use]
    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    #[must_use]
    pub fn current_dir(&self) -> Option<&Path> {
        self.current_dir.as_deref()
    }
}

fn linux_host_base_environment(session_id: &SessionId, actor_id: &str) -> Vec<(String, String)> {
    vec![
        (
            String::from("EREBOR_SESSION_ID"),
            session_id.as_str().to_owned(),
        ),
        (String::from("EREBOR_ACTOR_ID"), actor_id.to_owned()),
        (
            String::from("EREBOR_SESSION_RUNNER"),
            SessionRunnerKind::LinuxHost.as_str().to_owned(),
        ),
    ]
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct SessionSurfaceLayers {
    #[serde(default)]
    pub browser_cdp: BrowserCdpSurfaceLayerConfig,
    #[serde(default)]
    pub mcp: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub terminal: TerminalSurfaceLayerConfig,
    #[serde(default)]
    pub network: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub saas: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub desktop: SessionSurfaceToggleConfig,
    #[serde(default)]
    pub internal_system: SessionSurfaceToggleConfig,
}

impl SessionSurfaceLayers {
    #[must_use]
    pub fn enabled_surfaces(&self) -> Vec<SessionSurfaceKind> {
        let candidates = [
            (SessionSurfaceKind::BrowserCdp, self.browser_cdp.enabled),
            (SessionSurfaceKind::Mcp, self.mcp.enabled),
            (SessionSurfaceKind::Terminal, self.terminal.enabled),
            (SessionSurfaceKind::Network, self.network.enabled),
            (SessionSurfaceKind::Saas, self.saas.enabled),
            (SessionSurfaceKind::Desktop, self.desktop.enabled),
            (
                SessionSurfaceKind::InternalSystem,
                self.internal_system.enabled,
            ),
        ];

        candidates
            .into_iter()
            .filter_map(|(layer, enabled)| enabled.then_some(layer))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct BrowserCdpSurfaceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub policies: Vec<PathBuf>,
    #[serde(default)]
    pub browser_url: Option<String>,
    #[serde(default = "default_browser_cdp_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub browser: BrowserLaunchLayerConfig,
}

impl Default for BrowserCdpSurfaceLayerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policies: Vec::new(),
            browser_url: None,
            listen: default_browser_cdp_listen(),
            browser: BrowserLaunchLayerConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct BrowserLaunchLayerConfig {
    #[serde(default)]
    pub executable: Option<PathBuf>,
    #[serde(default)]
    pub user_data_dir: Option<PathBuf>,
    #[serde(default = "default_browser_headless")]
    pub headless: bool,
}

impl Default for BrowserLaunchLayerConfig {
    fn default() -> Self {
        Self {
            executable: None,
            user_data_dir: None,
            headless: default_browser_headless(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct SessionSurfaceToggleConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct TerminalSurfaceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tty: bool,
    #[serde(default)]
    pub policies: Vec<PathBuf>,
    #[serde(default)]
    pub process_guard: TerminalProcessGuardLayerConfig,
    #[serde(
        default,
        alias = "process_interception",
        alias = "browser_launch_mediation"
    )]
    pub process_mediation: TerminalProcessMediationLayerConfig,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct TerminalProcessGuardLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: TerminalProcessGuardBackend,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalProcessGuardBackend {
    #[default]
    #[serde(alias = "linux-ptrace")]
    LinuxPtrace,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct TerminalProcessMediationLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: TerminalProcessMediationMode,
    #[serde(default)]
    pub handlers: Vec<ProcessMediationHandlerLayerConfig>,
}

impl TerminalProcessMediationLayerConfig {
    fn validate(
        &self,
        terminal_enabled: bool,
        process_guard_enabled: bool,
        browser_cdp: &BrowserCdpSurfaceLayerConfig,
    ) -> Result<(), RuntimeConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if !terminal_enabled {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                "terminal surface must be enabled",
            ));
        }

        if !process_guard_enabled {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                "terminal process interception requires process_guard.enabled=true",
            ));
        }

        if self.handlers.is_empty() {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                "at least one process interception handler is required",
            ));
        }

        let mut ids = HashSet::new();
        for handler in &self.handlers {
            handler.validate(browser_cdp)?;
            if !ids.insert(handler.id.clone()) {
                return Err(RuntimeConfigError::invalid_process_mediation_config(
                    format!(
                        "process interception handler `{}` is duplicated",
                        handler.id
                    ),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalProcessMediationMode {
    #[default]
    Shim,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessInterceptionDecision {
    Allow,
    Deny,
    #[serde(alias = "approval_required", alias = "require_verification")]
    RequireApproval,
    #[default]
    Mediate,
}

impl ProcessInterceptionDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
            Self::Mediate => "mediate",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct ProcessMediationHandlerLayerConfig {
    pub id: String,
    #[serde(default)]
    pub decision: ProcessInterceptionDecision,
    pub kind: ProcessMediationHandlerKind,
    #[serde(rename = "match")]
    pub matcher: ProcessMediationMatcherLayerConfig,
    #[serde(default)]
    pub requested_endpoint: ProcessMediationRequestedEndpointLayerConfig,
    #[serde(default)]
    pub replacement: ProcessMediationReplacementLayerConfig,
    #[serde(default)]
    pub environment: ProcessMediationEnvironmentLayerConfig,
    #[serde(default)]
    pub compatibility: ProcessMediationCompatibilityLayerConfig,
}

impl ProcessMediationHandlerLayerConfig {
    fn validate(
        &self,
        browser_cdp: &BrowserCdpSurfaceLayerConfig,
    ) -> Result<(), RuntimeConfigError> {
        if self.id.trim().is_empty() {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                "process interception handler id cannot be empty",
            ));
        }

        self.matcher.validate(&self.id)?;
        self.requested_endpoint.validate(&self.id)?;
        self.environment.validate(&self.id)?;

        if self.kind == ProcessMediationHandlerKind::ManagedBrowserCdp {
            if self.replacement.surface != ProcessMediationReplacementSurface::BrowserCdp {
                return Err(RuntimeConfigError::invalid_process_mediation_config(
                    format!(
                        "handler `{}` kind managed_browser_cdp must replace with browser_cdp",
                        self.id
                    ),
                ));
            }

            if !browser_cdp.enabled {
                return Err(RuntimeConfigError::invalid_process_mediation_config(
                    format!(
                        "handler `{}` kind managed_browser_cdp requires browser_cdp surface enabled",
                        self.id
                    ),
                ));
            }

            if browser_cdp.listen.port() == 0 {
                return Err(RuntimeConfigError::invalid_process_mediation_config(
                    format!(
                        "handler `{}` requires browser_cdp.listen to use a fixed port in v1",
                        self.id
                    ),
                ));
            }

            if !self.requested_endpoint.allowed_ports.is_empty()
                && !self
                    .requested_endpoint
                    .allowed_ports
                    .contains(&browser_cdp.listen.port())
            {
                return Err(RuntimeConfigError::invalid_process_mediation_config(
                    format!(
                        "handler `{}` allowed_ports must include browser_cdp.listen port {}",
                        self.id,
                        browser_cdp.listen.port()
                    ),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMediationHandlerKind {
    ManagedBrowserCdp,
}

impl ProcessMediationHandlerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManagedBrowserCdp => "managed_browser_cdp",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct ProcessMediationMatcherLayerConfig {
    #[serde(default)]
    pub executables: Vec<String>,
    #[serde(default)]
    pub required_args: Vec<String>,
    #[serde(default)]
    pub require_remote_debugging_port: bool,
}

impl ProcessMediationMatcherLayerConfig {
    fn validate(&self, handler_id: &str) -> Result<(), RuntimeConfigError> {
        if self.executables.is_empty() {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                format!("handler `{handler_id}` must include at least one executable matcher"),
            ));
        }

        if self
            .executables
            .iter()
            .any(|executable| executable.trim().is_empty())
        {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                format!("handler `{handler_id}` executable matchers cannot be empty"),
            ));
        }

        if self
            .required_args
            .iter()
            .any(|argument| argument.trim().is_empty())
        {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                format!("handler `{handler_id}` required args cannot be empty"),
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct ProcessMediationRequestedEndpointLayerConfig {
    #[serde(default = "default_process_mediation_endpoint_source")]
    pub source: ProcessMediationEndpointSource,
    #[serde(default = "default_loopback_ip")]
    pub bind: IpAddr,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
}

impl Default for ProcessMediationRequestedEndpointLayerConfig {
    fn default() -> Self {
        Self {
            source: default_process_mediation_endpoint_source(),
            bind: default_loopback_ip(),
            allowed_ports: Vec::new(),
        }
    }
}

impl ProcessMediationRequestedEndpointLayerConfig {
    fn validate(&self, handler_id: &str) -> Result<(), RuntimeConfigError> {
        if !self.bind.is_loopback() {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                format!("handler `{handler_id}` requested endpoint bind must be loopback"),
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMediationEndpointSource {
    #[default]
    RemoteDebuggingPort,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct ProcessMediationReplacementLayerConfig {
    #[serde(default = "default_process_mediation_replacement_surface")]
    pub surface: ProcessMediationReplacementSurface,
}

impl Default for ProcessMediationReplacementLayerConfig {
    fn default() -> Self {
        Self {
            surface: default_process_mediation_replacement_surface(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMediationReplacementSurface {
    BrowserCdp,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct ProcessMediationEnvironmentLayerConfig {
    #[serde(default = "default_process_mediation_prepend_path")]
    pub prepend_path: bool,
    #[serde(default)]
    pub executable_env: Vec<String>,
}

impl Default for ProcessMediationEnvironmentLayerConfig {
    fn default() -> Self {
        Self {
            prepend_path: default_process_mediation_prepend_path(),
            executable_env: Vec::new(),
        }
    }
}

impl ProcessMediationEnvironmentLayerConfig {
    fn validate(&self, handler_id: &str) -> Result<(), RuntimeConfigError> {
        if self
            .executable_env
            .iter()
            .any(|variable| variable.trim().is_empty() || variable.contains('='))
        {
            return Err(RuntimeConfigError::invalid_process_mediation_config(
                format!(
                    "handler `{handler_id}` executable env names cannot be empty or contain `=`"
                ),
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
pub struct ProcessMediationCompatibilityLayerConfig {
    #[serde(default = "default_process_mediation_print_devtools")]
    pub print_devtools_listening_line: bool,
    #[serde(default = "default_process_mediation_keepalive")]
    pub keepalive: bool,
}

impl Default for ProcessMediationCompatibilityLayerConfig {
    fn default() -> Self {
        Self {
            print_devtools_listening_line: default_process_mediation_print_devtools(),
            keepalive: default_process_mediation_keepalive(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalSurfaceConfig {
    tty: bool,
    policies: Vec<PathBuf>,
    process_guard: TerminalProcessGuardConfig,
    process_mediation: TerminalProcessMediationConfig,
}

impl TerminalSurfaceConfig {
    #[must_use]
    pub const fn tty(&self) -> bool {
        self.tty
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn process_guard(&self) -> &TerminalProcessGuardConfig {
        &self.process_guard
    }

    #[must_use]
    pub const fn process_mediation(&self) -> &TerminalProcessMediationConfig {
        &self.process_mediation
    }

    #[must_use]
    pub const fn process_interception(&self) -> &TerminalProcessMediationConfig {
        &self.process_mediation
    }

    fn from_layer(config: &TerminalSurfaceLayerConfig, default_policies: Vec<PathBuf>) -> Self {
        Self {
            tty: config.tty,
            policies: surface_policies(&config.policies, default_policies),
            process_guard: config.process_guard.into(),
            process_mediation: config.process_mediation.clone().into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TerminalProcessGuardConfig {
    enabled: bool,
    backend: TerminalProcessGuardBackend,
}

impl TerminalProcessGuardConfig {
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn backend(&self) -> TerminalProcessGuardBackend {
        self.backend
    }
}

impl From<TerminalProcessGuardLayerConfig> for TerminalProcessGuardConfig {
    fn from(config: TerminalProcessGuardLayerConfig) -> Self {
        Self {
            enabled: config.enabled,
            backend: config.backend,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalProcessMediationConfig {
    enabled: bool,
    mode: TerminalProcessMediationMode,
    handlers: Vec<ProcessMediationHandlerConfig>,
}

impl TerminalProcessMediationConfig {
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn mode(&self) -> TerminalProcessMediationMode {
        self.mode
    }

    #[must_use]
    pub fn handlers(&self) -> &[ProcessMediationHandlerConfig] {
        &self.handlers
    }
}

impl From<TerminalProcessMediationLayerConfig> for TerminalProcessMediationConfig {
    fn from(config: TerminalProcessMediationLayerConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: config.mode,
            handlers: config.handlers.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationHandlerConfig {
    id: String,
    kind: ProcessMediationHandlerKind,
    matcher: ProcessMediationMatcherConfig,
    requested_endpoint: ProcessMediationRequestedEndpointConfig,
    replacement: ProcessMediationReplacementConfig,
    environment: ProcessMediationEnvironmentConfig,
    compatibility: ProcessMediationCompatibilityConfig,
    decision: ProcessInterceptionDecision,
}

impl ProcessMediationHandlerConfig {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn kind(&self) -> ProcessMediationHandlerKind {
        self.kind
    }

    #[must_use]
    pub const fn decision(&self) -> ProcessInterceptionDecision {
        self.decision
    }

    #[must_use]
    pub const fn matcher(&self) -> &ProcessMediationMatcherConfig {
        &self.matcher
    }

    #[must_use]
    pub const fn requested_endpoint(&self) -> &ProcessMediationRequestedEndpointConfig {
        &self.requested_endpoint
    }

    #[must_use]
    pub const fn replacement(&self) -> &ProcessMediationReplacementConfig {
        &self.replacement
    }

    #[must_use]
    pub const fn environment(&self) -> &ProcessMediationEnvironmentConfig {
        &self.environment
    }

    #[must_use]
    pub const fn compatibility(&self) -> &ProcessMediationCompatibilityConfig {
        &self.compatibility
    }
}

impl From<ProcessMediationHandlerLayerConfig> for ProcessMediationHandlerConfig {
    fn from(config: ProcessMediationHandlerLayerConfig) -> Self {
        Self {
            id: config.id,
            decision: config.decision,
            kind: config.kind,
            matcher: config.matcher.into(),
            requested_endpoint: config.requested_endpoint.into(),
            replacement: config.replacement.into(),
            environment: config.environment.into(),
            compatibility: config.compatibility.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationMatcherConfig {
    executables: Vec<String>,
    required_args: Vec<String>,
    require_remote_debugging_port: bool,
}

impl ProcessMediationMatcherConfig {
    #[must_use]
    pub fn executables(&self) -> &[String] {
        &self.executables
    }

    #[must_use]
    pub fn required_args(&self) -> &[String] {
        &self.required_args
    }

    #[must_use]
    pub const fn require_remote_debugging_port(&self) -> bool {
        self.require_remote_debugging_port
    }
}

impl From<ProcessMediationMatcherLayerConfig> for ProcessMediationMatcherConfig {
    fn from(config: ProcessMediationMatcherLayerConfig) -> Self {
        Self {
            executables: config.executables,
            required_args: config.required_args,
            require_remote_debugging_port: config.require_remote_debugging_port,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationRequestedEndpointConfig {
    source: ProcessMediationEndpointSource,
    bind: IpAddr,
    allowed_ports: Vec<u16>,
}

impl ProcessMediationRequestedEndpointConfig {
    #[must_use]
    pub const fn source(&self) -> ProcessMediationEndpointSource {
        self.source
    }

    #[must_use]
    pub const fn bind(&self) -> IpAddr {
        self.bind
    }

    #[must_use]
    pub fn allowed_ports(&self) -> &[u16] {
        &self.allowed_ports
    }
}

impl From<ProcessMediationRequestedEndpointLayerConfig>
    for ProcessMediationRequestedEndpointConfig
{
    fn from(config: ProcessMediationRequestedEndpointLayerConfig) -> Self {
        Self {
            source: config.source,
            bind: config.bind,
            allowed_ports: config.allowed_ports,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMediationReplacementConfig {
    surface: ProcessMediationReplacementSurface,
}

impl ProcessMediationReplacementConfig {
    #[must_use]
    pub const fn surface(&self) -> ProcessMediationReplacementSurface {
        self.surface
    }
}

impl From<ProcessMediationReplacementLayerConfig> for ProcessMediationReplacementConfig {
    fn from(config: ProcessMediationReplacementLayerConfig) -> Self {
        Self {
            surface: config.surface,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessMediationEnvironmentConfig {
    prepend_path: bool,
    executable_env: Vec<String>,
}

impl ProcessMediationEnvironmentConfig {
    #[must_use]
    pub const fn prepend_path(&self) -> bool {
        self.prepend_path
    }

    #[must_use]
    pub fn executable_env(&self) -> &[String] {
        &self.executable_env
    }
}

impl From<ProcessMediationEnvironmentLayerConfig> for ProcessMediationEnvironmentConfig {
    fn from(config: ProcessMediationEnvironmentLayerConfig) -> Self {
        Self {
            prepend_path: config.prepend_path,
            executable_env: config.executable_env,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessMediationCompatibilityConfig {
    print_devtools_listening_line: bool,
    keepalive: bool,
}

impl ProcessMediationCompatibilityConfig {
    #[must_use]
    pub const fn print_devtools_listening_line(&self) -> bool {
        self.print_devtools_listening_line
    }

    #[must_use]
    pub const fn keepalive(&self) -> bool {
        self.keepalive
    }
}

impl From<ProcessMediationCompatibilityLayerConfig> for ProcessMediationCompatibilityConfig {
    fn from(config: ProcessMediationCompatibilityLayerConfig) -> Self {
        Self {
            print_devtools_listening_line: config.print_devtools_listening_line,
            keepalive: config.keepalive,
        }
    }
}

pub type TerminalProcessInterceptionConfig = TerminalProcessMediationConfig;
pub type TerminalProcessInterceptionLayerConfig = TerminalProcessMediationLayerConfig;
pub type TerminalProcessInterceptionMode = TerminalProcessMediationMode;
pub type ProcessInterceptionHandlerConfig = ProcessMediationHandlerConfig;
pub type ProcessInterceptionHandlerKind = ProcessMediationHandlerKind;

impl TerminalProcessGuardBackend {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxPtrace => "linux_ptrace",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserCdpSurfaceConfig {
    policies: Vec<PathBuf>,
    listen: SocketAddr,
    browser_url: Option<String>,
    browser: BrowserLaunchConfig,
}

impl BrowserCdpSurfaceConfig {
    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    #[must_use]
    pub fn browser_url(&self) -> Option<&str> {
        self.browser_url.as_deref()
    }

    #[must_use]
    pub const fn browser(&self) -> &BrowserLaunchConfig {
        &self.browser
    }

    #[must_use]
    pub const fn owns_browser(&self) -> bool {
        self.browser_url.is_none()
    }

    fn from_layer(config: &BrowserCdpSurfaceLayerConfig, default_policies: Vec<PathBuf>) -> Self {
        Self {
            policies: surface_policies(&config.policies, default_policies),
            listen: config.listen,
            browser_url: config.browser_url.clone(),
            browser: config.browser.clone().into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserLaunchConfig {
    executable: Option<PathBuf>,
    user_data_dir: Option<PathBuf>,
    headless: bool,
}

impl BrowserLaunchConfig {
    #[must_use]
    pub fn executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }

    #[must_use]
    pub fn user_data_dir(&self) -> Option<&Path> {
        self.user_data_dir.as_deref()
    }

    #[must_use]
    pub const fn headless(&self) -> bool {
        self.headless
    }
}

impl From<BrowserLaunchLayerConfig> for BrowserLaunchConfig {
    fn from(config: BrowserLaunchLayerConfig) -> Self {
        Self {
            executable: config.executable,
            user_data_dir: config.user_data_dir,
            headless: config.headless,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionSurfaceKind {
    BrowserCdp,
    Mcp,
    Terminal,
    Network,
    Saas,
    Desktop,
    InternalSystem,
}

impl SessionSurfaceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserCdp => "browser_cdp",
            Self::Mcp => "mcp",
            Self::Terminal => "terminal",
            Self::Network => "network",
            Self::Saas => "saas",
            Self::Desktop => "desktop",
            Self::InternalSystem => "internal_system",
        }
    }
}

pub fn validate_policy_path(path: &Path) -> Result<(), RuntimeConfigError> {
    if path.as_os_str().is_empty() {
        Err(RuntimeConfigError::empty_policy_path())
    } else {
        Ok(())
    }
}

fn default_browser_cdp_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

const fn default_loopback_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn surface_policies(surface_policies: &[PathBuf], default_policies: Vec<PathBuf>) -> Vec<PathBuf> {
    if surface_policies.is_empty() {
        default_policies
    } else {
        surface_policies.to_vec()
    }
}

const fn default_browser_headless() -> bool {
    true
}

const fn default_process_mediation_endpoint_source() -> ProcessMediationEndpointSource {
    ProcessMediationEndpointSource::RemoteDebuggingPort
}

const fn default_process_mediation_replacement_surface() -> ProcessMediationReplacementSurface {
    ProcessMediationReplacementSurface::BrowserCdp
}

const fn default_process_mediation_prepend_path() -> bool {
    true
}

const fn default_process_mediation_print_devtools() -> bool {
    true
}

const fn default_process_mediation_keepalive() -> bool {
    true
}

fn default_session_actor_id() -> String {
    String::from("agent")
}

const fn default_session_actor_kind() -> ActorKind {
    ActorKind::Agent
}

const fn default_session_runner_kind() -> SessionRunnerKind {
    SessionRunnerKind::Docker
}

fn default_docker_session_image() -> String {
    String::from("alpine:3.20")
}

fn default_docker_session_network() -> String {
    String::from("bridge")
}

fn default_docker_session_workdir() -> PathBuf {
    PathBuf::from("/workspace")
}

#[must_use]
pub fn docker_container_name_for_session(session_id: &SessionId) -> String {
    let suffix = session_id
        .as_str()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect::<String>();

    if suffix.is_empty() {
        String::from("erebor-session")
    } else {
        format!("erebor-{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        path::{Path, PathBuf},
    };

    use erebor_runtime_events::SessionId;

    use crate::{
        DockerSessionCommandPlan, LinuxHostSessionCommandOptions, LinuxHostSessionCommandPlan,
        ProcessInterceptionDecision, ProcessMediationEndpointSource, ProcessMediationHandlerKind,
        RuntimeConfig, RuntimeConfigError, SessionAdoptPlan, SessionRunPlan, SessionRunnerKind,
        SessionSurfaceKind, TerminalProcessGuardBackend, TerminalProcessMediationMode,
    };

    #[test]
    fn loads_config_with_multiple_session_surfaces() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;

        assert_eq!(
            config.enabled_surfaces(),
            vec![SessionSurfaceKind::BrowserCdp, SessionSurfaceKind::Terminal]
        );

        Ok(())
    }

    #[test]
    fn terminal_process_guard_is_explicit_runtime_config() -> Result<(), RuntimeConfigError> {
        let default_config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let default_plan = default_config.surface_start_plan()?;
        let default_terminal = default_plan
            .terminal()
            .ok_or_else(RuntimeConfigError::no_session_surfaces)?;

        assert!(!default_terminal.process_guard().enabled());

        let guarded_config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_guard": {
                    "enabled": true,
                    "backend": "linux_ptrace"
                  }
                }
              }
            }
            "#,
        )?;
        let guarded_plan = guarded_config.surface_start_plan()?;
        let guarded_terminal = guarded_plan
            .terminal()
            .ok_or_else(RuntimeConfigError::no_session_surfaces)?;

        assert!(guarded_terminal.process_guard().enabled());
        assert_eq!(
            guarded_terminal.process_guard().backend(),
            TerminalProcessGuardBackend::LinuxPtrace
        );

        Ok(())
    }

    #[test]
    fn terminal_process_interception_is_generic_runtime_config() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_guard": {
                    "enabled": true,
                    "backend": "linux_ptrace"
                  },
                  "process_interception": {
                    "enabled": true,
                    "mode": "shim",
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "decision": "mediate",
                        "kind": "managed_browser_cdp",
                        "match": {
                          "executables": ["google-chrome", "chromium"],
                          "required_args": ["--remote-debugging-port"],
                          "require_remote_debugging_port": true
                        },
                        "requested_endpoint": {
                          "source": "remote_debugging_port",
                          "bind": "127.0.0.1",
                          "allowed_ports": [9222]
                        },
                        "replacement": {
                          "surface": "browser_cdp"
                        },
                        "environment": {
                          "prepend_path": true,
                          "executable_env": ["CHROME_PATH"]
                        },
                        "compatibility": {
                          "print_devtools_listening_line": true,
                          "keepalive": true
                        }
                      }
                    ]
                  }
                },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:9222"
                }
              }
            }
            "#,
        )?;

        let terminal = config
            .surface_start_plan()?
            .terminal()
            .ok_or_else(RuntimeConfigError::no_session_surfaces)?
            .clone();
        let interception = terminal.process_interception();
        let handler = interception
            .handlers()
            .first()
            .ok_or_else(RuntimeConfigError::no_session_surfaces)?;

        assert!(interception.enabled());
        assert_eq!(interception.mode(), TerminalProcessMediationMode::Shim);
        assert_eq!(handler.id(), "managed-browser-cdp");
        assert_eq!(handler.decision(), ProcessInterceptionDecision::Mediate);
        assert_eq!(
            handler.kind(),
            ProcessMediationHandlerKind::ManagedBrowserCdp
        );
        assert_eq!(
            handler.requested_endpoint().source(),
            ProcessMediationEndpointSource::RemoteDebuggingPort
        );
        assert_eq!(
            handler.matcher().executables(),
            &["google-chrome", "chromium"]
        );
        assert_eq!(handler.requested_endpoint().allowed_ports(), &[9222]);
        assert_eq!(handler.environment().executable_env(), &["CHROME_PATH"]);

        Ok(())
    }

    #[test]
    fn rejects_process_mediation_without_browser_cdp_surface() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_guard": { "enabled": true },
                  "process_interception": {
                    "enabled": true,
                    "handlers": [
                      {
                        "id": "managed-browser-cdp",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] }
                      }
                    ]
                  }
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::InvalidProcessMediationConfig { .. })
        ));
    }

    #[test]
    fn rejects_config_without_policies() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": [],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::MissingPolicy { .. })
        ));
    }

    #[test]
    fn rejects_empty_policy_paths() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": [""],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptyPolicyPath { .. })
        ));
    }

    #[test]
    fn rejects_config_without_enabled_session_surfaces_or_session() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {}
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::NoSessionSurfaces { .. })
        ));
    }

    #[test]
    fn creates_start_plan_from_config() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json", "policies/terminal.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo",
                  "listen": "127.0.0.1:3738"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = config.surface_start_plan()?;

        assert_eq!(plan.policies().len(), 2);
        assert_eq!(plan.audit().jsonl(), None);
        assert!(plan.contains_surface(SessionSurfaceKind::BrowserCdp));
        assert!(plan.contains_surface(SessionSurfaceKind::Terminal));
        assert!(!plan.contains_surface(SessionSurfaceKind::Mcp));
        assert!(plan.terminal().is_some());
        assert_eq!(
            plan.browser_cdp().map(|config| config.browser_url()),
            Some(Some("ws://127.0.0.1:9222/devtools/browser/demo"))
        );
        assert_eq!(
            plan.browser_cdp().map(|config| config.listen()),
            Some(SocketAddr::from(([127, 0, 0, 1], 3738)))
        );

        Ok(())
    }

    #[test]
    fn creates_session_run_plan_from_config() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "audit": { "jsonl": "audit/pilot.jsonl" },
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw", "kind": "agent" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "kind": "docker",
                  "docker": {
                    "image": "erebor/openclaw-pilot:local",
                    "network": "none",
                    "workdir": "/work"
                  }
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "tty": true,
                  "policies": ["policies/terminal.json"]
                }
              }
            }
            "#,
        )?;

        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            vec![String::from("openclaw"), String::from("--help")],
        )?;

        assert_eq!(plan.policies(), &[Path::new("policies/browser.json")]);
        assert_eq!(plan.audit().jsonl(), Some(Path::new("audit/pilot.jsonl")));
        assert_eq!(plan.session_id().as_str(), "session-1");
        assert_eq!(plan.actor().id, "openclaw");
        assert_eq!(plan.workspace(), Some(Path::new("/tmp/erebor-workspace")));
        assert_eq!(plan.runner().kind(), SessionRunnerKind::Docker);
        assert_eq!(
            plan.runner().docker().image(),
            "erebor/openclaw-pilot:local"
        );
        assert_eq!(plan.runner().docker().network(), "none");
        assert_eq!(plan.runner().docker().workdir(), Path::new("/work"));
        assert!(plan.terminal().tty());
        assert_eq!(
            plan.terminal().policies(),
            &[PathBuf::from("policies/terminal.json")]
        );
        assert_eq!(plan.command(), ["openclaw", "--help"]);

        Ok(())
    }

    #[test]
    fn docker_command_plan_wraps_session_command() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "docker": {
                    "image": "erebor/openclaw-pilot:local",
                    "network": "none",
                    "workdir": "/work"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            vec![String::from("openclaw"), String::from("--help")],
        )?;

        let launch = DockerSessionCommandPlan::from_session_run_plan(&plan);

        assert_eq!(launch.program(), "docker");
        assert_eq!(
            launch.args(),
            &[
                "run",
                "--rm",
                "--name",
                "erebor-session-1",
                "--label",
                "dev.erebor.session_id=session-1",
                "--label",
                "dev.erebor.actor_id=openclaw",
                "--network",
                "none",
                "-e",
                "EREBOR_SESSION_ID=session-1",
                "-e",
                "EREBOR_ACTOR_ID=openclaw",
                "-e",
                "EREBOR_SESSION_RUNNER=docker",
                "-v",
                "/tmp/erebor-workspace:/work",
                "-w",
                "/work",
                "erebor/openclaw-pilot:local",
                "openclaw",
                "--help"
            ]
        );
        Ok(())
    }

    #[test]
    fn linux_host_command_plan_relaunches_local_command_with_session_environment(
    ) -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "kind": "linux_host"
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-1"),
            vec![String::from("openclaw"), String::from("--help")],
        )?;

        let launch = LinuxHostSessionCommandPlan::from_session_run_plan_with_environment(
            &plan,
            &[(
                String::from("EREBOR_BROWSER_CDP_URL"),
                String::from("ws://127.0.0.1:3738/"),
            )],
        );

        assert_eq!(launch.program(), "openclaw");
        assert_eq!(launch.args(), &["--help"]);
        assert_eq!(
            launch.current_dir(),
            Some(Path::new("/tmp/erebor-workspace"))
        );
        assert!(launch
            .environment()
            .contains(&(String::from("EREBOR_SESSION_ID"), String::from("session-1"))));
        assert!(launch
            .environment()
            .contains(&(String::from("EREBOR_ACTOR_ID"), String::from("openclaw"))));
        assert!(launch.environment().contains(&(
            String::from("EREBOR_SESSION_RUNNER"),
            String::from("linux-host")
        )));
        assert!(launch.environment().contains(&(
            String::from("EREBOR_BROWSER_CDP_URL"),
            String::from("ws://127.0.0.1:3738/")
        )));
        Ok(())
    }

    #[test]
    fn linux_host_command_plan_can_wrap_command_with_process_guard(
    ) -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "kind": "linux-host"
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-guard"),
            vec![
                String::from("python3"),
                String::from("-c"),
                String::from("print('hello')"),
            ],
        )?;
        let options = LinuxHostSessionCommandOptions::new()
            .with_wrapper_program("/tmp/erebor-linux-process-guard")
            .with_environment("EREBOR_PROCESS_GUARD", "linux-ptrace");

        let launch =
            LinuxHostSessionCommandPlan::from_session_run_plan_with_environment_and_options(
                &plan,
                &[],
                &options,
            );

        assert_eq!(launch.program(), "/tmp/erebor-linux-process-guard");
        assert_eq!(launch.args(), &["python3", "-c", "print('hello')"]);
        assert!(launch.environment().contains(&(
            String::from("EREBOR_PROCESS_GUARD"),
            String::from("linux-ptrace")
        )));
        Ok(())
    }

    #[test]
    fn linux_host_adopt_plan_sets_guard_pid_environment() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runner": {
                  "kind": "linux-host"
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = SessionAdoptPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-adopt"),
            4242,
        )?;
        let options = LinuxHostSessionCommandOptions::new()
            .with_wrapper_program("/tmp/erebor-linux-process-guard")
            .with_environment("EREBOR_PROCESS_GUARD", "linux-ptrace");

        let launch =
            LinuxHostSessionCommandPlan::from_session_adopt_plan_with_environment_and_options(
                &plan,
                &[],
                &options,
            );

        assert_eq!(launch.program(), "/tmp/erebor-linux-process-guard");
        assert!(launch.args().is_empty());
        assert_eq!(
            launch.current_dir(),
            Some(Path::new("/tmp/erebor-workspace"))
        );
        assert!(launch
            .environment()
            .contains(&(String::from("EREBOR_GUARD_ADOPT_PID"), String::from("4242"))));
        assert!(launch.environment().contains(&(
            String::from("EREBOR_SESSION_RUNNER"),
            String::from("linux-host")
        )));
        Ok(())
    }

    #[test]
    fn docker_command_plan_allocates_tty_when_requested() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "bridge"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true, "tty": true }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-tty"),
            vec![String::from("openclaw")],
        )?;

        let launch = DockerSessionCommandPlan::from_session_run_plan(&plan);

        assert!(launch.args().iter().any(|argument| argument == "-i"));
        assert!(launch.args().iter().any(|argument| argument == "-t"));
        Ok(())
    }

    #[test]
    fn docker_command_plan_injects_session_side_resource_environment(
    ) -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "none"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            vec![
                String::from("printenv"),
                String::from("EREBOR_BROWSER_CDP_URL"),
            ],
        )?;

        let launch = DockerSessionCommandPlan::from_session_run_plan_with_environment(
            &plan,
            &[(
                String::from("EREBOR_BROWSER_CDP_URL"),
                String::from("ws://127.0.0.1:3738/"),
            )],
        );

        assert!(launch.args().windows(2).any(
            |args| args[0] == "-e" && args[1] == "EREBOR_BROWSER_CDP_URL=ws://127.0.0.1:3738/"
        ));
        Ok(())
    }

    #[test]
    fn docker_command_plan_can_start_detached_session_container() -> Result<(), RuntimeConfigError>
    {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "bridge"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-detached"),
            vec![String::from("openclaw")],
        )?;

        let launch =
            DockerSessionCommandPlan::detached_from_session_run_plan_with_command_and_environment(
                &plan,
                &[(
                    String::from("EREBOR_BROWSER_CDP_URL"),
                    String::from("ws://127.0.0.1:3738/"),
                )],
                &[
                    String::from("sh"),
                    String::from("-lc"),
                    String::from("sleep 3600"),
                ],
            );

        assert!(launch.args().iter().any(|argument| argument == "-d"));
        assert!(launch.args().windows(2).any(|args| args[0] == "-e"
            && args[1] == "EREBOR_BROWSER_CDP_URL=ws://host.docker.internal:3738/"));
        assert!(launch.args().ends_with(&[
            String::from("alpine:3.20"),
            String::from("sh"),
            String::from("-lc"),
            String::from("sleep 3600"),
        ]));
        Ok(())
    }

    #[test]
    fn docker_command_plan_rewrites_loopback_endpoints_for_bridge_network(
    ) -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "bridge"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            vec![String::from("printenv")],
        )?;

        let launch = DockerSessionCommandPlan::from_session_run_plan_with_environment(
            &plan,
            &[(
                String::from("EREBOR_BROWSER_CDP_URL"),
                String::from("ws://0.0.0.0:3738/"),
            )],
        );

        assert!(launch
            .args()
            .windows(2)
            .any(|args| args[0] == "--add-host" && args[1] == "host.docker.internal:host-gateway"));
        assert!(launch.args().windows(2).any(|args| args[0] == "-e"
            && args[1] == "EREBOR_BROWSER_CDP_URL=ws://host.docker.internal:3738/"));
        Ok(())
    }

    #[test]
    fn session_surface_start_plan_uses_host_reachable_browser_listen_for_docker_bridge(
    ) -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "bridge"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:0"
                }
              }
            }
            "#,
        )?;
        let session = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            vec![String::from("printenv")],
        )?;

        let start_plan = config.surface_start_plan_for_session(&session)?;

        assert_eq!(
            start_plan.browser_cdp().map(|config| config.listen()),
            Some(SocketAddr::from(([0, 0, 0, 0], 0)))
        );
        Ok(())
    }

    #[test]
    fn creates_session_run_plan_from_named_diagnostic() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "diagnostics": [
                  {
                    "name": "list-workspace",
                    "description": "List workspace files",
                    "command": ["sh", "-lc", "ls -la /workspace | head"]
                  }
                ],
                "runner": {
                  "docker": {
                    "image": "alpine:3.20",
                    "network": "none",
                    "workdir": "/workspace"
                  }
                }
              },
              "surfaces": {
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;

        let plan = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            "list-workspace",
        )?;

        assert_eq!(plan.diagnostic(), Some("list-workspace"));
        assert_eq!(plan.command(), ["sh", "-lc", "ls -la /workspace | head"]);
        Ok(())
    }

    #[test]
    fn rejects_unknown_session_diagnostic() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true }
            }
            "#,
        )?;

        let error = SessionRunPlan::from_diagnostic(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            "list-workspace",
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::UnknownSessionDiagnostic { name, .. })
                if name == "list-workspace"
        ));
        Ok(())
    }

    #[test]
    fn rejects_duplicate_session_diagnostic_names() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "diagnostics": [
                  { "name": "status", "command": ["true"] },
                  { "name": "status", "command": ["true"] }
                ]
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::DuplicateSessionDiagnosticName { name, .. })
                if name == "status"
        ));
    }

    #[test]
    fn rejects_empty_session_diagnostic_command() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "diagnostics": [
                  { "name": "status", "command": [] }
                ]
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptySessionDiagnosticCommand { name, .. })
                if name == "status"
        ));
    }

    #[test]
    fn rejects_empty_session_command() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true }
            }
            "#,
        )?;

        let error = SessionRunPlan::from_config(
            &config,
            SessionRunnerKind::Docker,
            SessionId::new("session-1"),
            Vec::new(),
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptySessionCommand { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_invalid_session_adopt_pid() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true }
            }
            "#,
        )?;

        let error = SessionAdoptPlan::from_config(
            &config,
            SessionRunnerKind::LinuxHost,
            SessionId::new("session-1"),
            0,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::InvalidSessionAdoptPid { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_empty_docker_session_image() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runner": { "docker": { "image": "" } }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptyDockerSessionImage { .. })
        ));
    }

    #[test]
    fn creates_owned_browser_surface_config_without_browser_url() -> Result<(), RuntimeConfigError>
    {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser": {
                    "headless": false,
                    "user_data_dir": "/tmp/erebor-browser-profile"
                  }
                }
              }
            }
            "#,
        )?;
        let start_plan = config.surface_start_plan()?;
        let browser_cdp = start_plan
            .browser_cdp()
            .ok_or_else(RuntimeConfigError::no_session_surfaces)?;

        assert_eq!(browser_cdp.browser_url(), None);
        assert!(browser_cdp.owns_browser());
        assert!(!browser_cdp.browser().headless());
        assert_eq!(
            browser_cdp.browser().user_data_dir(),
            Some(Path::new("/tmp/erebor-browser-profile"))
        );
        Ok(())
    }

    #[test]
    fn rejects_browser_cdp_without_local_ws_url() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "surfaces": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "wss://browser.example/ws"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::BrowserCdpInvalidBrowserUrl { .. })
        ));
    }
}
