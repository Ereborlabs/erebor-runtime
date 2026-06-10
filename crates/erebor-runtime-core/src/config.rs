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
        let mut combined_environment = vec![
            (
                String::from("EREBOR_SESSION_ID"),
                plan.session_id().as_str().to_owned(),
            ),
            (String::from("EREBOR_ACTOR_ID"), plan.actor().id.clone()),
            (
                String::from("EREBOR_SESSION_RUNNER"),
                SessionRunnerKind::LinuxHost.as_str().to_owned(),
            ),
        ];
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TerminalSurfaceConfig {
    tty: bool,
    policies: Vec<PathBuf>,
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

    fn from_layer(config: &TerminalSurfaceLayerConfig, default_policies: Vec<PathBuf>) -> Self {
        Self {
            tty: config.tty,
            policies: surface_policies(&config.policies, default_policies),
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
        RuntimeConfig, RuntimeConfigError, SessionRunPlan, SessionRunnerKind, SessionSurfaceKind,
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
