use std::path::{Path, PathBuf};

use erebor_runtime_events::SessionId;
use snafu::{ensure, OptionExt};

use crate::error::{
    EmptySessionCommandSnafu, InvalidSessionAdoptPidSnafu, UnknownSessionDiagnosticSnafu,
};
use crate::{RuntimeConfigError, DEFAULT_SESSION_REGISTRY_PATH};

use super::super::{
    RuntimeAuditConfig, RuntimeConfig, SessionRunnerConfig, SessionRunnerKind,
    TerminalSurfaceConfig,
};
use super::SessionActorLayerConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRunPlan {
    policies: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    session_id: SessionId,
    actor: SessionActorLayerConfig,
    workspace: Option<PathBuf>,
    registry_path: PathBuf,
    config_path: Option<PathBuf>,
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

        ensure!(!command.is_empty(), EmptySessionCommandSnafu);

        let mut runner = config.session.runner.clone();
        runner.kind = runtime_kind;
        runner.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            audit: config.audit.clone(),
            session_id,
            actor: config.session.actor.clone(),
            workspace: config.session.workspace.clone(),
            registry_path: SessionRegistryPathResolver::for_workspace(
                config.session.workspace.as_deref(),
            ),
            config_path: None,
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

        let diagnostic =
            config
                .session
                .diagnostic(diagnostic_name)
                .context(UnknownSessionDiagnosticSnafu {
                    name: diagnostic_name.to_string(),
                })?;
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
    pub fn registry_path(&self) -> &Path {
        &self.registry_path
    }

    #[must_use]
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    pub fn set_config_path(&mut self, path: impl Into<PathBuf>) {
        self.config_path = Some(path.into());
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionAdoptTarget {
    Pid(i32),
    ProcessMatch(String),
}

impl SessionAdoptTarget {
    #[must_use]
    pub const fn pid(pid: i32) -> Self {
        Self::Pid(pid)
    }

    #[must_use]
    pub fn process_match(pattern: impl Into<String>) -> Self {
        Self::ProcessMatch(pattern.into())
    }

    #[must_use]
    pub fn display_target(&self) -> String {
        match self {
            Self::Pid(pid) => format!("pid={pid}"),
            Self::ProcessMatch(pattern) => format!("match={pattern}"),
        }
    }
}

impl SessionAdoptPlan {
    pub fn from_config(
        config: &RuntimeConfig,
        runtime_kind: SessionRunnerKind,
        session_id: SessionId,
        pid: i32,
    ) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        ensure!(pid > 0, InvalidSessionAdoptPidSnafu);

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
struct SessionRegistryPathResolver;

impl SessionRegistryPathResolver {
    fn for_workspace(workspace: Option<&Path>) -> PathBuf {
        workspace.map_or_else(
            || PathBuf::from(DEFAULT_SESSION_REGISTRY_PATH),
            |path| path.join(DEFAULT_SESSION_REGISTRY_PATH),
        )
    }
}

#[cfg(test)]
mod tests;
