use std::path::PathBuf;

use serde::Deserialize;
use snafu::{ensure, ResultExt};

use crate::error::{
    BrowserCdpInvalidBrowserUrlSnafu, EmptyConfigSnafu, EmptyPolicyPathSnafu, InvalidJsonSnafu,
    MissingPolicySnafu, NoSessionSurfacesSnafu,
};
use crate::RuntimeConfigError;

use super::{
    CodexGovernanceLayerConfig, RuntimeAuditConfig, SessionInterceptionCapabilityReport,
    SessionInterceptionConfig, SessionInterceptionOperation, SessionLayerConfig, SessionRunPlan,
    SessionRunnerKind, SessionSurfaceKind, SessionSurfaceLayers, SessionSurfaceStartPlan,
};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct RuntimeConfig {
    pub policies: Vec<PathBuf>,
    #[serde(default)]
    pub audit: RuntimeAuditConfig,
    #[serde(default)]
    pub session: SessionLayerConfig,
    #[serde(default, alias = "surfaces")]
    pub surfaces: SessionSurfaceLayers,
    #[serde(default)]
    pub codex: CodexGovernanceLayerConfig,
}

impl RuntimeConfig {
    pub fn from_json_str(source: &str) -> Result<Self, RuntimeConfigError> {
        ensure!(!source.trim().is_empty(), EmptyConfigSnafu);

        let config: Self = serde_json::from_str(source).context(InvalidJsonSnafu)?;
        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(!self.policies.is_empty(), MissingPolicySnafu);

        ensure!(
            !self
                .policies
                .iter()
                .any(|policy| policy.as_os_str().is_empty())
                && !self
                    .surfaces
                    .browser_cdp
                    .policies
                    .iter()
                    .any(|policy| policy.as_os_str().is_empty())
                && !self
                    .surfaces
                    .terminal
                    .policies
                    .iter()
                    .any(|policy| policy.as_os_str().is_empty())
                && !self
                    .surfaces
                    .filesystem
                    .policies
                    .iter()
                    .any(|policy| policy.as_os_str().is_empty()),
            EmptyPolicyPathSnafu
        );

        self.audit.validate()?;

        self.codex
            .validate(self.session.enabled, self.surfaces.filesystem.enabled)?;

        if self.session.enabled || self.session.interception.enabled {
            self.session.validate()?;
        }

        ensure!(
            !(self.surfaces.enabled_surfaces().is_empty()
                && !self.session.enabled
                && !self.session.interception.enabled),
            NoSessionSurfacesSnafu
        );

        if self.surfaces.browser_cdp.enabled {
            if let Some(browser_url) = self.surfaces.browser_cdp.browser_url.as_deref() {
                ensure!(
                    browser_url.starts_with("ws://"),
                    BrowserCdpInvalidBrowserUrlSnafu
                );
            }
        }

        let session_interception = self.session_interception();
        self.surfaces.terminal.process_mediation.validate(
            self.surfaces.terminal.enabled,
            session_interception.operation_supported(SessionInterceptionOperation::ProcessExec),
            &self.surfaces.browser_cdp,
        )?;
        self.surfaces.filesystem.validate()?;

        Ok(())
    }

    #[must_use]
    pub fn enabled_surfaces(&self) -> Vec<SessionSurfaceKind> {
        self.surfaces.enabled_surfaces()
    }

    #[must_use]
    pub fn session_interception(&self) -> SessionInterceptionConfig {
        SessionInterceptionConfig::from_runtime_config(self)
    }

    #[must_use]
    pub fn session_interception_capabilities(&self) -> SessionInterceptionCapabilityReport {
        let interception = self.session_interception();
        interception.capability_report(&self.surfaces)
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

#[cfg(test)]
mod tests;
