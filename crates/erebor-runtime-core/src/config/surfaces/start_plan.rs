use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use crate::RuntimeConfigError;

use super::super::{
    RuntimeAuditConfig, RuntimeConfig, SessionInterceptionConfig, SessionRunPlan, SessionRunnerKind,
};
use super::{
    BrowserCdpSurfaceConfig, FilesystemSurfaceConfig, SessionSurfaceKind, TerminalSurfaceConfig,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSurfaceStartPlan {
    policies: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    interception: SessionInterceptionConfig,
    surfaces: Vec<SessionSurfaceKind>,
    browser_cdp: Option<BrowserCdpSurfaceConfig>,
    terminal: Option<TerminalSurfaceConfig>,
    filesystem: Option<FilesystemSurfaceConfig>,
}

impl SessionSurfaceStartPlan {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            audit: config.audit.clone(),
            interception: config.session_interception(),
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
            filesystem: config.surfaces.filesystem.enabled.then(|| {
                FilesystemSurfaceConfig::from_layer(
                    &config.surfaces.filesystem,
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
            let listen = browser_cdp.listen();
            if session.runner().kind() == SessionRunnerKind::Docker
                && session.runner().docker().needs_host_reachable_endpoints()
                && listen.ip().is_loopback()
            {
                browser_cdp.set_listen(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    listen.port(),
                ));
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
            let listen = browser_cdp.listen();
            if runner_kind == SessionRunnerKind::Docker && listen.ip().is_loopback() {
                browser_cdp.set_listen(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    listen.port(),
                ));
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
    pub const fn interception(&self) -> &SessionInterceptionConfig {
        &self.interception
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

    #[must_use]
    pub fn filesystem(&self) -> Option<&FilesystemSurfaceConfig> {
        self.filesystem.as_ref()
    }
}
