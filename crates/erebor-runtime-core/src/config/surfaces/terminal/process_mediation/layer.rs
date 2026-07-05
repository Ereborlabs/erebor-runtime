use std::collections::HashSet;

use serde::Deserialize;
use snafu::ensure;

use crate::error::InvalidProcessMediationConfigSnafu;
use crate::RuntimeConfigError;

use super::super::super::BrowserCdpSurfaceLayerConfig;
use super::{
    ProcessInterceptionDecision, ProcessMediationCompatibilityLayerConfig,
    ProcessMediationEnvironmentLayerConfig, ProcessMediationHandlerKind,
    ProcessMediationMatcherLayerConfig, ProcessMediationReplacementLayerConfig,
    ProcessMediationReplacementSurface, ProcessMediationRequestedEndpointLayerConfig,
    TerminalProcessMediationMode,
};

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
    pub(in crate::config) fn validate(
        &self,
        terminal_enabled: bool,
        process_exec_interception_enabled: bool,
        browser_cdp: &BrowserCdpSurfaceLayerConfig,
    ) -> Result<(), RuntimeConfigError> {
        if !self.enabled {
            return Ok(());
        }

        ensure!(
            terminal_enabled,
            InvalidProcessMediationConfigSnafu {
                reason: String::from("terminal surface must be enabled")
            }
        );

        ensure!(
            process_exec_interception_enabled,
            InvalidProcessMediationConfigSnafu {
                reason: String::from(
                    "terminal process interception requires session.interception process_exec support"
                )
            }
        );

        ensure!(
            !self.handlers.is_empty(),
            InvalidProcessMediationConfigSnafu {
                reason: String::from("at least one process interception handler is required")
            }
        );

        let mut ids = HashSet::new();
        for handler in &self.handlers {
            handler.validate(browser_cdp)?;
            ensure!(
                ids.insert(handler.id.clone()),
                InvalidProcessMediationConfigSnafu {
                    reason: format!(
                        "process interception handler `{}` is duplicated",
                        handler.id
                    )
                }
            );
        }

        Ok(())
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
        ensure!(
            !self.id.trim().is_empty(),
            InvalidProcessMediationConfigSnafu {
                reason: String::from("process interception handler id cannot be empty")
            }
        );

        self.matcher.validate(&self.id)?;
        self.requested_endpoint.validate(&self.id)?;
        self.replacement.private_endpoint.validate(&self.id)?;
        self.environment.validate(&self.id)?;

        if self.kind == ProcessMediationHandlerKind::ManagedBrowserCdp {
            ensure!(
                self.replacement.surface == ProcessMediationReplacementSurface::BrowserCdp,
                InvalidProcessMediationConfigSnafu {
                    reason: format!(
                        "handler `{}` kind managed_browser_cdp must replace with browser_cdp",
                        self.id
                    )
                }
            );

            ensure!(
                browser_cdp.enabled,
                InvalidProcessMediationConfigSnafu {
                    reason: format!(
                        "handler `{}` kind managed_browser_cdp requires browser_cdp surface enabled",
                        self.id
                    )
                }
            );

            ensure!(
                !(!self.requested_endpoint.allowed_ports.is_empty()
                    && browser_cdp.listen.port() != 0
                    && !self
                        .requested_endpoint
                        .allowed_ports
                        .contains(&browser_cdp.listen.port())),
                InvalidProcessMediationConfigSnafu {
                    reason: format!(
                        "handler `{}` allowed_ports must include browser_cdp.listen port {}",
                        self.id,
                        browser_cdp.listen.port()
                    )
                }
            );
        }

        Ok(())
    }
}
