use serde::{Deserialize, Serialize};

use crate::RuntimeConfigError;

use super::surfaces::{
    BrowserCdpAuditSurfaceLoggingConfig, DesktopAuditSurfaceLoggingConfig,
    FilesystemAuditSurfaceLoggingConfig, InternalSystemAuditSurfaceLoggingConfig,
    McpAuditSurfaceLoggingConfig, NetworkAuditSurfaceLoggingConfig, SaaSAuditSurfaceLoggingConfig,
    TerminalAuditSurfaceLoggingConfig,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuditConfig {
    #[serde(default)]
    pub surfaces: RuntimeAuditSurfaceLoggingConfig,
}

impl RuntimeAuditConfig {
    #[must_use]
    pub const fn surfaces(&self) -> &RuntimeAuditSurfaceLoggingConfig {
        &self.surfaces
    }

    pub(in crate::config) fn validate(&self) -> Result<(), RuntimeConfigError> {
        AuditLoggingConfigValidator::new(&self.surfaces).validate()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct RuntimeAuditSurfaceLoggingConfig {
    #[serde(default)]
    pub terminal: TerminalAuditSurfaceLoggingConfig,
    #[serde(default)]
    pub browser_cdp: BrowserCdpAuditSurfaceLoggingConfig,
    #[serde(default)]
    pub filesystem: FilesystemAuditSurfaceLoggingConfig,
    #[serde(default)]
    pub mcp: McpAuditSurfaceLoggingConfig,
    #[serde(default)]
    pub network: NetworkAuditSurfaceLoggingConfig,
    #[serde(default)]
    pub saas: SaaSAuditSurfaceLoggingConfig,
    #[serde(default)]
    pub desktop: DesktopAuditSurfaceLoggingConfig,
    #[serde(default)]
    pub internal_system: InternalSystemAuditSurfaceLoggingConfig,
}

impl RuntimeAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn terminal(&self) -> &TerminalAuditSurfaceLoggingConfig {
        &self.terminal
    }

    #[must_use]
    pub const fn browser_cdp(&self) -> &BrowserCdpAuditSurfaceLoggingConfig {
        &self.browser_cdp
    }

    #[must_use]
    pub const fn filesystem(&self) -> &FilesystemAuditSurfaceLoggingConfig {
        &self.filesystem
    }

    #[must_use]
    pub const fn mcp(&self) -> &McpAuditSurfaceLoggingConfig {
        &self.mcp
    }

    #[must_use]
    pub const fn network(&self) -> &NetworkAuditSurfaceLoggingConfig {
        &self.network
    }

    #[must_use]
    pub const fn saas(&self) -> &SaaSAuditSurfaceLoggingConfig {
        &self.saas
    }

    #[must_use]
    pub const fn desktop(&self) -> &DesktopAuditSurfaceLoggingConfig {
        &self.desktop
    }

    #[must_use]
    pub const fn internal_system(&self) -> &InternalSystemAuditSurfaceLoggingConfig {
        &self.internal_system
    }

    fn validate(&self) -> Result<(), RuntimeConfigError> {
        self.terminal.validate("terminal")?;
        self.browser_cdp.validate("browser_cdp")?;
        self.filesystem.validate("filesystem")?;
        self.mcp.validate("mcp")?;
        self.network.validate("network")?;
        self.saas.validate("saas")?;
        self.desktop.validate("desktop")?;
        self.internal_system.validate("internal_system")?;
        Ok(())
    }
}

struct AuditLoggingConfigValidator<'a> {
    surfaces: &'a RuntimeAuditSurfaceLoggingConfig,
}

impl<'a> AuditLoggingConfigValidator<'a> {
    const fn new(surfaces: &'a RuntimeAuditSurfaceLoggingConfig) -> Self {
        Self { surfaces }
    }

    fn validate(&self) -> Result<(), RuntimeConfigError> {
        self.surfaces.validate()
    }
}
