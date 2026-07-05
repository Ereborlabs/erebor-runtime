use serde::{Deserialize, Serialize};
use snafu::ensure;

use crate::error::EmptyAuditDebugMatcherSnafu;
use crate::RuntimeConfigError;

use super::AuditCommandLogLevel;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct TerminalAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    pub debug_commands: Vec<String>,
}

impl Default for TerminalAuditSurfaceLoggingConfig {
    fn default() -> Self {
        Self {
            level: AuditCommandLogLevel::default(),
            debug_commands: vec![String::from("sleep")],
        }
    }
}

impl TerminalAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_commands(&self) -> &[String] {
        &self.debug_commands
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        AuditDebugMatcherValidator::new(surface)
            .validate_values("debug_commands", &self.debug_commands)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct BrowserCdpAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    #[serde(alias = "debug_commands")]
    pub debug_methods: Vec<String>,
    pub debug_actions: Vec<String>,
}

impl BrowserCdpAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_methods(&self) -> &[String] {
        &self.debug_methods
    }

    #[must_use]
    pub fn debug_actions(&self) -> &[String] {
        &self.debug_actions
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        let validator = AuditDebugMatcherValidator::new(surface);
        validator.validate_values("debug_methods", &self.debug_methods)?;
        validator.validate_values("debug_actions", &self.debug_actions)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct FilesystemAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    #[serde(alias = "debug_commands")]
    pub debug_operations: Vec<String>,
    pub debug_actions: Vec<String>,
}

impl FilesystemAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_operations(&self) -> &[String] {
        &self.debug_operations
    }

    #[must_use]
    pub fn debug_actions(&self) -> &[String] {
        &self.debug_actions
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        let validator = AuditDebugMatcherValidator::new(surface);
        validator.validate_values("debug_operations", &self.debug_operations)?;
        validator.validate_values("debug_actions", &self.debug_actions)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct McpAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    #[serde(alias = "debug_commands")]
    pub debug_tools: Vec<String>,
    pub debug_actions: Vec<String>,
}

impl McpAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_tools(&self) -> &[String] {
        &self.debug_tools
    }

    #[must_use]
    pub fn debug_actions(&self) -> &[String] {
        &self.debug_actions
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        let validator = AuditDebugMatcherValidator::new(surface);
        validator.validate_values("debug_tools", &self.debug_tools)?;
        validator.validate_values("debug_actions", &self.debug_actions)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    #[serde(alias = "debug_commands")]
    pub debug_operations: Vec<String>,
    pub debug_actions: Vec<String>,
}

impl NetworkAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_operations(&self) -> &[String] {
        &self.debug_operations
    }

    #[must_use]
    pub fn debug_actions(&self) -> &[String] {
        &self.debug_actions
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        let validator = AuditDebugMatcherValidator::new(surface);
        validator.validate_values("debug_operations", &self.debug_operations)?;
        validator.validate_values("debug_actions", &self.debug_actions)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct SaaSAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    #[serde(alias = "debug_commands")]
    pub debug_operations: Vec<String>,
    pub debug_actions: Vec<String>,
}

impl SaaSAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_operations(&self) -> &[String] {
        &self.debug_operations
    }

    #[must_use]
    pub fn debug_actions(&self) -> &[String] {
        &self.debug_actions
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        let validator = AuditDebugMatcherValidator::new(surface);
        validator.validate_values("debug_operations", &self.debug_operations)?;
        validator.validate_values("debug_actions", &self.debug_actions)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct DesktopAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    pub debug_actions: Vec<String>,
}

impl DesktopAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_actions(&self) -> &[String] {
        &self.debug_actions
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        AuditDebugMatcherValidator::new(surface)
            .validate_values("debug_actions", &self.debug_actions)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct InternalSystemAuditSurfaceLoggingConfig {
    #[serde(alias = "command_level")]
    pub level: AuditCommandLogLevel,
    #[serde(alias = "debug_commands")]
    pub debug_operations: Vec<String>,
    pub debug_actions: Vec<String>,
}

impl InternalSystemAuditSurfaceLoggingConfig {
    #[must_use]
    pub const fn level(&self) -> AuditCommandLogLevel {
        self.level
    }

    #[must_use]
    pub fn debug_operations(&self) -> &[String] {
        &self.debug_operations
    }

    #[must_use]
    pub fn debug_actions(&self) -> &[String] {
        &self.debug_actions
    }

    pub(super) fn validate(&self, surface: &str) -> Result<(), RuntimeConfigError> {
        let validator = AuditDebugMatcherValidator::new(surface);
        validator.validate_values("debug_operations", &self.debug_operations)?;
        validator.validate_values("debug_actions", &self.debug_actions)?;
        Ok(())
    }
}

struct AuditDebugMatcherValidator<'a> {
    surface: &'a str,
}

impl<'a> AuditDebugMatcherValidator<'a> {
    const fn new(surface: &'a str) -> Self {
        Self { surface }
    }

    fn validate_values(&self, field: &str, values: &[String]) -> Result<(), RuntimeConfigError> {
        ensure!(
            !values.iter().any(|value| value.trim().is_empty()),
            EmptyAuditDebugMatcherSnafu {
                matcher: format!("{}.{}", self.surface, field)
            }
        );
        Ok(())
    }
}
