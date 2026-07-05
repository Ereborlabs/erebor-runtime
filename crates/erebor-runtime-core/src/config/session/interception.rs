use std::collections::HashSet;

use serde::Deserialize;
use snafu::ensure;

use crate::error::InvalidSessionInterceptionConfigSnafu;
use crate::RuntimeConfigError;

use super::super::{RuntimeConfig, SessionSurfaceKind, SessionSurfaceLayers};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct SessionInterceptionLayerConfig {
    pub enabled: bool,
    pub backend: SessionInterceptionBackendKind,
    pub operations: Vec<SessionInterceptionOperation>,
}

impl Default for SessionInterceptionLayerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: SessionInterceptionBackendKind::default(),
            operations: vec![SessionInterceptionOperation::ProcessExec],
        }
    }
}

impl SessionInterceptionLayerConfig {
    pub(super) fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(
            !(self.enabled && self.operations.is_empty()),
            InvalidSessionInterceptionConfigSnafu {
                reason: String::from(
                    "session interception operations cannot be empty when interception is enabled"
                )
            }
        );

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionInterceptionBackendKind {
    #[default]
    #[serde(alias = "linux-ptrace")]
    LinuxPtrace,
}

impl SessionInterceptionBackendKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxPtrace => "linux_ptrace",
        }
    }

    #[must_use]
    const fn supports_operation(self, operation: SessionInterceptionOperation) -> bool {
        match self {
            Self::LinuxPtrace => matches!(
                operation,
                SessionInterceptionOperation::ProcessExec
                    | SessionInterceptionOperation::FileOpen
                    | SessionInterceptionOperation::FileRead
                    | SessionInterceptionOperation::FileMutation
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionInterceptionOperation {
    ProcessExec,
    FileOpen,
    FileRead,
    FileMutation,
    SocketConnect,
}

impl SessionInterceptionOperation {
    #[must_use]
    const fn owning_surface(self) -> &'static str {
        match self {
            Self::ProcessExec => SessionSurfaceKind::Terminal.as_str(),
            Self::FileOpen | Self::FileRead | Self::FileMutation => {
                SessionSurfaceKind::Filesystem.as_str()
            }
            Self::SocketConnect => SessionSurfaceKind::Network.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInterceptionConfig {
    enabled: bool,
    backend: SessionInterceptionBackendKind,
    operations: Vec<SessionInterceptionOperation>,
}

impl SessionInterceptionConfig {
    #[must_use]
    fn disabled() -> Self {
        Self {
            enabled: false,
            backend: SessionInterceptionBackendKind::LinuxPtrace,
            operations: Vec::new(),
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn backend(&self) -> SessionInterceptionBackendKind {
        self.backend
    }

    #[must_use]
    pub fn operations(&self) -> &[SessionInterceptionOperation] {
        &self.operations
    }

    fn operation_enabled(&self, operation: SessionInterceptionOperation) -> bool {
        self.enabled && self.operations.contains(&operation)
    }

    #[must_use]
    pub fn operation_supported(&self, operation: SessionInterceptionOperation) -> bool {
        self.operation_enabled(operation) && self.backend.supports_operation(operation)
    }

    pub(in crate::config) fn from_runtime_config(config: &RuntimeConfig) -> Self {
        let explicit = &config.session.interception;
        if explicit.enabled {
            return Self {
                enabled: true,
                backend: explicit.backend,
                operations: SessionInterceptionOperations::dedupe(explicit.operations.clone()),
            };
        }

        Self::disabled()
    }

    pub(in crate::config) fn capability_report(
        &self,
        surfaces: &SessionSurfaceLayers,
    ) -> SessionInterceptionCapabilityReport {
        let operations = self
            .operations
            .iter()
            .copied()
            .map(|operation| {
                let backend_supported = self.operation_supported(operation);
                let surface_enabled = surfaces.operation_surface_enabled(operation);
                SessionInterceptionOperationCapability {
                    operation,
                    backend_supported,
                    owning_surface: operation.owning_surface(),
                    surface_enabled,
                    effective: backend_supported && surface_enabled,
                }
            })
            .collect();

        SessionInterceptionCapabilityReport { operations }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInterceptionCapabilityReport {
    operations: Vec<SessionInterceptionOperationCapability>,
}

impl SessionInterceptionCapabilityReport {
    #[must_use]
    pub fn operations(&self) -> &[SessionInterceptionOperationCapability] {
        &self.operations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInterceptionOperationCapability {
    operation: SessionInterceptionOperation,
    backend_supported: bool,
    owning_surface: &'static str,
    surface_enabled: bool,
    effective: bool,
}

impl SessionInterceptionOperationCapability {
    #[must_use]
    pub const fn operation(&self) -> SessionInterceptionOperation {
        self.operation
    }

    #[must_use]
    pub const fn backend_supported(&self) -> bool {
        self.backend_supported
    }

    #[must_use]
    pub const fn owning_surface(&self) -> &'static str {
        self.owning_surface
    }

    #[must_use]
    pub const fn surface_enabled(&self) -> bool {
        self.surface_enabled
    }

    #[must_use]
    pub const fn effective(&self) -> bool {
        self.effective
    }
}

struct SessionInterceptionOperations;

impl SessionInterceptionOperations {
    fn dedupe(operations: Vec<SessionInterceptionOperation>) -> Vec<SessionInterceptionOperation> {
        let mut seen = HashSet::new();
        let mut deduped = Vec::new();

        for operation in operations {
            if seen.insert(operation) {
                deduped.push(operation);
            }
        }

        deduped
    }
}

#[cfg(test)]
mod tests;
