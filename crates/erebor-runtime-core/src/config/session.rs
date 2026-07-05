use std::{collections::HashSet, path::PathBuf};

use erebor_runtime_events::ActorKind;
use serde::Deserialize;
use snafu::ensure;

mod interception;
mod plan;

pub use interception::{
    SessionInterceptionBackendKind, SessionInterceptionCapabilityReport, SessionInterceptionConfig,
    SessionInterceptionLayerConfig, SessionInterceptionOperation,
    SessionInterceptionOperationCapability,
};
pub use plan::{SessionAdoptPlan, SessionAdoptTarget, SessionRunPlan};

use crate::error::{
    DuplicateSessionDiagnosticNameSnafu, EmptySessionActorIdSnafu,
    EmptySessionDiagnosticCommandSnafu, EmptySessionDiagnosticNameSnafu,
    EmptySessionWorkspaceSnafu,
};
use crate::RuntimeConfigError;

use super::SessionRunnerLayerConfig;

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub actor: SessionActorLayerConfig,
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    #[serde(default)]
    pub interception: SessionInterceptionLayerConfig,
    #[serde(default)]
    pub diagnostics: Vec<SessionDiagnosticLayerConfig>,
    #[serde(default, alias = "runner")]
    pub runner: SessionRunnerLayerConfig,
}

impl SessionLayerConfig {
    pub(in crate::config) fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(!self.actor.id.trim().is_empty(), EmptySessionActorIdSnafu);

        ensure!(
            !self
                .workspace
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty()),
            EmptySessionWorkspaceSnafu
        );

        let mut diagnostics = HashSet::new();
        for diagnostic in &self.diagnostics {
            diagnostic.validate()?;
            ensure!(
                diagnostics.insert(diagnostic.name.clone()),
                DuplicateSessionDiagnosticNameSnafu {
                    name: diagnostic.name.clone()
                }
            );
        }

        self.interception.validate()?;
        self.runner.validate()
    }

    pub(in crate::config) fn diagnostic(
        &self,
        name: &str,
    ) -> Option<&SessionDiagnosticLayerConfig> {
        self.diagnostics
            .iter()
            .find(|diagnostic| diagnostic.name == name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(default)]
pub struct SessionActorLayerConfig {
    pub id: String,
    pub kind: ActorKind,
}

impl Default for SessionActorLayerConfig {
    fn default() -> Self {
        Self {
            id: String::from("agent"),
            kind: ActorKind::Agent,
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
        ensure!(
            !self.name.trim().is_empty(),
            EmptySessionDiagnosticNameSnafu
        );

        ensure!(
            !(self.command.is_empty()
                || self
                    .command
                    .iter()
                    .any(|argument| argument.trim().is_empty())),
            EmptySessionDiagnosticCommandSnafu {
                name: self.name.clone()
            }
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests;
