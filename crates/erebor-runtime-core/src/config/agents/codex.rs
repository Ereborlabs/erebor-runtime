use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
};

use serde::Deserialize;
use snafu::ensure;

use crate::{error::InvalidCodexGovernanceConfigSnafu, RuntimeConfigError, SessionRunnerKind};

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexGovernanceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub profiles: Vec<CodexProfileLayerConfig>,
}

impl CodexGovernanceLayerConfig {
    pub(in crate::config) fn validate(
        &self,
        session_enabled: bool,
        filesystem_enabled: bool,
    ) -> Result<(), RuntimeConfigError> {
        if !self.enabled {
            ensure!(
                self.profiles.is_empty(),
                InvalidCodexGovernanceConfigSnafu {
                    reason: String::from("profiles require codex governance to be enabled")
                }
            );
            return Ok(());
        }

        ensure!(
            session_enabled,
            InvalidCodexGovernanceConfigSnafu {
                reason: String::from("enabled codex governance requires session.enabled")
            }
        );
        ensure!(
            filesystem_enabled,
            InvalidCodexGovernanceConfigSnafu {
                reason: String::from(
                    "enabled codex governance requires the filesystem session surface"
                )
            }
        );
        ensure!(
            !self.profiles.is_empty(),
            InvalidCodexGovernanceConfigSnafu {
                reason: String::from("enabled codex governance requires at least one profile")
            }
        );

        let mut profile_ids = HashSet::new();
        let mut profile_executables = HashSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            ensure!(
                profile_ids.insert(profile.id.clone()),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!("codex profile `{}` is duplicated", profile.id)
                }
            );
            ensure!(
                profile_executables.insert(profile.executable.clone()),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex executable `{}` has conflicting profiles",
                        profile.executable.display()
                    )
                }
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn matching_profile(&self, executable: &Path) -> Option<&CodexProfileLayerConfig> {
        self.enabled.then_some(()).and_then(|()| {
            self.profiles
                .iter()
                .find(|profile| profile.executable == executable)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexProfileLayerConfig {
    pub id: String,
    pub runner: SessionRunnerKind,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub deployment: CodexDeploymentMode,
    pub trust_root: PathBuf,
    pub requirements_source: PathBuf,
    pub requirements_sha256: String,
    pub managed_hook_source: PathBuf,
    pub managed_hook_sha256: String,
    pub managed_hook_path: PathBuf,
    pub shell_startup_source: PathBuf,
    pub shell_startup_sha256: String,
    pub shell_startup_path: PathBuf,
    pub hook_shell: CodexHookShellKind,
    /// The exact guarded exec history, starting with the enrolled Codex
    /// executable and ending with the managed hook executable.
    pub hook_exec_history: Vec<PathBuf>,
    pub event_schemas: Vec<CodexHookEventSchemaLayerConfig>,
}

impl CodexProfileLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        ensure!(
            valid_id(&self.id),
            InvalidCodexGovernanceConfigSnafu {
                reason: format!("codex profile id `{}` is invalid", self.id)
            }
        );
        ensure!(
            self.runner == SessionRunnerKind::LinuxHost,
            InvalidCodexGovernanceConfigSnafu {
                reason: format!(
                    "codex profile `{}` requires the linux_host runner in Linux V1",
                    self.id
                )
            }
        );
        for (label, path) in [
            ("executable", &self.executable),
            ("trust_root", &self.trust_root),
            ("requirements_source", &self.requirements_source),
            ("managed_hook_source", &self.managed_hook_source),
            ("managed_hook_path", &self.managed_hook_path),
            ("shell_startup_source", &self.shell_startup_source),
            ("shell_startup_path", &self.shell_startup_path),
        ] {
            ensure!(
                normalized_absolute_path(path),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex profile `{}` {label} must be an absolute normalized path",
                        self.id
                    )
                }
            );
        }
        for (label, path) in [
            ("requirements_source", &self.requirements_source),
            ("managed_hook_source", &self.managed_hook_source),
            ("shell_startup_source", &self.shell_startup_source),
        ] {
            ensure!(
                path.starts_with(&self.trust_root),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex profile `{}` {label} must be below trust_root",
                        self.id
                    )
                }
            );
        }
        if self.deployment == CodexDeploymentMode::FleetManaged {
            for (label, path) in [
                ("executable", &self.executable),
                ("trust_root", &self.trust_root),
                ("requirements_source", &self.requirements_source),
                ("managed_hook_source", &self.managed_hook_source),
                ("shell_startup_source", &self.shell_startup_source),
            ] {
                ensure!(
                    nonvolatile_path(path),
                    InvalidCodexGovernanceConfigSnafu {
                        reason: format!(
                            "fleet-managed codex profile `{}` {label} cannot use a mutable user or temporary path",
                            self.id
                        )
                    }
                );
            }
        }
        ensure!(
            self.managed_hook_path.starts_with("/usr/lib/erebor/"),
            InvalidCodexGovernanceConfigSnafu {
                reason: format!(
                    "codex profile `{}` managed_hook_path must be below /usr/lib/erebor",
                    self.id
                )
            }
        );
        ensure!(
            self.shell_startup_path.starts_with("/usr/lib/erebor/"),
            InvalidCodexGovernanceConfigSnafu {
                reason: format!(
                    "codex profile `{}` shell_startup_path must be below /usr/lib/erebor",
                    self.id
                )
            }
        );
        ensure!(
            self.managed_hook_source.parent() == self.shell_startup_source.parent(),
            InvalidCodexGovernanceConfigSnafu {
                reason: format!(
                    "codex profile `{}` managed hook and shell startup sources must share a managed directory",
                    self.id
                )
            }
        );
        ensure!(
            self.managed_hook_path.parent() == self.shell_startup_path.parent(),
            InvalidCodexGovernanceConfigSnafu {
                reason: format!(
                    "codex profile `{}` managed hook and shell startup paths must share a managed directory",
                    self.id
                )
            }
        );
        let expected_history_len = match self.hook_shell {
            CodexHookShellKind::Direct => 2,
            CodexHookShellKind::Sh | CodexHookShellKind::Bash | CodexHookShellKind::Zsh => 3,
        };
        ensure!(
            self.hook_exec_history.len() == expected_history_len,
            InvalidCodexGovernanceConfigSnafu {
                reason: format!("codex profile `{}` hook_shell `{}` requires an exact {expected_history_len}-entry Codex-to-hook exec history", self.id, self.hook_shell.as_str())
            }
        );
        if let Some(expected_shell) = self.hook_shell.interpreter_name() {
            ensure!(
                self.hook_exec_history
                    .get(1)
                    .and_then(|path| path.file_name())
                    .and_then(|name| name.to_str())
                    == Some(expected_shell),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex profile `{}` hook_shell `{}` requires its exact history to name a `{expected_shell}` interpreter",
                        self.id,
                        self.hook_shell.as_str()
                    )
                }
            );
        }
        for path in &self.hook_exec_history {
            ensure!(
                normalized_absolute_path(path),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex profile `{}` hook_exec_history must contain absolute normalized paths",
                        self.id
                    )
                }
            );
        }
        ensure!(
            self.hook_exec_history.first() == Some(&self.executable)
                && self.hook_exec_history.last() == Some(&self.managed_hook_path),
            InvalidCodexGovernanceConfigSnafu {
                reason: format!(
                    "codex profile `{}` hook_exec_history must start with executable and end with managed_hook_path",
                    self.id
                )
            }
        );
        for (label, digest) in [
            ("executable_sha256", &self.executable_sha256),
            ("requirements_sha256", &self.requirements_sha256),
            ("managed_hook_sha256", &self.managed_hook_sha256),
            ("shell_startup_sha256", &self.shell_startup_sha256),
        ] {
            ensure!(
                valid_sha256(digest),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex profile `{}` {label} must be a lowercase SHA-256 digest",
                        self.id
                    )
                }
            );
        }
        ensure!(
            !self.event_schemas.is_empty(),
            InvalidCodexGovernanceConfigSnafu {
                reason: format!(
                    "codex profile `{}` requires event schema fingerprints",
                    self.id
                )
            }
        );
        let mut events = HashSet::new();
        for schema in &self.event_schemas {
            ensure!(
                valid_sha256(&schema.sha256),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex profile `{}` event `{}` must have a lowercase SHA-256 schema fingerprint",
                        self.id,
                        schema.event.as_str()
                    )
                }
            );
            ensure!(
                events.insert(schema.event),
                InvalidCodexGovernanceConfigSnafu {
                    reason: format!(
                        "codex profile `{}` event `{}` is duplicated",
                        self.id,
                        schema.event.as_str()
                    )
                }
            );
        }
        Ok(())
    }
}

/// The shell behavior Codex uses to dispatch the managed command hook for one
/// certified executable profile. The profile's exact exec history supplies the
/// concrete interpreter path; this kind determines which startup input Erebor
/// must root-control before launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexHookShellKind {
    Direct,
    Sh,
    Bash,
    Zsh,
}

impl CodexHookShellKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Sh => "sh",
            Self::Bash => "bash",
            Self::Zsh => "zsh",
        }
    }

    const fn interpreter_name(self) -> Option<&'static str> {
        match self {
            Self::Direct => None,
            Self::Sh => Some("sh"),
            Self::Bash => Some("bash"),
            Self::Zsh => Some("zsh"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexDeploymentMode {
    LocalCooperative,
    FleetManaged,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexHookEventSchemaLayerConfig {
    pub event: CodexHookEvent,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexHookEvent {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    SubagentStart,
    SubagentStop,
    Stop,
}

impl CodexHookEvent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionStart => "session_start",
            Self::UserPromptSubmit => "user_prompt_submit",
            Self::PreToolUse => "pre_tool_use",
            Self::PermissionRequest => "permission_request",
            Self::PostToolUse => "post_tool_use",
            Self::SubagentStart => "subagent_start",
            Self::SubagentStop => "subagent_stop",
            Self::Stop => "stop",
        }
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
}

fn nonvolatile_path(path: &Path) -> bool {
    normalized_absolute_path(path)
        && !path.starts_with("/tmp")
        && !path.starts_with("/var/tmp")
        && !path.starts_with("/run/user")
        && !path.starts_with("/home")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests;
