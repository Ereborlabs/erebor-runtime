use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use snafu::ensure;

use crate::{error::InvalidModelSnafu, ContentDigest, Result, CANONICAL_FORMAT_VERSION};

const PRIVATE_RUNTIME_ROOT: &str = "/run/erebor/codex";
const CODEX_REQUIREMENTS_PATH: &str = "/etc/codex/requirements.toml";
const CODEX_MANAGED_HOOK_PATH: &str = "/usr/lib/erebor/codex-hooks/erebor-codex-hook";
const CODEX_SHELL_STARTUP_PATH: &str = "/usr/lib/erebor/codex-hooks/shell-startup";

/// Immutable, root-curated facts for one supported Codex release.
///
/// The vendor executable itself is intentionally absent from this object. A
/// caller enrolls that executable into an installation record after the daemon
/// has resolved it under the caller UID and verified this release's digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexPackageDefinition {
    format_version: u32,
    release_id: String,
    executable_sha256: ContentDigest,
    supported_platform: CodexSupportedPlatform,
    entrypoints: Vec<CodexEntrypoint>,
    managed_artifacts: CodexManagedArtifacts,
    hook_contract: CodexHookContract,
}

impl CodexPackageDefinition {
    pub fn new(
        release_id: impl Into<String>,
        executable_sha256: ContentDigest,
        supported_platform: CodexSupportedPlatform,
        entrypoints: Vec<CodexEntrypoint>,
        managed_artifacts: CodexManagedArtifacts,
        hook_contract: CodexHookContract,
    ) -> Result<Self> {
        let definition = Self {
            format_version: CANONICAL_FORMAT_VERSION,
            release_id: release_id.into(),
            executable_sha256,
            supported_platform,
            entrypoints,
            managed_artifacts,
            hook_contract,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == CANONICAL_FORMAT_VERSION
                && valid_identifier(&self.release_id)
                && !self.entrypoints.is_empty()
                && self
                    .entrypoints
                    .iter()
                    .map(CodexEntrypoint::name)
                    .all(valid_identifier)
                && unique_entrypoint_names(&self.entrypoints),
            InvalidModelSnafu {
                reason: String::from(
                    "Codex package definition has an unsupported format or unsafe identity"
                )
            }
        );
        self.executable_sha256.validate()?;
        for entrypoint in &self.entrypoints {
            entrypoint.validate()?;
        }
        self.managed_artifacts.validate()?;
        self.hook_contract.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    #[must_use]
    pub fn executable_sha256(&self) -> &ContentDigest {
        &self.executable_sha256
    }

    #[must_use]
    pub const fn supported_platform(&self) -> CodexSupportedPlatform {
        self.supported_platform
    }

    #[must_use]
    pub fn entrypoints(&self) -> &[CodexEntrypoint] {
        &self.entrypoints
    }

    #[must_use]
    pub fn entrypoint(&self, name: &str) -> Option<&CodexEntrypoint> {
        self.entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == name)
    }

    #[must_use]
    pub const fn managed_artifacts(&self) -> &CodexManagedArtifacts {
        &self.managed_artifacts
    }

    #[must_use]
    pub const fn hook_contract(&self) -> &CodexHookContract {
        &self.hook_contract
    }
}

impl crate::CanonicalEncoding for CodexPackageDefinition {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexSupportedPlatform {
    LinuxX86_64,
}

impl CodexSupportedPlatform {
    #[must_use]
    pub const fn matches_host(self) -> bool {
        matches!(self, Self::LinuxX86_64) && cfg!(all(target_os = "linux", target_arch = "x86_64"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexEntrypoint {
    name: String,
    argv_suffix: Vec<String>,
    app_server_stdio: bool,
}

impl CodexEntrypoint {
    pub fn new(
        name: impl Into<String>,
        argv_suffix: Vec<String>,
        app_server_stdio: bool,
    ) -> Result<Self> {
        let entrypoint = Self {
            name: name.into(),
            argv_suffix,
            app_server_stdio,
        };
        entrypoint.validate()?;
        Ok(entrypoint)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            valid_identifier(&self.name)
                && self
                    .argv_suffix
                    .iter()
                    .all(|argument| !argument.is_empty() && !argument.contains('\0'))
                && (!self.app_server_stdio
                    || self.argv_suffix.as_slice() == ["app-server", "--stdio"]),
            InvalidModelSnafu {
                reason: String::from(
                    "Codex entrypoint has an unsafe name or unsupported argv contract"
                )
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn argv_suffix(&self) -> &[String] {
        &self.argv_suffix
    }

    #[must_use]
    pub const fn app_server_stdio(&self) -> bool {
        self.app_server_stdio
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexFrozenContextMode {
    None,
    All,
    LastTurns,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexManagedArtifacts {
    requirements_source: CodexArtifact,
    requirements_path: PathBuf,
    managed_hook_source: CodexArtifact,
    managed_hook_path: PathBuf,
    shell_startup_source: CodexArtifact,
    shell_startup_path: PathBuf,
    sandbox_launcher: Option<CodexArtifact>,
    sandbox_launcher_path: Option<PathBuf>,
}

impl CodexManagedArtifacts {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requirements_source: CodexArtifact,
        requirements_path: PathBuf,
        managed_hook_source: CodexArtifact,
        managed_hook_path: PathBuf,
        shell_startup_source: CodexArtifact,
        shell_startup_path: PathBuf,
        sandbox_launcher: Option<CodexArtifact>,
        sandbox_launcher_path: Option<PathBuf>,
    ) -> Result<Self> {
        let artifacts = Self {
            requirements_source,
            requirements_path,
            managed_hook_source,
            managed_hook_path,
            shell_startup_source,
            shell_startup_path,
            sandbox_launcher,
            sandbox_launcher_path,
        };
        artifacts.validate()?;
        Ok(artifacts)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            (self.private_runtime_targets() || self.codex_managed_profile_targets())
                && (self.sandbox_launcher.is_some() == self.sandbox_launcher_path.is_some())
                && self.managed_hook_path.parent() == self.shell_startup_path.parent()
                && self.managed_hook_source.path.parent()
                    == self.shell_startup_source.path.parent(),
            InvalidModelSnafu {
                reason: String::from(
                    "Codex managed artifact targets must use the private fixture layout or the fixed Codex managed-profile layout"
                )
            }
        );
        self.requirements_source.validate()?;
        self.managed_hook_source.validate()?;
        self.shell_startup_source.validate()?;
        if let Some(launcher) = &self.sandbox_launcher {
            launcher.validate()?;
        }
        Ok(())
    }

    fn private_runtime_targets(&self) -> bool {
        normalized_absolute(&self.requirements_path)
            && self.requirements_path.starts_with(PRIVATE_RUNTIME_ROOT)
            && self.managed_hook_path.starts_with(PRIVATE_RUNTIME_ROOT)
            && self.shell_startup_path.starts_with(PRIVATE_RUNTIME_ROOT)
            && self.sandbox_launcher_path.as_ref().is_none_or(|path| {
                normalized_absolute(path) && path.starts_with(PRIVATE_RUNTIME_ROOT)
            })
    }

    fn codex_managed_profile_targets(&self) -> bool {
        self.requirements_path == Path::new(CODEX_REQUIREMENTS_PATH)
            && self.managed_hook_path == Path::new(CODEX_MANAGED_HOOK_PATH)
            && self.shell_startup_path == Path::new(CODEX_SHELL_STARTUP_PATH)
            && self.sandbox_launcher_path.as_ref().is_none_or(|path| {
                normalized_absolute(path) && path.starts_with(PRIVATE_RUNTIME_ROOT)
            })
    }

    #[must_use]
    pub const fn requirements_source(&self) -> &CodexArtifact {
        &self.requirements_source
    }

    #[must_use]
    pub fn requirements_path(&self) -> &Path {
        &self.requirements_path
    }

    #[must_use]
    pub const fn managed_hook_source(&self) -> &CodexArtifact {
        &self.managed_hook_source
    }

    #[must_use]
    pub fn managed_hook_path(&self) -> &Path {
        &self.managed_hook_path
    }

    #[must_use]
    pub const fn shell_startup_source(&self) -> &CodexArtifact {
        &self.shell_startup_source
    }

    #[must_use]
    pub fn shell_startup_path(&self) -> &Path {
        &self.shell_startup_path
    }

    #[must_use]
    pub const fn sandbox_launcher(&self) -> Option<&CodexArtifact> {
        self.sandbox_launcher.as_ref()
    }

    #[must_use]
    pub fn sandbox_launcher_path(&self) -> Option<&Path> {
        self.sandbox_launcher_path.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexArtifact {
    path: PathBuf,
    sha256: ContentDigest,
}

impl CodexArtifact {
    pub fn new(path: PathBuf, sha256: ContentDigest) -> Result<Self> {
        let artifact = Self { path, sha256 };
        artifact.validate()?;
        Ok(artifact)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            normalized_absolute(&self.path),
            InvalidModelSnafu {
                reason: String::from("Codex artifact paths must be normalized absolute paths")
            }
        );
        self.sha256.validate()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn sha256(&self) -> &ContentDigest {
        &self.sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexHookContract {
    shell: CodexHookShell,
    exec_history: Vec<CodexHookExec>,
    events: Vec<CodexHookEventName>,
    command_dispatch: Option<CodexCommandDispatch>,
}

impl CodexHookContract {
    pub fn new(
        shell: CodexHookShell,
        exec_history: Vec<CodexHookExec>,
        events: Vec<CodexHookEventName>,
        command_dispatch: Option<CodexCommandDispatch>,
    ) -> Result<Self> {
        let contract = Self {
            shell,
            exec_history,
            events,
            command_dispatch,
        };
        contract.validate()?;
        Ok(contract)
    }

    fn validate(&self) -> Result<()> {
        let expected_history = match self.shell {
            CodexHookShell::Direct => 2,
            CodexHookShell::Sh | CodexHookShell::Bash | CodexHookShell::Zsh => 3,
        };
        ensure!(
            self.exec_history.len() == expected_history
                && matches!(
                    self.exec_history.first(),
                    Some(CodexHookExec::InstalledExecutable)
                )
                && matches!(self.exec_history.last(), Some(CodexHookExec::ManagedHook))
                && self
                    .shell
                    .interpreter_name()
                    .is_none_or(|expected| matches!(
                        self.exec_history.get(1),
                        Some(CodexHookExec::AbsolutePath(path))
                            if path.file_name().and_then(|name| name.to_str()) == Some(expected)
                    ))
                && !self.events.is_empty()
                && self
                    .events
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == self.events.len(),
            InvalidModelSnafu {
                reason: String::from(
                    "Codex hook contract has an invalid exact exec chain or duplicate event"
                )
            }
        );
        for entry in &self.exec_history {
            entry.validate()?;
        }
        if let Some(dispatch) = &self.command_dispatch {
            dispatch.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn shell(&self) -> CodexHookShell {
        self.shell
    }

    /// The pinned interpreter path that Codex must receive in `SHELL` before
    /// it starts a shell-wrapped managed hook. A direct hook has no shell
    /// environment requirement.
    #[must_use]
    pub fn shell_executable(&self) -> Option<&Path> {
        match self.shell {
            CodexHookShell::Direct => None,
            CodexHookShell::Sh | CodexHookShell::Bash | CodexHookShell::Zsh => {
                match self.exec_history.get(1) {
                    Some(CodexHookExec::AbsolutePath(path)) => Some(path),
                    Some(CodexHookExec::InstalledExecutable | CodexHookExec::ManagedHook)
                    | None => None,
                }
            }
        }
    }

    #[must_use]
    pub fn exec_history(&self) -> &[CodexHookExec] {
        &self.exec_history
    }

    #[must_use]
    pub fn events(&self) -> &[CodexHookEventName] {
        &self.events
    }

    #[must_use]
    pub const fn command_dispatch(&self) -> Option<&CodexCommandDispatch> {
        self.command_dispatch.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexHookShell {
    Direct,
    Sh,
    Bash,
    Zsh,
}

impl CodexHookShell {
    const fn interpreter_name(self) -> Option<&'static str> {
        match self {
            Self::Direct => None,
            Self::Sh => Some("sh"),
            Self::Bash => Some("bash"),
            Self::Zsh => Some("zsh"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "path")]
pub enum CodexHookExec {
    InstalledExecutable,
    AbsolutePath(PathBuf),
    ManagedHook,
}

impl CodexHookExec {
    fn validate(&self) -> Result<()> {
        if let Self::AbsolutePath(path) = self {
            ensure!(
                normalized_absolute(path),
                InvalidModelSnafu {
                    reason: String::from(
                        "Codex hook exec-chain paths must be normalized absolute paths"
                    )
                }
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexHookEventName {
    SessionStart,
    UserPromptSubmit,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    SubagentStart,
    SubagentStop,
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandDispatch {
    program: String,
    shell: PathBuf,
}

impl CodexCommandDispatch {
    pub fn new(program: impl Into<String>, shell: PathBuf) -> Result<Self> {
        let dispatch = Self {
            program: program.into(),
            shell,
        };
        dispatch.validate()?;
        Ok(dispatch)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            valid_identifier(&self.program) && normalized_absolute(&self.shell),
            InvalidModelSnafu {
                reason: String::from(
                    "Codex command dispatch must name a safe program and absolute shell"
                )
            }
        );
        Ok(())
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn shell(&self) -> &Path {
        &self.shell
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
}

fn unique_entrypoint_names(entrypoints: &[CodexEntrypoint]) -> bool {
    entrypoints
        .iter()
        .map(CodexEntrypoint::name)
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == entrypoints.len()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        CodexArtifact, CodexEntrypoint, CodexHookContract, CodexHookEventName, CodexHookExec,
        CodexHookShell, CodexManagedArtifacts, CodexPackageDefinition, CodexSupportedPlatform,
        CODEX_MANAGED_HOOK_PATH, CODEX_REQUIREMENTS_PATH, CODEX_SHELL_STARTUP_PATH,
    };
    use crate::{CanonicalEncoding, ContentDigest};

    fn digest(value: char) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(value.to_string().repeat(64))?)
    }

    #[test]
    fn codex_package_binds_exact_entrypoint_and_hook_contract(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let artifacts = CodexManagedArtifacts::new(
            CodexArtifact::new(
                "/var/lib/erebor/codex/v1/requirements.toml".into(),
                digest('a')?,
            )?,
            CODEX_REQUIREMENTS_PATH.into(),
            CodexArtifact::new("/var/lib/erebor/codex/v1/hooks/hook".into(), digest('b')?)?,
            CODEX_MANAGED_HOOK_PATH.into(),
            CodexArtifact::new(
                "/var/lib/erebor/codex/v1/hooks/startup".into(),
                digest('c')?,
            )?,
            CODEX_SHELL_STARTUP_PATH.into(),
            None,
            None,
        )?;
        let definition = CodexPackageDefinition::new(
            "codex-v1-test",
            digest('d')?,
            CodexSupportedPlatform::LinuxX86_64,
            vec![CodexEntrypoint::new(
                "codex-app-server",
                vec![String::from("app-server"), String::from("--stdio")],
                true,
            )?],
            artifacts,
            CodexHookContract::new(
                CodexHookShell::Direct,
                vec![
                    CodexHookExec::InstalledExecutable,
                    CodexHookExec::ManagedHook,
                ],
                vec![CodexHookEventName::SessionStart],
                None,
            )?,
        )?;
        assert_eq!(
            definition.canonical_digest()?,
            definition.canonical_digest()?
        );
        assert!(definition.entrypoint("codex-app-server").is_some());
        Ok(())
    }

    #[test]
    fn hook_contract_exposes_only_the_pinned_shell_environment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let direct = CodexHookContract::new(
            CodexHookShell::Direct,
            vec![
                CodexHookExec::InstalledExecutable,
                CodexHookExec::ManagedHook,
            ],
            vec![CodexHookEventName::SessionStart],
            None,
        )?;
        let bash = CodexHookContract::new(
            CodexHookShell::Bash,
            vec![
                CodexHookExec::InstalledExecutable,
                CodexHookExec::AbsolutePath(PathBuf::from("/usr/bin/bash")),
                CodexHookExec::ManagedHook,
            ],
            vec![CodexHookEventName::SessionStart],
            None,
        )?;

        assert_eq!(direct.shell_executable(), None);
        assert_eq!(bash.shell_executable(), Some(Path::new("/usr/bin/bash")));
        Ok(())
    }

    #[test]
    fn fixture_artifact_targets_cannot_mix_with_the_codex_managed_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let requirements = CodexArtifact::new(
            "/var/lib/erebor/codex/v1/requirements.toml".into(),
            digest('a')?,
        )?;
        let hook = CodexArtifact::new("/var/lib/erebor/codex/v1/hooks/hook".into(), digest('b')?)?;
        let startup = CodexArtifact::new(
            "/var/lib/erebor/codex/v1/hooks/startup".into(),
            digest('c')?,
        )?;

        assert!(CodexManagedArtifacts::new(
            requirements.clone(),
            "/run/erebor/codex/requirements.toml".into(),
            hook.clone(),
            CODEX_MANAGED_HOOK_PATH.into(),
            startup.clone(),
            "/run/erebor/codex/shell-startup".into(),
            None,
            None,
        )
        .is_err());
        assert!(CodexManagedArtifacts::new(
            requirements,
            "/run/erebor/codex/requirements.toml".into(),
            hook,
            "/run/erebor/codex/hooks/hook".into(),
            startup,
            "/run/erebor/codex/hooks/startup".into(),
            None,
            None,
        )
        .is_ok());
        Ok(())
    }
}
