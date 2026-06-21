use std::{io, path::PathBuf};

use erebor_runtime_policy::PolicyError;
use snafu::Location;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error("runtime config is empty")]
    EmptyConfig { location: Location },
    #[error("runtime config JSON is invalid: {source}")]
    InvalidJson {
        source: serde_json::Error,
        location: Location,
    },
    #[error("runtime config must include at least one policy")]
    MissingPolicy { location: Location },
    #[error("runtime config policy paths cannot be empty")]
    EmptyPolicyPath { location: Location },
    #[error("runtime config audit debug matcher `{matcher}` cannot be empty")]
    EmptyAuditDebugMatcher { matcher: String, location: Location },
    #[error("runtime config session actor id cannot be empty")]
    EmptySessionActorId { location: Location },
    #[error("runtime config session workspace path cannot be empty")]
    EmptySessionWorkspace { location: Location },
    #[error("runtime config session diagnostic name cannot be empty")]
    EmptySessionDiagnosticName { location: Location },
    #[error("runtime config session diagnostic `{name}` is duplicated")]
    DuplicateSessionDiagnosticName { name: String, location: Location },
    #[error("runtime config session diagnostic `{name}` command cannot be empty")]
    EmptySessionDiagnosticCommand { name: String, location: Location },
    #[error("runtime config session diagnostic `{name}` was not found")]
    UnknownSessionDiagnostic { name: String, location: Location },
    #[error("session adopt pid must be a positive process id")]
    InvalidSessionAdoptPid { location: Location },
    #[error("runtime config Docker/OCI session runner image cannot be empty")]
    EmptyDockerSessionImage { location: Location },
    #[error("runtime config Docker/OCI session runner network cannot be empty")]
    EmptyDockerSessionNetwork { location: Location },
    #[error("session run command cannot be empty")]
    EmptySessionCommand { location: Location },
    #[error("runtime config must enable at least one session surface or session runner")]
    NoSessionSurfaces { location: Location },
    #[error("runtime config browser_cdp browser_url must start with ws://")]
    BrowserCdpInvalidBrowserUrl { location: Location },
    #[error("runtime config terminal process interception is invalid: {reason}")]
    InvalidProcessMediationConfig { reason: String, location: Location },
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {source}")]
    Policy {
        source: PolicyError,
        location: Location,
    },
    #[error("failed to build async runtime: {source}")]
    BuildAsyncRuntime {
        source: io::Error,
        location: Location,
    },
    #[error("session surface start plan includes unsupported surface `{surface}`")]
    UnsupportedSessionSurface { surface: String, location: Location },
    #[error("session surface start plan did not include any services")]
    NoSessionSurfaceServices { location: Location },
    #[error("failed to start session surface `{surface}`: {reason}")]
    SurfaceStart {
        surface: String,
        reason: String,
        location: Location,
    },
    #[error("session surface `{surface}` exited: {reason}")]
    SurfaceExited {
        surface: String,
        reason: String,
        location: Location,
    },
    #[error("failed to launch session runner `{runner}` using `{program}`: {source}")]
    SessionRunnerLaunch {
        runner: String,
        program: String,
        source: io::Error,
        location: Location,
    },
    #[error("session runner `{runner}` exited unsuccessfully with code {code:?}")]
    SessionRunnerExit {
        runner: String,
        code: Option<i32>,
        location: Location,
    },
    #[error("session runner `{runner}` does not support `{operation}`")]
    UnsupportedSessionRunnerOperation {
        runner: String,
        operation: String,
        location: Location,
    },
}

#[derive(Debug, Error)]
pub enum SessionRegistryError {
    #[error("failed to create session registry directory `{}`: {source}", path.display())]
    CreateDir {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to copy session artifact from `{}` to `{}`: {source}", from.display(), to.display())]
    CopyArtifact {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to read session registry record `{}`: {source}", path.display())]
    ReadRecord {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to write session registry record `{}`: {source}", path.display())]
    WriteRecord {
        path: PathBuf,
        source: io::Error,
        location: Location,
    },
    #[error("failed to encode session registry record `{}`: {source}", path.display())]
    EncodeRecord {
        path: PathBuf,
        source: serde_json::Error,
        location: Location,
    },
    #[error("failed to decode session registry record `{}`: {source}", path.display())]
    DecodeRecord {
        path: PathBuf,
        source: serde_json::Error,
        location: Location,
    },
    #[error("session registry `{}` does not contain session `{session_id}`", root.display())]
    UnknownSession {
        root: PathBuf,
        session_id: String,
        location: Location,
    },
}

impl SessionRegistryError {
    #[track_caller]
    pub fn create_dir(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::CreateDir {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn copy_artifact(
        from: impl Into<PathBuf>,
        to: impl Into<PathBuf>,
        source: io::Error,
    ) -> Self {
        Self::CopyArtifact {
            from: from.into(),
            to: to.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn read_record(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::ReadRecord {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn write_record(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::WriteRecord {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn encode_record(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::EncodeRecord {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn decode_record(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::DecodeRecord {
            path: path.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unknown_session(root: impl Into<PathBuf>, session_id: impl Into<String>) -> Self {
        Self::UnknownSession {
            root: root.into(),
            session_id: session_id.into(),
            location: Location::default(),
        }
    }
}

impl RuntimeConfigError {
    #[track_caller]
    pub fn empty_config() -> Self {
        Self::EmptyConfig {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_json(source: serde_json::Error) -> Self {
        Self::InvalidJson {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn missing_policy() -> Self {
        Self::MissingPolicy {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_policy_path() -> Self {
        Self::EmptyPolicyPath {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_audit_debug_matcher(matcher: impl Into<String>) -> Self {
        Self::EmptyAuditDebugMatcher {
            matcher: matcher.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_actor_id() -> Self {
        Self::EmptySessionActorId {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_workspace() -> Self {
        Self::EmptySessionWorkspace {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_diagnostic_name() -> Self {
        Self::EmptySessionDiagnosticName {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn duplicate_session_diagnostic_name(name: impl Into<String>) -> Self {
        Self::DuplicateSessionDiagnosticName {
            name: name.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_diagnostic_command(name: impl Into<String>) -> Self {
        Self::EmptySessionDiagnosticCommand {
            name: name.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unknown_session_diagnostic(name: impl Into<String>) -> Self {
        Self::UnknownSessionDiagnostic {
            name: name.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_session_adopt_pid() -> Self {
        Self::InvalidSessionAdoptPid {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_docker_session_image() -> Self {
        Self::EmptyDockerSessionImage {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_docker_session_network() -> Self {
        Self::EmptyDockerSessionNetwork {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn empty_session_command() -> Self {
        Self::EmptySessionCommand {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn no_session_surfaces() -> Self {
        Self::NoSessionSurfaces {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn browser_cdp_invalid_browser_url() -> Self {
        Self::BrowserCdpInvalidBrowserUrl {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn invalid_process_mediation_config(reason: impl Into<String>) -> Self {
        Self::InvalidProcessMediationConfig {
            reason: reason.into(),
            location: Location::default(),
        }
    }
}

impl RuntimeError {
    #[track_caller]
    pub fn policy(source: PolicyError) -> Self {
        Self::Policy {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn build_async_runtime(source: io::Error) -> Self {
        Self::BuildAsyncRuntime {
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unsupported_session_surface(surface: impl Into<String>) -> Self {
        Self::UnsupportedSessionSurface {
            surface: surface.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn no_session_surface_services() -> Self {
        Self::NoSessionSurfaceServices {
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn surface_start(surface: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SurfaceStart {
            surface: surface.into(),
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn surface_exited(surface: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SurfaceExited {
            surface: surface.into(),
            reason: reason.into(),
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn session_runner_launch(
        runner: impl Into<String>,
        program: impl Into<String>,
        source: io::Error,
    ) -> Self {
        Self::SessionRunnerLaunch {
            runner: runner.into(),
            program: program.into(),
            source,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn session_runner_exit(runner: impl Into<String>, code: Option<i32>) -> Self {
        Self::SessionRunnerExit {
            runner: runner.into(),
            code,
            location: Location::default(),
        }
    }

    #[track_caller]
    pub fn unsupported_session_runner_operation(
        runner: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        Self::UnsupportedSessionRunnerOperation {
            runner: runner.into(),
            operation: operation.into(),
            location: Location::default(),
        }
    }
}
