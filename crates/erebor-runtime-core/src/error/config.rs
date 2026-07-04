use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum RuntimeConfigError {
    #[snafu(display("runtime config is empty"))]
    EmptyConfig {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config JSON is invalid: {source}"))]
    InvalidJson {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config must include at least one policy"))]
    MissingPolicy {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config policy paths cannot be empty"))]
    EmptyPolicyPath {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config audit debug matcher `{matcher}` cannot be empty"))]
    EmptyAuditDebugMatcher {
        matcher: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config session actor id cannot be empty"))]
    EmptySessionActorId {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config session workspace path cannot be empty"))]
    EmptySessionWorkspace {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config session diagnostic name cannot be empty"))]
    EmptySessionDiagnosticName {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config session diagnostic `{name}` is duplicated"))]
    DuplicateSessionDiagnosticName {
        name: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config session diagnostic `{name}` command cannot be empty"))]
    EmptySessionDiagnosticCommand {
        name: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config session diagnostic `{name}` was not found"))]
    UnknownSessionDiagnostic {
        name: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session adopt pid must be a positive process id"))]
    InvalidSessionAdoptPid {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config Docker/OCI session runner image cannot be empty"))]
    EmptyDockerSessionImage {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config Docker/OCI session runner network cannot be empty"))]
    EmptyDockerSessionNetwork {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session run command cannot be empty"))]
    EmptySessionCommand {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config must enable at least one session surface or session runner"))]
    NoSessionSurfaces {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config browser_cdp browser_url must start with ws://"))]
    BrowserCdpInvalidBrowserUrl {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config terminal process interception is invalid: {reason}"))]
    InvalidProcessMediationConfig {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config filesystem surface is invalid: {reason}"))]
    InvalidFilesystemSurfaceConfig {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime config session interception is invalid: {reason}"))]
    InvalidSessionInterceptionConfig {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for RuntimeConfigError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidJson { .. } => StatusCode::InvalidSyntax,
            Self::EmptyConfig { .. }
            | Self::MissingPolicy { .. }
            | Self::EmptyPolicyPath { .. }
            | Self::EmptyAuditDebugMatcher { .. }
            | Self::EmptySessionActorId { .. }
            | Self::EmptySessionWorkspace { .. }
            | Self::EmptySessionDiagnosticName { .. }
            | Self::DuplicateSessionDiagnosticName { .. }
            | Self::EmptySessionDiagnosticCommand { .. }
            | Self::UnknownSessionDiagnostic { .. }
            | Self::InvalidSessionAdoptPid { .. }
            | Self::EmptyDockerSessionImage { .. }
            | Self::EmptyDockerSessionNetwork { .. }
            | Self::EmptySessionCommand { .. }
            | Self::NoSessionSurfaces { .. }
            | Self::BrowserCdpInvalidBrowserUrl { .. }
            | Self::InvalidProcessMediationConfig { .. }
            | Self::InvalidFilesystemSurfaceConfig { .. }
            | Self::InvalidSessionInterceptionConfig { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_error::{ErrorExt, StatusCode};
    use snafu::Location;

    use super::RuntimeConfigError;

    #[test]
    fn runtime_config_statuses_distinguish_syntax_from_invalid_arguments() {
        let syntax = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => return,
            Err(source) => RuntimeConfigError::InvalidJson {
                source,
                location: Location::default(),
            },
        };
        assert_eq!(syntax.status_code(), StatusCode::InvalidSyntax);

        let invalid = RuntimeConfigError::MissingPolicy {
            location: Location::default(),
        };
        assert_eq!(invalid.status_code(), StatusCode::InvalidArguments);
    }
}
