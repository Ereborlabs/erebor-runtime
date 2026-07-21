use std::{any::Any, io, path::PathBuf};

use erebor_runtime_audit::{AuditLogError, EvidenceTraceError};
use erebor_runtime_client::DaemonClientError;
use erebor_runtime_core::{RuntimeConfigError, RuntimeError, SessionRegistryError};
use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_filesystem::FilesystemError;
use erebor_runtime_policy::PolicyError;
use erebor_runtime_session::SessionExecutionError;
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub(crate) enum CliError {
    #[snafu(display("failed to read runtime config `{}`: {source}", path.display()))]
    ReadConfig {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    InvalidConfig {
        source: RuntimeConfigError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read policy `{}`: {source}", path.display()))]
    ReadPolicy {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    InvalidPolicy {
        source: PolicyError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("policy evaluation failed: {source}"))]
    PolicyEvaluation {
        source: PolicyError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read event `{}`: {source}", path.display()))]
    ReadEvent {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("event fixture JSON is invalid: {source}"))]
    InvalidEvent {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Runtime {
        #[snafu(source(from(RuntimeError, Box::new)))]
        source: Box<RuntimeError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    SessionExecution {
        #[snafu(source(from(SessionExecutionError, Box::new)))]
        source: Box<SessionExecutionError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write session diagnostic output: {source}"))]
    WriteSessionOutput {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    AuditLog {
        source: AuditLogError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    EvidenceTrace {
        #[snafu(source(from(EvidenceTraceError, Box::new)))]
        source: Box<EvidenceTraceError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    SessionRegistry {
        source: SessionRegistryError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("{source}"))]
    Filesystem {
        #[snafu(source(from(FilesystemError, Box::new)))]
        source: Box<FilesystemError>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("filesystem command is invalid: {reason}"))]
    InvalidFilesystemCommand {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("session command is invalid: {reason}"))]
    InvalidSessionCommand {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode JSON output: {source}"))]
    EncodeJson {
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("daemon client request failed: {source}"))]
    DaemonClient {
        source: DaemonClientError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to initialize daemon command runtime: {source}"))]
    DaemonRuntime {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for CliError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ReadConfig { .. }
            | Self::ReadPolicy { .. }
            | Self::ReadEvent { .. }
            | Self::WriteSessionOutput { .. } => StatusCode::External,
            Self::InvalidConfig { source, .. } => source.status_code(),
            Self::InvalidPolicy { source, .. } | Self::PolicyEvaluation { source, .. } => {
                source.status_code()
            }
            Self::InvalidEvent { .. } => StatusCode::InvalidSyntax,
            Self::Runtime { source, .. } => source.status_code(),
            Self::SessionExecution { source, .. } => source.status_code(),
            Self::AuditLog { source, .. } => source.status_code(),
            Self::EvidenceTrace { source, .. } => source.status_code(),
            Self::SessionRegistry { source, .. } => source.status_code(),
            Self::Filesystem { source, .. } => source.status_code(),
            Self::InvalidFilesystemCommand { .. } => StatusCode::InvalidArguments,
            Self::InvalidSessionCommand { .. } => StatusCode::InvalidArguments,
            Self::EncodeJson { .. } => StatusCode::Internal,
            Self::DaemonClient { source, .. } => source.status_code(),
            Self::DaemonRuntime { .. } => StatusCode::Internal,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::ReadConfig { source, .. }
            | Self::ReadPolicy { source, .. }
            | Self::ReadEvent { source, .. }
            | Self::WriteSessionOutput { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidConfig { source, .. } => source.retry_hint(),
            Self::InvalidPolicy { source, .. } | Self::PolicyEvaluation { source, .. } => {
                source.retry_hint()
            }
            Self::InvalidEvent { .. } => RetryHint::NonRetryable,
            Self::Runtime { source, .. } => source.retry_hint(),
            Self::SessionExecution { source, .. } => source.retry_hint(),
            Self::AuditLog { source, .. } => source.retry_hint(),
            Self::EvidenceTrace { source, .. } => source.retry_hint(),
            Self::SessionRegistry { source, .. } => source.retry_hint(),
            Self::Filesystem { source, .. } => source.retry_hint(),
            Self::InvalidFilesystemCommand { .. } => RetryHint::NonRetryable,
            Self::InvalidSessionCommand { .. } => RetryHint::NonRetryable,
            Self::EncodeJson { .. } => RetryHint::NonRetryable,
            Self::DaemonClient { source, .. } => source.retry_hint(),
            Self::DaemonRuntime { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn output_msg(&self) -> String {
        match self.status_code() {
            StatusCode::Unknown | StatusCode::Internal => {
                format!("Internal error: {}", self.status_code().as_u32())
            }
            _ => match self {
                Self::InvalidConfig { source, .. } => source.to_string(),
                Self::InvalidPolicy { source, .. } | Self::PolicyEvaluation { source, .. } => {
                    source.to_string()
                }
                Self::Runtime { source, .. } => source.to_string(),
                Self::SessionExecution { source, .. } => source.to_string(),
                Self::AuditLog { source, .. } => source.to_string(),
                Self::EvidenceTrace { source, .. } => source.to_string(),
                Self::SessionRegistry { source, .. } => source.to_string(),
                Self::Filesystem { source, .. } => source.to_string(),
                Self::ReadConfig { .. }
                | Self::ReadPolicy { .. }
                | Self::ReadEvent { .. }
                | Self::InvalidEvent { .. }
                | Self::InvalidFilesystemCommand { .. }
                | Self::InvalidSessionCommand { .. }
                | Self::WriteSessionOutput { .. }
                | Self::EncodeJson { .. }
                | Self::DaemonClient { .. }
                | Self::DaemonRuntime { .. } => self.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use erebor_runtime_core::RuntimeConfig;
    use erebor_runtime_policy::LocalPolicy;
    use snafu::Location;

    use super::CliError;
    use erebor_runtime_error::{ErrorExt, StatusCode};

    #[test]
    fn empty_config_uses_invalid_argument_user_output() -> Result<(), Box<dyn std::error::Error>> {
        let source = match RuntimeConfig::from_json_str("") {
            Ok(_) => {
                return Err(io::Error::other("empty runtime config should be invalid").into());
            }
            Err(source) => source,
        };
        let error = CliError::InvalidConfig {
            source,
            location: Location::default(),
        };

        assert_eq!(error.status_code(), StatusCode::InvalidArguments);
        assert_eq!(error.output_msg(), "runtime config is empty");
        Ok(())
    }

    #[test]
    fn invalid_policy_syntax_uses_actionable_user_output() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = match LocalPolicy::from_json_str("{") {
            Ok(_) => {
                return Err(io::Error::other("malformed policy should be invalid").into());
            }
            Err(source) => source,
        };
        let error = CliError::InvalidPolicy {
            source,
            location: Location::default(),
        };

        assert_eq!(error.status_code(), StatusCode::InvalidSyntax);
        assert!(error.output_msg().contains("policy syntax is invalid"));
        Ok(())
    }

    #[test]
    fn internal_cli_errors_are_masked_for_stderr() -> Result<(), Box<dyn std::error::Error>> {
        let source = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => {
                return Err(io::Error::other("malformed JSON should fail").into());
            }
            Err(source) => source,
        };
        let error = CliError::EncodeJson {
            source,
            location: Location::default(),
        };

        assert_eq!(error.status_code(), StatusCode::Internal);
        assert_eq!(error.output_msg(), "Internal error: 1003");
        Ok(())
    }
}
