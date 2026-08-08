use std::any::Any;
use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Phase 0 input `{path:?}` is invalid: {reason}"))]
    InvalidInput {
        path: PathBuf,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Phase 0 I/O failed for `{path:?}`: {source}"))]
    Io {
        path: PathBuf,
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Phase 0 JSON failed for `{path:?}`: {source}"))]
    Json {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Phase 0 command `{program}` failed: {reason}"))]
    Command {
        program: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Phase 0 libbpf `{action}` failed for `{path:?}`: {source}"))]
    Libbpf {
        action: String,
        path: PathBuf,
        source: libbpf_rs::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl ErrorExt for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidInput { .. } | Self::Json { .. } => StatusCode::InvalidArguments,
            Self::Io { .. } | Self::Command { .. } | Self::Libbpf { .. } => StatusCode::External,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidInput { .. }
            | Self::Json { .. }
            | Self::Command { .. }
            | Self::Libbpf { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
