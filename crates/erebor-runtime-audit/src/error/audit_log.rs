use std::{any::Any, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum AuditLogError {
    #[snafu(display("failed to open audit log `{}`: {source}", path.display()))]
    Open {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read audit log `{}`: {source}", path.display()))]
    Read {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write audit log `{}`: {source}", path.display()))]
    Write {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to serialize audit record for `{}`: {source}", path.display()))]
    SerializeRecord {
        path: PathBuf,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("invalid audit record in `{}` at line {line}: {source}", path.display()))]
    InvalidRecord {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for AuditLogError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Open { .. } | Self::Read { .. } | Self::Write { .. } => StatusCode::External,
            Self::SerializeRecord { .. } => StatusCode::Unexpected,
            Self::InvalidRecord { .. } => StatusCode::InvalidSyntax,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Open { source, .. } | Self::Read { source, .. } | Self::Write { source, .. } => {
                RetryHint::from_io_error(source)
            }
            Self::SerializeRecord { .. } | Self::InvalidRecord { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{io, path::PathBuf};

    use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
    use snafu::Location;

    use super::AuditLogError;

    #[test]
    fn audit_log_statuses_cover_io_and_invalid_records() {
        let io_error = AuditLogError::Open {
            path: PathBuf::from("audit.jsonl"),
            source: io::Error::from(io::ErrorKind::TimedOut),
            location: Location::default(),
        };
        assert_eq!(io_error.status_code(), StatusCode::External);
        assert_eq!(io_error.retry_hint(), RetryHint::Retryable);

        let invalid = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => return,
            Err(source) => AuditLogError::InvalidRecord {
                path: PathBuf::from("audit.jsonl"),
                line: 1,
                source,
                location: Location::default(),
            },
        };
        assert_eq!(invalid.status_code(), StatusCode::InvalidSyntax);
    }
}
