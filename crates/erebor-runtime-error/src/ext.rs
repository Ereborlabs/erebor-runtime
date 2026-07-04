use std::any::Any;
use std::error::Error;
use std::fmt;
use std::io::ErrorKind;
use std::str::FromStr;

use crate::status_code::StatusCode;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RetryHint {
    Retryable,
    NonRetryable,
}

const RETRY_HINT_RETRYABLE: &str = "retryable";
const RETRY_HINT_NON_RETRYABLE: &str = "non_retryable";

impl RetryHint {
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retryable)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => RETRY_HINT_RETRYABLE,
            Self::NonRetryable => RETRY_HINT_NON_RETRYABLE,
        }
    }

    #[must_use]
    pub fn from_io_error(error: &std::io::Error) -> Self {
        match error.kind() {
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::Interrupted => Self::Retryable,
            _ => Self::NonRetryable,
        }
    }
}

impl fmt::Display for RetryHint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RetryHint {
    type Err = ParseRetryHintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            RETRY_HINT_RETRYABLE => Ok(Self::Retryable),
            RETRY_HINT_NON_RETRYABLE => Ok(Self::NonRetryable),
            _ => Err(ParseRetryHintError),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ParseRetryHintError;

impl fmt::Display for ParseRetryHintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown retry hint")
    }
}

impl Error for ParseRetryHintError {}

pub trait ErrorExt: Error + 'static {
    fn status_code(&self) -> StatusCode {
        StatusCode::Unknown
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }

    fn is_retryable(&self) -> bool {
        self.retry_hint().is_retryable()
    }

    fn as_any(&self) -> &dyn Any;

    fn output_msg(&self) -> String {
        match self.status_code() {
            StatusCode::Unknown | StatusCode::Internal => {
                format!("Internal error: {}", self.status_code().as_u32())
            }
            _ => match self.root_cause() {
                Some(root) => format!("{self}: {root}"),
                None => self.to_string(),
            },
        }
    }

    fn root_cause(&self) -> Option<&(dyn Error + 'static)> {
        let mut root = self.source()?;
        while let Some(source) = root.source() {
            root = source;
        }
        Some(root)
    }
}

#[must_use]
pub fn root_source<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a (dyn Error + 'static)> {
    let mut root = error.source()?;
    while let Some(source) = root.source() {
        root = source;
    }
    Some(root)
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::io;

    use snafu::{Location, Snafu};

    use super::{root_source, ErrorExt, RetryHint};
    use crate::StatusCode;

    #[derive(Debug, Snafu)]
    enum LeafError {
        #[snafu(display("leaf failure: {message}"))]
        Failure {
            message: String,
            #[snafu(implicit)]
            location: Location,
        },
    }

    impl ErrorExt for LeafError {
        fn status_code(&self) -> StatusCode {
            StatusCode::InvalidArguments
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[derive(Debug, Snafu)]
    enum TestError {
        #[snafu(display("internal detail: {detail}"))]
        Internal {
            detail: String,
            #[snafu(implicit)]
            location: Location,
        },
        #[snafu(display("bad request: {message}"))]
        Invalid {
            message: String,
            #[snafu(implicit)]
            location: Location,
        },
        #[snafu(display("outer failure"))]
        Outer {
            source: LeafError,
            #[snafu(implicit)]
            location: Location,
        },
    }

    impl ErrorExt for TestError {
        fn status_code(&self) -> StatusCode {
            match self {
                Self::Internal { .. } => StatusCode::Internal,
                Self::Invalid { .. } | Self::Outer { .. } => StatusCode::InvalidArguments,
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn retry_hint_marks_transient_io_errors_retryable() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Interrupted,
        ] {
            let error = io::Error::from(kind);
            assert_eq!(RetryHint::from_io_error(&error), RetryHint::Retryable);
            assert!(RetryHint::from_io_error(&error).is_retryable());
        }
    }

    #[test]
    fn retry_hint_marks_non_transient_io_errors_non_retryable() {
        for kind in [
            io::ErrorKind::InvalidInput,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::AlreadyExists,
        ] {
            let error = io::Error::from(kind);
            assert_eq!(RetryHint::from_io_error(&error), RetryHint::NonRetryable);
            assert!(!RetryHint::from_io_error(&error).is_retryable());
        }
    }

    #[test]
    fn retry_hint_round_trips_through_strings() {
        assert_eq!("retryable".parse(), Ok(RetryHint::Retryable));
        assert_eq!("non_retryable".parse(), Ok(RetryHint::NonRetryable));
        assert!("later".parse::<RetryHint>().is_err());
        assert_eq!(RetryHint::Retryable.to_string(), "retryable");
    }

    #[test]
    fn output_message_masks_unknown_and_internal_errors() {
        let error = TestError::Internal {
            detail: "secret path /tmp/private".to_string(),
            location: Location::default(),
        };

        assert_eq!(error.output_msg(), "Internal error: 1003");
    }

    #[test]
    fn output_message_preserves_user_actionable_errors() {
        let error = TestError::Invalid {
            message: "missing policy id".to_string(),
            location: Location::default(),
        };

        assert_eq!(error.output_msg(), "bad request: missing policy id");
    }

    #[test]
    fn output_message_includes_root_cause_for_user_actionable_wrappers() {
        let source = LeafError::Failure {
            message: "bad token".to_string(),
            location: Location::default(),
        };
        let error = TestError::Outer {
            source,
            location: Location::default(),
        };

        assert_eq!(error.output_msg(), "outer failure: leaf failure: bad token");
    }

    #[test]
    fn root_source_returns_deepest_source_without_nightly_helpers() {
        let source = LeafError::Failure {
            message: "deep root".to_string(),
            location: Location::default(),
        };
        let error = TestError::Outer {
            source,
            location: Location::default(),
        };

        let root = root_source(&error).map(ToString::to_string);
        assert_eq!(root, Some("leaf failure: deep root".to_string()));
    }
}
