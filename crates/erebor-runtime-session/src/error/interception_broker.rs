use std::{any::Any, io};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use erebor_runtime_ipc::IpcProtocolError;
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum RuntimeInterceptionBrokerError {
    #[snafu(display(
        "runtime interception broker transport `{transport}` is unsupported on this platform"
    ))]
    UnsupportedTransport {
        transport: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime interception broker state lock failed"))]
    StateLock {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "session `{session_id}` is already registered with the runtime interception broker"
    ))]
    SessionAlreadyRegistered {
        session_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "runtime interception broker is already restricted to session group `{expected_group}`, not `{requested_group}`"
    ))]
    SessionAccessConflict {
        expected_group: u32,
        requested_group: u32,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime interception broker server platform is not started"))]
    ServerNotStarted {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime interception broker rejected guard hello: {reason}"))]
    RejectedHello {
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime interception broker I/O failed: {source}"))]
    Io {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("runtime interception broker IPC protocol failed: {source}"))]
    Protocol {
        source: IpcProtocolError,
        #[snafu(implicit)]
        location: Location,
    },
}

impl ErrorExt for RuntimeInterceptionBrokerError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UnsupportedTransport { .. } => StatusCode::Unsupported,
            Self::StateLock { .. } => StatusCode::Internal,
            Self::SessionAlreadyRegistered { .. } => StatusCode::AlreadyExists,
            Self::SessionAccessConflict { .. } => StatusCode::IllegalState,
            Self::ServerNotStarted { .. } => StatusCode::IllegalState,
            Self::RejectedHello { .. } => StatusCode::InvalidArguments,
            Self::Io { .. } => StatusCode::External,
            Self::Protocol { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            Self::UnsupportedTransport { .. }
            | Self::StateLock { .. }
            | Self::SessionAlreadyRegistered { .. }
            | Self::SessionAccessConflict { .. }
            | Self::ServerNotStarted { .. }
            | Self::RejectedHello { .. }
            | Self::Protocol { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
    use snafu::Location;

    use super::RuntimeInterceptionBrokerError;

    #[test]
    fn broker_statuses_cover_wire_io_and_state() {
        let io_error = RuntimeInterceptionBrokerError::Io {
            source: io::Error::from(io::ErrorKind::TimedOut),
            location: Location::default(),
        };
        assert_eq!(io_error.status_code(), StatusCode::External);
        assert_eq!(io_error.retry_hint(), RetryHint::Retryable);

        let unsupported = RuntimeInterceptionBrokerError::UnsupportedTransport {
            transport: String::from("named-pipe"),
            location: Location::default(),
        };
        assert_eq!(unsupported.status_code(), StatusCode::Unsupported);

        let rejected = RuntimeInterceptionBrokerError::RejectedHello {
            reason: String::from("invalid interception token"),
            location: Location::default(),
        };
        assert_eq!(rejected.status_code(), StatusCode::InvalidArguments);

        let duplicate = RuntimeInterceptionBrokerError::SessionAlreadyRegistered {
            session_id: String::from("session-1"),
            location: Location::default(),
        };
        assert_eq!(duplicate.status_code(), StatusCode::AlreadyExists);
    }
}
