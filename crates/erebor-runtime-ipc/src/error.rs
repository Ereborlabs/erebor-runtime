use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum IpcProtocolError {
    #[snafu(display("IPC frame payload exceeds maximum size: {actual} > {maximum}"))]
    PayloadTooLarge {
        actual: usize,
        maximum: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC frame is too short: {actual} < {minimum}"))]
    FrameTooShort {
        actual: usize,
        minimum: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC frame magic is invalid"))]
    InvalidMagic {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC frame version `{version}` is not supported"))]
    UnsupportedFrameVersion {
        version: u16,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "IPC frame payload length is invalid: declared {declared}, available {available}"
    ))]
    InvalidPayloadLength {
        declared: usize,
        available: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "IPC envelope payload kind mismatch: expected `{expected}`, actual `{actual}`"
    ))]
    PayloadKindMismatch {
        expected: String,
        actual: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to encode protobuf IPC payload: {source}"))]
    EncodePayload {
        source: prost::EncodeError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to decode protobuf IPC payload: {source}"))]
    DecodePayload {
        source: prost::DecodeError,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, IpcProtocolError>;

impl ErrorExt for IpcProtocolError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UnsupportedFrameVersion { .. } => StatusCode::Unsupported,
            Self::EncodePayload { .. } => StatusCode::Unexpected,
            Self::PayloadTooLarge { .. }
            | Self::FrameTooShort { .. }
            | Self::InvalidMagic { .. }
            | Self::InvalidPayloadLength { .. }
            | Self::PayloadKindMismatch { .. }
            | Self::DecodePayload { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        RetryHint::NonRetryable
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
