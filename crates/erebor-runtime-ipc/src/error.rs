use std::{any::Any, io};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum IpcProtocolError {
    #[snafu(display("IPC stream reached EOF before another frame"))]
    EndOfStream {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC stream ended in the middle of a frame"))]
    TruncatedFrame {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC framed stream I/O failed: {source}"))]
    Io {
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
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
        "IPC envelope protocol version `{actual}` does not match supported version `{expected}`"
    ))]
    UnsupportedProtocolVersion {
        actual: u32,
        expected: u32,
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
    #[snafu(display("IPC envelope has too many headers: {actual} > {maximum}"))]
    TooManyHeaders {
        actual: usize,
        maximum: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC envelope header `{key}` exceeds the {maximum}-byte limit"))]
    HeaderTooLong {
        key: String,
        maximum: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC envelope header `{key}` is duplicated"))]
    DuplicateHeader {
        key: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC envelope header `{key}` is not allowed for this service"))]
    HeaderNotAllowed {
        key: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("IPC envelope header `{key}` requires a non-empty value"))]
    EmptyHeaderValue {
        key: String,
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
            Self::EndOfStream { .. } | Self::TruncatedFrame { .. } => StatusCode::Unavailable,
            Self::Io { .. } => StatusCode::External,
            Self::UnsupportedFrameVersion { .. } | Self::UnsupportedProtocolVersion { .. } => {
                StatusCode::Unsupported
            }
            Self::EncodePayload { .. } => StatusCode::Unexpected,
            Self::PayloadTooLarge { .. }
            | Self::FrameTooShort { .. }
            | Self::InvalidMagic { .. }
            | Self::InvalidPayloadLength { .. }
            | Self::TooManyHeaders { .. }
            | Self::HeaderTooLong { .. }
            | Self::DuplicateHeader { .. }
            | Self::HeaderNotAllowed { .. }
            | Self::EmptyHeaderValue { .. }
            | Self::PayloadKindMismatch { .. }
            | Self::DecodePayload { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::EndOfStream { .. } | Self::TruncatedFrame { .. } => RetryHint::Retryable,
            Self::Io { source, .. } => RetryHint::from_io_error(source),
            _ => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
