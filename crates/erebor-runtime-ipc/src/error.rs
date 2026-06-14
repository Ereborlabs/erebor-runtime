use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpcProtocolError {
    #[error("IPC frame payload exceeds maximum size: {actual} > {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("IPC frame is too short: {actual} < {minimum}")]
    FrameTooShort { actual: usize, minimum: usize },
    #[error("IPC frame magic is invalid")]
    InvalidMagic,
    #[error("IPC frame version `{version}` is not supported")]
    UnsupportedFrameVersion { version: u16 },
    #[error("IPC frame payload length is invalid: declared {declared}, available {available}")]
    InvalidPayloadLength { declared: usize, available: usize },
    #[error("IPC envelope payload kind mismatch: expected `{expected}`, actual `{actual}`")]
    PayloadKindMismatch { expected: String, actual: String },
    #[error("failed to encode protobuf IPC payload: {source}")]
    EncodePayload { source: prost::EncodeError },
    #[error("failed to decode protobuf IPC payload: {source}")]
    DecodePayload { source: prost::DecodeError },
}

impl IpcProtocolError {
    pub(crate) const fn payload_too_large(actual: usize, maximum: usize) -> Self {
        Self::PayloadTooLarge { actual, maximum }
    }

    pub(crate) const fn frame_too_short(actual: usize, minimum: usize) -> Self {
        Self::FrameTooShort { actual, minimum }
    }

    pub(crate) const fn invalid_payload_length(declared: usize, available: usize) -> Self {
        Self::InvalidPayloadLength {
            declared,
            available,
        }
    }

    pub(crate) const fn unsupported_frame_version(version: u16) -> Self {
        Self::UnsupportedFrameVersion { version }
    }

    pub(crate) fn payload_kind_mismatch(
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::PayloadKindMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    pub(crate) fn encode_payload(source: prost::EncodeError) -> Self {
        Self::EncodePayload { source }
    }

    pub(crate) fn decode_payload(source: prost::DecodeError) -> Self {
        Self::DecodePayload { source }
    }
}
