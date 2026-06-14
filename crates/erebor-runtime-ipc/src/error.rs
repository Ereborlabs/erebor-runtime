use thiserror::Error;

use crate::MessageType;

#[derive(Debug, Error)]
pub enum IpcProtocolError {
    #[error("IPC frame payload exceeds maximum size: {actual} > {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("IPC frame is too short: {actual} < {minimum}")]
    FrameTooShort { actual: usize, minimum: usize },
    #[error("IPC frame magic is invalid")]
    InvalidMagic,
    #[error("IPC frame message type `{message_type}` is unknown")]
    UnknownMessageType { message_type: u16 },
    #[error("IPC frame payload length is invalid: declared {declared}, available {available}")]
    InvalidPayloadLength { declared: usize, available: usize },
    #[error("IPC frame message type mismatch: expected {expected:?}, actual {actual:?}")]
    MessageTypeMismatch {
        expected: MessageType,
        actual: MessageType,
    },
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

    pub(crate) const fn unknown_message_type(message_type: u16) -> Self {
        Self::UnknownMessageType { message_type }
    }

    pub(crate) const fn message_type_mismatch(expected: MessageType, actual: MessageType) -> Self {
        Self::MessageTypeMismatch { expected, actual }
    }

    pub(crate) fn encode_payload(source: prost::EncodeError) -> Self {
        Self::EncodePayload { source }
    }

    pub(crate) fn decode_payload(source: prost::DecodeError) -> Self {
        Self::DecodePayload { source }
    }
}
