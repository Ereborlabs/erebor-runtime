use std::io::{Read, Write};

use erebor_runtime_ipc::{
    v1::{Envelope, Header},
    EreborIpcFrame, SyncFrameCodec,
};
use snafu::ResultExt;

use super::constants::INTERCEPTION_TOKEN_HEADER;
use crate::error::{BrokerProtocolSnafu, RuntimeInterceptionBrokerError};

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(super) fn interception_token(envelope: &Envelope) -> Option<&str> {
    envelope
        .headers
        .iter()
        .find(|header| header.key == INTERCEPTION_TOKEN_HEADER)
        .map(|header| header.value.as_str())
}

pub(super) fn envelope_with_token(mut envelope: Envelope, token: impl Into<String>) -> Envelope {
    envelope.headers.push(Header {
        key: String::from(INTERCEPTION_TOKEN_HEADER),
        value: token.into(),
    });
    envelope
}

pub(super) fn read_frame_from_stream(
    stream: &mut impl Read,
) -> Result<EreborIpcFrame, RuntimeInterceptionBrokerError> {
    SyncFrameCodec::read_frame(stream).context(BrokerProtocolSnafu)
}

pub(super) fn write_frame_to_stream(
    stream: &mut impl Write,
    frame: &EreborIpcFrame,
) -> Result<(), RuntimeInterceptionBrokerError> {
    SyncFrameCodec::write_frame(stream, frame).context(BrokerProtocolSnafu)
}
