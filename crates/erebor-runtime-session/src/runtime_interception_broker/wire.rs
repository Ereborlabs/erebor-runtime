use std::io::{Read, Write};

use erebor_runtime_ipc::{
    v1::{Envelope, Header},
    EreborIpcFrame, IpcProtocolError, FRAME_VERSION, HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN,
};

use super::{constants::INTERCEPTION_TOKEN_HEADER, server::RuntimeInterceptionBrokerError};

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
    let mut header = [0_u8; HEADER_LEN];
    stream
        .read_exact(&mut header)
        .map_err(RuntimeInterceptionBrokerError::io)?;

    if header[0..4] != MAGIC {
        return Err(RuntimeInterceptionBrokerError::protocol(
            IpcProtocolError::InvalidMagic,
        ));
    }

    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != FRAME_VERSION {
        return Err(RuntimeInterceptionBrokerError::protocol(
            IpcProtocolError::UnsupportedFrameVersion { version },
        ));
    }

    let payload_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(RuntimeInterceptionBrokerError::protocol(
            IpcProtocolError::PayloadTooLarge {
                actual: payload_len,
                maximum: MAX_PAYLOAD_LEN,
            },
        ));
    }

    let mut frame = Vec::with_capacity(HEADER_LEN + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(HEADER_LEN + payload_len, 0);
    stream
        .read_exact(&mut frame[HEADER_LEN..])
        .map_err(RuntimeInterceptionBrokerError::io)?;

    EreborIpcFrame::decode(&frame).map_err(RuntimeInterceptionBrokerError::protocol)
}

pub(super) fn write_frame_to_stream(
    stream: &mut impl Write,
    frame: &EreborIpcFrame,
) -> Result<(), RuntimeInterceptionBrokerError> {
    stream
        .write_all(
            &frame
                .encode()
                .map_err(RuntimeInterceptionBrokerError::protocol)?,
        )
        .map_err(RuntimeInterceptionBrokerError::io)
}
