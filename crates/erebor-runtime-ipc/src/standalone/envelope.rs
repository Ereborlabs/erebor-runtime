use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
};

use super::codec::{
    read_bytes, read_string, read_varint, skip_field, write_bytes_field, write_string_field,
    write_varint_field, PROTOCOL_VERSION,
};

const MAGIC: &[u8; 4] = b"ERB1";
const FRAME_VERSION: u16 = 1;
const HEADER_LEN: usize = 12;
const MAX_PAYLOAD_LEN: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Header {
    pub(super) key: String,
    pub(super) value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Envelope {
    pub(super) message_id: u64,
    pub(super) correlation_id: u64,
    pub(super) message_kind: String,
    pub(super) payload: Vec<u8>,
    pub(super) headers: Vec<Header>,
}

pub(super) fn write_envelope(stream: &mut UnixStream, envelope: &Envelope) -> Result<(), String> {
    let payload = encode_envelope(envelope);
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(String::from(
            "runtime interception broker frame payload is too large",
        ));
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    frame.extend_from_slice(&0u16.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    stream
        .write_all(&frame)
        .map_err(|error| format!("failed to write runtime interception broker frame: {error}"))
}

pub(super) fn read_envelope(stream: &mut UnixStream) -> Result<Envelope, String> {
    let mut header = [0_u8; HEADER_LEN];
    stream.read_exact(&mut header).map_err(|error| {
        format!("failed to read runtime interception broker frame header: {error}")
    })?;
    if &header[0..4] != MAGIC {
        return Err(String::from(
            "runtime interception broker frame has invalid magic",
        ));
    }
    let version = u16::from_le_bytes([header[4], header[5]]);
    if version != FRAME_VERSION {
        return Err(format!(
            "runtime interception broker frame version {version} is not supported"
        ));
    }
    let payload_len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(String::from(
            "runtime interception broker frame payload is too large",
        ));
    }
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).map_err(|error| {
        format!("failed to read runtime interception broker frame payload: {error}")
    })?;
    decode_envelope(&payload)
}

pub(super) fn encode_envelope(envelope: &Envelope) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, PROTOCOL_VERSION as u64);
    write_varint_field(&mut output, 2, envelope.message_id);
    write_varint_field(&mut output, 3, envelope.correlation_id);
    write_string_field(&mut output, 4, &envelope.message_kind);
    write_bytes_field(&mut output, 5, &envelope.payload);
    for header in &envelope.headers {
        let mut encoded = Vec::new();
        write_string_field(&mut encoded, 1, &header.key);
        write_string_field(&mut encoded, 2, &header.value);
        write_bytes_field(&mut output, 6, &encoded);
    }
    output
}

pub(super) fn decode_envelope(bytes: &[u8]) -> Result<Envelope, String> {
    let mut cursor = 0;
    let mut envelope = Envelope {
        message_id: 0,
        correlation_id: 0,
        message_kind: String::new(),
        payload: Vec::new(),
        headers: Vec::new(),
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (2, 0) => envelope.message_id = read_varint(bytes, &mut cursor)?,
            (3, 0) => envelope.correlation_id = read_varint(bytes, &mut cursor)?,
            (4, 2) => envelope.message_kind = read_string(bytes, &mut cursor)?,
            (5, 2) => envelope.payload = read_bytes(bytes, &mut cursor)?,
            (6, 2) => {
                let header = read_bytes(bytes, &mut cursor)?;
                envelope.headers.push(decode_header(&header)?);
            }
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(envelope)
}

fn decode_header(bytes: &[u8]) -> Result<Header, String> {
    let mut cursor = 0;
    let mut header = Header {
        key: String::new(),
        value: String::new(),
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => header.key = read_string(bytes, &mut cursor)?,
            (2, 2) => header.value = read_string(bytes, &mut cursor)?,
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(header)
}
