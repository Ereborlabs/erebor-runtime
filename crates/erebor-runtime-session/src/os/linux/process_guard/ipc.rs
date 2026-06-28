use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

const MAGIC: &[u8; 4] = b"ERB1";
const FRAME_VERSION: u16 = 1;
const HEADER_LEN: usize = 12;
const MAX_PAYLOAD_LEN: usize = 64 * 1024;
const PROTOCOL_VERSION: u32 = 1;
const INTERCEPTION_TOKEN_HEADER: &str = "interception_token";

const KIND_GUARD_HELLO: &str = "erebor.runtime.ipc.v1.GuardHello";
const KIND_GUARD_HELLO_ACK: &str = "erebor.runtime.ipc.v1.GuardHelloAck";
const KIND_INTERCEPTION_REQUEST: &str = "erebor.runtime.ipc.v1.InterceptionRequest";
const KIND_INTERCEPTION_DECISION: &str = "erebor.runtime.ipc.v1.InterceptionDecision";

const DECISION_ALLOW: i32 = 1;
const DECISION_DENY: i32 = 2;
const DECISION_REQUIRE_APPROVAL: i32 = 3;
const DECISION_MEDIATE: i32 = 4;
const INTERCEPTION_SOURCE_SHIM: i32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeInterceptionEndpoint {
    pub(super) path: String,
    pub(super) token: String,
    pub(super) timeout_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GuardHello {
    pub(super) session_id: String,
    pub(super) actor_id: String,
    pub(super) guard_pid: i64,
    pub(super) runner_kind: String,
    pub(super) platform: String,
    pub(super) capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InterceptionRequest {
    pub(super) request_id: u64,
    pub(super) actor_id: String,
    pub(super) pid: i64,
    pub(super) ppid: i64,
    pub(super) executable: String,
    pub(super) argv: Vec<String>,
    pub(super) cwd: String,
    pub(super) matched_handler_id: String,
    pub(super) timestamp: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InterceptionDecision {
    pub(super) request_id: u64,
    pub(super) kind: InterceptionDecisionKind,
    pub(super) rule_id: String,
    pub(super) reason: String,
    pub(super) allow_exec_target: Option<String>,
    pub(super) deny_exit_code: Option<i32>,
    pub(super) mediate: Option<MediateDecision>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterceptionDecisionKind {
    Allow,
    Deny,
    RequireApproval,
    Mediate,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MediateDecision {
    pub(super) kind: String,
    pub(super) replacement_surface: String,
    pub(super) endpoint: String,
    pub(super) lease_id: String,
    pub(super) print_line: String,
    pub(super) keepalive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Header {
    key: String,
    value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Envelope {
    message_id: u64,
    correlation_id: u64,
    message_kind: String,
    payload: Vec<u8>,
    headers: Vec<Header>,
}

pub(super) struct RuntimeInterceptionConnection {
    stream: UnixStream,
    next_message_id: u64,
}

impl RuntimeInterceptionConnection {
    pub(super) fn connect(
        endpoint: &RuntimeInterceptionEndpoint,
        hello: GuardHello,
    ) -> Result<Self, String> {
        let mut stream = UnixStream::connect(Path::new(&endpoint.path)).map_err(|error| {
            format!(
                "failed to connect to Erebor runtime interception broker at {}: {error}",
                endpoint.path
            )
        })?;
        let timeout = Duration::from_millis(endpoint.timeout_ms);
        stream.set_read_timeout(Some(timeout)).map_err(|error| {
            format!("failed to set runtime interception broker read timeout: {error}")
        })?;
        stream.set_write_timeout(Some(timeout)).map_err(|error| {
            format!("failed to set runtime interception broker write timeout: {error}")
        })?;

        let payload = encode_guard_hello(&hello);
        let mut envelope = Envelope {
            message_id: 1,
            correlation_id: 0,
            message_kind: String::from(KIND_GUARD_HELLO),
            payload,
            headers: Vec::new(),
        };
        envelope.headers.push(Header {
            key: String::from(INTERCEPTION_TOKEN_HEADER),
            value: endpoint.token.clone(),
        });
        write_envelope(&mut stream, &envelope)?;

        let response = read_envelope(&mut stream)?;
        if response.message_kind != KIND_GUARD_HELLO_ACK {
            return Err(format!(
                "runtime interception broker returned unexpected response `{}` to GuardHello",
                response.message_kind
            ));
        }
        let ack = decode_guard_hello_ack(&response.payload)?;
        if !ack.accepted {
            return Err(format!(
                "runtime interception broker rejected guard hello: {}",
                ack.reason
            ));
        }

        Ok(Self {
            stream,
            next_message_id: 2,
        })
    }

    pub(super) fn request_decision(
        &mut self,
        request: &InterceptionRequest,
    ) -> Result<InterceptionDecision, String> {
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.saturating_add(1);
        let envelope = Envelope {
            message_id,
            correlation_id: 1,
            message_kind: String::from(KIND_INTERCEPTION_REQUEST),
            payload: encode_interception_request(request),
            headers: Vec::new(),
        };
        write_envelope(&mut self.stream, &envelope)?;

        let response = read_envelope(&mut self.stream)?;
        if response.message_kind != KIND_INTERCEPTION_DECISION {
            return Err(format!(
                "runtime interception broker returned unexpected response `{}` to InterceptionRequest",
                response.message_kind
            ));
        }
        decode_interception_decision(&response.payload)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuardHelloAck {
    accepted: bool,
    reason: String,
}

fn write_envelope(stream: &mut UnixStream, envelope: &Envelope) -> Result<(), String> {
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

fn read_envelope(stream: &mut UnixStream) -> Result<Envelope, String> {
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

fn encode_envelope(envelope: &Envelope) -> Vec<u8> {
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

fn decode_envelope(bytes: &[u8]) -> Result<Envelope, String> {
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

fn encode_guard_hello(hello: &GuardHello) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, PROTOCOL_VERSION as u64);
    write_string_field(&mut output, 2, &hello.session_id);
    write_string_field(&mut output, 3, &hello.actor_id);
    write_varint_field(&mut output, 4, hello.guard_pid as u64);
    write_string_field(&mut output, 5, &hello.runner_kind);
    write_string_field(&mut output, 6, &hello.platform);
    for capability in &hello.capabilities {
        write_string_field(&mut output, 7, capability);
    }
    output
}

fn decode_guard_hello_ack(bytes: &[u8]) -> Result<GuardHelloAck, String> {
    let mut cursor = 0;
    let mut ack = GuardHelloAck {
        accepted: false,
        reason: String::new(),
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (3, 0) => ack.accepted = read_varint(bytes, &mut cursor)? != 0,
            (4, 2) => ack.reason = read_string(bytes, &mut cursor)?,
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(ack)
}

fn encode_interception_request(request: &InterceptionRequest) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, request.request_id);
    write_string_field(&mut output, 2, &request.actor_id);
    write_varint_field(&mut output, 3, INTERCEPTION_SOURCE_SHIM as u64);
    write_varint_field(&mut output, 4, request.pid as u64);
    write_varint_field(&mut output, 5, request.ppid as u64);
    write_string_field(&mut output, 6, &request.executable);
    for argument in &request.argv {
        write_string_field(&mut output, 7, argument);
    }
    write_string_field(&mut output, 8, &request.cwd);
    write_string_field(&mut output, 11, &request.matched_handler_id);
    write_string_field(&mut output, 12, &request.timestamp);
    output
}

fn decode_interception_decision(bytes: &[u8]) -> Result<InterceptionDecision, String> {
    let mut cursor = 0;
    let mut decision = InterceptionDecision {
        request_id: 0,
        kind: InterceptionDecisionKind::Unknown,
        rule_id: String::new(),
        reason: String::new(),
        allow_exec_target: None,
        deny_exit_code: None,
        mediate: None,
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 0) => decision.request_id = read_varint(bytes, &mut cursor)?,
            (2, 0) => {
                decision.kind = match read_varint(bytes, &mut cursor)? as i32 {
                    DECISION_ALLOW => InterceptionDecisionKind::Allow,
                    DECISION_DENY => InterceptionDecisionKind::Deny,
                    DECISION_REQUIRE_APPROVAL => InterceptionDecisionKind::RequireApproval,
                    DECISION_MEDIATE => InterceptionDecisionKind::Mediate,
                    _ => InterceptionDecisionKind::Unknown,
                };
            }
            (3, 2) => decision.rule_id = read_string(bytes, &mut cursor)?,
            (4, 2) => decision.reason = read_string(bytes, &mut cursor)?,
            (6, 2) => {
                let allow = read_bytes(bytes, &mut cursor)?;
                decision.allow_exec_target = decode_allow_decision(&allow)?;
            }
            (7, 2) => {
                let deny = read_bytes(bytes, &mut cursor)?;
                decision.deny_exit_code = decode_deny_decision(&deny)?;
            }
            (8, 2) => {
                let mediate = read_bytes(bytes, &mut cursor)?;
                decision.mediate = Some(decode_mediate_decision(&mediate)?);
            }
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(decision)
}

fn decode_allow_decision(bytes: &[u8]) -> Result<Option<String>, String> {
    let mut cursor = 0;
    let mut exec_target = None;
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => exec_target = Some(read_string(bytes, &mut cursor)?),
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(exec_target)
}

fn decode_deny_decision(bytes: &[u8]) -> Result<Option<i32>, String> {
    let mut cursor = 0;
    let mut exit_code = None;
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 0) => exit_code = Some(read_varint(bytes, &mut cursor)? as i32),
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(exit_code)
}

fn decode_mediate_decision(bytes: &[u8]) -> Result<MediateDecision, String> {
    let mut cursor = 0;
    let mut decision = MediateDecision {
        kind: String::new(),
        replacement_surface: String::new(),
        endpoint: String::new(),
        lease_id: String::new(),
        print_line: String::new(),
        keepalive: false,
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => decision.kind = read_string(bytes, &mut cursor)?,
            (2, 2) => decision.replacement_surface = read_string(bytes, &mut cursor)?,
            (3, 2) => decision.endpoint = read_string(bytes, &mut cursor)?,
            (4, 2) => decision.lease_id = read_string(bytes, &mut cursor)?,
            (5, 2) => decision.print_line = read_string(bytes, &mut cursor)?,
            (6, 0) => decision.keepalive = read_varint(bytes, &mut cursor)? != 0,
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(decision)
}

fn write_varint_field(output: &mut Vec<u8>, field_number: u64, value: u64) {
    write_varint(output, field_number << 3);
    write_varint(output, value);
}

fn write_string_field(output: &mut Vec<u8>, field_number: u64, value: &str) {
    write_bytes_field(output, field_number, value.as_bytes());
}

fn write_bytes_field(output: &mut Vec<u8>, field_number: u64, value: &[u8]) {
    write_varint(output, (field_number << 3) | 2);
    write_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let mut shift = 0;
    let mut value = 0_u64;
    loop {
        if *cursor >= bytes.len() {
            return Err(String::from("unexpected end of protobuf varint"));
        }
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(String::from("protobuf varint is too large"));
        }
    }
}

fn read_string(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let value = read_bytes(bytes, cursor)?;
    String::from_utf8(value).map_err(|error| format!("protobuf string is not UTF-8: {error}"))
}

fn read_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, String> {
    let len = read_varint(bytes, cursor)? as usize;
    if bytes.len().saturating_sub(*cursor) < len {
        return Err(String::from("unexpected end of protobuf bytes field"));
    }
    let value = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(value)
}

fn skip_field(bytes: &[u8], cursor: &mut usize, wire: u64) -> Result<(), String> {
    match wire {
        0 => {
            let _value = read_varint(bytes, cursor)?;
            Ok(())
        }
        2 => {
            let len = read_varint(bytes, cursor)? as usize;
            if bytes.len().saturating_sub(*cursor) < len {
                return Err(String::from("unexpected end of protobuf field"));
            }
            *cursor += len;
            Ok(())
        }
        _ => Err(format!("unsupported protobuf wire type {wire}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_envelope, decode_interception_decision, encode_envelope,
        encode_interception_request, Envelope, Header, InterceptionDecisionKind,
        InterceptionRequest, KIND_INTERCEPTION_DECISION, KIND_INTERCEPTION_REQUEST,
    };

    #[test]
    fn envelope_round_trips_without_session_id() {
        let envelope = Envelope {
            message_id: 2,
            correlation_id: 1,
            message_kind: String::from(KIND_INTERCEPTION_REQUEST),
            payload: vec![1, 2, 3],
            headers: vec![Header {
                key: String::from("interception_token"),
                value: String::from("token"),
            }],
        };

        let decoded = decode_envelope(&encode_envelope(&envelope)).expect("decode envelope");

        assert_eq!(decoded, envelope);
    }

    #[test]
    fn interception_request_encoding_omits_session_identity() {
        let request = InterceptionRequest {
            request_id: 7,
            actor_id: String::from("openclaw"),
            pid: 10,
            ppid: 9,
            executable: String::from("google-chrome"),
            argv: vec![String::from("google-chrome")],
            cwd: String::from("/tmp"),
            matched_handler_id: String::from("managed-browser"),
            timestamp: String::from("unix:1"),
        };

        let encoded = encode_interception_request(&request);

        assert!(encoded
            .windows("openclaw".len())
            .any(|window| window == b"openclaw"));
        assert!(!encoded
            .windows("session".len())
            .any(|window| window == b"session"));
    }

    #[test]
    fn decodes_mediate_decision_payload() {
        let mut mediate = Vec::new();
        super::write_string_field(&mut mediate, 1, "managed_browser_cdp");
        super::write_string_field(&mut mediate, 2, "browser_cdp");
        super::write_string_field(&mut mediate, 3, "ws://127.0.0.1:9222/");
        super::write_string_field(
            &mut mediate,
            5,
            "DevTools listening on ws://127.0.0.1:9222/devtools/browser/erebor",
        );
        super::write_varint_field(&mut mediate, 6, 1);

        let mut payload = Vec::new();
        super::write_varint_field(&mut payload, 1, 7);
        super::write_varint_field(&mut payload, 2, 4);
        super::write_string_field(&mut payload, 3, "mediate-browser");
        super::write_string_field(&mut payload, 4, "browser mediated");
        super::write_bytes_field(&mut payload, 8, &mediate);
        let decision = decode_interception_decision(&payload).expect("decode decision");

        assert_eq!(decision.request_id, 7);
        assert_eq!(decision.kind, InterceptionDecisionKind::Mediate);
        assert_eq!(
            decision.mediate.expect("mediate").replacement_surface,
            "browser_cdp"
        );

        let envelope = Envelope {
            message_id: 3,
            correlation_id: 7,
            message_kind: String::from(KIND_INTERCEPTION_DECISION),
            payload,
            headers: Vec::new(),
        };
        assert_eq!(
            decode_envelope(&encode_envelope(&envelope))
                .expect("decode envelope")
                .message_kind,
            KIND_INTERCEPTION_DECISION
        );
    }
}
