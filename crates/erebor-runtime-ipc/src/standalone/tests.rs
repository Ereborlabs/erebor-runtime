use super::{
    codec::{write_bytes_field, write_string_field, write_varint_field},
    decision::{decode_interception_decision, KIND_INTERCEPTION_DECISION},
    envelope::{decode_envelope, encode_envelope},
    request::{encode_guard_hello, encode_interception_request, KIND_INTERCEPTION_REQUEST},
    Envelope, FileIdentity, FileOperation, FileOperationKind, GuardHello, Header,
    InterceptionDecisionKind, InterceptionOperation, InterceptionRequest, InterceptionSource,
};
use crate::v1;
use prost::Message;

#[test]
fn envelope_round_trips_without_session_id() -> Result<(), String> {
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

    let decoded = decode_envelope(&encode_envelope(&envelope))?;

    assert_eq!(decoded, envelope);
    Ok(())
}

#[test]
fn standalone_envelope_encoding_matches_canonical_prost_contract() -> Result<(), String> {
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

    let decoded: v1::Envelope = decode_prost(&encode_envelope(&envelope))?;

    assert_eq!(decoded.protocol_version, v1::PROTOCOL_VERSION);
    assert_eq!(decoded.message_id, envelope.message_id);
    assert_eq!(decoded.correlation_id, envelope.correlation_id);
    assert_eq!(decoded.message_kind, envelope.message_kind);
    assert_eq!(decoded.payload, envelope.payload);
    assert_eq!(decoded.headers.len(), 1);
    assert_eq!(decoded.headers[0].key, "interception_token");
    assert_eq!(decoded.headers[0].value, "token");
    Ok(())
}

#[test]
fn canonical_prost_envelope_decodes_through_standalone_adapter() -> Result<(), String> {
    let envelope = v1::Envelope {
        protocol_version: v1::PROTOCOL_VERSION,
        message_id: 3,
        correlation_id: 2,
        message_kind: String::from(KIND_INTERCEPTION_DECISION),
        payload: vec![4, 5, 6],
        headers: vec![v1::Header {
            key: String::from("interception_token"),
            value: String::from("token"),
        }],
    };

    let decoded = decode_envelope(&envelope.encode_to_vec())?;

    assert_eq!(decoded.message_id, envelope.message_id);
    assert_eq!(decoded.correlation_id, envelope.correlation_id);
    assert_eq!(decoded.message_kind, envelope.message_kind);
    assert_eq!(decoded.payload, envelope.payload);
    assert_eq!(decoded.headers.len(), 1);
    assert_eq!(decoded.headers[0].key, "interception_token");
    assert_eq!(decoded.headers[0].value, "token");
    Ok(())
}

#[test]
fn standalone_guard_hello_encoding_matches_canonical_prost_contract() -> Result<(), String> {
    let hello = GuardHello {
        session_id: String::from("session-fixture"),
        actor_id: String::from("openclaw"),
        guard_pid: 42,
        runner_kind: String::from("linux_host"),
        platform: String::from("linux-x86_64"),
        capabilities: vec![String::from("interception_request")],
    };

    let decoded: v1::GuardHello = decode_prost(&encode_guard_hello(&hello))?;

    assert_eq!(decoded.protocol_version, v1::PROTOCOL_VERSION);
    assert_eq!(decoded.session_id, hello.session_id);
    assert_eq!(decoded.actor_id, hello.actor_id);
    assert_eq!(decoded.guard_pid, hello.guard_pid);
    assert_eq!(decoded.runner_kind, hello.runner_kind);
    assert_eq!(decoded.platform, hello.platform);
    assert_eq!(decoded.capabilities, hello.capabilities);
    Ok(())
}

#[test]
fn interception_request_encoding_omits_session_identity() {
    let request = InterceptionRequest {
        request_id: 7,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Shim,
        pid: 10,
        ppid: 9,
        executable: String::from("google-chrome"),
        argv: vec![String::from("google-chrome")],
        cwd: String::from("/tmp"),
        matched_handler_id: String::from("managed-browser"),
        timestamp: String::from("unix:1"),
        operation: InterceptionOperation::ProcessExec,
        file: None,
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
fn file_interception_request_encodes_operation_and_identity() {
    let request = InterceptionRequest {
        request_id: 8,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Ptrace,
        pid: 11,
        ppid: 10,
        executable: String::new(),
        argv: Vec::new(),
        cwd: String::from("/workspace"),
        matched_handler_id: String::new(),
        timestamp: String::from("unix:2"),
        operation: InterceptionOperation::FileRead,
        file: Some(FileOperation {
            kind: FileOperationKind::Read,
            path: String::from("/workspace/secret.txt"),
            resolved_identity: Some(FileIdentity {
                device: 123,
                inode: 456,
            }),
        }),
    };

    let encoded = encode_interception_request(&request);

    assert!(encoded
        .windows("secret.txt".len())
        .any(|window| window == b"secret.txt"));
    assert!(encoded
        .windows(2)
        .any(|window| window == [13 << 3, InterceptionOperation::FileRead.as_i32() as u8]));
}

#[test]
fn standalone_interception_request_encoding_matches_canonical_prost_contract() -> Result<(), String>
{
    let request = InterceptionRequest {
        request_id: 8,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Ptrace,
        pid: 11,
        ppid: 10,
        executable: String::new(),
        argv: Vec::new(),
        cwd: String::from("/workspace"),
        matched_handler_id: String::new(),
        timestamp: String::from("unix:2"),
        operation: InterceptionOperation::FileRead,
        file: Some(FileOperation {
            kind: FileOperationKind::Read,
            path: String::from("/workspace/secret.txt"),
            resolved_identity: Some(FileIdentity {
                device: 123,
                inode: 456,
            }),
        }),
    };

    let decoded: v1::InterceptionRequest = decode_prost(&encode_interception_request(&request))?;
    let file = decoded
        .file
        .ok_or_else(|| String::from("missing decoded file operation"))?;
    let identity = file
        .resolved_identity
        .ok_or_else(|| String::from("missing decoded file identity"))?;

    assert_eq!(decoded.request_id, request.request_id);
    assert_eq!(decoded.actor_id, request.actor_id);
    assert_eq!(decoded.source, v1::InterceptionSource::Ptrace as i32);
    assert_eq!(decoded.pid, request.pid);
    assert_eq!(decoded.ppid, request.ppid);
    assert_eq!(decoded.cwd, request.cwd);
    assert_eq!(decoded.timestamp, request.timestamp);
    assert_eq!(
        decoded.operation,
        v1::InterceptionOperation::FileRead as i32
    );
    assert_eq!(file.kind, v1::FileOperationKind::Read as i32);
    assert_eq!(file.path, "/workspace/secret.txt");
    assert_eq!(identity.device, 123);
    assert_eq!(identity.inode, 456);
    Ok(())
}

#[test]
fn decodes_mediate_decision_payload() -> Result<(), String> {
    let mut mediate = Vec::new();
    write_string_field(&mut mediate, 1, "managed_browser_cdp");
    write_string_field(&mut mediate, 2, "browser_cdp");
    write_string_field(&mut mediate, 3, "ws://127.0.0.1:9222/");
    write_string_field(
        &mut mediate,
        5,
        "DevTools listening on ws://127.0.0.1:9222/devtools/browser/erebor",
    );
    write_varint_field(&mut mediate, 6, 1);

    let mut payload = Vec::new();
    write_varint_field(&mut payload, 1, 7);
    write_varint_field(&mut payload, 2, 4);
    write_string_field(&mut payload, 3, "mediate-browser");
    write_string_field(&mut payload, 4, "browser mediated");
    write_bytes_field(&mut payload, 8, &mediate);
    let decision = decode_interception_decision(&payload)?;

    assert_eq!(decision.request_id, 7);
    assert_eq!(decision.kind, InterceptionDecisionKind::Mediate);
    assert_eq!(
        decision
            .mediate
            .ok_or_else(|| String::from("missing mediation decision"))?
            .replacement_surface,
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
        decode_envelope(&encode_envelope(&envelope))?.message_kind,
        KIND_INTERCEPTION_DECISION
    );
    Ok(())
}

#[test]
fn standalone_decision_decoder_accepts_canonical_prost_decision() -> Result<(), String> {
    let decision = v1::InterceptionDecision {
        request_id: 7,
        decision: v1::DecisionKind::Mediate as i32,
        rule_id: String::from("mediate-browser"),
        reason: String::from("browser mediated"),
        timeout_ms: 25,
        allow: None,
        deny: None,
        mediate: Some(v1::MediateDecision {
            kind: String::from("managed_browser_cdp"),
            replacement_surface: String::from("browser_cdp"),
            endpoint: String::from("ws://127.0.0.1:9222/"),
            lease_id: String::from("lease-fixture"),
            print_line: String::from(
                "DevTools listening on ws://127.0.0.1:9222/devtools/browser/erebor",
            ),
            keepalive: true,
        }),
    };

    let decoded = decode_interception_decision(&decision.encode_to_vec())?;
    let mediation = decoded
        .mediate
        .ok_or_else(|| String::from("missing decoded mediation"))?;

    assert_eq!(decoded.request_id, decision.request_id);
    assert_eq!(decoded.kind, InterceptionDecisionKind::Mediate);
    assert_eq!(decoded.rule_id, decision.rule_id);
    assert_eq!(decoded.reason, decision.reason);
    assert_eq!(mediation.kind, "managed_browser_cdp");
    assert_eq!(mediation.replacement_surface, "browser_cdp");
    assert_eq!(mediation.endpoint, "ws://127.0.0.1:9222/");
    assert_eq!(mediation.lease_id, "lease-fixture");
    assert!(mediation.keepalive);
    Ok(())
}

fn decode_prost<T>(bytes: &[u8]) -> Result<T, String>
where
    T: Message + Default,
{
    T::decode(bytes).map_err(|error| error.to_string())
}
