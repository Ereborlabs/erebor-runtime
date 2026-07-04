use std::error::Error;

use erebor_runtime_ipc::{
    v1::{
        AllowDecision, DecisionKind, DenyDecision, Envelope, GuardHello, InterceptionDecision,
        InterceptionOperation, InterceptionRequest, InterceptionSource, MediateDecision,
        ProcessExecOperation, KIND_GUARD_HELLO, KIND_INTERCEPTION_DECISION,
        KIND_INTERCEPTION_REQUEST, PROTOCOL_VERSION,
    },
    EreborIpcFrame, IpcProtocolError, FRAME_VERSION, HEADER_LEN, MAX_PAYLOAD_LEN,
};

#[test]
fn public_api_round_trips_guard_hello_through_envelope_and_frame() -> Result<(), Box<dyn Error>> {
    let hello = GuardHello {
        protocol_version: PROTOCOL_VERSION,
        session_id: String::from("session-public-contract"),
        actor_id: String::from("openclaw"),
        guard_pid: 1234,
        runner_kind: String::from("linux_host"),
        platform: String::from("linux-x86_64"),
        capabilities: vec![String::from("interception_request")],
    };

    let envelope = Envelope::wrap_message(1, 0, KIND_GUARD_HELLO, &hello)?;
    let encoded = envelope.into_frame()?.encode()?;
    let decoded_frame = EreborIpcFrame::decode(&encoded)?;
    let decoded_envelope: Envelope = decoded_frame.decode_payload()?;
    let decoded_hello: GuardHello = decoded_envelope.decode_typed_payload(KIND_GUARD_HELLO)?;

    assert_eq!(decoded_envelope.protocol_version, PROTOCOL_VERSION);
    assert_eq!(decoded_envelope.message_kind, KIND_GUARD_HELLO);
    assert_eq!(decoded_hello, hello);
    Ok(())
}

#[test]
fn public_api_round_trips_interception_request_and_deny_decision() -> Result<(), Box<dyn Error>> {
    let request = InterceptionRequest {
        request_id: 77,
        actor_id: String::from("openclaw"),
        source: InterceptionSource::Shim as i32,
        pid: 2001,
        ppid: 2000,
        executable: String::from("google-chrome"),
        argv: vec![
            String::from("google-chrome"),
            String::from("--remote-debugging-port=9222"),
        ],
        cwd: String::from("/workspace"),
        selected_env: Vec::new(),
        requested_endpoint: None,
        matched_handler_id: String::from("managed-browser-cdp"),
        timestamp: String::from("unix:1781200100"),
        operation: InterceptionOperation::ProcessExec as i32,
        process_exec: Some(ProcessExecOperation {
            executable: String::from("google-chrome"),
            argv: vec![
                String::from("google-chrome"),
                String::from("--remote-debugging-port=9222"),
            ],
            requested_endpoint: None,
            matched_handler_id: String::from("managed-browser-cdp"),
        }),
        file: None,
        socket: None,
    };
    let request_envelope = Envelope::wrap_message(2, 0, KIND_INTERCEPTION_REQUEST, &request)?;
    let request_frame = EreborIpcFrame::decode(&request_envelope.into_frame()?.encode()?)?;
    let decoded_request_envelope: Envelope = request_frame.decode_payload()?;
    let decoded_request: InterceptionRequest =
        decoded_request_envelope.decode_typed_payload(KIND_INTERCEPTION_REQUEST)?;

    assert_eq!(decoded_request, request);

    let decision = InterceptionDecision {
        request_id: decoded_request.request_id,
        decision: DecisionKind::Deny as i32,
        rule_id: String::from("deny-raw-cdp"),
        reason: String::from("raw browser CDP launch denied"),
        timeout_ms: 25,
        allow: None,
        deny: Some(DenyDecision { exit_code: 126 }),
        mediate: None,
    };
    let decision_envelope =
        Envelope::wrap_message(3, request.request_id, KIND_INTERCEPTION_DECISION, &decision)?;
    let decision_frame = EreborIpcFrame::decode(&decision_envelope.into_frame()?.encode()?)?;
    let decoded_decision_envelope: Envelope = decision_frame.decode_payload()?;
    let decoded_decision: InterceptionDecision =
        decoded_decision_envelope.decode_typed_payload(KIND_INTERCEPTION_DECISION)?;

    assert_eq!(decoded_decision_envelope.correlation_id, request.request_id);
    assert_eq!(decoded_decision.decision, DecisionKind::Deny as i32);
    assert_eq!(decoded_decision, decision);
    Ok(())
}

#[test]
fn frame_header_is_generic_and_future_envelope_kinds_survive_round_trip(
) -> Result<(), Box<dyn Error>> {
    let envelope = Envelope {
        protocol_version: PROTOCOL_VERSION,
        message_id: 9,
        correlation_id: 8,
        message_kind: String::from("erebor.runtime.ipc.v1.FuturePayload"),
        payload: vec![1, 2, 3, 4],
        headers: Vec::new(),
    };
    let encoded = envelope.into_frame()?.encode()?;

    assert_eq!(&encoded[0..4], b"ERB1");
    assert_eq!(u16::from_le_bytes([encoded[4], encoded[5]]), FRAME_VERSION);
    let encoded_payload_len =
        u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]) as usize;
    assert_eq!(encoded_payload_len, encoded.len() - HEADER_LEN);

    let decoded_frame = EreborIpcFrame::decode(&encoded)?;
    let decoded_envelope: Envelope = decoded_frame.decode_payload()?;

    assert_eq!(
        decoded_envelope.message_kind,
        "erebor.runtime.ipc.v1.FuturePayload"
    );
    assert_eq!(decoded_envelope.payload, &[1, 2, 3, 4]);
    Ok(())
}

#[test]
fn public_api_supports_all_phase_zero_decision_kinds() -> Result<(), Box<dyn Error>> {
    let decisions = [
        InterceptionDecision {
            request_id: 88,
            decision: DecisionKind::Allow as i32,
            rule_id: String::from("allow-process"),
            reason: String::from("process allowed"),
            timeout_ms: 25,
            allow: Some(AllowDecision {
                exec_target: String::from("/usr/bin/true"),
            }),
            deny: None,
            mediate: None,
        },
        InterceptionDecision {
            request_id: 88,
            decision: DecisionKind::Deny as i32,
            rule_id: String::from("deny-process"),
            reason: String::from("process denied"),
            timeout_ms: 25,
            allow: None,
            deny: Some(DenyDecision { exit_code: 126 }),
            mediate: None,
        },
        InterceptionDecision {
            request_id: 88,
            decision: DecisionKind::RequireApproval as i32,
            rule_id: String::from("approve-process"),
            reason: String::from("process requires approval"),
            timeout_ms: 25,
            allow: None,
            deny: None,
            mediate: None,
        },
        InterceptionDecision {
            request_id: 88,
            decision: DecisionKind::Mediate as i32,
            rule_id: String::from("mediate-browser"),
            reason: String::from("browser launch mediated"),
            timeout_ms: 25,
            allow: None,
            deny: None,
            mediate: Some(MediateDecision {
                kind: String::from("managed_browser_cdp"),
                replacement_surface: String::from("browser_cdp"),
                endpoint: String::from("ws://127.0.0.1:9222/"),
                lease_id: String::from("lease-public-contract"),
                print_line: String::from("DevTools listening on ws://127.0.0.1:9222/"),
                keepalive: true,
            }),
        },
    ];

    for decision in decisions {
        let envelope = Envelope::wrap_message(
            10,
            decision.request_id,
            KIND_INTERCEPTION_DECISION,
            &decision,
        )?;
        let frame = EreborIpcFrame::decode(&envelope.into_frame()?.encode()?)?;
        let decoded_envelope: Envelope = frame.decode_payload()?;
        let decoded_decision: InterceptionDecision =
            decoded_envelope.decode_typed_payload(KIND_INTERCEPTION_DECISION)?;

        assert_eq!(decoded_decision, decision);
    }

    Ok(())
}

#[test]
fn frame_payload_boundary_is_enforced_on_create_and_decode() -> Result<(), Box<dyn Error>> {
    let max_payload_frame = EreborIpcFrame::new(0, vec![7; MAX_PAYLOAD_LEN])?;
    let encoded = max_payload_frame.encode()?;
    let decoded = EreborIpcFrame::decode(&encoded)?;

    assert_eq!(decoded.payload().len(), MAX_PAYLOAD_LEN);

    let too_large = EreborIpcFrame::new(0, vec![7; MAX_PAYLOAD_LEN + 1]);
    assert!(matches!(
        too_large,
        Err(IpcProtocolError::PayloadTooLarge { .. })
    ));

    let mut oversized_decode = Vec::from(*b"ERB1");
    oversized_decode.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    oversized_decode.extend_from_slice(&0u16.to_le_bytes());
    oversized_decode.extend_from_slice(&((MAX_PAYLOAD_LEN + 1) as u32).to_le_bytes());
    assert!(matches!(
        EreborIpcFrame::decode(&oversized_decode),
        Err(IpcProtocolError::PayloadTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn proto_contract_file_contains_phase_zero_schema() {
    let proto = include_str!("../proto/erebor/runtime/ipc/v1/control.proto");

    assert!(proto.contains("message Envelope"));
    assert!(proto.contains("message InterceptionRequest"));
    assert!(proto.contains("message InterceptionDecision"));
    assert!(proto.contains("message FileOperation"));
    assert!(proto.contains("message FileIdentity"));
    assert!(proto.contains("message SocketOperation"));
    assert!(proto.contains("enum InterceptionOperation"));
    assert!(proto.contains("enum DecisionKind"));
    assert!(proto.contains("DECISION_KIND_REQUIRE_APPROVAL"));
    assert!(!proto.contains("message Envelope {\n  uint32 protocol_version = 1;\n  uint64 message_id = 2;\n  uint64 correlation_id = 3;\n  string session_id"));
}
