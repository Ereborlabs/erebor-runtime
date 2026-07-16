include!(concat!(env!("OUT_DIR"), "/erebor.runtime.ipc.v1.rs"));

mod operation;

pub use operation::operation_name;

use prost::Message;
use snafu::ResultExt;

use crate::error::{DecodePayloadSnafu, EncodePayloadSnafu, PayloadKindMismatchSnafu};
use crate::EreborIpcFrame;

pub const PROTOCOL_VERSION: u32 = 1;
pub const KIND_GUARD_HELLO: &str = "erebor.runtime.ipc.v1.GuardHello";
pub const KIND_GUARD_HELLO_ACK: &str = "erebor.runtime.ipc.v1.GuardHelloAck";
pub const KIND_INTERCEPTION_REQUEST: &str = "erebor.runtime.ipc.v1.InterceptionRequest";
pub const KIND_INTERCEPTION_DECISION: &str = "erebor.runtime.ipc.v1.InterceptionDecision";
pub const KIND_GUARD_LIFECYCLE_EVENT: &str = "erebor.runtime.ipc.v1.GuardLifecycleEvent";
pub const KIND_GUARD_LIFECYCLE_REPLY: &str = "erebor.runtime.ipc.v1.GuardLifecycleReply";
pub const KIND_GUARD_EVENT: &str = "erebor.runtime.ipc.v1.GuardEvent";
pub const KIND_GUARD_GOODBYE: &str = "erebor.runtime.ipc.v1.GuardGoodbye";
pub const KIND_HOOK_HELLO: &str = "erebor.runtime.ipc.v1.HookHello";
pub const KIND_HOOK_HELLO_ACK: &str = "erebor.runtime.ipc.v1.HookHelloAck";
pub const KIND_HOOK_PEER_EVIDENCE: &str = "erebor.runtime.ipc.v1.HookPeerEvidence";
pub const KIND_HOOK_EVENT: &str = "erebor.runtime.ipc.v1.HookEvent";
pub const KIND_HOOK_RESULT: &str = "erebor.runtime.ipc.v1.HookResult";
pub const KIND_HOOK_REJECTION: &str = "erebor.runtime.ipc.v1.HookRejection";

impl HookHello {
    #[must_use]
    pub const fn uses_supported_protocol(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

impl Envelope {
    pub fn wrap_message<T: Message>(
        message_id: u64,
        correlation_id: u64,
        message_kind: impl Into<String>,
        message: &T,
    ) -> crate::Result<Self> {
        let mut payload = Vec::with_capacity(message.encoded_len());
        message.encode(&mut payload).context(EncodePayloadSnafu)?;

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            message_id,
            correlation_id,
            message_kind: message_kind.into(),
            payload,
            headers: Vec::new(),
        })
    }

    pub fn decode_typed_payload<T: Message + Default>(
        &self,
        expected_kind: &str,
    ) -> crate::Result<T> {
        if self.message_kind != expected_kind {
            return PayloadKindMismatchSnafu {
                expected: expected_kind.to_string(),
                actual: self.message_kind.clone(),
            }
            .fail();
        }

        T::decode(self.payload.as_slice()).context(DecodePayloadSnafu)
    }

    pub fn into_frame(&self) -> crate::Result<EreborIpcFrame> {
        EreborIpcFrame::from_message(self)
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::{
        AllowDecision, DecisionKind, DenyDecision, EnvVar, GuardHello, HookEvent, HookEventKind,
        HookHello, HookHelloAck, HookPeerEvidence, HookRejection, HookRejectionCode, HookResult,
        InterceptionDecision, InterceptionOperation, InterceptionRequest, InterceptionSource,
        MediateDecision, PipeIdentity, ProcessExecOperation, RequestedEndpoint, PROTOCOL_VERSION,
    };

    pub(crate) fn guard_hello() -> GuardHello {
        GuardHello {
            protocol_version: PROTOCOL_VERSION,
            session_id: String::from("session-fixture"),
            actor_id: String::from("openclaw"),
            guard_pid: 42,
            runner_kind: String::from("linux_host"),
            platform: String::from("linux-x86_64"),
            capabilities: vec![String::from("interception_request")],
        }
    }

    pub(crate) fn interception_request() -> InterceptionRequest {
        InterceptionRequest {
            request_id: 7,
            actor_id: String::from("openclaw"),
            source: InterceptionSource::Shim as i32,
            pid: 1001,
            ppid: 1000,
            executable: String::from("google-chrome"),
            argv: vec![
                String::from("google-chrome"),
                String::from("--remote-debugging-port=9222"),
            ],
            cwd: String::from("/workspace"),
            selected_env: vec![EnvVar {
                key: String::from("CHROME_PATH"),
                value: String::from("/tmp/erebor/shims/google-chrome"),
            }],
            requested_endpoint: Some(RequestedEndpoint {
                scheme: String::from("ws"),
                host: String::from("127.0.0.1"),
                port: 9222,
                path: String::from("/"),
            }),
            matched_handler_id: String::from("managed-browser-cdp"),
            timestamp: String::from("unix:1781200000"),
            operation: InterceptionOperation::ProcessExec as i32,
            process_exec: Some(ProcessExecOperation {
                executable: String::from("google-chrome"),
                argv: vec![
                    String::from("google-chrome"),
                    String::from("--remote-debugging-port=9222"),
                ],
                requested_endpoint: Some(RequestedEndpoint {
                    scheme: String::from("ws"),
                    host: String::from("127.0.0.1"),
                    port: 9222,
                    path: String::from("/"),
                }),
                matched_handler_id: String::from("managed-browser-cdp"),
            }),
            file: None,
            socket: None,
        }
    }

    pub(crate) fn allow_decision() -> InterceptionDecision {
        InterceptionDecision {
            request_id: 7,
            decision: DecisionKind::Allow as i32,
            rule_id: String::from("allow-browser-launch"),
            reason: String::from("process launch allowed"),
            timeout_ms: 25,
            allow: Some(AllowDecision {
                exec_target: String::from("/usr/bin/google-chrome"),
            }),
            deny: None,
            mediate: None,
        }
    }

    pub(crate) fn deny_decision() -> InterceptionDecision {
        InterceptionDecision {
            request_id: 7,
            decision: DecisionKind::Deny as i32,
            rule_id: String::from("deny-raw-cdp"),
            reason: String::from("raw browser CDP launch denied"),
            timeout_ms: 25,
            allow: None,
            deny: Some(DenyDecision { exit_code: 126 }),
            mediate: None,
        }
    }

    pub(crate) fn require_approval_decision() -> InterceptionDecision {
        InterceptionDecision {
            request_id: 7,
            decision: DecisionKind::RequireApproval as i32,
            rule_id: String::from("approve-browser-launch"),
            reason: String::from("browser launch requires approval"),
            timeout_ms: 25,
            allow: None,
            deny: None,
            mediate: None,
        }
    }

    pub(crate) fn hook_hello() -> HookHello {
        HookHello {
            protocol_version: PROTOCOL_VERSION,
            ticket_id: String::from("ticket-fixture"),
        }
    }

    pub(crate) fn hook_hello_ack() -> HookHelloAck {
        HookHelloAck {
            protocol_version: PROTOCOL_VERSION,
            accepted: true,
            reason: String::new(),
        }
    }

    pub(crate) fn hook_peer_evidence() -> HookPeerEvidence {
        HookPeerEvidence {
            ticket_id: String::from("ticket-fixture"),
            observed_pid: 1234,
            process_start_time_ticks: 987_654,
            executable: String::from("/usr/lib/erebor/codex-hooks/erebor-codex-hook"),
            argv: vec![String::from("erebor-codex-hook")],
            cgroup_inode: 123,
            mount_namespace_inode: 456,
            stdin: Some(PipeIdentity {
                device: 15,
                inode: 111,
            }),
            stdout: Some(PipeIdentity {
                device: 15,
                inode: 222,
            }),
            pidfd_identity: 321,
            exec_chain: vec![
                String::from("/bin/sh"),
                String::from("/usr/lib/erebor/codex-hooks/erebor-codex-hook"),
            ],
            observed_uid: 1000,
            observed_gid: 1000,
        }
    }

    pub(crate) fn hook_event(event: HookEventKind) -> HookEvent {
        HookEvent {
            event: event as i32,
            schema_sha256: String::from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            native_event_json: br#"{\"session_id\":\"native-session\"}"#.to_vec(),
        }
    }

    pub(crate) fn hook_result(event: HookEventKind) -> HookResult {
        HookResult {
            event: event as i32,
            accepted: true,
            result_json: br#"{\"continue\":true}"#.to_vec(),
        }
    }

    pub(crate) fn hook_rejection() -> HookRejection {
        HookRejection {
            code: HookRejectionCode::TicketMismatch as i32,
            reason: String::from("hook peer did not match the issued ticket"),
        }
    }

    pub(crate) fn mediate_decision() -> InterceptionDecision {
        InterceptionDecision {
            request_id: 7,
            decision: DecisionKind::Mediate as i32,
            rule_id: String::from("mediate-managed-browser"),
            reason: String::from("browser launch mediated to Erebor-owned CDP"),
            timeout_ms: 25,
            allow: None,
            deny: None,
            mediate: Some(MediateDecision {
                kind: String::from("managed_browser_cdp"),
                replacement_surface: String::from("browser_cdp"),
                endpoint: String::from("ws://127.0.0.1:9222/"),
                lease_id: String::from("lease-fixture"),
                print_line: String::from(
                    "DevTools listening on ws://127.0.0.1:9222/devtools/browser/erebor",
                ),
                keepalive: true,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::{EreborIpcFrame, IpcProtocolError};

    use super::{
        fixtures, DecisionKind, Envelope, GuardHello, HookEvent, HookEventKind, HookHello,
        HookHelloAck, HookPeerEvidence, HookRejection, HookResult, InterceptionDecision,
        InterceptionRequest, KIND_GUARD_HELLO, KIND_HOOK_EVENT, KIND_HOOK_HELLO,
        KIND_HOOK_HELLO_ACK, KIND_HOOK_PEER_EVIDENCE, KIND_HOOK_REJECTION, KIND_HOOK_RESULT,
        KIND_INTERCEPTION_DECISION, KIND_INTERCEPTION_REQUEST, PROTOCOL_VERSION,
    };

    #[test]
    fn proto_file_is_the_v1_contract_artifact() {
        let proto = include_str!("../proto/erebor/runtime/ipc/v1/control.proto");

        assert!(proto.contains("message Envelope"));
        assert!(proto.contains("message InterceptionRequest"));
        assert!(proto.contains("message InterceptionDecision"));
        assert!(proto.contains("message GuardLifecycleEvent"));
        assert!(proto.contains("message GuardLifecycleReply"));
        assert!(proto.contains("enum GuardLifecycleReplyKind"));
        assert!(proto.contains("enum DecisionKind"));
        assert!(proto.contains("message HookHello"));
        assert!(proto.contains("message HookPeerEvidence"));
        assert!(proto.contains("message HookEvent"));
        assert!(proto.contains("message HookResult"));
        assert!(proto.contains("message HookRejection"));
        assert!(proto.contains("enum HookEventKind"));
    }

    #[test]
    fn guard_hello_fixture_round_trips_through_envelope_frame() -> Result<(), Box<dyn Error>> {
        let fixture = fixtures::guard_hello();
        let envelope = Envelope::wrap_message(1, 0, KIND_GUARD_HELLO, &fixture)?;
        let frame = envelope.into_frame()?;
        let encoded = frame.encode()?;
        let decoded_frame = EreborIpcFrame::decode(&encoded)?;
        let decoded_envelope: Envelope = decoded_frame.decode_payload()?;
        let decoded_payload: GuardHello =
            decoded_envelope.decode_typed_payload(KIND_GUARD_HELLO)?;

        assert_eq!(decoded_envelope.message_kind, KIND_GUARD_HELLO);
        assert_eq!(decoded_payload, fixture);
        Ok(())
    }

    #[test]
    fn interception_request_fixture_round_trips_through_generic_envelope(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = fixtures::interception_request();
        let envelope = Envelope::wrap_message(2, 1, KIND_INTERCEPTION_REQUEST, &fixture)?;
        let encoded = envelope.into_frame()?.encode()?;
        let decoded_frame = EreborIpcFrame::decode(&encoded)?;
        let decoded_envelope: Envelope = decoded_frame.decode_payload()?;
        let decoded_payload: InterceptionRequest =
            decoded_envelope.decode_typed_payload(KIND_INTERCEPTION_REQUEST)?;

        assert_eq!(decoded_envelope.message_id, 2);
        assert_eq!(decoded_envelope.correlation_id, 1);
        assert_eq!(decoded_payload, fixture);
        Ok(())
    }

    #[test]
    fn all_interception_decision_fixtures_round_trip_through_envelope_frames(
    ) -> Result<(), Box<dyn Error>> {
        for (expected_kind, fixture) in [
            (DecisionKind::Allow, fixtures::allow_decision()),
            (DecisionKind::Deny, fixtures::deny_decision()),
            (
                DecisionKind::RequireApproval,
                fixtures::require_approval_decision(),
            ),
            (DecisionKind::Mediate, fixtures::mediate_decision()),
        ] {
            let envelope = Envelope::wrap_message(
                3,
                fixture.request_id,
                KIND_INTERCEPTION_DECISION,
                &fixture,
            )?;
            let encoded = envelope.into_frame()?.encode()?;
            let decoded_frame = EreborIpcFrame::decode(&encoded)?;
            let decoded_envelope: Envelope = decoded_frame.decode_payload()?;
            let decoded_payload: InterceptionDecision =
                decoded_envelope.decode_typed_payload(KIND_INTERCEPTION_DECISION)?;

            assert_eq!(decoded_payload.decision, expected_kind as i32);
            assert_eq!(decoded_payload, fixture);
        }

        Ok(())
    }

    #[test]
    fn envelope_decode_fails_closed_on_kind_mismatch() -> Result<(), Box<dyn Error>> {
        let fixture = fixtures::interception_request();
        let envelope = Envelope::wrap_message(4, 0, KIND_INTERCEPTION_REQUEST, &fixture)?;
        let error = match envelope
            .decode_typed_payload::<InterceptionDecision>(KIND_INTERCEPTION_DECISION)
        {
            Ok(_payload) => {
                return Err("expected payload kind mismatch".into());
            }
            Err(error) => error,
        };

        assert!(matches!(
            error,
            IpcProtocolError::PayloadKindMismatch { .. }
        ));
        Ok(())
    }

    #[test]
    fn hook_handshake_and_rejection_messages_round_trip() -> Result<(), Box<dyn Error>> {
        let hello = fixtures::hook_hello();
        let hello_envelope = Envelope::wrap_message(5, 0, KIND_HOOK_HELLO, &hello)?;
        let decoded_hello: HookHello = hello_envelope
            .into_frame()?
            .decode_payload::<Envelope>()?
            .decode_typed_payload(KIND_HOOK_HELLO)?;
        assert_eq!(decoded_hello, hello);
        assert!(decoded_hello.uses_supported_protocol());

        let unsupported = HookHello {
            protocol_version: PROTOCOL_VERSION + 1,
            ..hello
        };
        assert!(!unsupported.uses_supported_protocol());

        let ack = fixtures::hook_hello_ack();
        let ack_envelope = Envelope::wrap_message(6, 5, KIND_HOOK_HELLO_ACK, &ack)?;
        let decoded_ack: HookHelloAck = ack_envelope
            .into_frame()?
            .decode_payload::<Envelope>()?
            .decode_typed_payload(KIND_HOOK_HELLO_ACK)?;
        assert_eq!(decoded_ack, ack);

        let peer_evidence = fixtures::hook_peer_evidence();
        let peer_envelope = Envelope::wrap_message(7, 5, KIND_HOOK_PEER_EVIDENCE, &peer_evidence)?;
        let decoded_peer: HookPeerEvidence = peer_envelope
            .into_frame()?
            .decode_payload::<Envelope>()?
            .decode_typed_payload(KIND_HOOK_PEER_EVIDENCE)?;
        assert_eq!(decoded_peer, peer_evidence);

        let rejection = fixtures::hook_rejection();
        let rejection_envelope = Envelope::wrap_message(8, 5, KIND_HOOK_REJECTION, &rejection)?;
        let decoded_rejection: HookRejection = rejection_envelope
            .into_frame()?
            .decode_payload::<Envelope>()?
            .decode_typed_payload(KIND_HOOK_REJECTION)?;
        assert_eq!(decoded_rejection, rejection);
        Ok(())
    }

    #[test]
    fn every_hook_event_contract_round_trips() -> Result<(), Box<dyn Error>> {
        for event_kind in [
            HookEventKind::SessionStart,
            HookEventKind::UserPromptSubmit,
            HookEventKind::PreToolUse,
            HookEventKind::PermissionRequest,
            HookEventKind::PostToolUse,
            HookEventKind::SubagentStart,
            HookEventKind::SubagentStop,
            HookEventKind::Stop,
        ] {
            let event = fixtures::hook_event(event_kind);
            let event_envelope = Envelope::wrap_message(8, 5, KIND_HOOK_EVENT, &event)?;
            let decoded_event: HookEvent = event_envelope
                .into_frame()?
                .decode_payload::<Envelope>()?
                .decode_typed_payload(KIND_HOOK_EVENT)?;
            assert_eq!(decoded_event, event);

            let result = fixtures::hook_result(event_kind);
            let result_envelope = Envelope::wrap_message(9, 8, KIND_HOOK_RESULT, &result)?;
            let decoded_result: HookResult = result_envelope
                .into_frame()?
                .decode_payload::<Envelope>()?
                .decode_typed_payload(KIND_HOOK_RESULT)?;
            assert_eq!(decoded_result, result);
        }
        Ok(())
    }
}
