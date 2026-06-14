include!(concat!(env!("OUT_DIR"), "/erebor.runtime.ipc.v1.rs"));

use prost::Message;

use crate::{EreborIpcFrame, IpcProtocolError};

pub const PROTOCOL_VERSION: u32 = 1;
pub const KIND_GUARD_HELLO: &str = "erebor.runtime.ipc.v1.GuardHello";
pub const KIND_GUARD_HELLO_ACK: &str = "erebor.runtime.ipc.v1.GuardHelloAck";
pub const KIND_INTERCEPTION_REQUEST: &str = "erebor.runtime.ipc.v1.InterceptionRequest";
pub const KIND_INTERCEPTION_DECISION: &str = "erebor.runtime.ipc.v1.InterceptionDecision";
pub const KIND_GUARD_EVENT: &str = "erebor.runtime.ipc.v1.GuardEvent";
pub const KIND_GUARD_GOODBYE: &str = "erebor.runtime.ipc.v1.GuardGoodbye";

impl Envelope {
    pub fn wrap_message<T: Message>(
        message_id: u64,
        correlation_id: u64,
        session_id: impl Into<String>,
        message_kind: impl Into<String>,
        message: &T,
    ) -> Result<Self, IpcProtocolError> {
        let mut payload = Vec::with_capacity(message.encoded_len());
        message
            .encode(&mut payload)
            .map_err(IpcProtocolError::encode_payload)?;

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            message_id,
            correlation_id,
            session_id: session_id.into(),
            message_kind: message_kind.into(),
            payload,
            headers: Vec::new(),
        })
    }

    pub fn decode_typed_payload<T: Message + Default>(
        &self,
        expected_kind: &str,
    ) -> Result<T, IpcProtocolError> {
        if self.message_kind != expected_kind {
            return Err(IpcProtocolError::payload_kind_mismatch(
                expected_kind,
                self.message_kind.clone(),
            ));
        }

        T::decode(self.payload.as_slice()).map_err(IpcProtocolError::decode_payload)
    }

    pub fn into_frame(&self) -> Result<EreborIpcFrame, IpcProtocolError> {
        EreborIpcFrame::from_message(self)
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::{
        AllowDecision, DecisionKind, DenyDecision, EnvVar, GuardHello, InterceptionDecision,
        InterceptionRequest, InterceptionSource, MediateDecision, RequestedEndpoint,
        PROTOCOL_VERSION,
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
            session_id: String::from("session-fixture"),
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
        fixtures, DecisionKind, Envelope, GuardHello, InterceptionDecision, InterceptionRequest,
        KIND_GUARD_HELLO, KIND_INTERCEPTION_DECISION, KIND_INTERCEPTION_REQUEST,
    };

    #[test]
    fn proto_file_is_the_v1_contract_artifact() {
        let proto = include_str!("../proto/erebor/runtime/ipc/v1/control.proto");

        assert!(proto.contains("message Envelope"));
        assert!(proto.contains("message InterceptionRequest"));
        assert!(proto.contains("message InterceptionDecision"));
        assert!(proto.contains("enum DecisionKind"));
    }

    #[test]
    fn guard_hello_fixture_round_trips_through_envelope_frame() -> Result<(), Box<dyn Error>> {
        let fixture = fixtures::guard_hello();
        let envelope = Envelope::wrap_message(1, 0, "session-fixture", KIND_GUARD_HELLO, &fixture)?;
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
        let envelope =
            Envelope::wrap_message(2, 1, "session-fixture", KIND_INTERCEPTION_REQUEST, &fixture)?;
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
                "session-fixture",
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
        let envelope =
            Envelope::wrap_message(4, 0, "session-fixture", KIND_INTERCEPTION_REQUEST, &fixture)?;
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
}
