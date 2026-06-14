use prost::{Enumeration, Message};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, PartialEq, Message)]
pub struct GuardHello {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub session_id: String,
    #[prost(string, tag = "3")]
    pub actor_id: String,
    #[prost(int64, tag = "4")]
    pub guard_pid: i64,
    #[prost(string, tag = "5")]
    pub runner_kind: String,
    #[prost(string, tag = "6")]
    pub platform: String,
    #[prost(string, repeated, tag = "7")]
    pub capabilities: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GuardHelloAck {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub broker_id: String,
    #[prost(bool, tag = "3")]
    pub accepted: bool,
    #[prost(string, tag = "4")]
    pub reason: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct InterceptionRequest {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(string, tag = "2")]
    pub session_id: String,
    #[prost(string, tag = "3")]
    pub actor_id: String,
    #[prost(enumeration = "InterceptionSource", tag = "4")]
    pub source: i32,
    #[prost(int64, tag = "5")]
    pub pid: i64,
    #[prost(int64, tag = "6")]
    pub ppid: i64,
    #[prost(string, tag = "7")]
    pub executable: String,
    #[prost(string, repeated, tag = "8")]
    pub argv: Vec<String>,
    #[prost(string, tag = "9")]
    pub cwd: String,
    #[prost(message, repeated, tag = "10")]
    pub selected_env: Vec<EnvVar>,
    #[prost(message, optional, tag = "11")]
    pub requested_endpoint: Option<RequestedEndpoint>,
    #[prost(string, tag = "12")]
    pub matched_handler_id: String,
    #[prost(string, tag = "13")]
    pub timestamp: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct InterceptionDecision {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(enumeration = "DecisionKind", tag = "2")]
    pub decision: i32,
    #[prost(string, tag = "3")]
    pub rule_id: String,
    #[prost(string, tag = "4")]
    pub reason: String,
    #[prost(uint32, tag = "5")]
    pub timeout_ms: u32,
    #[prost(message, optional, tag = "6")]
    pub allow: Option<AllowDecision>,
    #[prost(message, optional, tag = "7")]
    pub deny: Option<DenyDecision>,
    #[prost(message, optional, tag = "8")]
    pub mediate: Option<MediateDecision>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GuardEvent {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(string, tag = "2")]
    pub session_id: String,
    #[prost(string, tag = "3")]
    pub message: String,
    #[prost(string, tag = "4")]
    pub timestamp: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct GuardGoodbye {
    #[prost(string, tag = "1")]
    pub session_id: String,
    #[prost(int64, tag = "2")]
    pub guard_pid: i64,
    #[prost(int32, tag = "3")]
    pub exit_code: i32,
    #[prost(string, tag = "4")]
    pub reason: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct EnvVar {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct RequestedEndpoint {
    #[prost(string, tag = "1")]
    pub scheme: String,
    #[prost(string, tag = "2")]
    pub host: String,
    #[prost(uint32, tag = "3")]
    pub port: u32,
    #[prost(string, tag = "4")]
    pub path: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct AllowDecision {
    #[prost(string, tag = "1")]
    pub exec_target: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct DenyDecision {
    #[prost(int32, tag = "1")]
    pub exit_code: i32,
}

#[derive(Clone, PartialEq, Message)]
pub struct MediateDecision {
    #[prost(string, tag = "1")]
    pub kind: String,
    #[prost(string, tag = "2")]
    pub replacement_surface: String,
    #[prost(string, tag = "3")]
    pub endpoint: String,
    #[prost(string, tag = "4")]
    pub lease_id: String,
    #[prost(string, tag = "5")]
    pub print_line: String,
    #[prost(bool, tag = "6")]
    pub keepalive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumeration)]
#[repr(i32)]
pub enum InterceptionSource {
    Unspecified = 0,
    Ptrace = 1,
    Shim = 2,
    FutureEndpoint = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumeration)]
#[repr(i32)]
pub enum DecisionKind {
    Unspecified = 0,
    Allow = 1,
    Deny = 2,
    RequireApproval = 3,
    Mediate = 4,
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

    use prost::Message;

    use crate::{EreborIpcFrame, MessageType};

    use super::{fixtures, DecisionKind, GuardHello, InterceptionDecision, InterceptionRequest};

    #[test]
    fn guard_hello_fixture_round_trips_through_frame() -> Result<(), Box<dyn Error>> {
        let fixture = fixtures::guard_hello();
        let encoded = EreborIpcFrame::from_message(MessageType::GuardHello, &fixture)?.encode()?;
        let frame = EreborIpcFrame::decode(&encoded)?;
        let decoded: GuardHello = frame.decode_payload(MessageType::GuardHello)?;

        assert_eq!(decoded, fixture);
        Ok(())
    }

    #[test]
    fn interception_request_fixture_round_trips_through_protobuf() -> Result<(), Box<dyn Error>> {
        let fixture = fixtures::interception_request();
        let mut encoded = Vec::new();
        fixture.encode(&mut encoded)?;
        let decoded = InterceptionRequest::decode(encoded.as_slice())?;

        assert_eq!(decoded, fixture);
        Ok(())
    }

    #[test]
    fn all_interception_decision_fixtures_round_trip_through_frames() -> Result<(), Box<dyn Error>>
    {
        for (expected_kind, fixture) in [
            (DecisionKind::Allow, fixtures::allow_decision()),
            (DecisionKind::Deny, fixtures::deny_decision()),
            (
                DecisionKind::RequireApproval,
                fixtures::require_approval_decision(),
            ),
            (DecisionKind::Mediate, fixtures::mediate_decision()),
        ] {
            let encoded =
                EreborIpcFrame::from_message(MessageType::InterceptionDecision, &fixture)?
                    .encode()?;
            let frame = EreborIpcFrame::decode(&encoded)?;
            let decoded: InterceptionDecision =
                frame.decode_payload(MessageType::InterceptionDecision)?;

            assert_eq!(decoded.decision, expected_kind as i32);
            assert_eq!(decoded, fixture);
        }

        Ok(())
    }
}
