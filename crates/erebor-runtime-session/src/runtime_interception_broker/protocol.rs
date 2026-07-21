use std::io::{Read, Write};

use erebor_runtime_ipc::v1::{
    Envelope, EnvelopeServiceFamily, GuardHello, GuardHelloAck, GuardLifecycleEvent,
    GuardLifecycleReply, GuardLifecycleReplyKind, InterceptionDecision, InterceptionRequest,
    KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK, KIND_GUARD_LIFECYCLE_EVENT, KIND_GUARD_LIFECYCLE_REPLY,
    KIND_INTERCEPTION_DECISION, KIND_INTERCEPTION_REQUEST, PROTOCOL_VERSION,
};
use snafu::ResultExt;

use crate::error::{BrokerProtocolSnafu, BrokerStateLockSnafu, RuntimeInterceptionBrokerError};

use super::{
    decision::InterceptionDecisionReply,
    handlers::RoutedInterception,
    server::{
        GuardPeerIdentity, RuntimeInterceptionBrokerServer, SessionConnectionPermit,
        SessionRegistrationKey,
    },
    wire::{interception_token, read_frame_from_stream, write_frame_to_stream},
};

struct BoundConnection {
    key: SessionRegistrationKey,
    _permit: SessionConnectionPermit,
}

impl RuntimeInterceptionBrokerServer {
    pub(super) fn handle_stream(
        &self,
        stream: &mut (impl Read + Write),
        peer: Option<GuardPeerIdentity>,
    ) {
        let mut bound = None::<BoundConnection>;
        while let Ok(request_frame) = read_frame_from_stream(stream) {
            let envelope = match request_frame.decode_payload::<Envelope>() {
                Ok(envelope) => envelope,
                Err(_error) => break,
            };
            let response =
                match self.handle_runtime_interception_envelope(envelope, &mut bound, peer) {
                    Ok(response) => response,
                    Err(_error) => break,
                };
            let response_frame = match response.into_frame() {
                Ok(frame) => frame,
                Err(_error) => break,
            };
            if write_frame_to_stream(stream, &response_frame).is_err() {
                break;
            }
        }
    }

    fn handle_runtime_interception_envelope(
        &self,
        envelope: Envelope,
        bound: &mut Option<BoundConnection>,
        peer: Option<GuardPeerIdentity>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        envelope
            .validate_headers(EnvelopeServiceFamily::RuntimeGuard)
            .context(BrokerProtocolSnafu)?;
        if bound.is_none() {
            return self.handle_hello_envelope(envelope, bound, peer);
        }

        match envelope.message_kind.as_str() {
            KIND_INTERCEPTION_REQUEST => self.handle_interception_request_envelope(envelope, bound),
            KIND_GUARD_LIFECYCLE_EVENT => {
                self.handle_guard_lifecycle_event_envelope(envelope, bound)
            }
            _ => deny_unexpected_bound_message(envelope),
        }
    }

    fn handle_hello_envelope(
        &self,
        envelope: Envelope,
        bound: &mut Option<BoundConnection>,
        peer: Option<GuardPeerIdentity>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        let mut broker_id = String::from("unregistered");
        let mut accepted = false;
        let mut accepted_binding = None;

        let reason = if envelope.message_kind != KIND_GUARD_HELLO {
            format!("unexpected message kind `{}`", envelope.message_kind)
        } else {
            let hello: GuardHello = envelope
                .decode_typed_payload(KIND_GUARD_HELLO)
                .context(BrokerProtocolSnafu)?;
            let sessions = self
                .sessions
                .lock()
                .map_err(|_error| BrokerStateLockSnafu.build())?;
            let key = session_registration_key(&sessions, &hello.session_id, peer);
            match key.and_then(|key| sessions.get(&key).map(|registration| (key, registration))) {
                Some((_key, registration))
                    if interception_token(&envelope) != Some(registration.token.as_str()) =>
                {
                    String::from("invalid interception token")
                }
                Some((_key, registration))
                    if !registration.expected_peer_uid.is_none_or(|expected| {
                        peer.is_some_and(|observed| observed.uid == expected)
                    }) || (registration.require_peer_pid_match
                        && peer.and_then(|observed| observed.pid)
                            != u32::try_from(hello.guard_pid).ok()) =>
                {
                    String::from("guard peer credentials do not match admission")
                }
                Some((key, registration)) => {
                    let Some(permit) = registration.try_acquire_connection() else {
                        return self.hello_ack(
                            &envelope,
                            broker_id,
                            false,
                            "session connection limit reached",
                        );
                    };
                    broker_id = registration.broker_id.clone();
                    accepted = true;
                    accepted_binding = Some(BoundConnection {
                        key,
                        _permit: permit,
                    });
                    String::from("accepted")
                }
                None => String::from("unknown session"),
            }
        };
        let response = self.hello_ack(&envelope, broker_id, accepted, reason)?;
        if accepted {
            if let Some(binding) = accepted_binding {
                *bound = Some(binding);
            }
        }
        Ok(response)
    }

    fn hello_ack(
        &self,
        envelope: &Envelope,
        broker_id: String,
        accepted: bool,
        reason: impl Into<String>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        Envelope::wrap_message(
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_GUARD_HELLO_ACK,
            &GuardHelloAck {
                protocol_version: PROTOCOL_VERSION,
                broker_id,
                accepted,
                reason: reason.into(),
            },
        )
        .context(BrokerProtocolSnafu)
    }

    fn handle_interception_request_envelope(
        &self,
        envelope: Envelope,
        bound: &Option<BoundConnection>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        let request: InterceptionRequest = envelope
            .decode_typed_payload(KIND_INTERCEPTION_REQUEST)
            .context(BrokerProtocolSnafu)?;
        let decision = self.interception_decision_for_request(bound, &request)?;

        Envelope::wrap_message(
            envelope.message_id.saturating_add(1),
            request.request_id,
            KIND_INTERCEPTION_DECISION,
            &decision,
        )
        .context(BrokerProtocolSnafu)
    }

    fn interception_decision_for_request(
        &self,
        bound: &Option<BoundConnection>,
        request: &InterceptionRequest,
    ) -> Result<InterceptionDecision, RuntimeInterceptionBrokerError> {
        let reply = InterceptionDecisionReply::new(request.request_id);
        let Some(bound) = bound else {
            return Ok(reply.deny(
                "erebor-runtime-interception-broker-unbound",
                "interception request arrived before GuardHello",
            ));
        };
        let router = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_error| BrokerStateLockSnafu.build())?;
            let Some(registration) = sessions.get(&bound.key) else {
                return Ok(reply.deny(
                    "erebor-runtime-interception-broker-unknown-session",
                    "session is no longer registered with the runtime interception broker",
                ));
            };
            registration.router.clone()
        };
        Ok(match router.route_interception(request) {
            RoutedInterception::Decision(decision) => reply.surface(decision),
            RoutedInterception::Unrouted { rule_id, reason } => reply.deny(rule_id, reason),
        })
    }

    fn handle_guard_lifecycle_event_envelope(
        &self,
        envelope: Envelope,
        bound: &Option<BoundConnection>,
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        let event: GuardLifecycleEvent = envelope
            .decode_typed_payload(KIND_GUARD_LIFECYCLE_EVENT)
            .context(BrokerProtocolSnafu)?;
        let reply = self.lifecycle_reply_for_event(bound, &event)?;
        Envelope::wrap_message(
            envelope.message_id.saturating_add(1),
            event.request_id,
            KIND_GUARD_LIFECYCLE_REPLY,
            &reply,
        )
        .context(BrokerProtocolSnafu)
    }

    fn lifecycle_reply_for_event(
        &self,
        bound: &Option<BoundConnection>,
        event: &GuardLifecycleEvent,
    ) -> Result<GuardLifecycleReply, RuntimeInterceptionBrokerError> {
        let Some(bound) = bound else {
            return Ok(lifecycle_deny(
                event.request_id,
                "guard lifecycle event arrived before GuardHello",
            ));
        };
        let router = {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_error| BrokerStateLockSnafu.build())?;
            let Some(registration) = sessions.get(&bound.key) else {
                return Ok(lifecycle_deny(
                    event.request_id,
                    "session is no longer registered with the runtime interception broker",
                ));
            };
            registration.router.clone()
        };
        Ok(router.route_guard_lifecycle(event))
    }
}

fn session_registration_key(
    sessions: &std::collections::HashMap<SessionRegistrationKey, super::server::RegisteredSession>,
    session_id: &str,
    peer: Option<GuardPeerIdentity>,
) -> Option<SessionRegistrationKey> {
    let exact = SessionRegistrationKey {
        expected_peer_uid: peer.map(|identity| identity.uid),
        session_id: session_id.to_owned(),
    };
    if sessions.contains_key(&exact) {
        return Some(exact);
    }
    let unscoped = SessionRegistrationKey {
        expected_peer_uid: None,
        session_id: session_id.to_owned(),
    };
    if sessions.contains_key(&unscoped) {
        return Some(unscoped);
    }
    sessions
        .keys()
        .find(|key| key.session_id == session_id)
        .cloned()
}

fn lifecycle_deny(request_id: u64, reason: impl Into<String>) -> GuardLifecycleReply {
    GuardLifecycleReply {
        request_id,
        decision: GuardLifecycleReplyKind::Deny as i32,
        reason: reason.into(),
    }
}

fn deny_unexpected_bound_message(
    envelope: Envelope,
) -> Result<Envelope, RuntimeInterceptionBrokerError> {
    let decision = InterceptionDecisionReply::new(envelope.message_id).deny(
        "erebor-runtime-interception-broker-unexpected-message",
        format!(
            "unexpected message kind `{}` on bound guard connection",
            envelope.message_kind
        ),
    );
    Envelope::wrap_message(
        envelope.message_id.saturating_add(1),
        envelope.message_id,
        KIND_INTERCEPTION_DECISION,
        &decision,
    )
    .context(BrokerProtocolSnafu)
}

#[cfg(test)]
mod tests {
    use erebor_runtime_ipc::v1::{
        Envelope, GuardHello, GuardHelloAck, KIND_GUARD_HELLO, KIND_GUARD_HELLO_ACK,
        PROTOCOL_VERSION,
    };
    use rustix::process::{getegid, geteuid};
    use tempfile::TempDir;

    use super::BoundConnection;
    use crate::runtime_interception_broker::{
        handlers::SessionInterceptionRouter,
        server::{
            GuardPeerIdentity, RuntimeGuardServerConfig, RuntimeGuardServerLimits,
            RuntimeGuardSocketAccess, RuntimeInterceptionBrokerServer,
        },
        wire::envelope_with_token,
    };

    #[test]
    fn shared_server_rejects_the_right_token_from_the_wrong_uid(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let server = server(&temporary)?;
        let token = "11111111111111111111111111111111";
        let _registration = server.register_session(
            String::from("shared-session"),
            String::from("agent"),
            SessionInterceptionRouter::new(),
            Some(1001),
            false,
            Some(String::from(token)),
        )?;
        let mut bound = None::<BoundConnection>;
        let response = server.handle_runtime_interception_envelope(
            hello("shared-session", token, 41)?,
            &mut bound,
            Some(GuardPeerIdentity {
                pid: Some(41),
                uid: 1002,
            }),
        )?;
        let ack: GuardHelloAck = response.decode_typed_payload(KIND_GUARD_HELLO_ACK)?;

        assert!(!ack.accepted);
        assert_eq!(ack.reason, "guard peer credentials do not match admission");
        assert!(bound.is_none());
        Ok(())
    }

    #[test]
    fn shared_server_routes_equal_session_ids_by_observed_uid(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = TempDir::new()?;
        let server = server(&temporary)?;
        let first_token = "11111111111111111111111111111111";
        let second_token = "22222222222222222222222222222222";
        let _first = server.register_session(
            String::from("same-id"),
            String::from("first"),
            SessionInterceptionRouter::new(),
            Some(1001),
            false,
            Some(String::from(first_token)),
        )?;
        let _second = server.register_session(
            String::from("same-id"),
            String::from("second"),
            SessionInterceptionRouter::new(),
            Some(1002),
            false,
            Some(String::from(second_token)),
        )?;
        let mut bound = None::<BoundConnection>;
        let response = server.handle_runtime_interception_envelope(
            hello("same-id", second_token, 42)?,
            &mut bound,
            Some(GuardPeerIdentity {
                pid: Some(42),
                uid: 1002,
            }),
        )?;
        let ack: GuardHelloAck = response.decode_typed_payload(KIND_GUARD_HELLO_ACK)?;

        assert!(ack.accepted);
        assert_eq!(ack.broker_id, "same-id:second");
        assert!(bound.is_some());
        Ok(())
    }

    fn server(
        temporary: &TempDir,
    ) -> Result<
        std::sync::Arc<RuntimeInterceptionBrokerServer>,
        crate::RuntimeInterceptionBrokerError,
    > {
        RuntimeInterceptionBrokerServer::start(RuntimeGuardServerConfig {
            directory: Some(temporary.path().to_path_buf()),
            owner_uid: geteuid().as_raw(),
            owner_gid: getegid().as_raw(),
            directory_mode: 0o700,
            socket_mode: 0o600,
            limits: RuntimeGuardServerLimits::default(),
            socket_access: RuntimeGuardSocketAccess::ProjectedShared,
        })
    }

    fn hello(
        session_id: &str,
        token: &str,
        guard_pid: i64,
    ) -> Result<Envelope, erebor_runtime_ipc::IpcProtocolError> {
        let envelope = Envelope::wrap_message(
            1,
            0,
            KIND_GUARD_HELLO,
            &GuardHello {
                protocol_version: PROTOCOL_VERSION,
                session_id: session_id.to_owned(),
                actor_id: String::from("agent"),
                guard_pid,
                runner_kind: String::from("linux-host"),
                platform: String::from("linux-x86_64"),
                capabilities: Vec::new(),
            },
        )?;
        Ok(envelope_with_token(envelope, token))
    }
}
