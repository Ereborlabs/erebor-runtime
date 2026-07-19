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
    server::RuntimeInterceptionBrokerServer,
    wire::{interception_token, read_frame_from_stream, write_frame_to_stream},
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundConnection {
    session_id: String,
}

impl RuntimeInterceptionBrokerServer {
    pub(super) fn handle_stream(&self, stream: &mut (impl Read + Write)) {
        let mut bound = None::<BoundConnection>;
        while let Ok(request_frame) = read_frame_from_stream(stream) {
            let envelope = match request_frame.decode_payload::<Envelope>() {
                Ok(envelope) => envelope,
                Err(_error) => break,
            };
            let response = match self.handle_runtime_interception_envelope(envelope, &mut bound) {
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
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        envelope
            .validate_headers(EnvelopeServiceFamily::RuntimeGuard)
            .context(BrokerProtocolSnafu)?;
        if bound.is_none() {
            return self.handle_hello_envelope(envelope, bound);
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
    ) -> Result<Envelope, RuntimeInterceptionBrokerError> {
        let mut broker_id = String::from("unregistered");
        let mut accepted = false;
        let mut accepted_session_id = None;

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
            match sessions.get(&hello.session_id) {
                Some(registration)
                    if interception_token(&envelope) == Some(registration.token.as_str()) =>
                {
                    broker_id = registration.broker_id.clone();
                    accepted = true;
                    accepted_session_id = Some(hello.session_id);
                    String::from("accepted")
                }
                Some(_) => String::from("invalid interception token"),
                None => String::from("unknown session"),
            }
        };
        let ack = GuardHelloAck {
            protocol_version: PROTOCOL_VERSION,
            broker_id,
            accepted,
            reason,
        };
        if accepted {
            if let Some(session_id) = accepted_session_id {
                *bound = Some(BoundConnection { session_id });
            }
        }

        Envelope::wrap_message(
            envelope.message_id.saturating_add(1),
            envelope.message_id,
            KIND_GUARD_HELLO_ACK,
            &ack,
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
        let sessions = self
            .sessions
            .lock()
            .map_err(|_error| BrokerStateLockSnafu.build())?;
        let Some(registration) = sessions.get(&bound.session_id) else {
            return Ok(reply.deny(
                "erebor-runtime-interception-broker-unknown-session",
                "session is no longer registered with the runtime interception broker",
            ));
        };
        Ok(match registration.router.route_interception(request) {
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
        let sessions = self
            .sessions
            .lock()
            .map_err(|_error| BrokerStateLockSnafu.build())?;
        let Some(registration) = sessions.get(&bound.session_id) else {
            return Ok(lifecycle_deny(
                event.request_id,
                "session is no longer registered with the runtime interception broker",
            ));
        };
        Ok(registration.router.route_guard_lifecycle(event))
    }
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
