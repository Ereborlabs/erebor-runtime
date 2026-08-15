use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt as _};
use tonic::{Request, Response, Status, Streaming};

use crate::control_envelope::Payload as ControlPayload;
use crate::node_control_server::NodeControl;
use crate::node_envelope::Payload as NodePayload;
use crate::{
    ControlEnvelope, NodeEnvelope, RegistrationAccepted, TrustGeneration, CONTROL_PROTOCOL_VERSION,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AllowedNodeIdentity {
    pub node_id: String,
    pub certificate_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustGenerationV1 {
    pub generation: u64,
    pub bundle_digest: String,
}

#[derive(Default)]
struct ControlState {
    node_sequences: BTreeMap<(String, Vec<u8>), u64>,
    trust_acks: BTreeMap<String, TrustGenerationV1>,
    sessions: BTreeMap<String, NodeSession>,
    pending: BTreeMap<Vec<u8>, PendingAdministrativeResponse>,
}

struct NodeSession {
    identity: StreamIdentity,
    output: mpsc::Sender<Result<ControlEnvelope, Status>>,
    next_sequence: u64,
}

enum PendingAdministrativeResponse {
    Resolution {
        node_id: String,
        sender: oneshot::Sender<crate::AdministrativeExecResolution>,
    },
    Arm {
        node_id: String,
        sender: oneshot::Sender<crate::AdministrativeExecArmResult>,
    },
}

const ADMINISTRATIVE_NODE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone)]
pub struct ControlPlane {
    allowed_nodes: Arc<BTreeMap<String, String>>,
    trust: TrustGenerationV1,
    state: Arc<Mutex<ControlState>>,
}

impl ControlPlane {
    #[must_use]
    pub fn new(allowed: Vec<AllowedNodeIdentity>, trust: TrustGenerationV1) -> Self {
        Self {
            allowed_nodes: Arc::new(
                allowed
                    .into_iter()
                    .map(|identity| (identity.node_id, identity.certificate_sha256))
                    .collect(),
            ),
            trust,
            state: Arc::new(Mutex::new(ControlState::default())),
        }
    }

    #[must_use]
    pub fn allowed_nodes(&self) -> &BTreeMap<String, String> {
        &self.allowed_nodes
    }

    #[must_use]
    pub fn acknowledged_trust(&self, node_id: &str) -> Option<TrustGenerationV1> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.trust_acks.get(node_id).cloned())
    }

    #[must_use]
    pub fn registered_nonce_count(&self) -> usize {
        self.state
            .lock()
            .map_or(0, |state| state.node_sequences.len())
    }

    pub async fn resolve_administrative_exec(
        &self,
        node_id: &str,
        request: crate::ResolveAdministrativeExec,
    ) -> Result<crate::AdministrativeExecResolution, Status> {
        let request_id = request.request_id.clone();
        let (receiver, output, envelope) = {
            let (sender, receiver) = oneshot::channel();
            let mut state = self
                .state
                .lock()
                .map_err(|_| Status::internal("control session state is poisoned"))?;
            ensure_request_id_available(&state, &request_id)?;
            let session = state
                .sessions
                .get_mut(node_id)
                .ok_or_else(|| Status::unavailable("target node has no ready control stream"))?;
            let sequence = session.next_sequence;
            session.next_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("control stream sequence exhausted"))?;
            let output = session.output.clone();
            let envelope = session
                .identity
                .envelope(sequence, ControlPayload::ResolveAdministrativeExec(request));
            state.pending.insert(
                request_id.clone(),
                PendingAdministrativeResponse::Resolution {
                    node_id: node_id.to_owned(),
                    sender,
                },
            );
            (receiver, output, envelope)
        };
        if output.send(Ok(envelope)).await.is_err() {
            self.remove_pending(&request_id);
            return Err(Status::unavailable(
                "target node disconnected before administrative resolution",
            ));
        }
        match tokio::time::timeout(ADMINISTRATIVE_NODE_TIMEOUT, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Status::unavailable(
                "target node disconnected before administrative resolution",
            )),
            Err(_) => {
                self.remove_pending(&request_id);
                Err(Status::deadline_exceeded(
                    "target node did not resolve administrative exec before the deadline",
                ))
            }
        }
    }

    pub async fn arm_administrative_exec(
        &self,
        node_id: &str,
        request: crate::ArmAdministrativeExec,
    ) -> Result<crate::AdministrativeExecArmResult, Status> {
        let request_id = request.request_id.clone();
        let (receiver, output, envelope) = {
            let (sender, receiver) = oneshot::channel();
            let mut state = self
                .state
                .lock()
                .map_err(|_| Status::internal("control session state is poisoned"))?;
            ensure_request_id_available(&state, &request_id)?;
            let session = state
                .sessions
                .get_mut(node_id)
                .ok_or_else(|| Status::unavailable("target node has no ready control stream"))?;
            let sequence = session.next_sequence;
            session.next_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| Status::out_of_range("control stream sequence exhausted"))?;
            let output = session.output.clone();
            let envelope = session
                .identity
                .envelope(sequence, ControlPayload::ArmAdministrativeExec(request));
            state.pending.insert(
                request_id.clone(),
                PendingAdministrativeResponse::Arm {
                    node_id: node_id.to_owned(),
                    sender,
                },
            );
            (receiver, output, envelope)
        };
        if output.send(Ok(envelope)).await.is_err() {
            self.remove_pending(&request_id);
            return Err(Status::unavailable(
                "target node disconnected before administrative slot installation",
            ));
        }
        match tokio::time::timeout(ADMINISTRATIVE_NODE_TIMEOUT, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Status::unavailable(
                "target node disconnected before administrative slot installation",
            )),
            Err(_) => {
                self.remove_pending(&request_id);
                Err(Status::deadline_exceeded(
                    "target node did not install the administrative slot before the deadline",
                ))
            }
        }
    }

    fn remove_pending(&self, request_id: &[u8]) {
        if let Ok(mut state) = self.state.lock() {
            state.pending.remove(request_id);
        }
    }

    // Tonic requires `Status` at this boundary; wrapping it would only duplicate
    // the framework's error type.
    #[allow(clippy::result_large_err)]
    fn register(&self, node_id: &str, nonce: &[u8], peer_digest: &str) -> Result<(), Status> {
        let expected = self
            .allowed_nodes
            .get(node_id)
            .ok_or_else(|| Status::permission_denied("node identity is not enrolled"))?;
        if expected != peer_digest {
            return Err(Status::permission_denied(
                "node ID does not match the authenticated client certificate",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| Status::internal("control registration state is poisoned"))?;
        let key = (node_id.to_owned(), nonce.to_vec());
        if state.node_sequences.contains_key(&key) {
            return Err(Status::already_exists("registration nonce was replayed"));
        }
        state.node_sequences.insert(key, 1);
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn record_node_sequence(
        &self,
        node_id: &str,
        nonce: &[u8],
        sequence: u64,
    ) -> Result<(), Status> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Status::internal("control sequence state is poisoned"))?;
        let last = state
            .node_sequences
            .get_mut(&(node_id.to_owned(), nonce.to_vec()))
            .ok_or_else(|| Status::unauthenticated("connection is not registered"))?;
        if last.checked_add(1) != Some(sequence) {
            return Err(Status::aborted(
                "node stream sequence was replayed or skipped",
            ));
        }
        *last = sequence;
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn acknowledge(&self, node_id: &str, generation: u64, digest: &str) -> Result<(), Status> {
        if generation != self.trust.generation || digest != self.trust.bundle_digest {
            return Err(Status::failed_precondition(
                "trust acknowledgement does not match the delivered generation",
            ));
        }
        self.state
            .lock()
            .map_err(|_| Status::internal("control acknowledgement state is poisoned"))?
            .trust_acks
            .insert(node_id.to_owned(), self.trust.clone());
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn validate_readiness(&self, report: &crate::NodeReadinessReport) -> Result<(), Status> {
        if !report.kernel_ready || !report.control_ready || !report.admission_ready {
            return Err(Status::failed_precondition(
                "node readiness requires kernel, control, and admission readiness",
            ));
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn register_ready_session(
        &self,
        identity: &StreamIdentity,
        output: &mpsc::Sender<Result<ControlEnvelope, Status>>,
    ) -> Result<(), Status> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Status::internal("control session state is poisoned"))?;
        if state
            .sessions
            .get(&identity.node_id)
            .is_some_and(|session| session.identity.connection_nonce != identity.connection_nonce)
        {
            return Err(Status::already_exists(
                "target node already has a ready control stream",
            ));
        }
        state.sessions.insert(
            identity.node_id.clone(),
            NodeSession {
                identity: identity.clone(),
                output: output.clone(),
                next_sequence: 3,
            },
        );
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn deliver_resolution(
        &self,
        node_id: &str,
        response: crate::AdministrativeExecResolution,
    ) -> Result<(), Status> {
        let pending = self
            .state
            .lock()
            .map_err(|_| Status::internal("control session state is poisoned"))?
            .pending
            .remove(&response.request_id)
            .ok_or_else(|| Status::aborted("administrative response has no pending request"))?;
        match pending {
            PendingAdministrativeResponse::Resolution {
                node_id: expected,
                sender,
            } if expected == node_id => sender
                .send(response)
                .map_err(|_| Status::cancelled("administrative requester stopped waiting")),
            _ => Err(Status::unauthenticated(
                "administrative response does not match its node or operation",
            )),
        }
    }

    #[allow(clippy::result_large_err)]
    fn deliver_arm_result(
        &self,
        node_id: &str,
        response: crate::AdministrativeExecArmResult,
    ) -> Result<(), Status> {
        let pending = self
            .state
            .lock()
            .map_err(|_| Status::internal("control session state is poisoned"))?
            .pending
            .remove(&response.request_id)
            .ok_or_else(|| Status::aborted("administrative response has no pending request"))?;
        match pending {
            PendingAdministrativeResponse::Arm {
                node_id: expected,
                sender,
            } if expected == node_id => sender
                .send(response)
                .map_err(|_| Status::cancelled("administrative requester stopped waiting")),
            _ => Err(Status::unauthenticated(
                "administrative response does not match its node or operation",
            )),
        }
    }

    fn unregister(&self, identity: &StreamIdentity) {
        if let Ok(mut state) = self.state.lock() {
            if state
                .sessions
                .get(&identity.node_id)
                .is_some_and(|session| {
                    session.identity.connection_nonce == identity.connection_nonce
                })
            {
                state.sessions.remove(&identity.node_id);
            }
            state.pending.retain(|_, pending| match pending {
                PendingAdministrativeResponse::Resolution { node_id, .. }
                | PendingAdministrativeResponse::Arm { node_id, .. } => {
                    node_id != &identity.node_id
                }
            });
        }
    }
}

#[tonic::async_trait]
impl NodeControl for ControlPlane {
    type OpenStreamStream = Pin<Box<dyn Stream<Item = Result<ControlEnvelope, Status>> + Send>>;

    async fn open_stream(
        &self,
        request: Request<Streaming<NodeEnvelope>>,
    ) -> Result<Response<Self::OpenStreamStream>, Status> {
        let peer_digest = request
            .peer_certs()
            .and_then(|certificates| certificates.first().cloned())
            .map(|certificate| format!("{:x}", Sha256::digest(certificate.as_ref())))
            .ok_or_else(|| Status::unauthenticated("mTLS client certificate is required"))?;
        let mut input = request.into_inner();
        let first = input
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("registration message is required"))?;
        validate_header(&first, 1, None)?;
        let Some(NodePayload::Registration(registration)) = &first.payload else {
            return Err(Status::invalid_argument(
                "the first node message must be registration",
            ));
        };
        if !registration.kernel_ready {
            return Err(Status::failed_precondition(
                "node registration requires kernel readiness",
            ));
        }
        if !valid_registration(registration) {
            return Err(Status::invalid_argument(
                "node registration contains an invalid digest, epoch, or capability set",
            ));
        }
        self.register(&first.node_id, &first.connection_nonce, &peer_digest)?;

        let (output, receiver) = mpsc::channel(8);
        let identity = StreamIdentity::from(&first);
        send_control(
            &output,
            &identity,
            1,
            ControlPayload::RegistrationAccepted(RegistrationAccepted {}),
        )
        .await?;
        send_control(
            &output,
            &identity,
            2,
            ControlPayload::TrustGeneration(TrustGeneration {
                generation: self.trust.generation,
                bundle_digest: self.trust.bundle_digest.clone(),
            }),
        )
        .await?;

        let control = self.clone();
        let session_output = output.clone();
        tokio::spawn(async move {
            let mut expected_sequence = 2;
            while let Some(message) = input.next().await {
                #[allow(clippy::result_large_err)]
                let result = message.and_then(|message| {
                    validate_header(&message, expected_sequence, Some(&identity))?;
                    control.record_node_sequence(
                        &identity.node_id,
                        &identity.connection_nonce,
                        expected_sequence,
                    )?;
                    expected_sequence = expected_sequence
                        .checked_add(1)
                        .ok_or_else(|| Status::out_of_range("node stream sequence exhausted"))?;
                    match message.payload {
                        Some(NodePayload::TrustAck(ack)) => control.acknowledge(
                            &identity.node_id,
                            ack.generation,
                            &ack.bundle_digest,
                        ),
                        Some(NodePayload::ReadinessReport(report)) => {
                            control.validate_readiness(&report)?;
                            control.register_ready_session(&identity, &session_output)
                        }
                        Some(NodePayload::Resolution(response)) => {
                            control.deliver_resolution(&identity.node_id, *response)
                        }
                        Some(NodePayload::ArmResult(response)) => {
                            control.deliver_arm_result(&identity.node_id, response)
                        }
                        Some(NodePayload::Registration(_)) | None => Err(Status::invalid_argument(
                            "registration is allowed only as the first stream message",
                        )),
                    }
                });
                if let Err(error) = result {
                    let _result = output.send(Err(error)).await;
                    control.unregister(&identity);
                    return;
                }
            }
            control.unregister(&identity);
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

fn valid_registration(registration: &crate::NodeRegistration) -> bool {
    registration.label_epoch > 0
        && is_sha256_hex(&registration.platform_digest)
        && is_sha256_hex(&registration.program_digest)
        && !registration.capabilities.is_empty()
        && registration.capabilities.iter().all(|capability| {
            !capability.capability_id.is_empty()
                && matches!(
                    capability.state.as_str(),
                    "SUPPORTED" | "UNSUPPORTED" | "DEGRADED" | "UNHEALTHY"
                )
                && !capability.reason_code.is_empty()
        })
        && registration
            .capabilities
            .iter()
            .map(|capability| capability.capability_id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == registration.capabilities.len()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone)]
struct StreamIdentity {
    node_id: String,
    node_boot_id: Vec<u8>,
    connection_nonce: Vec<u8>,
}

impl StreamIdentity {
    fn envelope(&self, sequence: u64, payload: ControlPayload) -> ControlEnvelope {
        ControlEnvelope {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            node_id: self.node_id.clone(),
            node_boot_id: self.node_boot_id.clone(),
            connection_nonce: self.connection_nonce.clone(),
            sequence,
            payload: Some(payload),
        }
    }
}

#[allow(clippy::result_large_err)]
fn ensure_request_id_available(state: &ControlState, request_id: &[u8]) -> Result<(), Status> {
    if request_id.len() != 16 || request_id.iter().all(|byte| *byte == 0) {
        return Err(Status::invalid_argument(
            "administrative request ID must be one nonzero Id128",
        ));
    }
    if state.pending.contains_key(request_id) {
        return Err(Status::already_exists(
            "administrative request ID is already pending",
        ));
    }
    Ok(())
}

impl From<&NodeEnvelope> for StreamIdentity {
    fn from(message: &NodeEnvelope) -> Self {
        Self {
            node_id: message.node_id.clone(),
            node_boot_id: message.node_boot_id.clone(),
            connection_nonce: message.connection_nonce.clone(),
        }
    }
}

#[allow(clippy::result_large_err)]
fn validate_header(
    message: &NodeEnvelope,
    expected_sequence: u64,
    identity: Option<&StreamIdentity>,
) -> Result<(), Status> {
    if !message.has_supported_header() {
        return Err(Status::failed_precondition(
            "unsupported protocol or malformed stream identity",
        ));
    }
    if message.sequence != expected_sequence {
        return Err(Status::aborted("node stream sequence is not monotonic"));
    }
    if identity.is_some_and(|identity| {
        message.node_id != identity.node_id
            || message.node_boot_id != identity.node_boot_id
            || message.connection_nonce != identity.connection_nonce
    }) {
        return Err(Status::unauthenticated(
            "node stream identity changed within a connection",
        ));
    }
    Ok(())
}

async fn send_control(
    output: &mpsc::Sender<Result<ControlEnvelope, Status>>,
    identity: &StreamIdentity,
    sequence: u64,
    payload: ControlPayload,
) -> Result<(), Status> {
    output
        .send(Ok(ControlEnvelope {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            node_id: identity.node_id.clone(),
            node_boot_id: identity.node_boot_id.clone(),
            connection_nonce: identity.connection_nonce.clone(),
            sequence,
            payload: Some(payload),
        }))
        .await
        .map_err(|_| Status::unavailable("node disconnected during registration"))
}

#[cfg(test)]
mod tests {
    use super::{
        valid_registration, validate_header, AllowedNodeIdentity, ControlPlane, StreamIdentity,
        TrustGenerationV1,
    };
    use crate::control_envelope::Payload as ControlPayload;
    use crate::{
        AdministrativeExecResolution, CapabilityRecord, NodeEnvelope, NodeRegistration,
        ResolveAdministrativeExec, CONTROL_PROTOCOL_VERSION,
    };

    fn control() -> ControlPlane {
        ControlPlane::new(
            vec![AllowedNodeIdentity {
                node_id: "node-a".to_owned(),
                certificate_sha256: "a".repeat(64),
            }],
            TrustGenerationV1 {
                generation: 7,
                bundle_digest: "b".repeat(64),
            },
        )
    }

    #[test]
    fn registration_nonce_is_one_use_across_stream_teardown_and_certificate_bound() {
        let control = control();
        let identity = StreamIdentity {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![1; 16],
        };
        assert!(control
            .register("node-a", &[1; 16], &"a".repeat(64))
            .is_ok());
        assert!(control.record_node_sequence("node-a", &[1; 16], 2).is_ok());
        assert_eq!(
            control
                .register("node-a", &[1; 16], &"a".repeat(64))
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
        assert!(control.record_node_sequence("node-a", &[1; 16], 3).is_ok());
        control.unregister(&identity);
        assert_eq!(
            control
                .register("node-a", &[1; 16], &"a".repeat(64))
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
        assert!(control
            .register("node-a", &[2; 16], &"c".repeat(64))
            .is_err());
        assert_eq!(control.registered_nonce_count(), 1);
    }

    #[test]
    fn stream_rejects_gap_and_identity_change() {
        let identity = StreamIdentity {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let valid = NodeEnvelope {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            node_id: identity.node_id.clone(),
            node_boot_id: identity.node_boot_id.clone(),
            connection_nonce: identity.connection_nonce.clone(),
            sequence: 2,
            payload: None,
        };
        assert!(validate_header(&valid, 2, Some(&identity)).is_ok());
        assert!(validate_header(&valid, 3, Some(&identity)).is_err());
        let mut changed = valid;
        changed.connection_nonce = vec![9; 16];
        assert!(validate_header(&changed, 2, Some(&identity)).is_err());
    }

    #[test]
    fn registration_accepts_the_closed_capability_states_used_by_nodes() {
        for state in ["SUPPORTED", "UNSUPPORTED", "DEGRADED", "UNHEALTHY"] {
            let registration = NodeRegistration {
                platform_digest: "a".repeat(64),
                program_digest: "b".repeat(64),
                label_epoch: 1,
                kernel_ready: true,
                effect_prevention_claims_enabled: state == "SUPPORTED",
                capabilities: vec![CapabilityRecord {
                    capability_id: "capability".to_owned(),
                    state: state.to_owned(),
                    reason_code: "MEASURED_STATE".to_owned(),
                }],
            };

            assert!(valid_registration(&registration), "state {state}");
        }

        let mut invalid = NodeRegistration {
            platform_digest: "a".repeat(64),
            program_digest: "b".repeat(64),
            label_epoch: 1,
            kernel_ready: true,
            effect_prevention_claims_enabled: false,
            capabilities: vec![CapabilityRecord {
                capability_id: "capability".to_owned(),
                state: "UNKNOWN".to_owned(),
                reason_code: "MEASURED_STATE".to_owned(),
            }],
        };
        assert!(!valid_registration(&invalid));
        invalid.capabilities[0].state = "ABSENT".to_owned();
        assert!(!valid_registration(&invalid));
    }

    #[tokio::test]
    async fn administrative_resolution_uses_the_ready_authenticated_node_stream(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let control = control();
        let identity = StreamIdentity {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let (output, mut input) = tokio::sync::mpsc::channel(1);
        control.register_ready_session(&identity, &output)?;
        let request_id = vec![3; 16];
        let request = ResolveAdministrativeExec {
            request_id: request_id.clone(),
            ..ResolveAdministrativeExec::default()
        };
        let waiting = tokio::spawn({
            let control = control.clone();
            async move { control.resolve_administrative_exec("node-a", request).await }
        });
        let envelope = input
            .recv()
            .await
            .transpose()?
            .ok_or("node request missing")?;
        assert_eq!(envelope.sequence, 3);
        assert!(matches!(
            envelope.payload,
            Some(ControlPayload::ResolveAdministrativeExec(_))
        ));
        control.deliver_resolution(
            "node-a",
            AdministrativeExecResolution {
                request_id: request_id.clone(),
                resolved: true,
                ..AdministrativeExecResolution::default()
            },
        )?;
        assert_eq!(waiting.await??.request_id, request_id);
        Ok(())
    }
}
