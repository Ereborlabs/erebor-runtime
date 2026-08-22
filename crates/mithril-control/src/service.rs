#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, BTreeSet},
    pin::Pin,
    sync::{Arc, Mutex},
};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt as _};
use tonic::{Request, Response, Status, Streaming};

use crate::{
    node_administrative_arm_server::NodeAdministrativeArm,
    node_administrative_resolution_server::NodeAdministrativeResolution,
    node_coverage_server::NodeCoverage, node_evidence_server::NodeEvidence,
    node_registry_server::NodeRegistry, node_trust_server::NodeTrust, AdministrativeExecArmResult,
    AdministrativeExecArmStreamRequest, AdministrativeExecResolution,
    AdministrativeExecResolutionStreamRequest, ArmAdministrativeExec, CoverageAck,
    CoverageReportRequest, EvidenceAck, EvidenceBatchRequest, NodeReadinessRequest,
    NodeRegistrationRequest, NodeSessionContext, RegistrationAccepted, ResolveAdministrativeExec,
    TrustGeneration, TrustGenerationAckRequest, IDENTITY_BYTES,
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
    registrations: BTreeSet<StreamIdentity>,
    trust_acks: BTreeMap<String, TrustGenerationV1>,
    sessions: BTreeMap<String, NodeSession>,
    pending: BTreeMap<Vec<u8>, PendingAdministrativeResponse>,
}

struct NodeSession {
    identity: StreamIdentity,
    resolution_output: Option<mpsc::Sender<Result<ResolveAdministrativeExec, Status>>>,
    arm_output: Option<mpsc::Sender<Result<ArmAdministrativeExec, Status>>>,
    admission_ready: bool,
}

enum PendingAdministrativeResponse {
    Resolution {
        node_id: String,
        sender: oneshot::Sender<AdministrativeExecResolution>,
    },
    Arm {
        node_id: String,
        sender: oneshot::Sender<AdministrativeExecArmResult>,
    },
}

const ADMINISTRATIVE_NODE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone)]
pub struct ControlPlane {
    allowed_nodes: Arc<BTreeMap<String, String>>,
    trust: TrustGenerationV1,
    state: Arc<Mutex<ControlState>>,
    evidence: Option<crate::EvidenceIntakeOwner>,
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
            evidence: None,
        }
    }

    pub fn with_evidence_directory(
        allowed: Vec<AllowedNodeIdentity>,
        trust: TrustGenerationV1,
        directory: impl Into<std::path::PathBuf>,
    ) -> crate::Result<Self> {
        let mut control = Self::new(allowed, trust);
        control.evidence = Some(crate::EvidenceIntakeOwner::open(directory)?);
        Ok(control)
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
            .map_or(0, |state| state.registrations.len())
    }

    pub async fn resolve_administrative_exec(
        &self,
        node_id: &str,
        request: ResolveAdministrativeExec,
    ) -> Result<AdministrativeExecResolution, Status> {
        let request_id = request.request_id.clone();
        let (receiver, output) = {
            let (sender, receiver) = oneshot::channel();
            let mut state = self.lock_state()?;
            ensure_request_id_available(&state, &request_id)?;
            let session = ready_session_mut(&mut state, node_id)?;
            let output = session
                .resolution_output
                .clone()
                .ok_or_else(|| Status::unavailable("target node has no resolution stream"))?;
            state.pending.insert(
                request_id.clone(),
                PendingAdministrativeResponse::Resolution {
                    node_id: node_id.to_owned(),
                    sender,
                },
            );
            (receiver, output)
        };
        if output.send(Ok(request)).await.is_err() {
            self.remove_pending(&request_id);
            return Err(Status::unavailable(
                "target node disconnected before administrative resolution",
            ));
        }
        await_administrative(receiver, &request_id, self, "resolve administrative exec").await
    }

    pub async fn arm_administrative_exec(
        &self,
        node_id: &str,
        request: ArmAdministrativeExec,
    ) -> Result<AdministrativeExecArmResult, Status> {
        let request_id = request.request_id.clone();
        let (receiver, output) = {
            let (sender, receiver) = oneshot::channel();
            let mut state = self.lock_state()?;
            ensure_request_id_available(&state, &request_id)?;
            let session = ready_session_mut(&mut state, node_id)?;
            let output = session
                .arm_output
                .clone()
                .ok_or_else(|| Status::unavailable("target node has no arm stream"))?;
            state.pending.insert(
                request_id.clone(),
                PendingAdministrativeResponse::Arm {
                    node_id: node_id.to_owned(),
                    sender,
                },
            );
            (receiver, output)
        };
        if output.send(Ok(request)).await.is_err() {
            self.remove_pending(&request_id);
            return Err(Status::unavailable(
                "target node disconnected before administrative slot installation",
            ));
        }
        await_administrative(receiver, &request_id, self, "arm administrative exec").await
    }

    fn authenticated_node<T>(&self, request: &Request<T>) -> Result<String, Status> {
        let digest = request
            .peer_certs()
            .and_then(|certificates| certificates.first().cloned())
            .map(|certificate| format!("{:x}", Sha256::digest(certificate.as_ref())))
            .ok_or_else(|| Status::unauthenticated("mTLS client certificate is required"))?;
        let mut matching = self
            .allowed_nodes
            .iter()
            .filter(|(_node_id, expected)| *expected == &digest)
            .map(|(node_id, _expected)| node_id.clone());
        let node_id = matching
            .next()
            .ok_or_else(|| Status::permission_denied("node certificate is not enrolled"))?;
        if matching.next().is_some() {
            return Err(Status::failed_precondition(
                "node certificate is enrolled for more than one node",
            ));
        }
        Ok(node_id)
    }

    fn register(
        &self,
        node_id: String,
        context: &NodeSessionContext,
        registration: &crate::NodeRegistration,
    ) -> Result<(), Status> {
        if context.node_id != node_id {
            return Err(Status::permission_denied(
                "node identity does not match its mTLS certificate",
            ));
        }
        let identity = StreamIdentity::new(node_id.clone(), context)?;
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
        let mut state = self.lock_state()?;
        if !state.registrations.insert(identity.clone()) {
            return Err(Status::already_exists("registration nonce was replayed"));
        }
        state
            .pending
            .retain(|_, pending| pending.node_id() != node_id);
        state.sessions.insert(
            node_id,
            NodeSession {
                identity,
                resolution_output: None,
                arm_output: None,
                admission_ready: false,
            },
        );
        Ok(())
    }

    fn require_session(
        &self,
        node_id: &str,
        context: &NodeSessionContext,
    ) -> Result<StreamIdentity, Status> {
        if context.node_id != node_id {
            return Err(Status::permission_denied(
                "node identity does not match its mTLS certificate",
            ));
        }
        let identity = StreamIdentity::new(node_id.to_owned(), context)?;
        let state = self.lock_state()?;
        let active = state
            .sessions
            .get(node_id)
            .ok_or_else(|| Status::unauthenticated("node session is not registered"))?;
        if active.identity != identity {
            return Err(Status::unauthenticated(
                "node boot identity or connection nonce is stale",
            ));
        }
        Ok(identity)
    }

    fn require_ready_session(
        &self,
        node_id: &str,
        context: &NodeSessionContext,
    ) -> Result<StreamIdentity, Status> {
        let identity = self.require_session(node_id, context)?;
        let state = self.lock_state()?;
        if !state
            .sessions
            .get(node_id)
            .is_some_and(|session| session.admission_ready)
        {
            return Err(Status::failed_precondition("node admission is not ready"));
        }
        Ok(identity)
    }

    fn remove_pending(&self, request_id: &[u8]) {
        if let Ok(mut state) = self.state.lock() {
            state.pending.remove(request_id);
        }
    }

    fn deliver_resolution(
        &self,
        node_id: &str,
        response: AdministrativeExecResolution,
    ) -> Result<(), Status> {
        let pending = self
            .lock_state()?
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

    fn deliver_arm_result(
        &self,
        node_id: &str,
        response: AdministrativeExecArmResult,
    ) -> Result<(), Status> {
        let pending = self
            .lock_state()?
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

    fn clear_resolution_output(&self, identity: &StreamIdentity) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(session) = state.sessions.get_mut(&identity.node_id) {
                if session.identity == *identity {
                    session.resolution_output = None;
                }
            }
        }
    }

    fn clear_arm_output(&self, identity: &StreamIdentity) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(session) = state.sessions.get_mut(&identity.node_id) {
                if session.identity == *identity {
                    session.arm_output = None;
                }
            }
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, ControlState>, Status> {
        self.state
            .lock()
            .map_err(|_| Status::internal("control session state is poisoned"))
    }
}

#[tonic::async_trait]
impl NodeRegistry for ControlPlane {
    async fn register(
        &self,
        request: Request<NodeRegistrationRequest>,
    ) -> Result<Response<RegistrationAccepted>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let registration = request
            .registration
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node registration is required"))?;
        self.register(node_id, context, registration)?;
        Ok(Response::new(RegistrationAccepted {}))
    }

    async fn report_readiness(
        &self,
        request: Request<NodeReadinessRequest>,
    ) -> Result<Response<RegistrationAccepted>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let report = request
            .report
            .ok_or_else(|| Status::invalid_argument("node readiness report is required"))?;
        let identity = self.require_session(&node_id, context)?;
        if !report.kernel_ready || !report.control_ready {
            return Err(Status::failed_precondition(
                "node readiness requires kernel and control readiness",
            ));
        }
        let mut state = self.lock_state()?;
        let session = state
            .sessions
            .get_mut(&node_id)
            .ok_or_else(|| Status::unauthenticated("node session is not registered"))?;
        if session.identity != identity {
            return Err(Status::unauthenticated("node session changed"));
        }
        session.admission_ready = report.admission_ready;
        Ok(Response::new(RegistrationAccepted {}))
    }
}

#[tonic::async_trait]
impl NodeTrust for ControlPlane {
    type WatchStream = Pin<Box<dyn Stream<Item = Result<TrustGeneration, Status>> + Send>>;

    async fn watch(
        &self,
        request: Request<NodeSessionContext>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let node_id = self.authenticated_node(&request)?;
        self.require_session(&node_id, request.get_ref())?;
        let trust = TrustGeneration {
            generation: self.trust.generation,
            bundle_digest: self.trust.bundle_digest.clone(),
        };
        Ok(Response::new(Box::pin(tokio_stream::iter([Ok(trust)]))))
    }

    async fn acknowledge(
        &self,
        request: Request<TrustGenerationAckRequest>,
    ) -> Result<Response<RegistrationAccepted>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        self.require_session(&node_id, context)?;
        let acknowledgement = request
            .acknowledgement
            .ok_or_else(|| Status::invalid_argument("trust acknowledgement is required"))?;
        if acknowledgement.generation != self.trust.generation
            || acknowledgement.bundle_digest != self.trust.bundle_digest
        {
            return Err(Status::failed_precondition(
                "trust acknowledgement does not match the delivered generation",
            ));
        }
        self.lock_state()?.trust_acks.insert(
            node_id,
            TrustGenerationV1 {
                generation: acknowledgement.generation,
                bundle_digest: acknowledgement.bundle_digest,
            },
        );
        Ok(Response::new(RegistrationAccepted {}))
    }
}

#[tonic::async_trait]
impl NodeEvidence for ControlPlane {
    async fn upload(
        &self,
        request: Request<EvidenceBatchRequest>,
    ) -> Result<Response<EvidenceAck>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        self.require_ready_session(&node_id, context)?;
        let batch = request
            .batch
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("evidence batch is required"))?;
        let evidence = self.evidence.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable evidence intake owner")
        })?;
        Ok(Response::new(evidence.receive(&node_id, batch)?))
    }
}

#[tonic::async_trait]
impl NodeCoverage for ControlPlane {
    async fn report(
        &self,
        request: Request<CoverageReportRequest>,
    ) -> Result<Response<CoverageAck>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        self.require_session(&node_id, context)?;
        let report = request
            .report
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("coverage report is required"))?;
        let evidence = self.evidence.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable evidence intake owner")
        })?;
        Ok(Response::new(evidence.receive_coverage(&node_id, report)?))
    }
}

#[tonic::async_trait]
impl NodeAdministrativeResolution for ControlPlane {
    type OpenStream = Pin<Box<dyn Stream<Item = Result<ResolveAdministrativeExec, Status>> + Send>>;

    async fn open(
        &self,
        request: Request<Streaming<AdministrativeExecResolutionStreamRequest>>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let mut input = request.into_inner();
        let first = input
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let context = first
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let identity = self.require_session(&node_id, context)?;
        if first.result.is_some() {
            return Err(Status::invalid_argument(
                "the first resolution stream message must contain only session context",
            ));
        }
        let (output, receiver) = mpsc::channel(8);
        self.lock_state()?
            .sessions
            .get_mut(&node_id)
            .ok_or_else(|| Status::unauthenticated("node session is not registered"))?
            .resolution_output = Some(output.clone());
        let control = self.clone();
        tokio::spawn(async move {
            while let Some(message) = input.next().await {
                let result = message.and_then(|message| {
                    let context = message.session.as_ref().ok_or_else(|| {
                        Status::invalid_argument("node session context is required")
                    })?;
                    control.require_session(&node_id, context)?;
                    let response = message.result.ok_or_else(|| {
                        Status::invalid_argument("administrative resolution result is required")
                    })?;
                    control.deliver_resolution(&node_id, response)
                });
                if let Err(error) = result {
                    let _result = output.send(Err(error)).await;
                    break;
                }
            }
            control.clear_resolution_output(&identity);
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

#[tonic::async_trait]
impl NodeAdministrativeArm for ControlPlane {
    type OpenStream = Pin<Box<dyn Stream<Item = Result<ArmAdministrativeExec, Status>> + Send>>;

    async fn open(
        &self,
        request: Request<Streaming<AdministrativeExecArmStreamRequest>>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let mut input = request.into_inner();
        let first = input
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let context = first
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let identity = self.require_session(&node_id, context)?;
        if first.result.is_some() {
            return Err(Status::invalid_argument(
                "the first arm stream message must contain only session context",
            ));
        }
        let (output, receiver) = mpsc::channel(8);
        self.lock_state()?
            .sessions
            .get_mut(&node_id)
            .ok_or_else(|| Status::unauthenticated("node session is not registered"))?
            .arm_output = Some(output.clone());
        let control = self.clone();
        tokio::spawn(async move {
            while let Some(message) = input.next().await {
                let result = message.and_then(|message| {
                    let context = message.session.as_ref().ok_or_else(|| {
                        Status::invalid_argument("node session context is required")
                    })?;
                    control.require_session(&node_id, context)?;
                    let response = message.result.ok_or_else(|| {
                        Status::invalid_argument("administrative arm result is required")
                    })?;
                    control.deliver_arm_result(&node_id, response)
                });
                if let Err(error) = result {
                    let _result = output.send(Err(error)).await;
                    break;
                }
            }
            control.clear_arm_output(&identity);
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StreamIdentity {
    node_id: String,
    node_boot_id: Vec<u8>,
    connection_nonce: Vec<u8>,
}

impl StreamIdentity {
    fn new(node_id: String, context: &NodeSessionContext) -> Result<Self, Status> {
        if context.node_boot_id.len() != IDENTITY_BYTES
            || context.connection_nonce.len() != IDENTITY_BYTES
        {
            return Err(Status::invalid_argument(
                "node boot identity and connection nonce must be Id128 values",
            ));
        }
        Ok(Self {
            node_id,
            node_boot_id: context.node_boot_id.clone(),
            connection_nonce: context.connection_nonce.clone(),
        })
    }
}

impl PendingAdministrativeResponse {
    fn node_id(&self) -> &str {
        match self {
            Self::Resolution { node_id, .. } | Self::Arm { node_id, .. } => node_id,
        }
    }
}

fn ready_session_mut<'a>(
    state: &'a mut ControlState,
    node_id: &str,
) -> Result<&'a mut NodeSession, Status> {
    let session = state
        .sessions
        .get_mut(node_id)
        .ok_or_else(|| Status::unavailable("target node has no registered session"))?;
    if !session.admission_ready {
        return Err(Status::failed_precondition(
            "target node admission is not ready",
        ));
    }
    Ok(session)
}

fn ensure_request_id_available(state: &ControlState, request_id: &[u8]) -> Result<(), Status> {
    if request_id.len() != IDENTITY_BYTES || request_id.iter().all(|byte| *byte == 0) {
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

async fn await_administrative<T>(
    receiver: oneshot::Receiver<T>,
    request_id: &[u8],
    control: &ControlPlane,
    operation: &'static str,
) -> Result<T, Status> {
    match tokio::time::timeout(ADMINISTRATIVE_NODE_TIMEOUT, receiver).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_closed)) => Err(Status::unavailable(format!(
            "target node disconnected before it could {operation}"
        ))),
        Err(_elapsed) => {
            control.remove_pending(request_id);
            Err(Status::deadline_exceeded(format!(
                "target node did not {operation} before the deadline"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{valid_registration, ControlPlane, StreamIdentity};
    use crate::{
        AllowedNodeIdentity, CapabilityRecord, NodeRegistration, NodeSessionContext,
        TrustGenerationV1,
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

    fn registration() -> NodeRegistration {
        NodeRegistration {
            platform_digest: "a".repeat(64),
            program_digest: "b".repeat(64),
            label_epoch: 1,
            kernel_ready: true,
            effect_prevention_claims_enabled: true,
            capabilities: vec![CapabilityRecord {
                capability_id: "capability".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "MEASURED_STATE".to_owned(),
            }],
        }
    }

    #[test]
    fn registration_nonce_is_one_use() {
        let control = control();
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        assert!(control
            .register("node-a".to_owned(), &context, &registration())
            .is_ok());
        assert!(control
            .register("node-a".to_owned(), &context, &registration())
            .is_err());
        assert_eq!(control.registered_nonce_count(), 1);
    }

    #[test]
    fn stale_session_context_is_rejected() -> Result<(), tonic::Status> {
        let control = control();
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        control.register("node-a".to_owned(), &context, &registration())?;
        let stale = NodeSessionContext {
            connection_nonce: vec![3; 16],
            ..context
        };
        assert!(control.require_session("node-a", &stale).is_err());
        Ok::<(), tonic::Status>(())
    }

    #[test]
    fn registration_accepts_closed_capability_states() {
        for state in ["SUPPORTED", "UNSUPPORTED", "DEGRADED", "UNHEALTHY"] {
            let mut registration = registration();
            registration.capabilities[0].state = state.to_owned();
            assert!(valid_registration(&registration));
        }
    }

    #[test]
    fn stream_identity_requires_exact_id128_values() {
        let invalid = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 15],
            connection_nonce: vec![2; 16],
        };
        assert!(StreamIdentity::new("node-a".to_owned(), &invalid).is_err());
    }
}
