#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, BTreeSet},
    pin::Pin,
    sync::{Arc, Mutex},
};

use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt as _};
use tonic::{Request, Response, Status, Streaming};

use crate::{
    control_health_server::ControlHealth, node_administrative_arm_server::NodeAdministrativeArm,
    node_administrative_resolution_server::NodeAdministrativeResolution,
    node_coverage_server::NodeCoverage, node_evidence_server::NodeEvidence,
    node_policy_server::NodePolicy, node_registry_server::NodeRegistry,
    node_trust_server::NodeTrust, AdministrativeExecArmResult, AdministrativeExecArmStreamRequest,
    AdministrativeExecResolution, AdministrativeExecResolutionStreamRequest, ArmAdministrativeExec,
    ControlConvergenceHealth, CoverageAck, CoverageReportRequest, EvidenceAck,
    EvidenceBatchRequest, NodeReadinessRequest, NodeRegistrationRequest, NodeSessionContext,
    PolicyAcknowledgementAccepted, PolicyAcknowledgementRequest, PolicyChunk, PolicyChunkRequest,
    PolicyInventory, PolicyInventoryRequest, RegistrationAccepted, ResolveAdministrativeExec,
    TrustGeneration, TrustGenerationAckRequest, IDENTITY_BYTES,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AllowedNodeIdentity {
    pub node_id: String,
    pub certificate_sha256: String,
    pub tenant_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustGenerationV1 {
    pub generation: u64,
    pub bundle_digest: String,
    #[serde(default)]
    pub policy_issuer_sequence_epoch: u64,
    #[serde(default)]
    pub policy_signers: Vec<PolicySignerTrustV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignerTrustV1 {
    pub signing_key_id: String,
    pub ed25519_public_key_hex: String,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Default)]
struct ControlState {
    registrations: BTreeSet<StreamIdentity>,
    sessions: BTreeMap<String, NodeSession>,
    pending: BTreeMap<Vec<u8>, PendingAdministrativeResponse>,
}

struct NodeSession {
    identity: StreamIdentity,
    resolution_output: Option<mpsc::Sender<Result<ResolveAdministrativeExec, Status>>>,
    arm_output: Option<mpsc::Sender<Result<ArmAdministrativeExec, Status>>>,
    admission_ready: bool,
    label_epoch: u64,
    workload_targets: Vec<crate::WorkloadTargetFactV1>,
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
    allowed_nodes: Arc<BTreeMap<String, AllowedNodeIdentity>>,
    trust: crate::TrustBundleOwner,
    state: Arc<Mutex<ControlState>>,
    evidence: Option<crate::EvidenceIntakeOwner>,
    policy_store: Option<crate::ControlStore>,
    policy_rollout: Option<crate::PolicyRolloutOwner>,
    policy_desired_state: Option<crate::PolicyDesiredStateOwner>,
}

impl ControlPlane {
    #[must_use]
    pub fn new(allowed: Vec<AllowedNodeIdentity>, trust: TrustGenerationV1) -> Self {
        Self {
            allowed_nodes: Arc::new(
                allowed
                    .into_iter()
                    .map(|identity| (identity.node_id.clone(), identity))
                    .collect(),
            ),
            trust: crate::TrustBundleOwner::static_generation(trust),
            state: Arc::new(Mutex::new(ControlState::default())),
            evidence: None,
            policy_store: None,
            policy_rollout: None,
            policy_desired_state: None,
        }
    }

    pub fn with_evidence_directory(
        allowed: Vec<AllowedNodeIdentity>,
        trust: TrustGenerationV1,
        directory: impl Into<std::path::PathBuf>,
    ) -> crate::Result<Self> {
        Self::with_control_store(allowed, trust, crate::ControlStore::open(directory)?)
    }

    pub fn with_control_store(
        allowed: Vec<AllowedNodeIdentity>,
        trust: TrustGenerationV1,
        store: crate::ControlStore,
    ) -> crate::Result<Self> {
        let trust = crate::TrustBundleOwner::open(store.clone(), trust)?;
        Ok(Self {
            allowed_nodes: Arc::new(
                allowed
                    .into_iter()
                    .map(|identity| (identity.node_id.clone(), identity))
                    .collect(),
            ),
            trust,
            state: Arc::new(Mutex::new(ControlState::default())),
            evidence: Some(crate::EvidenceIntakeOwner::from_store(store)),
            policy_store: None,
            policy_rollout: None,
            policy_desired_state: None,
        })
    }

    #[must_use]
    pub fn with_policy_desired_state(mut self, owner: crate::PolicyDesiredStateOwner) -> Self {
        self.policy_store = Some(owner.store());
        self.policy_rollout = Some(owner.rollout_owner());
        self.policy_desired_state = Some(owner);
        self
    }

    #[must_use]
    pub fn policy_desired_state(&self) -> Option<crate::PolicyDesiredStateOwner> {
        self.policy_desired_state.clone()
    }

    #[must_use]
    pub fn allowed_nodes(&self) -> &BTreeMap<String, AllowedNodeIdentity> {
        &self.allowed_nodes
    }

    #[must_use]
    pub fn acknowledged_trust(&self, node_id: &str) -> Option<TrustGenerationV1> {
        self.trust.acknowledged(node_id).ok().flatten()
    }

    #[must_use]
    pub fn trust_bundle_owner(&self) -> crate::TrustBundleOwner {
        self.trust.clone()
    }

    #[must_use]
    pub fn registered_nonce_count(&self) -> usize {
        self.state
            .lock()
            .map_or(0, |state| state.registrations.len())
    }

    #[must_use]
    pub fn workload_inventory(&self) -> Vec<crate::WorkloadTargetFactV1> {
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .sessions
                    .values()
                    .flat_map(|session| session.workload_targets.iter().cloned())
                    .collect()
            },
        )
    }

    pub fn convergence_health(&self) -> Result<ControlConvergenceHealth, Status> {
        let owner = self
            .policy_desired_state
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("Control has no Kubernetes policy owner"))?;
        let policy = owner.health().map_err(internal_status)?;
        let store = self
            .policy_store
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("Control has no durable policy store"))?
            .health()
            .map_err(internal_status)?;
        let state = self.lock_state()?;
        let connected_nodes = count(state.sessions.len());
        let ready_nodes = count(
            state
                .sessions
                .values()
                .filter(|session| session.admission_ready)
                .count(),
        );
        Ok(ControlConvergenceHealth {
            queue_healthy: policy.reconcile_in_flight <= policy.configured_namespaces,
            reconcile_in_flight: policy.reconcile_in_flight,
            reconcile_queue_limit: policy.configured_namespaces,
            storage_healthy: true,
            control_commit_index: store.commit_index,
            watch_healthy: policy.watched_namespaces == policy.configured_namespaces,
            configured_namespaces: policy.configured_namespaces,
            watched_namespaces: policy.watched_namespaces,
            successful_relists: policy.successful_relists,
            failed_relists: policy.failed_relists,
            watch_failures: policy.watch_failures,
            successful_reconciles: policy.successful_reconciles,
            rejected_reconciles: policy.rejected_reconciles,
            successful_compiles: policy.successful_compiles,
            failed_compiles: policy.failed_compiles,
            target_snapshots: store.target_snapshots,
            rollout_targets: store.rollout_targets,
            unsettled_rollout_targets: store.unsettled_rollout_targets,
            allowed_nodes: count(self.allowed_nodes.len()),
            connected_nodes,
            ready_nodes,
            evidence_cursors: store.evidence_cursors,
            pending_evidence_batches: store.pending_evidence_batches,
            pending_evidence_records: store.pending_evidence_records,
            coverage_cursors: store.coverage_cursors,
        })
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
            .filter(|(_node_id, expected)| expected.certificate_sha256 == digest)
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

    fn authenticated_evidence_node(
        &self,
        node_id: &str,
        context: &NodeSessionContext,
    ) -> Result<crate::AuthenticatedEvidenceNodeV1, Status> {
        let enrolled = self.allowed_nodes.get(node_id).ok_or_else(|| {
            Status::permission_denied("node identity is not enrolled for evidence")
        })?;
        let tenant = uuid::Uuid::parse_str(&enrolled.tenant_id)
            .map_err(|_| Status::failed_precondition("node tenant enrollment is invalid"))?;
        let node_boot_id: [u8; 16] = context
            .node_boot_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("node boot identity is not Id128"))?;
        Ok(crate::AuthenticatedEvidenceNodeV1 {
            tenant_id: *tenant.as_bytes(),
            node_id: node_id.to_owned(),
            node_boot_id,
            label_epoch: self
                .session_label_epoch(&StreamIdentity::new(node_id.to_owned(), context)?)?,
        })
    }

    fn require_current_trust(
        &self,
        node_id: &str,
        context: &NodeSessionContext,
    ) -> Result<(), Status> {
        let node_boot_id: [u8; 16] = context
            .node_boot_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("node boot identity is not Id128"))?;
        let identity = StreamIdentity::new(node_id.to_owned(), context)?;
        self.trust
            .require_session_acknowledged(
                node_id,
                node_boot_id,
                self.session_label_epoch(&identity)?,
            )
            .map_err(invalid_policy_status)
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
        let workload_targets = registration
            .workload_targets
            .iter()
            .map(|target| registered_workload_target(&node_id, target))
            .collect::<Result<Vec<_>, _>>()?;
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
                label_epoch: registration.label_epoch,
                workload_targets,
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

    fn session_label_epoch(&self, identity: &StreamIdentity) -> Result<u64, Status> {
        let state = self.lock_state()?;
        let session = state
            .sessions
            .get(&identity.node_id)
            .ok_or_else(|| Status::unauthenticated("node session is not registered"))?;
        if session.identity != *identity || session.label_epoch == 0 {
            return Err(Status::unauthenticated(
                "node boot identity, label epoch, or connection nonce is stale",
            ));
        }
        Ok(session.label_epoch)
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
impl ControlHealth for ControlPlane {
    async fn get(
        &self,
        request: Request<NodeSessionContext>,
    ) -> Result<Response<ControlConvergenceHealth>, Status> {
        let node_id = self.authenticated_node(&request)?;
        self.require_session(&node_id, request.get_ref())?;
        self.require_current_trust(&node_id, request.get_ref())?;
        Ok(Response::new(self.convergence_health()?))
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
        let receiver = self.trust.subscribe().map_err(internal_status)?;
        let stream =
            ReceiverStream::new(receiver).map(|trust| Ok(trust_generation_message(&trust)));
        Ok(Response::new(Box::pin(stream)))
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
        let identity = self.require_session(&node_id, context)?;
        let acknowledgement = request
            .acknowledgement
            .ok_or_else(|| Status::invalid_argument("trust acknowledgement is required"))?;
        self.trust
            .acknowledge(
                &node_id,
                context
                    .node_boot_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("node boot identity is not Id128"))?,
                self.session_label_epoch(&identity)?,
                acknowledgement.generation,
                &acknowledgement.bundle_digest,
            )
            .map_err(invalid_policy_status)?;
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
        self.require_current_trust(&node_id, context)?;
        let authenticated = self.authenticated_evidence_node(&node_id, context)?;
        let batch = request
            .batch
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("evidence batch is required"))?;
        let evidence = self.evidence.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable evidence intake owner")
        })?;
        Ok(Response::new(evidence.receive(&authenticated, batch)?))
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
        let authenticated = self.authenticated_evidence_node(&node_id, context)?;
        let report = request
            .report
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("coverage report is required"))?;
        let evidence = self.evidence.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable evidence intake owner")
        })?;
        Ok(Response::new(
            evidence.receive_coverage(&authenticated, report)?,
        ))
    }
}

#[tonic::async_trait]
impl NodePolicy for ControlPlane {
    async fn inventory(
        &self,
        request: Request<PolicyInventoryRequest>,
    ) -> Result<Response<PolicyInventory>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        self.require_ready_session(&node_id, context)?;
        self.require_current_trust(&node_id, context)?;
        if request.durable_bundle_digests.len() > 256
            || request
                .durable_bundle_digests
                .iter()
                .any(|digest| !is_sha256_hex(digest))
            || (!request.active_candidate_content_id.is_empty()
                && !is_sha256_hex(&request.active_candidate_content_id))
        {
            return Err(Status::invalid_argument(
                "policy inventory identities or bounds are invalid",
            ));
        }
        let store = self.policy_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable policy rollout store")
        })?;
        let Some(bundle) = store
            .next_bundle_for_node(
                &node_id,
                &request.active_candidate_content_id,
                &request.durable_bundle_digests,
            )
            .map_err(internal_status)?
        else {
            return Ok(Response::new(PolicyInventory::default()));
        };
        let chunks = bundle.chunks().map_err(internal_status)?;
        let bundle_bytes = serde_json::to_vec(&bundle)
            .map_err(|error| Status::internal(format!("policy bundle encoding failed: {error}")))?;
        Ok(Response::new(PolicyInventory {
            candidate_available: true,
            candidate_content_id: bundle.candidate.candidate_content_id,
            policy_source_revision_id: bundle.candidate.policy_source_revision_id,
            target_snapshot_digest: bundle.candidate.target_snapshot_digest,
            bundle_digest: bundle.bundle_digest,
            bundle_bytes: u64::try_from(bundle_bytes.len()).unwrap_or(u64::MAX),
            chunk_count: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
            operation: policy_operation_name(bundle.candidate.operation).to_owned(),
        }))
    }

    async fn fetch(
        &self,
        request: Request<PolicyChunkRequest>,
    ) -> Result<Response<PolicyChunk>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        self.require_ready_session(&node_id, context)?;
        self.require_current_trust(&node_id, context)?;
        let store = self.policy_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable policy rollout store")
        })?;
        let bundle = store
            .bundle_for_candidate(&node_id, &request.candidate_content_id)
            .map_err(internal_status)?
            .ok_or_else(|| Status::not_found("the node has no desired policy candidate"))?;
        if request.candidate_content_id != bundle.candidate.candidate_content_id
            || request.bundle_digest != bundle.bundle_digest
        {
            return Err(Status::failed_precondition(
                "the requested policy candidate or bundle is stale",
            ));
        }
        let chunk = bundle
            .chunks()
            .map_err(internal_status)?
            .into_iter()
            .nth(request.chunk_index as usize)
            .ok_or_else(|| Status::out_of_range("the policy chunk index is out of range"))?;
        Ok(Response::new(PolicyChunk {
            candidate_content_id: request.candidate_content_id,
            bundle_digest: chunk.bundle_digest,
            chunk_index: chunk.chunk_index,
            chunk_count: chunk.chunk_count,
            chunk_sha256: chunk.chunk_sha256,
            payload: chunk.payload,
        }))
    }

    async fn acknowledge(
        &self,
        request: Request<PolicyAcknowledgementRequest>,
    ) -> Result<Response<PolicyAcknowledgementAccepted>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let channel_receipt_digest = policy_channel_receipt_digest(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let identity = self.require_ready_session(&node_id, context)?;
        self.require_current_trust(&node_id, context)?;
        let label_epoch = self.session_label_epoch(&identity)?;
        let acknowledgement = request
            .acknowledgement
            .ok_or_else(|| Status::invalid_argument("policy acknowledgement is required"))?;
        let state = parse_policy_activation_state(&acknowledgement.state)?;
        let acknowledgement = crate::PolicyActivationAcknowledgementV1 {
            acknowledgement_content_id: String::new(),
            tenant_id: acknowledgement.tenant_id,
            node_id,
            node_boot_id: context.node_boot_id.clone(),
            label_epoch,
            candidate_content_id: acknowledgement.candidate_content_id,
            policy_source_revision_id: acknowledgement.policy_source_revision_id,
            target_snapshot_digest: acknowledgement.target_snapshot_digest,
            state,
            node_bound_generation_digest: nonempty(acknowledgement.node_bound_generation_digest),
            profile_generation_ref_id: (acknowledgement.profile_generation_ref_id > 0)
                .then_some(acknowledgement.profile_generation_ref_id),
            readback_digest: nonempty(acknowledgement.readback_digest),
            probe_result_digest: nonempty(acknowledgement.probe_result_digest),
            reason_code: nonempty(acknowledgement.reason_code),
            observed_utc_ns: acknowledgement.observed_utc_ns,
            authenticated_channel_receipt_digest: channel_receipt_digest,
        }
        .finalize()
        .map_err(invalid_policy_status)?;
        let rollout = self
            .policy_rollout
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("Control has no policy rollout owner"))?;
        let state = rollout
            .acknowledge(acknowledgement)
            .map_err(invalid_policy_status)?;
        let store = self.policy_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable policy rollout store")
        })?;
        Ok(Response::new(PolicyAcknowledgementAccepted {
            control_commit_index: store.commit_index(),
            rollout_state: rollout_state_name(state.state).to_owned(),
        }))
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

fn policy_channel_receipt_digest(
    request: &Request<PolicyAcknowledgementRequest>,
) -> Result<String, Status> {
    let certificate = request
        .peer_certs()
        .and_then(|certificates| certificates.first().cloned())
        .ok_or_else(|| Status::unauthenticated("mTLS client certificate is required"))?;
    let mut digest = Sha256::new();
    digest.update(certificate.as_ref());
    digest.update(request.get_ref().encode_to_vec());
    Ok(format!("{:x}", digest.finalize()))
}

fn trust_generation_message(trust: &TrustGenerationV1) -> TrustGeneration {
    TrustGeneration {
        generation: trust.generation,
        bundle_digest: trust.bundle_digest.clone(),
        policy_issuer_sequence_epoch: trust.policy_issuer_sequence_epoch,
        policy_signers: trust
            .policy_signers
            .iter()
            .map(|signer| crate::PolicySignerTrust {
                signing_key_id: signer.signing_key_id.clone(),
                ed25519_public_key: hex::decode(&signer.ed25519_public_key_hex).unwrap_or_default(),
                revoked: signer.revoked,
            })
            .collect(),
    }
}

fn parse_policy_activation_state(value: &str) -> Result<crate::PolicyActivationStateV1, Status> {
    match value {
        "RECEIVED" => Ok(crate::PolicyActivationStateV1::Received),
        "STAGED" => Ok(crate::PolicyActivationStateV1::Staged),
        "ACTIVE" => Ok(crate::PolicyActivationStateV1::Active),
        "REJECTED" => Ok(crate::PolicyActivationStateV1::Rejected),
        "STALE" => Ok(crate::PolicyActivationStateV1::Stale),
        "UNKNOWN" => Ok(crate::PolicyActivationStateV1::Unknown),
        _ => Err(Status::invalid_argument(
            "policy acknowledgement has an unsupported state",
        )),
    }
}

const fn policy_operation_name(value: crate::PolicyDeliveryOperationV1) -> &'static str {
    match value {
        crate::PolicyDeliveryOperationV1::Activate => "ACTIVATE",
        crate::PolicyDeliveryOperationV1::Replace => "REPLACE",
        crate::PolicyDeliveryOperationV1::RetireToRestrictiveTerminal => {
            "RETIRE_TO_RESTRICTIVE_TERMINAL"
        }
    }
}

const fn rollout_state_name(value: crate::PolicyRolloutStatusV1) -> &'static str {
    match value {
        crate::PolicyRolloutStatusV1::Pending => "PENDING",
        crate::PolicyRolloutStatusV1::Delivered => "DELIVERED",
        crate::PolicyRolloutStatusV1::Staged => "STAGED",
        crate::PolicyRolloutStatusV1::Active => "ACTIVE",
        crate::PolicyRolloutStatusV1::Rejected => "REJECTED",
        crate::PolicyRolloutStatusV1::Stale => "STALE",
        crate::PolicyRolloutStatusV1::Unknown => "UNKNOWN",
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn internal_status(error: crate::Error) -> Status {
    Status::internal(error.to_string())
}

fn invalid_policy_status(error: crate::Error) -> Status {
    Status::failed_precondition(error.to_string())
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
        && registration.workload_targets.len() <= 65_536
        && registration
            .workload_targets
            .iter()
            .map(|target| target.workload_binding_generation_digest.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == registration.workload_targets.len()
}

fn registered_workload_target(
    node_id: &str,
    target: &crate::RegisteredWorkloadTarget,
) -> Result<crate::WorkloadTargetFactV1, Status> {
    let container_kind = match target.container_kind.as_str() {
        "INIT" => crate::ContainerKindV1::Init,
        "SIDECAR" => crate::ContainerKindV1::Sidecar,
        "APPLICATION" => crate::ContainerKindV1::Application,
        "EPHEMERAL" => crate::ContainerKindV1::Ephemeral,
        _ => {
            return Err(Status::invalid_argument(
                "workload target has an unsupported container kind",
            ));
        }
    };
    let canonical_uuid = |value: &str| {
        uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
    };
    let bounded_identity = |value: &str| !value.is_empty() && value.len() <= 512;
    if !is_sha256_hex(&target.workload_binding_generation_digest)
        || !bounded_identity(&target.execution_set_id)
        || !canonical_uuid(&target.cluster_uid)
        || !canonical_uuid(&target.namespace_uid)
        || !canonical_uuid(&target.controller_uid)
        || !canonical_uuid(&target.service_account_uid)
        || !canonical_uuid(&target.pod_uid)
        || !bounded_identity(&target.container_id)
        || !bounded_identity(&target.container_name)
        || !bounded_identity(&target.image_digest)
        || target.pod_labels.len() > 256
        || target
            .pod_labels
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 253 || value.len() > 4_096)
    {
        return Err(Status::invalid_argument(
            "workload target identities or bounds are invalid",
        ));
    }
    Ok(crate::WorkloadTargetFactV1 {
        node_id: node_id.to_owned(),
        workload_binding_generation_digest: target.workload_binding_generation_digest.clone(),
        execution_set_id: target.execution_set_id.clone(),
        cluster_uid: target.cluster_uid.clone(),
        namespace_uid: target.namespace_uid.clone(),
        controller_uid: target.controller_uid.clone(),
        service_account_uid: target.service_account_uid.clone(),
        pod_uid: target.pod_uid.clone(),
        container_id: target.container_id.clone(),
        container_name: target.container_name.clone(),
        container_kind,
        image_digest: target.image_digest.clone(),
        pod_labels: target
            .pod_labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    })
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
                tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
            }],
            TrustGenerationV1 {
                generation: 7,
                bundle_digest: "b".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
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
            workload_targets: Vec::new(),
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
