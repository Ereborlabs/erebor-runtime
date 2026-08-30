#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, BTreeSet},
    pin::Pin,
    sync::{Arc, Mutex},
};

use erebor_telemetry::{debug, error, info, trace, warn};
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
    EvidenceBatchRequest, EvidenceStreamRequest, ExceptionAcknowledgementRequest,
    ExceptionInventory, ExceptionInventoryRequest, NodeReadinessRequest, NodeRegistrationRequest,
    NodeSessionContext, PolicyAcknowledgementAccepted, PolicyAcknowledgementRequest, PolicyChunk,
    PolicyChunkRequest, PolicyInventory, PolicyInventoryRequest, RegistrationAccepted,
    ResolveAdministrativeExec, TrustGeneration, TrustGenerationAckRequest, IDENTITY_BYTES,
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

impl TrustGenerationV1 {
    #[must_use]
    pub fn computed_bundle_digest(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"MITHRIL-CONTROL-TRUST-BUNDLE-V1\0");
        digest.update(self.generation.to_be_bytes());
        digest.update(self.policy_issuer_sequence_epoch.to_be_bytes());
        for signer in &self.policy_signers {
            digest.update(
                u64::try_from(signer.signing_key_id.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            digest.update(signer.signing_key_id.as_bytes());
            digest.update(signer.ed25519_public_key_hex.as_bytes());
            digest.update([u8::from(signer.revoked)]);
        }
        format!("{:x}", digest.finalize())
    }

    #[must_use]
    pub fn with_computed_bundle_digest(mut self) -> Self {
        self.bundle_digest = self.computed_bundle_digest();
        self
    }
}

#[derive(Default)]
struct ControlState {
    // Sessions and stream senders are connection state. Durable policy and evidence live in store.
    registrations: BTreeSet<StreamIdentity>,
    sessions: BTreeMap<String, NodeSession>,
    pending: BTreeMap<Vec<u8>, PendingAdministrativeResponse>,
    kubernetes_workload_targets: BTreeMap<String, crate::WorkloadTargetFactV1>,
    kubernetes_workload_inventory_complete: bool,
}

struct NodeSession {
    // The connection nonce replaces streams but does not define a physical enforcement epoch.
    identity: StreamIdentity,
    kubernetes_node_name: Option<String>,
    kubernetes_node_uid: Option<String>,
    resolution_output: Option<mpsc::Sender<Result<ResolveAdministrativeExec, Status>>>,
    arm_output: Option<mpsc::Sender<Result<ArmAdministrativeExec, Status>>>,
    admission_ready: bool,
    label_epoch: u64,
    last_seen: std::time::Instant,
    workload_targets: Vec<crate::WorkloadTargetFactV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesNodeSessionV1 {
    pub node_id: String,
    pub kubernetes_node_name: String,
    pub kubernetes_node_uid: String,
    pub node_boot_id: Vec<u8>,
    pub label_epoch: u64,
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
/// Terminates authenticated node RPCs and delegates durable changes to domain owners.
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
            evidence: Some(crate::EvidenceIntakeOwner::from_store(store.clone())),
            policy_store: Some(store),
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
        // Combine node-reported static facts with the complete Kubernetes inventory projection.
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .sessions
                    .values()
                    .flat_map(|session| session.workload_targets.iter().cloned())
                    .chain(state.kubernetes_workload_targets.values().cloned())
                    .collect()
            },
        )
    }

    #[must_use]
    pub fn kubernetes_workload_inventory(&self) -> Vec<crate::WorkloadTargetFactV1> {
        // CRD reconciliation accepts only scheduler facts that the API inventory owner projected.
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .kubernetes_workload_targets
                    .values()
                    .cloned()
                    .collect()
            },
        )
    }

    pub(crate) fn complete_kubernetes_workload_inventory(
        &self,
    ) -> Option<Vec<crate::WorkloadTargetFactV1>> {
        self.state.lock().ok().and_then(|state| {
            state.kubernetes_workload_inventory_complete.then(|| {
                state
                    .kubernetes_workload_targets
                    .values()
                    .cloned()
                    .collect()
            })
        })
    }

    pub fn replace_kubernetes_workload_inventory(
        &self,
        targets: Vec<crate::WorkloadTargetFactV1>,
    ) -> Result<bool, Status> {
        if targets.len() > 65_536 {
            return Err(Status::resource_exhausted(
                "Kubernetes workload inventory exceeds 65,536 targets",
            ));
        }
        let target_count = targets.len();
        if targets.iter().any(|target| {
            target.kubernetes.is_none()
                || crate::workload_target_fact_digest(target).ok().as_deref()
                    != Some(&target.workload_binding_generation_digest)
        }) {
            return Err(Status::invalid_argument(
                "Kubernetes workload inventory contains incomplete or altered scheduler facts",
            ));
        }
        // Key by the complete fact digest so replacement removes targets absent from the snapshot.
        let targets = targets
            .into_iter()
            .map(|target| (target.workload_binding_generation_digest.clone(), target))
            .collect::<BTreeMap<_, _>>();
        if targets.len() != target_count {
            return Err(Status::invalid_argument(
                "Kubernetes workload inventory contains duplicate scheduler facts",
            ));
        }
        let mut state = self.lock_state()?;
        let changed = !state.kubernetes_workload_inventory_complete
            || state.kubernetes_workload_targets != targets;
        state.kubernetes_workload_inventory_complete = true;
        if changed {
            state.kubernetes_workload_targets = targets;
        }
        Ok(changed)
    }

    #[must_use]
    pub fn ready_kubernetes_node_sessions(
        &self,
        maximum_age: std::time::Duration,
    ) -> Vec<KubernetesNodeSessionV1> {
        let now = std::time::Instant::now();
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .sessions
                    .values()
                    // Readiness expires even when a dead connection has not been removed yet.
                    .filter(|session| {
                        session.admission_ready
                            && now.saturating_duration_since(session.last_seen) <= maximum_age
                    })
                    .filter_map(|session| {
                        Some(KubernetesNodeSessionV1 {
                            node_id: session.identity.node_id.clone(),
                            kubernetes_node_name: session.kubernetes_node_name.clone()?,
                            kubernetes_node_uid: session.kubernetes_node_uid.clone()?,
                            node_boot_id: session.identity.node_boot_id.clone(),
                            label_epoch: session.label_epoch,
                        })
                    })
                    .collect()
            },
        )
    }

    pub fn bind_kubernetes_node_session(
        &self,
        kubernetes_node_name: &str,
        kubernetes_node_uid: &str,
    ) -> Result<(), Status> {
        let mut state = self.lock_state()?;
        let session = state
            .sessions
            .values_mut()
            .find(|session| session.kubernetes_node_name.as_deref() == Some(kubernetes_node_name))
            .ok_or_else(|| Status::unavailable("Kubernetes Node has no registered session"))?;
        if let Some(store) = &self.policy_store {
            store
                .bind_kubernetes_node_session(
                    &session.identity.node_id,
                    &session.identity.node_boot_id,
                    session.label_epoch,
                    kubernetes_node_name,
                    kubernetes_node_uid,
                )
                .map_err(invalid_policy_status)?;
        }
        // A Node UID is scheduling provenance, not a new physical enforcement epoch.
        // Projection still requires this exact UID before the scheduler can use the Node.
        session.kubernetes_node_uid = Some(kubernetes_node_uid.to_owned());
        Ok(())
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
            queue_healthy: policy.reconcile_in_flight <= policy.reconcile_queue_limit,
            reconcile_in_flight: policy.reconcile_in_flight,
            reconcile_queue_limit: policy.reconcile_queue_limit,
            storage_healthy: true,
            control_commit_index: store.commit_index,
            watch_healthy: policy.connected_watches == policy.configured_watches,
            configured_watches: policy.configured_watches,
            connected_watches: policy.connected_watches,
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
            exception_candidates: store.exception_candidates,
            unsettled_exception_candidates: store.unsettled_exception_candidates,
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
        // The certificate digest, not a request field, selects the enrolled node identity.
        let digest = request
            .peer_certs()
            .and_then(|certificates| certificates.first().cloned())
            .map(|certificate| format!("{:x}", Sha256::digest(certificate.as_ref())))
            .ok_or_else(|| {
                warn!(
                    "rejected a node request without an mTLS certificate",
                    grpc_code = %tonic::Code::Unauthenticated
                );
                Status::unauthenticated("mTLS client certificate is required")
            })?;
        let mut matching = self
            .allowed_nodes
            .iter()
            .filter(|(_node_id, expected)| expected.certificate_sha256 == digest)
            .map(|(node_id, _expected)| node_id.clone());
        let node_id = matching.next().ok_or_else(|| {
            warn!(
                "rejected a request from an unenrolled node certificate",
                grpc_code = %tonic::Code::PermissionDenied
            );
            Status::permission_denied("node certificate is not enrolled")
        })?;
        if matching.next().is_some() {
            error!("one node certificate is enrolled for multiple node identities");
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
        let node_boot_id: [u8; 16] = context
            .node_boot_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("node boot identity is not Id128"))?;
        Ok(crate::AuthenticatedEvidenceNodeV1 {
            tenant_id: self.evidence_tenant(node_id)?,
            node_id: node_id.to_owned(),
            node_boot_id,
            label_epoch: self
                .session_label_epoch(&StreamIdentity::new(node_id.to_owned(), context)?)?,
        })
    }

    fn evidence_tenant(&self, node_id: &str) -> Result<[u8; 16], Status> {
        let enrolled = self.allowed_nodes.get(node_id).ok_or_else(|| {
            Status::permission_denied("node identity is not enrolled for evidence")
        })?;
        uuid::Uuid::parse_str(&enrolled.tenant_id)
            .map(|tenant| *tenant.as_bytes())
            .map_err(|_| Status::failed_precondition("node tenant enrollment is invalid"))
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
        // Policy and evidence RPCs require trust acknowledgement from this boot and label epoch.
        self.trust
            .require_session_acknowledged(
                node_id,
                node_boot_id,
                self.session_label_epoch(&identity)?,
            )
            .map_err(invalid_policy_status)
    }

    fn require_current_evidence_trust(
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
            .require_evidence_session_acknowledged(
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
        let proof_digest = crate::startup_absence_proof_digest(
            &node_id,
            &context.node_boot_id,
            registration.label_epoch,
            registration.policy_authority_absent,
            registration.exception_authority_absent,
        );
        if registration.startup_absence_proof_digest != proof_digest {
            return Err(Status::invalid_argument(
                "node registration has an invalid startup absence proof",
            ));
        }
        let workload_targets = registration
            .workload_targets
            .iter()
            .map(|target| registered_workload_target(&node_id, target))
            .collect::<Result<Vec<_>, _>>()?;
        let kubernetes_node_name = (!registration.kubernetes_node_name.is_empty())
            .then(|| registration.kubernetes_node_name.clone());
        let mut state = self.lock_state()?;
        if kubernetes_node_name.as_ref().is_some_and(|name| {
            state.sessions.values().any(|session| {
                session.identity.node_id != node_id
                    && session.kubernetes_node_name.as_ref() == Some(name)
            })
        }) {
            return Err(Status::already_exists(
                "Kubernetes Node name is registered by another node identity",
            ));
        }
        if state.registrations.contains(&identity) {
            return Err(Status::already_exists("registration nonce was replayed"));
        }
        let previous_session = state.sessions.get(&node_id);
        let kubernetes_node_uid = if let Some(store) = &self.policy_store {
            store
                .register_node_physical_session(
                    &node_id,
                    &context.node_boot_id,
                    registration.label_epoch,
                    kubernetes_node_name.as_deref(),
                    &registration.startup_absence_proof_digest,
                    registration.policy_authority_absent,
                    registration.exception_authority_absent,
                    utc_now_ns()?,
                )
                .map_err(invalid_policy_status)?
                .kubernetes_node_uid
        } else {
            if let Some(previous) = previous_session {
                let reconnect = previous.identity.node_boot_id == context.node_boot_id
                    && previous.label_epoch == registration.label_epoch;
                let advance = registration.label_epoch > previous.label_epoch
                    && registration.policy_authority_absent
                    && registration.exception_authority_absent;
                if !reconnect && !advance {
                    return Err(Status::failed_precondition(
                        "node physical session did not advance its label epoch",
                    ));
                }
            } else if !registration.policy_authority_absent
                || !registration.exception_authority_absent
            {
                return Err(Status::failed_precondition(
                    "initial node registration requires startup authority absence",
                ));
            }
            previous_session.and_then(|session| {
                (session.identity.node_boot_id == context.node_boot_id
                    && session.label_epoch == registration.label_epoch)
                    .then(|| session.kubernetes_node_uid.clone())
                    .flatten()
            })
        };
        state.registrations.insert(identity.clone());
        // A valid reconnect replaces prior streams and pending requests for this node identity.
        state
            .pending
            .retain(|_, pending| pending.node_id() != node_id);
        state.sessions.insert(
            node_id.clone(),
            NodeSession {
                identity,
                kubernetes_node_name,
                kubernetes_node_uid,
                resolution_output: None,
                arm_output: None,
                admission_ready: false,
                label_epoch: registration.label_epoch,
                last_seen: std::time::Instant::now(),
                workload_targets,
            },
        );
        info!(
            "authenticated a Mithril node session",
            node_id = %node_id,
            node_boot_id = %hex::encode(&context.node_boot_id),
            label_epoch = %registration.label_epoch
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
        let mut state = self.lock_state()?;
        let active = state
            .sessions
            .get_mut(node_id)
            .ok_or_else(|| Status::unauthenticated("node session is not registered"))?;
        if active.identity != identity {
            return Err(Status::unauthenticated(
                "node boot identity or connection nonce is stale",
            ));
        }
        active.last_seen = std::time::Instant::now();
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

    fn set_session_readiness(
        &self,
        node_id: &str,
        context: &NodeSessionContext,
        report: &crate::NodeReadinessReport,
    ) -> Result<(), Status> {
        let identity = self.require_session(node_id, context)?;
        if !report.kernel_ready || !report.control_ready {
            return Err(Status::failed_precondition(
                "node readiness requires kernel and control readiness",
            ));
        }
        // Trust must be current before Control exposes the node to the Kubernetes scheduler.
        self.require_current_trust(node_id, context)?;
        let mut state = self.lock_state()?;
        let session = state
            .sessions
            .get_mut(node_id)
            .ok_or_else(|| Status::unauthenticated("node session is not registered"))?;
        if session.identity != identity {
            return Err(Status::unauthenticated("node session changed"));
        }
        let changed = session.admission_ready != report.admission_ready;
        session.admission_ready = report.admission_ready;
        if changed {
            info!(
                "changed Mithril node admission readiness",
                node_id = %node_id,
                node_boot_id = %hex::encode(&context.node_boot_id),
                admission_ready = %report.admission_ready
            );
        }
        Ok(())
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
        self.set_session_readiness(&node_id, context, &report)?;
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
    type OpenStream = Pin<Box<dyn Stream<Item = Result<EvidenceAck, Status>> + Send>>;

    async fn upload(
        &self,
        request: Request<EvidenceBatchRequest>,
    ) -> Result<Response<EvidenceAck>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let control = self.clone();
        // Durable evidence intake performs fsync. Keep it off the RPC executor so policy and
        // readiness requests can enter their owners while evidence upload is busy.
        let acknowledgement =
            tokio::task::spawn_blocking(move || control.receive_evidence_batch(&node_id, request))
                .await
                .map_err(|error| {
                    Status::internal(format!("evidence intake worker failed: {error}"))
                })??;
        Ok(Response::new(acknowledgement))
    }

    async fn open(
        &self,
        request: Request<Streaming<EvidenceStreamRequest>>,
    ) -> Result<Response<Self::OpenStream>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let mut input = request.into_inner();
        let (output, receiver) = mpsc::channel(8);
        let (pending_output, mut pending_input) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(message) = input.next().await {
                if pending_output.send(message).await.is_err() {
                    return;
                }
            }
        });
        let control = self.clone();
        tokio::spawn(async move {
            let mut group = Vec::new();
            let mut framed_bytes = 0_usize;
            loop {
                let message = pending_input.recv().await;
                let closing = message.is_none();
                if let Some(message) = message {
                    let request = match message {
                        Ok(request) => request,
                        Err(status) => {
                            let _result = output.send(Err(status)).await;
                            return;
                        }
                    };
                    let Some(batch) = request.batch.as_ref() else {
                        let _result = output
                            .send(Err(Status::invalid_argument("evidence batch is required")))
                            .await;
                        return;
                    };
                    framed_bytes = framed_bytes.saturating_add(batch.framed_records.len());
                    if framed_bytes > crate::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES {
                        let _result = output
                            .send(Err(Status::invalid_argument(
                                "an evidence commit group exceeds one segment",
                            )))
                            .await;
                        return;
                    }
                    let commit_group_tail = batch.commit_group_tail;
                    group.push(request);
                    if !commit_group_tail {
                        continue;
                    }
                } else if group.is_empty() {
                    return;
                }
                let ready = std::mem::take(&mut group);
                framed_bytes = 0;
                let control = control.clone();
                let node_id = node_id.clone();
                let result = match tokio::task::spawn_blocking(move || {
                    control.receive_evidence_stream_group(&node_id, ready)
                })
                .await
                {
                    Ok(result) => result,
                    Err(error) => Err(Status::internal(format!(
                        "evidence intake worker failed: {error}"
                    ))),
                };
                match result {
                    Ok(acknowledgement) => {
                        if output.send(Ok(acknowledgement)).await.is_err() {
                            return;
                        }
                    }
                    Err(status) => {
                        let _result = output.send(Err(status)).await;
                        return;
                    }
                }
                if closing {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

impl ControlPlane {
    fn receive_evidence_batch(
        &self,
        node_id: &str,
        request: EvidenceBatchRequest,
    ) -> Result<EvidenceAck, Status> {
        self.receive_evidence_stream_group(
            node_id,
            vec![EvidenceStreamRequest {
                session: request.session,
                batch: request.batch,
            }],
        )
    }

    fn receive_evidence_stream_group(
        &self,
        node_id: &str,
        requests: Vec<EvidenceStreamRequest>,
    ) -> Result<EvidenceAck, Status> {
        let evidence = self.evidence.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable evidence intake owner")
        })?;
        let mut batches = Vec::with_capacity(requests.len());
        let mut first_cursor = None;
        let mut framed_bytes = 0_usize;
        for request in requests {
            let context = request
                .session
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
            // A degraded node must upload retained evidence before it can recover readiness.
            self.require_session(node_id, context)?;
            self.require_current_evidence_trust(node_id, context)?;
            let batch = request
                .batch
                .ok_or_else(|| Status::invalid_argument("evidence batch is required"))?;
            let authenticated = match evidence.authenticate_retained_batch(
                self.evidence_tenant(node_id)?,
                node_id,
                &batch,
            ) {
                Ok(authenticated) => authenticated,
                Err(status) => {
                    warn!(
                        "rejected a Mithril evidence batch",
                        node_id = %node_id,
                        node_boot_id = %hex::encode(&context.node_boot_id),
                        grpc_code = %status.code()
                    );
                    return Err(status);
                }
            };
            first_cursor.get_or_insert(batch.first_cursor);
            framed_bytes = framed_bytes.saturating_add(batch.framed_records.len());
            batches.push((authenticated, batch));
        }
        let batch_count = batches.len();
        let acknowledgement = evidence.receive_group(batches)?;
        debug!(
            "accepted a Mithril evidence commit group",
            node_id = %node_id,
            first_cursor = %first_cursor.unwrap_or_default(),
            contiguous_cursor = %acknowledgement.contiguous_cursor,
            batch_count = %batch_count,
            framed_bytes = %framed_bytes
        );
        Ok(acknowledgement)
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
        let control = self.clone();
        let acknowledgement =
            tokio::task::spawn_blocking(move || control.receive_coverage_report(&node_id, request))
                .await
                .map_err(|error| {
                    Status::internal(format!("coverage intake worker failed: {error}"))
                })??;
        Ok(Response::new(acknowledgement))
    }
}

impl ControlPlane {
    fn receive_coverage_report(
        &self,
        node_id: &str,
        request: CoverageReportRequest,
    ) -> Result<CoverageAck, Status> {
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        self.require_session(node_id, context)?;
        let authenticated = self.authenticated_evidence_node(node_id, context)?;
        let report = request
            .report
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("coverage report is required"))?;
        let evidence = self.evidence.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable evidence intake owner")
        })?;
        let acknowledgement = evidence.receive_coverage(&authenticated, report)?;
        debug!(
            "accepted a Mithril coverage report",
            node_id = %node_id,
            node_boot_id = %hex::encode(&context.node_boot_id),
            source_epoch = %report.source_epoch,
            revision = %report.revision
        );
        Ok(acknowledgement)
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
        let identity = self.require_ready_session(&node_id, context)?;
        self.require_current_trust(&node_id, context)?;
        let label_epoch = self.session_label_epoch(&identity)?;
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
        // Durable bundle digests identify the active candidate for each profile on this mTLS node.
        let (bundle, desired_bundle_digests) = store
            .policy_inventory_for_node_session(
                &node_id,
                &context.node_boot_id,
                label_epoch,
                &request.durable_bundle_digests,
            )
            .map_err(internal_status)?;
        let Some(bundle) = bundle else {
            return Ok(Response::new(PolicyInventory {
                desired_bundle_digests,
                desired_inventory_complete: true,
                ..PolicyInventory::default()
            }));
        };
        let chunks = bundle.chunks().map_err(internal_status)?;
        let bundle_bytes = serde_json::to_vec(&bundle)
            .map_err(|error| Status::internal(format!("policy bundle encoding failed: {error}")))?;
        debug!(
            "selected a policy candidate for a Mithril node",
            node_id = %node_id,
            candidate_id = %bundle.candidate.candidate_content_id,
            operation = %policy_operation_name(bundle.candidate.operation),
            chunk_count = %chunks.len()
        );
        Ok(Response::new(PolicyInventory {
            candidate_available: true,
            candidate_content_id: bundle.candidate.candidate_content_id,
            policy_source_revision_id: bundle.candidate.policy_source_revision_id,
            target_snapshot_digest: bundle.candidate.target_snapshot_digest,
            bundle_digest: bundle.bundle_digest,
            bundle_bytes: u64::try_from(bundle_bytes.len()).unwrap_or(u64::MAX),
            chunk_count: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
            operation: policy_operation_name(bundle.candidate.operation).to_owned(),
            desired_bundle_digests,
            desired_inventory_complete: true,
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
        let identity = self.require_ready_session(&node_id, context)?;
        self.require_current_trust(&node_id, context)?;
        let label_epoch = self.session_label_epoch(&identity)?;
        let store = self.policy_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable policy rollout store")
        })?;
        // Re-resolve every chunk request against the immutable node-specific candidate.
        let bundle = store
            .bundle_for_candidate_for_session(
                &node_id,
                &context.node_boot_id,
                label_epoch,
                &request.candidate_content_id,
            )
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
        trace!(
            "served a policy bundle chunk",
            node_id = %node_id,
            candidate_id = %request.candidate_content_id,
            chunk_index = %chunk.chunk_index,
            chunk_count = %chunk.chunk_count
        );
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
        // Bind the acknowledgement bytes to the certificate on this authenticated channel.
        let channel_receipt_digest = authenticated_channel_receipt_digest(&request)?;
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
            node_id: node_id.clone(),
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
        let result = rollout
            .acknowledge(acknowledgement)
            .map_err(invalid_policy_status)?;
        let store = self.policy_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable policy rollout store")
        })?;
        info!(
            "accepted a policy rollout transition",
            node_id = %node_id,
            candidate_id = %result.rollout_state.desired_candidate_content_id,
            rollout_state = %rollout_state_name(result.rollout_state.state)
        );
        // Return only after the acknowledgement and rollout transition share one durable commit.
        Ok(Response::new(PolicyAcknowledgementAccepted {
            control_commit_index: store.commit_index(),
            rollout_state: rollout_state_name(result.rollout_state.state).to_owned(),
            terminal_chain_closure_authorized: result.terminal_chain_closure_authorized,
        }))
    }

    async fn inventory_exceptions(
        &self,
        request: Request<ExceptionInventoryRequest>,
    ) -> Result<Response<ExceptionInventory>, Status> {
        let node_id = self.authenticated_node(&request)?;
        let request = request.into_inner();
        let context = request
            .session
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("node session context is required"))?;
        let identity = self.require_ready_session(&node_id, context)?;
        self.require_current_trust(&node_id, context)?;
        let label_epoch = self.session_label_epoch(&identity)?;
        // Inventory never accepts a node name from the payload. mTLS owns the target identity.
        if request.durable_candidate_content_ids.len() > 256
            || request
                .durable_candidate_content_ids
                .iter()
                .any(|digest| !is_sha256_hex(digest))
        {
            return Err(Status::invalid_argument(
                "exception inventory identities or bounds are invalid",
            ));
        }
        let store = self.policy_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable policy rollout store")
        })?;
        let Some(candidate) = store
            .next_exception_candidate_for_session(
                &node_id,
                &context.node_boot_id,
                label_epoch,
                &request.durable_candidate_content_ids,
            )
            .map_err(internal_status)?
        else {
            return Ok(Response::new(ExceptionInventory::default()));
        };
        // The signed target is checked again after the authenticated-node store lookup.
        if candidate.exact_target.node_id != node_id {
            return Err(Status::internal(
                "the exception store returned a candidate for another node",
            ));
        }
        let candidate_json = serde_json::to_vec(&candidate).map_err(|error| {
            Status::internal(format!("exception candidate encoding failed: {error}"))
        })?;
        if candidate_json.len() > crate::MAX_EXCEPTION_CANDIDATE_BYTES {
            return Err(Status::resource_exhausted(
                "the exception candidate exceeds the delivery bound",
            ));
        }
        debug!(
            "selected an exception candidate for a Mithril node",
            node_id = %node_id,
            candidate_id = %candidate.candidate_content_id,
            operation = %exception_operation_name(candidate.operation)
        );
        Ok(Response::new(ExceptionInventory {
            candidate_available: true,
            candidate_content_id: candidate.candidate_content_id,
            operation: exception_operation_name(candidate.operation).to_owned(),
            candidate_json,
        }))
    }

    async fn acknowledge_exception(
        &self,
        request: Request<ExceptionAcknowledgementRequest>,
    ) -> Result<Response<PolicyAcknowledgementAccepted>, Status> {
        let node_id = self.authenticated_node(&request)?;
        // The receipt binds the reported runtime state to this authenticated request.
        let channel_receipt_digest = authenticated_channel_receipt_digest(&request)?;
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
            .ok_or_else(|| Status::invalid_argument("exception acknowledgement is required"))?;
        let acknowledgement = crate::ExceptionActivationAcknowledgementV1 {
            acknowledgement_content_id: String::new(),
            tenant_id: acknowledgement.tenant_id,
            node_id: node_id.clone(),
            node_boot_id: context.node_boot_id.clone(),
            label_epoch,
            candidate_content_id: acknowledgement.candidate_content_id,
            exception_source_revision_id: acknowledgement.exception_source_revision_id,
            state: parse_exception_activation_state(&acknowledgement.state)?,
            consumed_uses: acknowledgement.consumed_uses,
            transition_version: acknowledgement.transition_version,
            observed_utc_ns: acknowledgement.observed_utc_ns,
            reason_code: nonempty(acknowledgement.reason_code),
            authenticated_channel_receipt_digest: channel_receipt_digest,
        }
        .finalize()
        .map_err(invalid_policy_status)?;
        let rollout = self
            .policy_rollout
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("Control has no policy rollout owner"))?;
        let state = rollout
            .acknowledge_exception(acknowledgement)
            .map_err(invalid_policy_status)?;
        let store = self.policy_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("Control has no durable policy rollout store")
        })?;
        info!(
            "accepted an exception rollout transition",
            node_id = %node_id,
            candidate_id = %state.candidate_content_id,
            rollout_state = %exception_rollout_state_name(state.state)
        );
        Ok(Response::new(PolicyAcknowledgementAccepted {
            control_commit_index: store.commit_index(),
            rollout_state: exception_rollout_state_name(state.state).to_owned(),
            terminal_chain_closure_authorized: false,
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

fn authenticated_channel_receipt_digest<M: prost::Message>(
    request: &Request<M>,
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

fn parse_exception_activation_state(
    value: &str,
) -> Result<crate::ExceptionActivationStateV1, Status> {
    match value {
        "ACTIVE" => Ok(crate::ExceptionActivationStateV1::Active),
        "CONSUMED" => Ok(crate::ExceptionActivationStateV1::Consumed),
        "EXPIRED" => Ok(crate::ExceptionActivationStateV1::Expired),
        "REVOKED" => Ok(crate::ExceptionActivationStateV1::Revoked),
        "REJECTED" => Ok(crate::ExceptionActivationStateV1::Rejected),
        "STALE" => Ok(crate::ExceptionActivationStateV1::Stale),
        _ => Err(Status::invalid_argument(
            "exception acknowledgement has an unsupported state",
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

const fn exception_operation_name(value: crate::ExceptionDeliveryOperationV1) -> &'static str {
    match value {
        crate::ExceptionDeliveryOperationV1::Activate => "ACTIVATE",
        crate::ExceptionDeliveryOperationV1::Revoke => "REVOKE",
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

const fn exception_rollout_state_name(
    value: crate::WorkloadProtectionExceptionStateV1,
) -> &'static str {
    match value {
        crate::WorkloadProtectionExceptionStateV1::Pending => "PENDING",
        crate::WorkloadProtectionExceptionStateV1::Active => "ACTIVE",
        crate::WorkloadProtectionExceptionStateV1::Consumed => "CONSUMED",
        crate::WorkloadProtectionExceptionStateV1::Expired => "EXPIRED",
        crate::WorkloadProtectionExceptionStateV1::Revoked => "REVOKED",
        crate::WorkloadProtectionExceptionStateV1::Failed => "FAILED",
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn utc_now_ns() -> Result<i64, Status> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Status::internal("system time is before the Unix epoch"))?
        .as_nanos();
    i64::try_from(nanos).map_err(|_| Status::internal("system time exceeds the signed range"))
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
        && is_sha256_hex(&registration.startup_absence_proof_digest)
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
        && (registration.kubernetes_node_name.is_empty()
            || crate::store::kubernetes_node_name_is_valid(&registration.kubernetes_node_name))
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
        kubernetes: None,
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
        AllowedNodeIdentity, CapabilityRecord, NodeReadinessReport, NodeRegistration,
        NodeSessionContext, RegisteredWorkloadTarget, TrustGenerationV1,
    };
    use tempfile::TempDir;
    use tonic::Request;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

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
            kubernetes_node_name: String::new(),
            startup_absence_proof_digest: crate::startup_absence_proof_digest(
                "node-a", &[1; 16], 1, true, true,
            ),
            policy_authority_absent: true,
            exception_authority_absent: true,
            capabilities: vec![CapabilityRecord {
                capability_id: "capability".to_owned(),
                state: "SUPPORTED".to_owned(),
                reason_code: "MEASURED_STATE".to_owned(),
            }],
            workload_targets: Vec::new(),
        }
    }

    fn registration_for(
        context: &NodeSessionContext,
        label_epoch: u64,
        policy_authority_absent: bool,
        exception_authority_absent: bool,
    ) -> NodeRegistration {
        let mut registration = registration();
        registration.label_epoch = label_epoch;
        registration.policy_authority_absent = policy_authority_absent;
        registration.exception_authority_absent = exception_authority_absent;
        registration.startup_absence_proof_digest = crate::startup_absence_proof_digest(
            &context.node_id,
            &context.node_boot_id,
            label_epoch,
            policy_authority_absent,
            exception_authority_absent,
        );
        registration
    }

    #[test]
    fn node_session_transitions_emit_owned_logs() -> TestResult {
        let directory = TempDir::new()?;
        let telemetry = erebor_telemetry::JsonlTelemetry::open(
            directory.path().join("control-logs"),
            16 * 1_024,
        )?;
        let control = control();
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let report = NodeReadinessReport {
            kernel_ready: true,
            control_ready: true,
            admission_ready: true,
        };

        telemetry.emit(|| -> TestResult {
            control.register("node-a".to_owned(), &context, &registration())?;
            let trust = control.trust.current()?;
            control.trust.acknowledge(
                "node-a",
                [1; 16],
                1,
                trust.generation,
                &trust.bundle_digest,
            )?;
            control.set_session_readiness("node-a", &context, &report)?;
            control.set_session_readiness("node-a", &context, &report)?;
            Ok(())
        })??;

        let records = telemetry.records_after(0, 16)?;
        let registration = records
            .iter()
            .find(|record| record.message == "authenticated a Mithril node session")
            .ok_or("the node-session transition log is absent")?;
        assert_eq!(registration.target, "mithril_control::service");
        assert_eq!(
            registration.fields.get("node_id").map(String::as_str),
            Some("node-a")
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record.message == "changed Mithril node admission readiness")
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn missing_node_certificate_emits_one_bounded_warning() -> TestResult {
        let directory = TempDir::new()?;
        let telemetry = erebor_telemetry::JsonlTelemetry::open(
            directory.path().join("control-auth-logs"),
            16 * 1_024,
        )?;
        let control = control();

        telemetry.emit(|| {
            let error = control
                .authenticated_node(&Request::new(()))
                .err()
                .map(|status| status.code());
            assert_eq!(error, Some(tonic::Code::Unauthenticated));
        })?;

        let records = telemetry.records_after(0, 16)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].level, "WARN");
        assert_eq!(
            records[0].message,
            "rejected a node request without an mTLS certificate"
        );
        assert!(!records[0].rendered_message().contains("certificate="));
        Ok(())
    }

    fn durable_control(
        directory: &TempDir,
    ) -> Result<(ControlPlane, crate::ControlStore), Box<dyn std::error::Error>> {
        let store = crate::ControlStore::open(directory.path())?;
        let control = ControlPlane::with_control_store(
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
            store.clone(),
        )?;
        Ok((control, store))
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
    fn first_durable_session_rejects_existing_unowned_authority() -> TestResult {
        let directory = TempDir::new()?;
        let (control, store) = durable_control(&directory)?;
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let registration = registration_for(&context, 1, false, true);
        let committed = store.commit_index();

        assert!(control
            .register("node-a".to_owned(), &context, &registration)
            .is_err());
        assert_eq!(store.commit_index(), committed);
        assert_eq!(control.registered_nonce_count(), 0);
        Ok(())
    }

    #[test]
    fn reconnect_preserves_the_durable_physical_session_without_an_advance() -> TestResult {
        let directory = TempDir::new()?;
        let (control, store) = durable_control(&directory)?;
        let first = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let mut registration = registration_for(&first, 1, true, true);
        registration.kubernetes_node_name = "worker-a.example".to_owned();
        control.register("node-a".to_owned(), &first, &registration)?;
        control.bind_kubernetes_node_session(
            "worker-a.example",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )?;
        let committed = store.commit_index();
        drop(control);
        drop(store);

        let reconnect = NodeSessionContext {
            connection_nonce: vec![3; 16],
            ..first
        };
        let (control, store) = durable_control(&directory)?;
        control.register("node-a".to_owned(), &reconnect, &registration)?;
        assert_eq!(store.commit_index(), committed);
        assert_eq!(
            control
                .lock_state()?
                .sessions
                .get("node-a")
                .and_then(|session| session.kubernetes_node_uid.as_deref()),
            Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        );
        Ok(())
    }

    #[test]
    fn uid_only_rebind_preserves_the_ready_physical_session() -> TestResult {
        let directory = TempDir::new()?;
        let (control, store) = durable_control(&directory)?;
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let mut registration = registration_for(&context, 1, true, true);
        registration.kubernetes_node_name = "worker-a.example".to_owned();
        control.register("node-a".to_owned(), &context, &registration)?;
        control.bind_kubernetes_node_session(
            "worker-a.example",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )?;
        control
            .lock_state()?
            .sessions
            .get_mut("node-a")
            .ok_or("the test session is absent")?
            .admission_ready = true;
        let committed = store.commit_index();

        control.bind_kubernetes_node_session(
            "worker-a.example",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )?;
        let state = control.lock_state()?;
        let session = state
            .sessions
            .get("node-a")
            .ok_or("the rebound session is absent")?;
        assert_eq!(session.identity.node_boot_id, vec![1; 16]);
        assert_eq!(session.label_epoch, 1);
        assert_eq!(
            session.kubernetes_node_uid.as_deref(),
            Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        );
        assert!(session.admission_ready);
        assert_eq!(store.commit_index(), committed + 1);
        drop(state);
        let ready = control.ready_kubernetes_node_sessions(std::time::Duration::from_secs(1));
        assert_eq!(
            ready
                .first()
                .ok_or("the rebound session is not ready")?
                .kubernetes_node_uid,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        );
        drop(control);
        drop(store);

        let (replayed, replayed_store) = durable_control(&directory)?;
        let reconnect = NodeSessionContext {
            connection_nonce: vec![3; 16],
            ..context
        };
        replayed.register("node-a".to_owned(), &reconnect, &registration)?;
        assert_eq!(replayed_store.commit_index(), committed + 1);
        assert_eq!(
            replayed
                .lock_state()?
                .sessions
                .get("node-a")
                .and_then(|session| session.kubernetes_node_uid.as_deref()),
            Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        );
        Ok(())
    }

    #[test]
    fn physical_reset_requires_a_higher_label_and_exact_absence() -> TestResult {
        let directory = TempDir::new()?;
        let (control, store) = durable_control(&directory)?;
        let first = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let mut first_registration = registration_for(&first, 1, true, true);
        first_registration.kubernetes_node_name = "worker-a.example".to_owned();
        control.register("node-a".to_owned(), &first, &first_registration)?;
        let committed = store.commit_index();

        let same_label_new_boot = NodeSessionContext {
            node_boot_id: vec![2; 16],
            connection_nonce: vec![3; 16],
            ..first.clone()
        };
        let mut same_label_registration = registration_for(&same_label_new_boot, 1, true, true);
        same_label_registration.kubernetes_node_name = "worker-a.example".to_owned();
        assert!(control
            .register(
                "node-a".to_owned(),
                &same_label_new_boot,
                &same_label_registration,
            )
            .is_err());
        let missing_absence = NodeSessionContext {
            connection_nonce: vec![4; 16],
            ..same_label_new_boot.clone()
        };
        let mut missing_absence_registration = registration_for(&missing_absence, 2, false, true);
        missing_absence_registration.kubernetes_node_name = "worker-a.example".to_owned();
        assert!(control
            .register(
                "node-a".to_owned(),
                &missing_absence,
                &missing_absence_registration,
            )
            .is_err());
        assert_eq!(store.commit_index(), committed);

        let advanced = NodeSessionContext {
            connection_nonce: vec![5; 16],
            ..same_label_new_boot
        };
        let mut advanced_registration = registration_for(&advanced, 2, true, true);
        advanced_registration.kubernetes_node_name = "worker-a.example".to_owned();
        control.register("node-a".to_owned(), &advanced, &advanced_registration)?;
        assert_eq!(store.commit_index(), committed + 1);
        assert!(control.require_session("node-a", &first).is_err());
        control.bind_kubernetes_node_session(
            "worker-a.example",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )?;
        let rebound_commit = store.commit_index();
        drop(control);
        drop(store);

        let (replayed, replayed_store) = durable_control(&directory)?;
        let reconnect = NodeSessionContext {
            connection_nonce: vec![6; 16],
            ..advanced.clone()
        };
        replayed.register("node-a".to_owned(), &reconnect, &advanced_registration)?;
        assert_eq!(replayed_store.commit_index(), rebound_commit);
        assert_eq!(
            replayed
                .lock_state()?
                .sessions
                .get("node-a")
                .and_then(|session| session.kubernetes_node_uid.as_deref()),
            Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        );

        let same_boot_advance = NodeSessionContext {
            connection_nonce: vec![7; 16],
            ..advanced
        };
        let mut same_boot_registration = registration_for(&same_boot_advance, 3, true, true);
        same_boot_registration.kubernetes_node_name = "worker-a.example".to_owned();
        replayed.register(
            "node-a".to_owned(),
            &same_boot_advance,
            &same_boot_registration,
        )?;
        assert_eq!(replayed_store.commit_index(), rebound_commit + 1);
        Ok(())
    }

    #[test]
    fn kubernetes_inventory_excludes_node_reported_targets() -> Result<(), tonic::Status> {
        let control = control();
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let mut registration = registration();
        registration.workload_targets = vec![RegisteredWorkloadTarget {
            workload_binding_generation_digest: "1".repeat(64),
            execution_set_id: "40000000-0000-4000-8000-000000000001".to_owned(),
            cluster_uid: "50000000-0000-4000-8000-000000000001".to_owned(),
            namespace_uid: "60000000-0000-4000-8000-000000000001".to_owned(),
            controller_uid: "70000000-0000-4000-8000-000000000001".to_owned(),
            service_account_uid: "80000000-0000-4000-8000-000000000001".to_owned(),
            pod_uid: "90000000-0000-4000-8000-000000000001".to_owned(),
            container_id: "containerd://converter".to_owned(),
            container_name: "converter".to_owned(),
            container_kind: "APPLICATION".to_owned(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            pod_labels: std::collections::HashMap::new(),
        }];

        control.register("node-a".to_owned(), &context, &registration)?;

        assert_eq!(control.workload_inventory().len(), 1);
        assert!(control.kubernetes_workload_inventory().is_empty());
        Ok(())
    }

    #[test]
    fn kubernetes_outage_inventory_distinguishes_unknown_from_complete_empty(
    ) -> Result<(), tonic::Status> {
        let control = control();

        assert_eq!(control.complete_kubernetes_workload_inventory(), None);
        assert!(control.replace_kubernetes_workload_inventory(Vec::new())?);
        assert_eq!(
            control.complete_kubernetes_workload_inventory(),
            Some(Vec::new())
        );
        assert!(!control.replace_kubernetes_workload_inventory(Vec::new())?);
        Ok(())
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
    fn readiness_requires_current_trust_acknowledgement() -> Result<(), tonic::Status> {
        let control = control();
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        control.register("node-a".to_owned(), &context, &registration())?;
        let report = NodeReadinessReport {
            kernel_ready: true,
            control_ready: true,
            admission_ready: true,
        };

        assert!(control
            .set_session_readiness("node-a", &context, &report)
            .is_err());
        let trust = control
            .trust
            .current()
            .map_err(super::invalid_policy_status)?;
        control
            .trust
            .acknowledge(
                "node-a",
                context.node_boot_id.as_slice().try_into().map_err(|_| {
                    tonic::Status::invalid_argument("test boot identity is not Id128")
                })?,
                registration().label_epoch,
                trust.generation,
                &trust.bundle_digest,
            )
            .map_err(super::invalid_policy_status)?;
        control.set_session_readiness("node-a", &context, &report)?;

        assert!(control.require_ready_session("node-a", &context).is_ok());
        Ok(())
    }

    #[test]
    fn only_ready_named_session_is_projected_to_kubernetes() -> Result<(), tonic::Status> {
        let control = control();
        let context = NodeSessionContext {
            node_id: "node-a".to_owned(),
            node_boot_id: vec![1; 16],
            connection_nonce: vec![2; 16],
        };
        let mut registration = registration();
        registration.kubernetes_node_name = "worker-a.example".to_owned();
        control.register("node-a".to_owned(), &context, &registration)?;
        assert!(control
            .ready_kubernetes_node_sessions(std::time::Duration::from_secs(1))
            .is_empty());
        control
            .lock_state()?
            .sessions
            .get_mut("node-a")
            .ok_or_else(|| tonic::Status::internal("test session disappeared"))?
            .admission_ready = true;
        control.bind_kubernetes_node_session(
            "worker-a.example",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )?;
        let sessions = control.ready_kubernetes_node_sessions(std::time::Duration::from_secs(1));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].kubernetes_node_name, "worker-a.example");
        assert_eq!(
            sessions[0].kubernetes_node_uid,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(sessions[0].node_boot_id, vec![1; 16]);
        Ok(())
    }

    #[test]
    fn registration_rejects_invalid_kubernetes_node_name() {
        let mut registration = registration();
        registration.kubernetes_node_name = "Worker A".to_owned();
        assert!(!valid_registration(&registration));
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
