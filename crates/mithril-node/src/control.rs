use std::{collections::BTreeSet, fs, time::Duration};

use mithril_control::{
    node_administrative_arm_client::NodeAdministrativeArmClient,
    node_administrative_resolution_client::NodeAdministrativeResolutionClient,
    node_coverage_client::NodeCoverageClient, node_evidence_client::NodeEvidenceClient,
    node_policy_client::NodePolicyClient, node_registry_client::NodeRegistryClient,
    node_trust_client::NodeTrustClient, AdministrativeExecArmResult,
    AdministrativeExecArmStreamRequest, AdministrativeExecResolution,
    AdministrativeExecResolutionStreamRequest, ArmAdministrativeExec, CoverageAck,
    CoverageCounters, CoverageInterval, CoverageReport, CoverageReportRequest, EvidenceAck,
    EvidenceBatchRequest, NodeReadinessReport, NodeReadinessRequest, NodeRegistration,
    NodeRegistrationRequest, NodeSessionContext, PolicyAcknowledgementAccepted,
    PolicyAcknowledgementRequest, PolicyActivationAcknowledgement, PolicyChunkRequest,
    PolicyInventory, PolicyInventoryRequest, ResolveAdministrativeExec, TrustGenerationAck,
    TrustGenerationAckRequest, MAX_EVIDENCE_GRPC_MESSAGE_BYTES, MAX_POLICY_GRPC_MESSAGE_BYTES,
};
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
    Request, Streaming,
};
use uuid::Uuid;

use crate::error::{ControlProtocolSnafu, ControlRpcSnafu, ControlTransportSnafu, IoSnafu};
use crate::{NodeControlConfig, Result, TrustCache};

const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct NodeControlConnector {
    config: NodeControlConfig,
    node_id: String,
    node_boot_id: [u8; 16],
}

pub struct ControlConnection {
    identity: NodeSessionContext,
    resolution_output: mpsc::Sender<AdministrativeExecResolutionStreamRequest>,
    resolution_input: Streaming<ResolveAdministrativeExec>,
    arm_output: mpsc::Sender<AdministrativeExecArmStreamRequest>,
    arm_input: Streaming<ArmAdministrativeExec>,
    evidence: NodeEvidenceClient<Channel>,
    coverage: NodeCoverageClient<Channel>,
    policy: NodePolicyClient<Channel>,
    queued: std::collections::VecDeque<NodeControlMessage>,
    resolution_closed: bool,
    arm_closed: bool,
}

pub enum AdministrativeControlRequest {
    Resolve(ResolveAdministrativeExec),
    Arm(ArmAdministrativeExec),
}

pub enum NodeControlMessage {
    Administrative(AdministrativeControlRequest),
    EvidenceAck(EvidenceAck),
    CoverageAck(CoverageAck),
}

impl NodeControlConnector {
    #[must_use]
    pub fn new(config: NodeControlConfig, node_id: String, node_boot_id: [u8; 16]) -> Self {
        Self {
            config,
            node_id,
            node_boot_id,
        }
    }

    pub async fn connect(
        &self,
        registration: NodeRegistration,
        admission_ready: bool,
        trust_cache: &mut TrustCache,
    ) -> Result<ControlConnection> {
        let kernel_ready = registration.kernel_ready;
        let channel = self.channel().await?;
        let identity = NodeSessionContext {
            node_id: self.node_id.clone(),
            node_boot_id: self.node_boot_id.to_vec(),
            connection_nonce: Uuid::new_v4().as_bytes().to_vec(),
        };

        NodeRegistryClient::new(channel.clone())
            .register(Request::new(NodeRegistrationRequest {
                session: Some(identity.clone()),
                registration: Some(registration),
            }))
            .await
            .context(ControlRpcSnafu)?;

        let mut trust_stream = NodeTrustClient::new(channel.clone())
            .watch(Request::new(identity.clone()))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();
        let trust = trust_stream
            .message()
            .await
            .context(ControlRpcSnafu)?
            .ok_or_else(|| {
                ControlProtocolSnafu {
                    reason: String::from("Control did not deliver a trust generation"),
                }
                .build()
            })?;
        trust_cache.install_with_policy(
            trust.generation,
            trust.bundle_digest.clone(),
            trust.policy_issuer_sequence_epoch,
            &trust.policy_signers,
            &identity.connection_nonce,
        )?;
        NodeTrustClient::new(channel.clone())
            .acknowledge(Request::new(TrustGenerationAckRequest {
                session: Some(identity.clone()),
                acknowledgement: Some(TrustGenerationAck {
                    generation: trust.generation,
                    bundle_digest: trust.bundle_digest,
                }),
            }))
            .await
            .context(ControlRpcSnafu)?;
        NodeRegistryClient::new(channel.clone())
            .report_readiness(Request::new(NodeReadinessRequest {
                session: Some(identity.clone()),
                report: Some(NodeReadinessReport {
                    kernel_ready,
                    control_ready: true,
                    admission_ready,
                }),
            }))
            .await
            .context(ControlRpcSnafu)?;

        let (resolution_output, resolution_receiver) = mpsc::channel(8);
        resolution_output
            .send(AdministrativeExecResolutionStreamRequest {
                session: Some(identity.clone()),
                result: None,
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("resolution stream closed before registration"),
                }
                .build()
            })?;
        let resolution_input = NodeAdministrativeResolutionClient::new(channel.clone())
            .open(ReceiverStream::new(resolution_receiver))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();

        let (arm_output, arm_receiver) = mpsc::channel(8);
        arm_output
            .send(AdministrativeExecArmStreamRequest {
                session: Some(identity.clone()),
                result: None,
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("administrative arm stream closed before registration"),
                }
                .build()
            })?;
        let arm_input = NodeAdministrativeArmClient::new(channel.clone())
            .open(ReceiverStream::new(arm_receiver))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();

        Ok(ControlConnection {
            identity,
            resolution_output,
            resolution_input,
            arm_output,
            arm_input,
            evidence: NodeEvidenceClient::new(channel.clone())
                .max_decoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES),
            coverage: NodeCoverageClient::new(channel.clone())
                .max_decoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES),
            policy: NodePolicyClient::new(channel)
                .max_decoding_message_size(MAX_POLICY_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_POLICY_GRPC_MESSAGE_BYTES),
            queued: std::collections::VecDeque::new(),
            resolution_closed: false,
            arm_closed: false,
        })
    }

    async fn channel(&self) -> Result<Channel> {
        let ca = read(&self.config.ca_path)?;
        let certificate = read(&self.config.certificate_path)?;
        let private_key = read(&self.config.private_key_path)?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(certificate, private_key))
            .domain_name(self.config.server_name.clone());
        Endpoint::from_shared(self.config.endpoint.clone())
            .context(ControlTransportSnafu)?
            .tls_config(tls)
            .context(ControlTransportSnafu)?
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .http2_keep_alive_interval(Duration::from_secs(15))
            .keep_alive_while_idle(true)
            .connect_timeout(CONTROL_CONNECT_TIMEOUT)
            .connect()
            .await
            .context(ControlTransportSnafu)
    }
}

impl ControlConnection {
    pub async fn policy_inventory(
        &mut self,
        active_candidate_content_id: Option<&str>,
        durable_bundle_digests: Vec<String>,
    ) -> Result<PolicyInventory> {
        self.policy
            .inventory(Request::new(PolicyInventoryRequest {
                session: Some(self.identity.clone()),
                active_candidate_content_id: active_candidate_content_id
                    .unwrap_or_default()
                    .to_owned(),
                durable_bundle_digests,
            }))
            .await
            .context(ControlRpcSnafu)
            .map(tonic::Response::into_inner)
    }

    pub async fn fetch_policy_chunk(
        &mut self,
        candidate_content_id: String,
        bundle_digest: String,
        chunk_index: u32,
    ) -> Result<mithril_control::PolicyChunk> {
        self.policy
            .fetch(Request::new(PolicyChunkRequest {
                session: Some(self.identity.clone()),
                candidate_content_id,
                bundle_digest,
                chunk_index,
            }))
            .await
            .context(ControlRpcSnafu)
            .map(tonic::Response::into_inner)
    }

    pub async fn acknowledge_policy(
        &mut self,
        acknowledgement: PolicyActivationAcknowledgement,
    ) -> Result<PolicyAcknowledgementAccepted> {
        self.policy
            .acknowledge(Request::new(PolicyAcknowledgementRequest {
                session: Some(self.identity.clone()),
                acknowledgement: Some(acknowledgement),
            }))
            .await
            .context(ControlRpcSnafu)
            .map(tonic::Response::into_inner)
    }

    pub async fn next_message(&mut self) -> Result<NodeControlMessage> {
        if let Some(message) = self.queued.pop_front() {
            return Ok(message);
        }
        loop {
            if self.resolution_closed && self.arm_closed {
                return ControlProtocolSnafu {
                    reason: String::from("Control closed all administrative streams"),
                }
                .fail();
            }
            tokio::select! {
                message = self.resolution_input.message(), if !self.resolution_closed => {
                    match message.context(ControlRpcSnafu)? {
                        Some(request) => return Ok(NodeControlMessage::Administrative(
                            AdministrativeControlRequest::Resolve(request),
                        )),
                        None => self.resolution_closed = true,
                    }
                }
                message = self.arm_input.message(), if !self.arm_closed => {
                    match message.context(ControlRpcSnafu)? {
                        Some(request) => return Ok(NodeControlMessage::Administrative(
                            AdministrativeControlRequest::Arm(request),
                        )),
                        None => self.arm_closed = true,
                    }
                }
            }
        }
    }

    pub async fn next_administrative_request(&mut self) -> Result<AdministrativeControlRequest> {
        match self.next_message().await? {
            NodeControlMessage::Administrative(request) => Ok(request),
            NodeControlMessage::EvidenceAck(_) => ControlProtocolSnafu {
                reason: String::from(
                    "Control returned evidence acknowledgement to an administrative owner",
                ),
            }
            .fail(),
            NodeControlMessage::CoverageAck(_) => ControlProtocolSnafu {
                reason: String::from(
                    "Control returned coverage acknowledgement to an administrative owner",
                ),
            }
            .fail(),
        }
    }

    pub async fn send_evidence_batch(&mut self, batch: crate::EvidenceBatchV1) -> Result<()> {
        let response = self
            .evidence
            .upload(Request::new(EvidenceBatchRequest {
                session: Some(self.identity.clone()),
                batch: Some(batch.into()),
            }))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();
        self.queued
            .push_back(NodeControlMessage::EvidenceAck(response));
        Ok(())
    }

    pub async fn send_coverage_report(
        &mut self,
        snapshot: crate::CoverageSnapshotV1,
    ) -> Result<CoverageAck> {
        let current: BTreeSet<_> = snapshot
            .current_intervals()
            .into_iter()
            .map(|interval| interval.interval_id)
            .collect();
        let intervals = snapshot
            .all_intervals()
            .into_iter()
            .map(|interval| {
                let is_current = current.contains(&interval.interval_id);
                CoverageInterval {
                    interval_id: interval.interval_id.to_be_bytes().to_vec(),
                    source_id: interval.source_id.to_be_bytes().to_vec(),
                    source_epoch: interval.source_epoch,
                    cpu_id: interval.cpu_id,
                    revision: interval.revision,
                    state: interval.state.as_str().to_owned(),
                    first_sequence: interval.first_sequence,
                    last_sequence: interval.last_sequence,
                    opening_counters: Some(coverage_counters(interval.opening_counters)),
                    closing_counters: interval.closing_counters.map(coverage_counters),
                    gap_reasons: interval
                        .gap_reasons
                        .into_iter()
                        .map(|reason| reason.as_str().to_owned())
                        .collect(),
                    current: is_current,
                }
            })
            .collect();
        let mut report = CoverageReport {
            source_epoch: snapshot.source_epoch,
            revision: snapshot.revision,
            intervals,
            negative_claim_eligible: snapshot.supports_negative_claim(),
            report_sha256: Vec::new(),
        };
        report.report_sha256 = Sha256::digest(report.encode_to_vec()).to_vec();
        let expected = CoverageAck {
            source_epoch: report.source_epoch,
            revision: report.revision,
            report_sha256: report.report_sha256.clone(),
        };
        let response = self
            .coverage
            .report(Request::new(CoverageReportRequest {
                session: Some(self.identity.clone()),
                report: Some(report),
            }))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();
        self.queued
            .push_back(NodeControlMessage::CoverageAck(response));
        Ok(expected)
    }

    pub async fn send_resolution(&mut self, response: AdministrativeExecResolution) -> Result<()> {
        self.resolution_output
            .send(AdministrativeExecResolutionStreamRequest {
                session: Some(self.identity.clone()),
                result: Some(response),
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("Control closed the administrative resolution stream"),
                }
                .build()
            })
    }

    pub async fn send_arm_result(&mut self, response: AdministrativeExecArmResult) -> Result<()> {
        self.arm_output
            .send(AdministrativeExecArmStreamRequest {
                session: Some(self.identity.clone()),
                result: Some(response),
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("Control closed the administrative arm stream"),
                }
                .build()
            })
    }

    pub async fn wait_for_disconnect(&mut self) -> Result<()> {
        self.next_administrative_request()
            .await
            .map(|_| ())
            .and_then(|()| {
                ControlProtocolSnafu {
                    reason: String::from(
                        "Control sent an administrative request to a node without an owner",
                    ),
                }
                .fail()
            })
    }
}

fn coverage_counters(counters: crate::CoverageCountersV1) -> CoverageCounters {
    CoverageCounters {
        attempted: counters.attempted,
        suppressed: counters.suppressed,
        requested: counters.requested,
        emitted: counters.emitted,
        lost: counters.lost,
        classifier_miss_count: counters.classifier_miss_count,
        unresolved: counters.unresolved,
        next_sequence: counters.next_sequence,
    }
}

impl AdministrativeControlRequest {
    #[must_use]
    pub fn request_id(&self) -> &[u8] {
        match self {
            Self::Resolve(request) => &request.request_id,
            Self::Arm(request) => &request.request_id,
        }
    }
}

fn read(path: &std::path::Path) -> Result<Vec<u8>> {
    fs::read(path).context(IoSnafu { path })
}
