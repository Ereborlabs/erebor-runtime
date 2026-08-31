use std::{fs, future::Future, time::Duration};

use mithril_control::{
    node_administrative_arm_client::NodeAdministrativeArmClient,
    node_administrative_resolution_client::NodeAdministrativeResolutionClient,
    node_coverage_client::NodeCoverageClient, node_decommission_client::NodeDecommissionClient,
    node_evidence_client::NodeEvidenceClient, node_policy_client::NodePolicyClient,
    node_registry_client::NodeRegistryClient, node_trust_client::NodeTrustClient,
    AdministrativeExecArmResult, AdministrativeExecArmStreamRequest, AdministrativeExecResolution,
    AdministrativeExecResolutionStreamRequest, ArmAdministrativeExec, CoverageCounters,
    CoverageInterval, CoverageReport, CoverageReportRequest, EvidenceAck, EvidenceStreamRequest,
    ExceptionAcknowledgementRequest, ExceptionActivationAcknowledgement, ExceptionInventory,
    ExceptionInventoryRequest, NodeDecommissionCommand, NodeDecommissionResult,
    NodeDecommissionStreamRequest, NodeReadinessReport, NodeReadinessRequest, NodeRegistration,
    NodeRegistrationRequest, NodeSessionContext, PolicyAcknowledgementAccepted,
    PolicyAcknowledgementRequest, PolicyActivationAcknowledgement, PolicyChunkRequest,
    PolicyInventory, PolicyInventoryRequest, ResolveAdministrativeExec, TrustGenerationAck,
    TrustGenerationAckRequest, MAX_EVIDENCE_GRPC_MESSAGE_BYTES, MAX_POLICY_GRPC_MESSAGE_BYTES,
};
use snafu::ResultExt as _;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
    Request, Streaming,
};
use uuid::Uuid;

use crate::error::{ControlProtocolSnafu, ControlRpcSnafu, ControlTransportSnafu, IoSnafu};
use crate::{NodeControlConfig, Result, TrustCache};

const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// A policy or readiness RPC can wait for the current durable evidence fsync before its priority
// store operation runs. Keep that wait bounded without forcing retries during one durable flush.
const CONTROL_UNARY_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_READINESS_RENEWAL_INTERVAL: Duration = Duration::from_secs(1);
const EVIDENCE_PIPELINE_BATCHES: usize = 64;

#[derive(Clone)]
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
    decommission_output: mpsc::Sender<NodeDecommissionStreamRequest>,
    decommission_input: Streaming<NodeDecommissionCommand>,
    evidence_output: mpsc::Sender<EvidenceStreamRequest>,
    evidence_input: Streaming<EvidenceAck>,
    coverage: NodeCoverageClient<Channel>,
    policy: NodePolicyClient<Channel>,
    readiness_updates: mpsc::Sender<ReadinessUpdate>,
    readiness_failure: mpsc::Receiver<crate::Error>,
    readiness_renewal: tokio::task::JoinHandle<()>,
    queued: std::collections::VecDeque<NodeControlMessage>,
    resolution_closed: bool,
    arm_closed: bool,
}

#[derive(Clone, Copy)]
struct ControlReadinessV1 {
    kernel_ready: bool,
    admission_ready: bool,
}

struct ReadinessUpdate {
    readiness: ControlReadinessV1,
    result: oneshot::Sender<Result<()>>,
}

pub enum AdministrativeControlRequest {
    Resolve(ResolveAdministrativeExec),
    Arm(ArmAdministrativeExec),
}

pub enum NodeControlMessage {
    Administrative(AdministrativeControlRequest),
    Decommission(NodeDecommissionCommand),
    EvidenceAck(crate::EvidenceAckV1),
    CoverageAck(CoverageAckV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageAckV1 {
    pub source_epoch: u64,
    pub revision: u64,
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

        bounded_response(
            NodeRegistryClient::new(channel.clone()).register(bounded_request(
                NodeRegistrationRequest {
                    session: Some(identity.clone()),
                    registration: Some(registration),
                },
            )),
        )
        .await?;

        // Install and acknowledge trust before this session reports admission readiness.
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
        bounded_response(
            NodeTrustClient::new(channel.clone()).acknowledge(bounded_request(
                TrustGenerationAckRequest {
                    session: Some(identity.clone()),
                    acknowledgement: Some(TrustGenerationAck {
                        generation: trust.generation,
                        bundle_digest: trust.bundle_digest,
                    }),
                },
            )),
        )
        .await?;
        bounded_response(NodeRegistryClient::new(channel.clone()).report_readiness(
            bounded_request(readiness_request(
                &identity,
                ControlReadinessV1 {
                    kernel_ready,
                    admission_ready,
                },
            )),
        ))
        .await?;

        let readiness = ControlReadinessV1 {
            kernel_ready,
            admission_ready,
        };
        let (readiness_updates, readiness_update_input) = mpsc::channel(1);
        let (readiness_failure_output, readiness_failure) = mpsc::channel(1);
        let readiness_renewal = tokio::spawn(renew_readiness(
            NodeRegistryClient::new(channel.clone()),
            identity.clone(),
            readiness,
            readiness_update_input,
            readiness_failure_output,
        ));

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
            .open(Request::new(ReceiverStream::new(resolution_receiver)))
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
            .open(Request::new(ReceiverStream::new(arm_receiver)))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();

        let (decommission_output, decommission_receiver) = mpsc::channel(4);
        decommission_output
            .send(NodeDecommissionStreamRequest {
                session: Some(identity.clone()),
                result: None,
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("decommission stream closed before registration"),
                }
                .build()
            })?;
        let decommission_input = NodeDecommissionClient::new(channel.clone())
            .open(Request::new(ReceiverStream::new(decommission_receiver)))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();

        let (evidence_output, evidence_receiver) = mpsc::channel(EVIDENCE_PIPELINE_BATCHES);
        let evidence_input = NodeEvidenceClient::new(channel.clone())
            .max_decoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES)
            .open(Request::new(ReceiverStream::new(evidence_receiver)))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();

        Ok(ControlConnection {
            identity,
            resolution_output,
            resolution_input,
            arm_output,
            arm_input,
            decommission_output,
            decommission_input,
            evidence_output,
            evidence_input,
            coverage: NodeCoverageClient::new(channel.clone())
                .max_decoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES),
            policy: NodePolicyClient::new(channel)
                .max_decoding_message_size(MAX_POLICY_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_POLICY_GRPC_MESSAGE_BYTES),
            readiness_updates,
            readiness_failure,
            readiness_renewal,
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
    pub async fn report_readiness(&self, kernel_ready: bool, admission_ready: bool) -> Result<()> {
        let (result, accepted) = oneshot::channel();
        self.readiness_updates
            .send(ReadinessUpdate {
                readiness: ControlReadinessV1 {
                    kernel_ready,
                    admission_ready,
                },
                result,
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("Control readiness owner stopped"),
                }
                .build()
            })?;
        accepted.await.map_err(|_closed| {
            ControlProtocolSnafu {
                reason: String::from("Control readiness update was not acknowledged"),
            }
            .build()
        })?
    }

    pub async fn policy_inventory(
        &mut self,
        active_candidate_content_id: Option<&str>,
        durable_bundle_digests: Vec<String>,
    ) -> Result<PolicyInventory> {
        // The active candidate and durable bundle set let Control avoid unnecessary transfer.
        bounded_response(
            self.policy
                .inventory(bounded_request(PolicyInventoryRequest {
                    session: Some(self.identity.clone()),
                    active_candidate_content_id: active_candidate_content_id
                        .unwrap_or_default()
                        .to_owned(),
                    durable_bundle_digests,
                })),
        )
        .await
        .map(tonic::Response::into_inner)
    }

    pub async fn fetch_policy_chunk(
        &mut self,
        candidate_content_id: String,
        bundle_digest: String,
        chunk_index: u32,
    ) -> Result<mithril_control::PolicyChunk> {
        bounded_response(self.policy.fetch(bounded_request(PolicyChunkRequest {
            session: Some(self.identity.clone()),
            candidate_content_id,
            bundle_digest,
            chunk_index,
        })))
        .await
        .map(tonic::Response::into_inner)
    }

    pub async fn acknowledge_policy(
        &mut self,
        acknowledgement: PolicyActivationAcknowledgement,
    ) -> Result<PolicyAcknowledgementAccepted> {
        bounded_response(
            self.policy
                .acknowledge(bounded_request(PolicyAcknowledgementRequest {
                    session: Some(self.identity.clone()),
                    acknowledgement: Some(acknowledgement),
                })),
        )
        .await
        .map(tonic::Response::into_inner)
    }

    pub async fn exception_inventory(
        &mut self,
        durable_candidate_content_ids: Vec<String>,
    ) -> Result<ExceptionInventory> {
        bounded_response(self.policy.inventory_exceptions(bounded_request(
            ExceptionInventoryRequest {
                session: Some(self.identity.clone()),
                durable_candidate_content_ids,
            },
        )))
        .await
        .map(tonic::Response::into_inner)
    }

    pub async fn acknowledge_exception(
        &mut self,
        acknowledgement: ExceptionActivationAcknowledgement,
    ) -> Result<PolicyAcknowledgementAccepted> {
        bounded_response(self.policy.acknowledge_exception(bounded_request(
            ExceptionAcknowledgementRequest {
                session: Some(self.identity.clone()),
                acknowledgement: Some(acknowledgement),
            },
        )))
        .await
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
                failure = self.readiness_failure.recv() => {
                    return match failure {
                        Some(error) => Err(error),
                        None => ControlProtocolSnafu {
                            reason: String::from("Control readiness renewal stopped"),
                        }
                        .fail(),
                    };
                }
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
                message = self.decommission_input.message() => {
                    return match message.context(ControlRpcSnafu)? {
                        Some(command) => Ok(NodeControlMessage::Decommission(command)),
                        None => ControlProtocolSnafu {
                            reason: String::from("Control closed the decommission stream"),
                        }
                        .fail(),
                    };
                }
                message = self.evidence_input.message() => {
                    return match message.context(ControlRpcSnafu)? {
                        Some(acknowledgement) => Ok(NodeControlMessage::EvidenceAck(
                            acknowledgement.try_into()?,
                        )),
                        None => ControlProtocolSnafu {
                            reason: String::from("Control closed the evidence stream"),
                        }
                        .fail(),
                    };
                }
            }
        }
    }

    pub async fn next_administrative_request(&mut self) -> Result<AdministrativeControlRequest> {
        match self.next_message().await? {
            NodeControlMessage::Administrative(request) => Ok(request),
            NodeControlMessage::Decommission(_) => ControlProtocolSnafu {
                reason: String::from(
                    "Control returned a decommission command to an administrative owner",
                ),
            }
            .fail(),
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

    pub async fn send_decommission_result(
        &self,
        artifact_sha256: [u8; 32],
        state: &str,
        reason_code: String,
    ) -> Result<()> {
        self.decommission_output
            .send(NodeDecommissionStreamRequest {
                session: Some(self.identity.clone()),
                result: Some(NodeDecommissionResult {
                    artifact_sha256: artifact_sha256.to_vec(),
                    state: state.to_owned(),
                    reason_code,
                }),
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("Control decommission stream closed"),
                }
                .build()
            })
    }

    pub async fn send_evidence_batch(&mut self, batch: crate::EvidenceBatchV1) -> Result<()> {
        let mut batch: mithril_control::EvidenceBatch = batch.into();
        batch.commit_group_tail = true;
        self.send_evidence_wire_batch(batch).await
    }

    pub async fn send_evidence_group(
        &mut self,
        batches: Vec<crate::EvidenceBatchV1>,
    ) -> Result<()> {
        let count = batches.len();
        for (index, batch) in batches.into_iter().enumerate() {
            let mut batch: mithril_control::EvidenceBatch = batch.into();
            batch.commit_group_tail = index.checked_add(1) == Some(count);
            self.send_evidence_wire_batch(batch).await?;
        }
        Ok(())
    }

    async fn send_evidence_wire_batch(
        &mut self,
        batch: mithril_control::EvidenceBatch,
    ) -> Result<()> {
        self.evidence_output
            .send(EvidenceStreamRequest {
                session: Some(self.identity.clone()),
                batch: Some(batch),
            })
            .await
            .map_err(|_closed| {
                ControlProtocolSnafu {
                    reason: String::from("Control closed the evidence stream"),
                }
                .build()
            })
    }

    pub async fn send_coverage_report(
        &mut self,
        snapshot: &crate::CoverageSnapshotV1,
        current_interval: &crate::CoverageIntervalV1,
    ) -> Result<CoverageAckV1> {
        let all_intervals = snapshot.all_intervals();
        // Control persists one cursor per source, so each report has one current identity.
        let intervals = all_intervals
            .into_iter()
            .filter(|interval| interval.source_id == current_interval.source_id)
            .map(|interval| CoverageInterval {
                current: interval.interval_id == current_interval.interval_id,
                interval_id: interval.interval_id.to_be_bytes().to_vec(),
                source_epoch: interval.source_epoch,
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
            })
            .collect();
        let report = CoverageReport {
            source_id: current_interval.source_id.to_be_bytes().to_vec(),
            cpu_id: current_interval.cpu_id,
            source_epoch: snapshot.source_epoch,
            revision: snapshot.revision,
            intervals,
        };
        let expected = CoverageAckV1 {
            source_epoch: report.source_epoch,
            revision: report.revision,
        };
        bounded_response(self.coverage.report(bounded_request(CoverageReportRequest {
            session: Some(self.identity.clone()),
            report: Some(report),
        })))
        .await?;
        self.queued
            .push_back(NodeControlMessage::CoverageAck(expected));
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

impl Drop for ControlConnection {
    fn drop(&mut self) {
        // A detached renewal could keep a stale session ready after its owner reconnects.
        self.readiness_renewal.abort();
    }
}

fn readiness_request(
    identity: &NodeSessionContext,
    readiness: ControlReadinessV1,
) -> NodeReadinessRequest {
    NodeReadinessRequest {
        session: Some(identity.clone()),
        report: Some(NodeReadinessReport {
            kernel_ready: readiness.kernel_ready,
            control_ready: true,
            admission_ready: readiness.admission_ready,
        }),
    }
}

async fn renew_readiness(
    mut registry: NodeRegistryClient<Channel>,
    identity: NodeSessionContext,
    mut readiness: ControlReadinessV1,
    mut updates: mpsc::Receiver<ReadinessUpdate>,
    failure: mpsc::Sender<crate::Error>,
) {
    let mut interval = tokio::time::interval(CONTROL_READINESS_RENEWAL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The connection setup sent the first report. Do not send a duplicate immediately.
    interval.tick().await;
    loop {
        tokio::select! {
            update = updates.recv() => {
                let Some(update) = update else {
                    return;
                };
                // One owner serializes transition reports and lease renewals. An old
                // periodic report cannot race a newer local readiness transition.
                readiness = update.readiness;
                let result = report_readiness(&mut registry, &identity, readiness).await;
                if let Err(Err(error)) = update.result.send(result) {
                    let _result = failure.send(error).await;
                }
            }
            _instant = interval.tick() => {
                if let Err(error) = report_readiness(&mut registry, &identity, readiness).await {
                    if error.control_rpc_can_reuse_session() {
                        erebor_telemetry::debug!(
                            "Control readiness renewal failed",
                            node_id = %identity.node_id,
                            retry = %"same_session"
                        );
                        continue;
                    }
                    let _result = failure.send(error).await;
                    return;
                }
            }
        }
    }
}

async fn report_readiness(
    registry: &mut NodeRegistryClient<Channel>,
    identity: &NodeSessionContext,
    readiness: ControlReadinessV1,
) -> Result<()> {
    bounded_response(
        registry.report_readiness(bounded_request(readiness_request(identity, readiness))),
    )
    .await
    .map(|_response| ())
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

fn bounded_request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    // Propagate the deadline so Control can stop work after the node stops waiting.
    request.set_timeout(CONTROL_UNARY_TIMEOUT);
    request
}

async fn bounded_response<T>(
    response: impl Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
) -> Result<tonic::Response<T>> {
    bounded_response_with_timeout(response, CONTROL_UNARY_TIMEOUT).await
}

async fn bounded_response_with_timeout<T>(
    response: impl Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    timeout: Duration,
) -> Result<tonic::Response<T>> {
    // Enforce the same deadline locally because a remote peer can ignore metadata.
    let response = tokio::time::timeout(timeout, response)
        .await
        .map_err(|_elapsed| tonic::Status::deadline_exceeded("Control unary RPC timed out"))
        .context(ControlRpcSnafu)?;
    response.context(ControlRpcSnafu)
}

fn read(path: &std::path::Path) -> Result<Vec<u8>> {
    fs::read(path).context(IoSnafu { path })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{bounded_request, bounded_response_with_timeout, CONTROL_UNARY_TIMEOUT};

    #[tokio::test]
    async fn kubernetes_outage_rpc_deadline_covers_one_slow_durable_response() {
        let slow_response = async {
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            Ok(tonic::Response::new(()))
        };
        assert!(
            bounded_response_with_timeout(slow_response, Duration::from_secs(1))
                .await
                .is_err()
        );

        let slow_response = async {
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            Ok(tonic::Response::new(()))
        };
        assert!(
            bounded_response_with_timeout(slow_response, CONTROL_UNARY_TIMEOUT)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unary_requests_propagate_and_enforce_a_deadline() {
        let request = bounded_request(());
        assert!(request.metadata().contains_key("grpc-timeout"));

        let response =
            std::future::pending::<std::result::Result<tonic::Response<()>, tonic::Status>>();
        assert!(matches!(
            bounded_response_with_timeout(response, Duration::from_millis(10)).await,
            Err(crate::Error::ControlRpc { source, .. })
                if source.code() == tonic::Code::DeadlineExceeded
        ));
    }
}
