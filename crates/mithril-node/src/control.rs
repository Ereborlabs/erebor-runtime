use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;

use mithril_control::control_envelope::Payload as ControlPayload;
use mithril_control::node_control_client::NodeControlClient as GrpcNodeControlClient;
use mithril_control::node_envelope::Payload as NodePayload;
use mithril_control::{
    AdministrativeExecArmResult, AdministrativeExecResolution, ArmAdministrativeExec,
    ControlEnvelope, CoverageAck, CoverageCounters, CoverageInterval, CoverageReport, EvidenceAck,
    NodeEnvelope, NodeReadinessReport, NodeRegistration, ResolveAdministrativeExec,
    TrustGenerationAck, CONTROL_PROTOCOL_VERSION,
};
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use tonic::Streaming;
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
    output: mpsc::Sender<NodeEnvelope>,
    input: Streaming<ControlEnvelope>,
    identity: ConnectionIdentity,
    next_control_sequence: u64,
    next_node_sequence: u64,
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

struct ConnectionIdentity {
    node_id: String,
    node_boot_id: Vec<u8>,
    nonce: Vec<u8>,
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
        let ca = read(&self.config.ca_path)?;
        let certificate = read(&self.config.certificate_path)?;
        let private_key = read(&self.config.private_key_path)?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(certificate, private_key))
            .domain_name(self.config.server_name.clone());
        let channel = Endpoint::from_shared(self.config.endpoint.clone())
            .context(ControlTransportSnafu)?
            .tls_config(tls)
            .context(ControlTransportSnafu)?
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .http2_keep_alive_interval(Duration::from_secs(15))
            .keep_alive_while_idle(true)
            .connect_timeout(CONTROL_CONNECT_TIMEOUT)
            .connect()
            .await
            .context(ControlTransportSnafu)?;
        let mut client = GrpcNodeControlClient::new(channel);
        let (output, receiver) = mpsc::channel(8);
        let identity = ConnectionIdentity {
            node_id: self.node_id.clone(),
            node_boot_id: self.node_boot_id.to_vec(),
            nonce: Uuid::new_v4().as_bytes().to_vec(),
        };
        output
            .send(identity.envelope(1, NodePayload::Registration(registration)))
            .await
            .map_err(|_| {
                ControlProtocolSnafu {
                    reason: "registration stream closed before send".to_owned(),
                }
                .build()
            })?;
        let mut input = client
            .open_stream(ReceiverStream::new(receiver))
            .await
            .context(ControlRpcSnafu)?
            .into_inner();
        let accepted = next_control(&mut input, &identity, 1).await?;
        if !matches!(
            accepted.payload,
            Some(ControlPayload::RegistrationAccepted(_))
        ) {
            return ControlProtocolSnafu {
                reason: "Control did not accept registration first".to_owned(),
            }
            .fail();
        }
        let trust = next_control(&mut input, &identity, 2).await?;
        let Some(ControlPayload::TrustGeneration(trust)) = trust.payload else {
            return ControlProtocolSnafu {
                reason: "Control did not deliver trust after registration".to_owned(),
            }
            .fail();
        };
        trust_cache.install(
            trust.generation,
            trust.bundle_digest.clone(),
            &identity.nonce,
            2,
        )?;
        output
            .send(identity.envelope(
                2,
                NodePayload::TrustAck(TrustGenerationAck {
                    generation: trust.generation,
                    bundle_digest: trust.bundle_digest,
                }),
            ))
            .await
            .map_err(|_| {
                ControlProtocolSnafu {
                    reason: "registration stream closed before trust acknowledgement".to_owned(),
                }
                .build()
            })?;
        output
            .send(identity.envelope(
                3,
                NodePayload::ReadinessReport(NodeReadinessReport {
                    kernel_ready,
                    control_ready: true,
                    admission_ready,
                }),
            ))
            .await
            .map_err(|_| {
                ControlProtocolSnafu {
                    reason: "registration stream closed before readiness report".to_owned(),
                }
                .build()
            })?;
        Ok(ControlConnection {
            output,
            input,
            identity,
            next_control_sequence: 3,
            next_node_sequence: 4,
        })
    }
}

impl ControlConnection {
    pub async fn next_message(&mut self) -> Result<NodeControlMessage> {
        let Some(message) = self.input.message().await.context(ControlRpcSnafu)? else {
            return ControlProtocolSnafu {
                reason: "Control closed the node stream".to_owned(),
            }
            .fail();
        };
        validate_control(&message, &self.identity, self.next_control_sequence)?;
        self.next_control_sequence =
            self.next_control_sequence.checked_add(1).ok_or_else(|| {
                ControlProtocolSnafu {
                    reason: "Control input sequence exhausted".to_owned(),
                }
                .build()
            })?;
        match message.payload {
            Some(ControlPayload::ResolveAdministrativeExec(request)) => Ok(
                NodeControlMessage::Administrative(AdministrativeControlRequest::Resolve(request)),
            ),
            Some(ControlPayload::ArmAdministrativeExec(request)) => Ok(
                NodeControlMessage::Administrative(AdministrativeControlRequest::Arm(request)),
            ),
            Some(ControlPayload::EvidenceAck(ack)) => Ok(NodeControlMessage::EvidenceAck(ack)),
            Some(ControlPayload::CoverageAck(ack)) => Ok(NodeControlMessage::CoverageAck(ack)),
            _ => ControlProtocolSnafu {
                reason: "Control sent an unexpected post-registration message".to_owned(),
            }
            .fail(),
        }
    }

    pub async fn next_administrative_request(&mut self) -> Result<AdministrativeControlRequest> {
        match self.next_message().await? {
            NodeControlMessage::Administrative(request) => Ok(request),
            NodeControlMessage::EvidenceAck(_) => ControlProtocolSnafu {
                reason: "Control sent evidence acknowledgement to an administrative-only owner"
                    .to_owned(),
            }
            .fail(),
            NodeControlMessage::CoverageAck(_) => ControlProtocolSnafu {
                reason: "Control sent coverage acknowledgement to an administrative-only owner"
                    .to_owned(),
            }
            .fail(),
        }
    }

    pub async fn send_evidence_batch(&mut self, batch: crate::EvidenceBatchV1) -> Result<()> {
        self.send(NodePayload::EvidenceBatch(batch.into())).await
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
                let current_interval = current.contains(&interval.interval_id);
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
                    current: current_interval,
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
        self.send(NodePayload::CoverageReport(report)).await?;
        Ok(expected)
    }

    pub async fn send_resolution(&mut self, response: AdministrativeExecResolution) -> Result<()> {
        self.send(NodePayload::Resolution(Box::new(response))).await
    }

    pub async fn send_arm_result(&mut self, response: AdministrativeExecArmResult) -> Result<()> {
        self.send(NodePayload::ArmResult(response)).await
    }

    async fn send(&mut self, payload: NodePayload) -> Result<()> {
        let sequence = self.next_node_sequence;
        self.next_node_sequence = sequence.checked_add(1).ok_or_else(|| {
            ControlProtocolSnafu {
                reason: "node output sequence exhausted".to_owned(),
            }
            .build()
        })?;
        self.output
            .send(self.identity.envelope(sequence, payload))
            .await
            .map_err(|_| {
                ControlProtocolSnafu {
                    reason: "Control stream closed before administrative response".to_owned(),
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
                    reason: "Control sent an administrative request to a node without an owner"
                        .to_owned(),
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

impl ConnectionIdentity {
    fn envelope(&self, sequence: u64, payload: NodePayload) -> NodeEnvelope {
        NodeEnvelope {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            node_id: self.node_id.clone(),
            node_boot_id: self.node_boot_id.clone(),
            connection_nonce: self.nonce.clone(),
            sequence,
            payload: Some(payload),
        }
    }
}

async fn next_control(
    input: &mut Streaming<ControlEnvelope>,
    identity: &ConnectionIdentity,
    expected_sequence: u64,
) -> Result<ControlEnvelope> {
    let message = input
        .message()
        .await
        .context(ControlRpcSnafu)?
        .ok_or_else(|| {
            ControlProtocolSnafu {
                reason: "Control closed registration stream".to_owned(),
            }
            .build()
        })?;
    validate_control(&message, identity, expected_sequence)?;
    Ok(message)
}

fn validate_control(
    message: &ControlEnvelope,
    identity: &ConnectionIdentity,
    expected_sequence: u64,
) -> Result<()> {
    if !message.has_supported_header()
        || message.node_id != identity.node_id
        || message.node_boot_id != identity.node_boot_id
        || message.connection_nonce != identity.nonce
        || message.sequence != expected_sequence
    {
        return ControlProtocolSnafu {
            reason: "Control stream version, identity, nonce, or sequence changed".to_owned(),
        }
        .fail();
    }
    Ok(())
}

fn read(path: &std::path::Path) -> Result<Vec<u8>> {
    fs::read(path).context(IoSnafu { path })
}
