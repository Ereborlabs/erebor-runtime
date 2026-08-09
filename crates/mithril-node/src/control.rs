use std::fs;
use std::time::Duration;

use mithril_control::control_envelope::Payload as ControlPayload;
use mithril_control::node_control_client::NodeControlClient as GrpcNodeControlClient;
use mithril_control::node_envelope::Payload as NodePayload;
use mithril_control::{
    ControlEnvelope, NodeCapabilityReport, NodeEnvelope, NodeKeepalive, NodeRegistration,
    TrustGenerationAck, CONTROL_PROTOCOL_VERSION,
};
use snafu::ResultExt as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use tonic::Streaming;
use uuid::Uuid;

use crate::error::{ControlProtocolSnafu, ControlRpcSnafu, ControlTransportSnafu, IoSnafu};
use crate::{NodeControlConfig, Result, TrustCache};

pub struct NodeControlConnector {
    config: NodeControlConfig,
    node_id: String,
    node_boot_id: [u8; 16],
}

pub struct ControlConnection {
    output: mpsc::Sender<NodeEnvelope>,
    input: Streaming<ControlEnvelope>,
    identity: ConnectionIdentity,
    next_node_sequence: u64,
    next_control_sequence: u64,
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
        report: NodeCapabilityReport,
        trust_cache: &mut TrustCache,
    ) -> Result<ControlConnection> {
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
            .send(identity.envelope(3, NodePayload::CapabilityReport(report)))
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
            next_node_sequence: 4,
            next_control_sequence: 3,
        })
    }
}

impl ControlConnection {
    pub async fn keepalive(&mut self) -> Result<()> {
        self.output
            .send(self.identity.envelope(
                self.next_node_sequence,
                NodePayload::Keepalive(NodeKeepalive {}),
            ))
            .await
            .map_err(|_| {
                ControlProtocolSnafu {
                    reason: "Control stream is closed".to_owned(),
                }
                .build()
            })?;
        self.next_node_sequence += 1;
        Ok(())
    }

    pub async fn wait_for_disconnect(&mut self) -> Result<()> {
        loop {
            let Some(message) = self.input.message().await.context(ControlRpcSnafu)? else {
                return ControlProtocolSnafu {
                    reason: "Control closed the node stream".to_owned(),
                }
                .fail();
            };
            validate_control(&message, &self.identity, self.next_control_sequence)?;
            self.next_control_sequence += 1;
            if !matches!(message.payload, Some(ControlPayload::Keepalive(_))) {
                return ControlProtocolSnafu {
                    reason: "Control sent an unexpected post-registration message".to_owned(),
                }
                .fail();
            }
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
