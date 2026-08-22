use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use snafu::{ensure, ResultExt as _};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::error::{InvalidConfigurationSnafu, IoSnafu, ServeSnafu, TlsSnafu};
use crate::{
    control_health_server::ControlHealthServer,
    node_administrative_arm_server::NodeAdministrativeArmServer,
    node_administrative_resolution_server::NodeAdministrativeResolutionServer,
    node_coverage_server::NodeCoverageServer, node_evidence_server::NodeEvidenceServer,
    node_policy_server::NodePolicyServer, node_registry_server::NodeRegistryServer,
    node_trust_server::NodeTrustServer, ControlPlane, Result, MAX_EVIDENCE_GRPC_MESSAGE_BYTES,
    MAX_POLICY_GRPC_MESSAGE_BYTES,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlServerTls {
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub node_ca_path: PathBuf,
}

pub async fn serve(
    address: SocketAddr,
    tls: &ControlServerTls,
    control: ControlPlane,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    ensure!(
        !control.allowed_nodes().is_empty(),
        InvalidConfigurationSnafu {
            reason: "at least one node identity must be configured",
        }
    );
    let certificate = read(&tls.certificate_path)?;
    let private_key = read(&tls.private_key_path)?;
    let node_ca = read(&tls.node_ca_path)?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(certificate, private_key))
        .client_ca_root(Certificate::from_pem(node_ca));
    Server::builder()
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keepalive_interval(Some(Duration::from_secs(15)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .tls_config(tls)
        .context(TlsSnafu)?
        .add_service(NodeRegistryServer::new(control.clone()))
        .add_service(NodeTrustServer::new(control.clone()))
        .add_service(
            NodeEvidenceServer::new(control.clone())
                .max_decoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES),
        )
        .add_service(
            NodeCoverageServer::new(control.clone())
                .max_decoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_EVIDENCE_GRPC_MESSAGE_BYTES),
        )
        .add_service(
            NodePolicyServer::new(control.clone())
                .max_decoding_message_size(MAX_POLICY_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_POLICY_GRPC_MESSAGE_BYTES),
        )
        .add_service(ControlHealthServer::new(control.clone()))
        .add_service(NodeAdministrativeResolutionServer::new(control.clone()))
        .add_service(NodeAdministrativeArmServer::new(control))
        .serve_with_shutdown(address, shutdown)
        .await
        .context(ServeSnafu { address })
}

fn read(path: &PathBuf) -> Result<Vec<u8>> {
    fs::read(path).context(IoSnafu { path })
}
