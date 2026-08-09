use std::error::Error as StdError;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mithril_control::{
    serve, AllowedNodeIdentity, CapabilityRecord, ControlPlane, ControlServerTls, NodeRegistration,
    TrustGenerationV1,
};
use mithril_node::{NodeControlConfig, NodeControlConnector, TrustCache};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

#[tokio::test]
async fn mtls_registration_acknowledges_trust_and_reconnects_with_a_fresh_nonce(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
        }],
        TrustGenerationV1 {
            generation: 4,
            bundle_digest: "d".repeat(64),
        },
    );
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;

    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let first = connector.connect(registration(), &mut trust).await?;
    assert_eq!(trust.installed().generation, 4);
    drop(first);
    let second = connector.connect(registration(), &mut trust).await?;
    for _ in 0..20 {
        if control.registered_connection_count() == 2
            && control.acknowledged_trust("node-a").is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(control.registered_connection_count(), 2);
    assert_eq!(
        control.acknowledged_trust("node-a"),
        Some(TrustGenerationV1 {
            generation: 4,
            bundle_digest: "d".repeat(64),
        })
    );
    drop(second);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_rejects_wrong_node_binding_and_expired_client_identity(
) -> Result<(), Box<dyn StdError>> {
    assert_rejected_identity(false, "node-b").await?;
    assert_rejected_identity(true, "node-a").await?;
    assert_wrong_ca_rejected().await
}

async fn assert_wrong_ca_rejected() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let server_certificates = Certificates::issue(false)?;
    let files = server_certificates.write(directory.path())?;
    let wrong_ca_directory = directory.path().join("wrong-ca");
    fs::create_dir(&wrong_ca_directory)?;
    let wrong_ca = Certificates::issue(false)?.write(&wrong_ca_directory)?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: server_certificates.node_digest(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "f".repeat(64),
        },
    );
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut config = files.node_config(address);
    config.ca_path = wrong_ca.ca;
    let connector = NodeControlConnector::new(config, "node-a".to_owned(), [9; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    assert!(connector.connect(registration(), &mut trust).await.is_err());
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

async fn assert_rejected_identity(
    expired: bool,
    registered_node_id: &str,
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(expired)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "e".repeat(64),
        },
    );
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let connector = NodeControlConnector::new(
        files.node_config(address),
        registered_node_id.to_owned(),
        [8; 16],
    );
    let mut trust = TrustCache::load(directory.path())?;
    assert!(connector.connect(registration(), &mut trust).await.is_err());
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

fn registration() -> NodeRegistration {
    NodeRegistration {
        platform_digest: "a".repeat(64),
        program_digest: "b".repeat(64),
        label_epoch: 1,
        inventory_process_count: 1,
        inventory_digest: "c".repeat(64),
        kernel_ready: true,
        effect_prevention_claims_enabled: false,
        capabilities: capabilities(),
    }
}

fn capabilities() -> Vec<CapabilityRecord> {
    vec![CapabilityRecord {
        capability_id: "KERNEL_LSM_CHASSIS".to_owned(),
        state: "SUPPORTED".to_owned(),
        reason_code: "EXACT_ATTACH_READBACK".to_owned(),
    }]
}

fn start_server(
    address: SocketAddr,
    files: &CertificateFiles,
    control: ControlPlane,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<mithril_control::Result<()>>,
) {
    let tls = files.server_tls();
    let (shutdown, receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        serve(address, &tls, control, async move {
            let _result = receiver.await;
        })
        .await
    });
    (shutdown, server)
}

fn free_address() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

struct Certificates {
    ca: Certificate,
    server: Certificate,
    server_key: KeyPair,
    node: Certificate,
    node_key: KeyPair,
}

impl Certificates {
    fn issue(expired_node: bool) -> Result<Self, rcgen::Error> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;

        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()])?;
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server = server_params.signed_by(&server_key, &ca, &ca_key)?;

        let mut node_params = CertificateParams::new(vec!["node-a.local".to_owned()])?;
        node_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        if expired_node {
            node_params.not_before = date_time_ymd(2010, 1, 1);
            node_params.not_after = date_time_ymd(2011, 1, 1);
        }
        let node_key = KeyPair::generate()?;
        let node = node_params.signed_by(&node_key, &ca, &ca_key)?;
        Ok(Self {
            ca,
            server,
            server_key,
            node,
            node_key,
        })
    }

    fn node_digest(&self) -> String {
        format!("{:x}", Sha256::digest(self.node.der().as_ref()))
    }

    fn write(&self, directory: &Path) -> Result<CertificateFiles, std::io::Error> {
        let files = CertificateFiles {
            ca: directory.join("ca.pem"),
            server_certificate: directory.join("server.pem"),
            server_key: directory.join("server-key.pem"),
            node_certificate: directory.join("node.pem"),
            node_key: directory.join("node-key.pem"),
        };
        fs::write(&files.ca, self.ca.pem())?;
        fs::write(&files.server_certificate, self.server.pem())?;
        fs::write(&files.server_key, self.server_key.serialize_pem())?;
        fs::write(&files.node_certificate, self.node.pem())?;
        fs::write(&files.node_key, self.node_key.serialize_pem())?;
        Ok(files)
    }
}

struct CertificateFiles {
    ca: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    node_certificate: PathBuf,
    node_key: PathBuf,
}

impl CertificateFiles {
    fn server_tls(&self) -> ControlServerTls {
        ControlServerTls {
            certificate_path: self.server_certificate.clone(),
            private_key_path: self.server_key.clone(),
            node_ca_path: self.ca.clone(),
        }
    }

    fn node_config(&self, address: SocketAddr) -> NodeControlConfig {
        NodeControlConfig {
            endpoint: format!("https://{address}"),
            server_name: "localhost".to_owned(),
            ca_path: self.ca.clone(),
            certificate_path: self.node_certificate.clone(),
            private_key_path: self.node_key.clone(),
            reconnect_minimum_ms: 10,
            reconnect_maximum_ms: 20,
        }
    }
}
