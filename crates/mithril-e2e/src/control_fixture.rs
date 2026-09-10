use std::error::Error as StdError;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mithril_control::{
    serve, AllowedNodeIdentity, ControlPlane, ControlServerTls, ControlStore, TrustGenerationV1,
};
use mithril_node::{NodeControlConfig, NodeControlConnector};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

use crate::physical::wait_for_async;

pub(crate) struct ControlServerFixture {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<mithril_control::Result<()>>>,
}

pub(crate) struct MtlsFixture {
    directory: tempfile::TempDir,
    certificates: Certificates,
    pub(crate) files: CertificateFiles,
}

impl MtlsFixture {
    pub(crate) fn new(expired_node: bool) -> Result<Self, Box<dyn StdError>> {
        let directory = tempfile::tempdir()?;
        let certificates = Certificates::issue(expired_node)?;
        let files = certificates.write(directory.path())?;
        Ok(Self {
            directory,
            certificates,
            files,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn control(&self, generation: u64) -> mithril_control::Result<ControlPlane> {
        self.control_with_store(
            ControlStore::open(self.path().join("control-store"))?,
            generation,
        )
    }

    pub(crate) fn control_with_store(
        &self,
        store: ControlStore,
        generation: u64,
    ) -> mithril_control::Result<ControlPlane> {
        ControlPlane::with_control_store(
            vec![AllowedNodeIdentity {
                node_id: "node-a".to_owned(),
                certificate_sha256: self.certificates.node_digest(),
                tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
            }],
            TrustGenerationV1 {
                generation,
                bundle_digest: "d".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            },
            store,
        )
    }

    pub(crate) async fn start(
        &self,
        control: ControlPlane,
    ) -> Result<ControlServerFixture, Box<dyn StdError>> {
        ControlServerFixture::start(&self.files, control).await
    }

    pub(crate) fn connector(
        &self,
        server: &ControlServerFixture,
        node_id: &str,
        node_boot_id: [u8; 16],
    ) -> NodeControlConnector {
        NodeControlConnector::new(
            self.node_config(server.address()),
            node_id.to_owned(),
            node_boot_id,
        )
    }

    pub(crate) fn node_config(&self, address: SocketAddr) -> NodeControlConfig {
        self.files.node_config(address)
    }
}

impl ControlServerFixture {
    pub(crate) async fn start(
        files: &CertificateFiles,
        control: ControlPlane,
    ) -> Result<Self, Box<dyn StdError>> {
        let address = free_address()?;
        let tls = files.server_tls();
        let (shutdown, receiver) = oneshot::channel();
        let server = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| mithril_control::Error::Io {
                    path: PathBuf::from("Control test runtime"),
                    source,
                    location: snafu::Location::default(),
                })?;
            runtime.block_on(serve(address, &tls, control, async move {
                let _result = receiver.await;
            }))
        });
        if let Err(error) = tokio::time::timeout(Duration::from_secs(5), async {
            while tokio::net::TcpStream::connect(address).await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        {
            let _result = shutdown.send(());
            server.await??;
            return Err(error.into());
        }
        Ok(Self {
            address,
            shutdown: Some(shutdown),
            server: Some(server),
        })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) async fn from_running(
        address: SocketAddr,
        shutdown: oneshot::Sender<()>,
        server: tokio::task::JoinHandle<mithril_control::Result<()>>,
    ) -> Result<Self, Box<dyn StdError>> {
        let path = PathBuf::from(address.to_string());
        if let Err(error) = wait_for_async(
            &path,
            "the test server to accept TCP connections",
            Duration::from_secs(5),
            || Ok(std::net::TcpStream::connect(address).ok().map(|_stream| ())),
            || {
                format!(
                    "server task finished before readiness: {}",
                    server.is_finished()
                )
            },
        )
        .await
        {
            let _result = shutdown.send(());
            server.await??;
            return Err(error.into());
        }
        Ok(Self {
            address,
            shutdown: Some(shutdown),
            server: Some(server),
        })
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), Box<dyn StdError>> {
        if let Some(shutdown) = self.shutdown.take() {
            let _result = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.await??;
        }
        Ok(())
    }
}

impl Drop for ControlServerFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _result = shutdown.send(());
        }
    }
}

pub(crate) fn free_address() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

pub(crate) struct Certificates {
    ca: Certificate,
    server: Certificate,
    server_key: KeyPair,
    node: Certificate,
    node_key: KeyPair,
}

impl Certificates {
    pub(crate) fn issue(expired_node: bool) -> Result<Self, rcgen::Error> {
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

    pub(crate) fn node_digest(&self) -> String {
        format!("{:x}", Sha256::digest(self.node.der().as_ref()))
    }

    pub(crate) fn write(&self, directory: &Path) -> Result<CertificateFiles, std::io::Error> {
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

pub(crate) struct CertificateFiles {
    pub(crate) ca: PathBuf,
    pub(crate) server_certificate: PathBuf,
    pub(crate) server_key: PathBuf,
    pub(crate) node_certificate: PathBuf,
    pub(crate) node_key: PathBuf,
}

impl CertificateFiles {
    pub(crate) fn server_tls(&self) -> ControlServerTls {
        ControlServerTls {
            certificate_path: self.server_certificate.clone(),
            private_key_path: self.server_key.clone(),
            node_ca_path: self.ca.clone(),
        }
    }

    pub(crate) fn node_config(&self, address: SocketAddr) -> NodeControlConfig {
        NodeControlConfig {
            endpoint: format!("https://{address}"),
            server_name: "localhost".to_owned(),
            ca_path: self.ca.clone(),
            certificate_path: self.node_certificate.clone(),
            private_key_path: self.node_key.clone(),
            reconnect_minimum_ms: 10,
            reconnect_maximum_ms: 20,
            maximum_clock_skew_ns: 30_000_000_000,
        }
    }
}
