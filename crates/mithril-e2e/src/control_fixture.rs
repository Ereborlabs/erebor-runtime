use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mithril_control::{
    lower_kubernetes_policy, serve, workload_target_fact_digest, AllowedNodeIdentity,
    ContainerKindV1, ControlPlane, ControlServerTls, ControlStore, KubernetesWorkloadIdentityV1,
    PolicyDesiredStateConfigV1, PolicyDesiredStateOwner, PolicySignerConfigV1,
    PolicySourceRevisionV1, PolicySourceStateV1, ProfileSealRequestV1, RegistryDigestsV1,
    TrustGenerationV1, WorkloadProtectionPolicy, WorkloadTargetFactV1,
};
use mithril_node::{NodeControlConfig, NodeControlConnector};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

use crate::physical::wait_for_async;

pub(crate) fn control_store_lease_ready<T>(
    result: mithril_control::Result<T>,
) -> crate::Result<Option<T>> {
    match result {
        Ok(store) => Ok(Some(store)),
        Err(mithril_control::Error::ControlStore { reason, .. })
            if reason.starts_with("another Control store owner holds the lease") =>
        {
            Ok(None)
        }
        Err(source) => Err(crate::Error::Policy {
            source,
            location: snafu::Location::default(),
        }),
    }
}

pub(crate) async fn reopen_control_store(path: &Path) -> crate::Result<ControlStore> {
    wait_for_async(
        path,
        "the stopped Control server to release its store lease",
        Duration::from_secs(5),
        || control_store_lease_ready(ControlStore::open(path)),
        || "the stopped server still owns the store lease".to_owned(),
    )
    .await
}

#[cfg(test)]
#[tokio::test]
async fn discovery_read_restart_waits_for_lease_and_preserves_other_errors(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let store = ControlStore::open(directory.path())?;
    let reopening = reopen_control_store(directory.path());
    tokio::pin!(reopening);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut reopening)
            .await
            .is_err()
    );
    assert!(ControlStore::open(directory.path()).is_err());
    drop(store);
    drop(reopening.await?);
    let invalid = directory.path().join("not-a-directory");
    fs::write(&invalid, b"invalid")?;
    assert!(matches!(
        reopen_control_store(&invalid).await,
        Err(crate::Error::Policy {
            source: mithril_control::Error::Io { .. },
            ..
        })
    ));
    Ok(())
}

const OUTAGE_POLICY: &[u8] = include_bytes!("../fixtures/convergence/outage-policy-v1.json");
pub(crate) const OUTAGE_TENANT_ID: &str = "00000000-0000-0001-0000-000000000002";
pub(crate) const OUTAGE_CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
pub(crate) const OUTAGE_NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
pub(crate) const OUTAGE_POLICY_UID: &str = "30000000-0000-4000-8000-000000000001";

pub(crate) struct OutagePolicyFixture {
    pub(crate) owner: PolicyDesiredStateOwner,
}

impl OutagePolicyFixture {
    pub(crate) fn new(store: ControlStore) -> Self {
        let digest = "0".repeat(64);
        Self {
            owner: PolicyDesiredStateOwner::new(
                PolicyDesiredStateConfigV1 {
                    tenant_id: OUTAGE_TENANT_ID.to_owned(),
                    cluster_uid: OUTAGE_CLUSTER_UID.to_owned(),
                    signer: PolicySignerConfigV1 {
                        signing_key_id: "outage-policy-key".to_owned(),
                        signing_key_path: PathBuf::from("/unused/outage-policy-key"),
                        seal_request_path: PathBuf::from("/unused/outage-seal-request"),
                        distribution_sequence_epoch: 9,
                        candidate_validity_ns: 900_000_000_000,
                    },
                },
                store,
                SigningKey::from_bytes(&[7; 32]),
                ProfileSealRequestV1 {
                    signing_key_id: "outage-policy-key".to_owned(),
                    issuer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                    sequence_epoch: 4,
                    issuer_sequence: 0,
                    rollback_authorization_id: None,
                    registry_digests: RegistryDigestsV1 {
                        provider_numeric_registry_bundle_digest: digest.clone(),
                        required_capability_schema_digest: digest.clone(),
                        source_selector_registry_digest: digest.clone(),
                        object_classifier_registry_digest: digest.clone(),
                        reason_code_registry_digest: digest.clone(),
                        correlation_package_registry_digest: digest.clone(),
                        provider_vocabulary_registry_digest: digest,
                    },
                },
            ),
        }
    }

    pub(crate) fn resource(
        &self,
        generation: i64,
    ) -> Result<WorkloadProtectionPolicy, Box<dyn StdError>> {
        let mut resource: WorkloadProtectionPolicy = serde_json::from_slice(OUTAGE_POLICY)?;
        resource.metadata.namespace = Some("tenant-a".to_owned());
        resource.metadata.uid = Some(OUTAGE_POLICY_UID.to_owned());
        resource.metadata.generation = Some(generation);
        resource.metadata.resource_version = Some(format!("outage-{generation}"));
        if generation == 2 {
            resource.spec.roles[0]
                .files
                .push(serde_json::from_value(serde_json::json!({
                    "name": "deny-update-target",
                    "path": "/var/lib/mithril-convergence/outage-update.denied",
                    "recursive": false,
                    "operations": ["OpenRead"],
                    "action": "Deny"
                }))?);
        }
        Ok(resource)
    }

    pub(crate) fn inventory(
        &self,
        resource: &WorkloadProtectionPolicy,
    ) -> Result<Vec<WorkloadTargetFactV1>, Box<dyn StdError>> {
        let policy = lower_kubernetes_policy(
            resource,
            OUTAGE_TENANT_ID,
            OUTAGE_CLUSTER_UID,
            OUTAGE_NAMESPACE_UID,
        )?;
        let source = PolicySourceRevisionV1::from_resource(
            resource,
            &policy,
            OUTAGE_TENANT_ID,
            OUTAGE_CLUSTER_UID,
            OUTAGE_NAMESPACE_UID,
            PolicySourceStateV1::Accepted,
        )?;
        let mut target = WorkloadTargetFactV1 {
            node_id: "node-a".to_owned(),
            workload_binding_generation_digest: String::new(),
            execution_set_id: "44444444-4444-4444-8444-444444444444".to_owned(),
            cluster_uid: OUTAGE_CLUSTER_UID.to_owned(),
            namespace_uid: OUTAGE_NAMESPACE_UID.to_owned(),
            controller_uid: "88888888-8888-4888-8888-888888888888".to_owned(),
            service_account_uid: "77777777-7777-4777-8777-777777777777".to_owned(),
            pod_uid: "99999999-9999-4999-8999-999999999999".to_owned(),
            container_id: format!("scheduled:{}", "1".repeat(64)),
            container_name: "worker".to_owned(),
            container_kind: ContainerKindV1::Application,
            image_digest: concat!(
                "sha256:",
                "73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
            )
            .to_owned(),
            pod_labels: BTreeMap::from([(
                "app.kubernetes.io/name".to_owned(),
                "mithril-outage-worker".to_owned(),
            )]),
            kubernetes: Some(KubernetesWorkloadIdentityV1 {
                namespace_name: "tenant-a".to_owned(),
                pod_name: "outage-a".to_owned(),
                profile_id: policy.profile_id().to_owned(),
                policy_source_revision_id: source.policy_source_revision_id,
                binding_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                protected_scope_id: policy.protected_universe.protected_scope_ids[0].clone(),
                workload_selector_id: policy.workload_selectors[0].workload_selector_id.clone(),
                kubernetes_node_name: "worker-a".to_owned(),
                kubernetes_node_uid: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned(),
                node_boot_id: "07".repeat(16),
                label_epoch: 1,
            }),
        };
        target.workload_binding_generation_digest = workload_target_fact_digest(&target)?;
        Ok(vec![target])
    }
}

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

    #[cfg(test)]
    pub(crate) fn kubernetes(server_name: &str) -> Result<Self, Box<dyn StdError>> {
        let directory = tempfile::tempdir()?;
        let certificates = Certificates::issue_for(false, &["localhost", server_name])?;
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

    #[cfg(test)]
    pub(crate) fn node_digest(&self) -> String {
        self.certificates.node_digest()
    }

    #[cfg(test)]
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

    #[cfg(test)]
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
        Self::issue_for(expired_node, &["localhost"])
    }

    fn issue_for(expired_node: bool, server_names: &[&str]) -> Result<Self, rcgen::Error> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;

        let mut server_params = CertificateParams::new(
            server_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )?;
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
