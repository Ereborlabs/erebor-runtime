use std::{path::Path, sync::Arc};

use araphor_data::{PackageRequestV1, PackageResponseV1};
use erebor_runtime_client::{AraphorClient, AraphorProfile};
use erebor_runtime_ipc::araphor::{
    self as wire, araphor_client_service_server::AraphorClientService as _,
};
use mithril_control::{
    AllowedNodeIdentity, ClientAuth, ClientAuthConfig, ClientGrpcConfig, ClientGrpcOwner,
    ClientListener, ClientListenerConfig, ControlPlane, ControlStore, EvidenceIntakeOwner,
    TrustGenerationV1,
};

use crate::control_fixture::{free_address, ControlServerFixture, MtlsFixture};

use super::Result;

pub(super) struct Fixture {
    pub(super) control: ControlPlane,
    service: ClientGrpcOwner,
    auth: Arc<ClientAuth>,
    stop: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl Fixture {
    pub(super) fn open(path: &Path, auth: Arc<ClientAuth>) -> Result<Self> {
        let intake = EvidenceIntakeOwner::try_from(ControlStore::open(path)?)?;
        let control = ControlPlane::from_intake(
            vec![AllowedNodeIdentity {
                node_id: "qualification-node".into(),
                certificate_sha256: "1".repeat(64),
                tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            }],
            TrustGenerationV1 {
                generation: 1,
                bundle_digest: String::new(),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            }
            .with_computed_bundle_digest(),
            intake.clone(),
        )?;
        Self::from_control(control, auth, ClientGrpcConfig::default())
    }

    fn from_control(
        control: ControlPlane,
        auth: Arc<ClientAuth>,
        client: ClientGrpcConfig,
    ) -> Result<Self> {
        let service = ClientGrpcOwner::new(control.clone(), auth.clone(), client)?;
        let (stop, _) = tokio::sync::watch::channel(false);
        Ok(Self {
            control,
            service,
            auth,
            stop,
            tasks: Vec::new(),
        })
    }

    pub(super) fn configured(
        config: mithril_control::ControlConfig,
        auth: Arc<ClientAuth>,
    ) -> Result<Self> {
        let parts = config.into_parts()?;
        if let Some(error) = parts.data_error.or(parts.discovery_error) {
            return Err(error.into());
        }
        if parts.discovery.is_some() {
            return Err("instance fixture cannot discard optional Discovery".into());
        }
        let client = parts
            .client
            .as_ref()
            .and_then(|client| client.investigation.clone())
            .unwrap_or_default();
        let host = parts.instances.ok_or("configured Instance Host absent")?;
        let mut fixture = Self::from_control(parts.control, auth, client)?;
        let stopped = fixture.stop.subscribe();
        let stopping = stopped.clone();
        let mut tasks = vec![tokio::spawn(async move {
            host.serve(stopping, u64::MAX)
                .await
                .map_err(std::io::Error::other)
        })];
        if let Some(graph) = parts.graph {
            tasks.push(tokio::spawn(async move {
                graph.run(stopped).await.map_err(std::io::Error::other)
            }));
        }
        fixture.tasks = tasks;
        Ok(fixture)
    }

    pub(super) async fn shutdown(mut self) -> Result<()> {
        self.stop.send_replace(true);
        for joined in futures_util::future::join_all(std::mem::take(&mut self.tasks)).await {
            joined??;
        }
        Ok(())
    }

    pub(super) async fn observe<T>(
        &self,
        wait: std::time::Duration,
        mut read: impl FnMut(&araphor_data::AnalysisStore) -> Result<Option<T>>,
    ) -> Result<T> {
        let data = self.control.analysis_store().ok_or("observation store")?;
        let mut changes = data.subscribe_revision();
        tokio::time::timeout(wait, async {
            loop {
                if let Some(value) = read(&data)? {
                    return Ok::<_, Box<dyn std::error::Error>>(value);
                }
                changes.changed().await?;
            }
        })
        .await?
    }

    pub(super) async fn listening(self, tls: &MtlsFixture) -> Result<(Self, ControlServerFixture)> {
        match tls.start(self.control.clone()).await {
            Ok(server) => Ok((self, server)),
            Err(error) => {
                self.shutdown().await?;
                Err(error)
            }
        }
    }

    pub(super) async fn connected(
        self,
        tls: &MtlsFixture,
        auth: &ClientAuthConfig,
        credential: &Path,
    ) -> Result<(Self, AraphorClient, ControlServerFixture)> {
        match self.client(tls, auth, credential, [1; 16]).await {
            Ok((client, server)) => Ok((self, client, server)),
            Err(error) => {
                self.shutdown().await?;
                Err(error)
            }
        }
    }

    pub(super) async fn client(
        &self,
        tls: &MtlsFixture,
        auth: &ClientAuthConfig,
        credential: &Path,
        tenant: [u8; 16],
    ) -> Result<(AraphorClient, ControlServerFixture)> {
        let address = free_address()?;
        let endpoint = format!("https://localhost:{}", address.port());
        let listener = ClientListener::new(
            ClientListenerConfig {
                listen: address,
                tls_certificate_path: tls.files.server_certificate.clone(),
                tls_private_key_path: tls.files.server_key.clone(),
                auth: auth.clone(),
                administrative: None,
                investigation: Some(ClientGrpcConfig::default()),
                assets: None,
            },
            self.auth.clone(),
            None,
            Some(self.service.clone()),
        )?;
        let server = ControlServerFixture::client(listener, address).await?;
        match AraphorClient::connect(AraphorProfile {
            endpoint,
            tenant_id: uuid::Uuid::from_bytes(tenant).to_string(),
            credential_file: credential.to_path_buf(),
            ca_file: Some(tls.files.ca.clone()),
        })
        .await
        {
            Ok(client) => Ok((client, server)),
            Err(error) => {
                server.shutdown().await?;
                Err(error.into())
            }
        }
    }

    pub(super) async fn operation(
        &self,
        operation: PackageRequestV1,
    ) -> std::result::Result<PackageResponseV1, tonic::Status> {
        let mut request = tonic::Request::new(wire::PackageOperationRequest {
            definition: operation
                .encode()
                .map_err(|_| tonic::Status::internal("fixture request"))?,
            selection: None,
        });
        request.metadata_mut().insert(
            "authorization",
            "Bearer fixture-access"
                .parse()
                .map_err(|_| tonic::Status::internal("fixture credential"))?,
        );
        request.metadata_mut().insert(
            "x-araphor-tenant",
            uuid::Uuid::from_bytes([1; 16])
                .to_string()
                .parse()
                .map_err(|_| tonic::Status::internal("fixture tenant"))?,
        );
        let reply = self.service.package_operation(request).await?.into_inner();
        PackageResponseV1::from_bytes(&reply.result)
            .map_err(|_| tonic::Status::internal("fixture response"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
