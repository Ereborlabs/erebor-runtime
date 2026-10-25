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
    host: Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )>,
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
        Self::from_control(control, auth)
    }

    fn from_control(control: ControlPlane, auth: Arc<ClientAuth>) -> Result<Self> {
        let service =
            ClientGrpcOwner::new(control.clone(), auth.clone(), ClientGrpcConfig::default())?;
        Ok(Self {
            control,
            service,
            auth,
            host: None,
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
        if parts.graph.is_some() || parts.discovery.is_some() {
            return Err("instance fixture cannot discard configured source owners".into());
        }
        let host = parts.instances.ok_or("configured Instance Host absent")?;
        let mut fixture = Self::from_control(parts.control, auth)?;
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            host.serve(stopped, u64::MAX)
                .await
                .map_err(std::io::Error::other)
        });
        fixture.host = Some((stop, task));
        Ok(fixture)
    }

    pub(super) async fn shutdown(mut self) -> Result<()> {
        if let Some((stop, task)) = self.host.take() {
            stop.send_replace(true);
            task.await??;
        }
        Ok(())
    }

    pub(super) async fn connected(
        self,
        tls: &MtlsFixture,
        auth: &ClientAuthConfig,
        credential: &Path,
    ) -> Result<(Self, AraphorClient, ControlServerFixture)> {
        match self.client(tls, auth, credential).await {
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
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
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
        if let Some((stop, _)) = &self.host {
            stop.send_replace(true);
        }
    }
}
