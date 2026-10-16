use std::{path::Path, sync::Arc, time::Duration};

use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisSelectionV1, ContextSensitivityV1,
    PackageActionV1, PackageRequestV1, PackageResponseV1,
};
use duckdb::arrow::array::UInt64Array;
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
    pub(super) intake: EvidenceIntakeOwner,
    service: ClientGrpcOwner,
    auth: Arc<ClientAuth>,
}

pub(super) struct Worker {
    stop: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<araphor_analysis::Result<()>>>,
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
        let service =
            ClientGrpcOwner::new(control.clone(), auth.clone(), ClientGrpcConfig::default())?;
        Ok(Self {
            control,
            intake,
            service,
            auth,
        })
    }

    pub(super) fn worker(&self) -> Result<Worker> {
        let owner = self
            .service
            .package_owner()
            .ok_or("package owner is absent")?;
        let (stop, receiver) = tokio::sync::watch::channel(false);
        Ok(Worker {
            stop,
            task: Some(tokio::spawn(owner.serve(receiver))),
        })
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

    pub(super) async fn wait_current(
        &self,
        previous: &str,
        worker: &mut Worker,
    ) -> Result<PackageResponseV1> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        let store = self
            .control
            .analysis_store()
            .ok_or("retained store is absent")?;
        let mut revisions = store.subscribe_revision();
        loop {
            worker.check().await?;
            let _revision = *revisions.borrow_and_update();
            let response = match self.inspect().await {
                Ok(response) => response,
                Err(error)
                    if error.code() == tonic::Code::Unavailable
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let results: Vec<_> = response
                .exports
                .iter()
                .flat_map(|export| &export.results)
                .collect();
            if !results.is_empty()
                && results
                    .iter()
                    .all(|result| !result.stale && result.result_id != previous)
            {
                return Ok(response);
            }
            if tokio::time::Instant::now() >= deadline {
                let upstream = self
                    .operation(PackageRequestV1::Inspect {
                        scope_id: "qualified".into(),
                        package_id: "denials.count".into(),
                    })
                    .await?;
                let states: Vec<_> = upstream.exports.into_iter().chain(response.exports)
                    .take(2).map(|export| serde_json::json!({
                        "export":export.descriptor.name,"active":export.active,"readiness":export.readiness,
                        "results":export.results.iter().take(1).map(|result| serde_json::json!({
                            "id":result.result_id,"stale":result.stale,"revision":result.commit_revision,
                        })).collect::<Vec<_>>(),
                    })).collect();
                return Err(format!(
                    "automatic source replacement did not finish: {}",
                    serde_json::to_string(&states)?
                )
                .into());
            }
            if let Ok(changed) = tokio::time::timeout_at(deadline, revisions.changed()).await {
                changed?;
            }
        }
    }

    pub(super) async fn checkpoint(&self) -> Result<u64> {
        let response = self
            .operation(PackageRequestV1::Inspect {
                scope_id: "qualified".into(),
                package_id: "denials.count".into(),
            })
            .await?;
        let export = response.exports.first().ok_or("count export is absent")?;
        let receipt = export
            .results
            .iter()
            .max_by_key(|result| result.commit_revision)
            .ok_or("count result is absent")?;
        let access = self.auth.service("fixture-access", [1; 16]).await?;
        let grant = access.package_grant(
            AnalysisSelectionV1::tenant([1; 16]),
            PackageActionV1::Inspect,
        )?;
        let owner = self
            .service
            .package_owner()
            .ok_or("package owner is absent")?;
        let output = owner.read_output(
            &grant,
            "qualified",
            "denials.count",
            "count",
            &receipt.result_id,
        )?;
        let checkpoint =
            araphor_analysis::AnalysisPackageOwner::decode_output(&output, &export.descriptor)?
                .checkpoint
                .ok_or("checkpoint is absent")?;
        if checkpoint.version != 1 || checkpoint.datasets.len() != 1 {
            return Err("checkpoint shape changed".into());
        }
        let state = &checkpoint.datasets[0];
        if state.name != "state" || state.batches.len() != 1 || state.batches[0].num_rows() != 1 {
            return Err("checkpoint state shape changed".into());
        }
        let runs = state.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("checkpoint runs has another type")?;
        Ok(runs.value(0))
    }

    pub(super) fn window(&self, revision: u64, count: u8) -> Result<()> {
        let store = self
            .control
            .analysis_store()
            .ok_or("retained store is absent")?;
        for event in 1..=count {
            store.commit_context(&AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: [1; 16],
                    owner_id: "qualification-denials-v1".into(),
                    entity_key: format!("denial-{event}").into_bytes(),
                    lifetime_key: b"subject-instance".to_vec(),
                    owner_revision: revision,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                body: b"credential-file".to_vec(),
            })?;
        }
        store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "qualification-window-v1".into(),
                entity_key: b"window".to_vec(),
                lifetime_key: b"window-1".to_vec(),
                owner_revision: revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"complete".to_vec(),
        })?;
        Ok(())
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
        serde_json::from_slice(&reply.result_json)
            .map_err(|_| tonic::Status::internal("fixture response"))
    }

    pub(super) async fn inspect(&self) -> std::result::Result<PackageResponseV1, tonic::Status> {
        self.operation(PackageRequestV1::Inspect {
            scope_id: "qualified".into(),
            package_id: "denials.repeated".into(),
        })
        .await
    }

    pub(super) async fn run(&self, identity: &str) -> Result<PackageResponseV1> {
        Ok(self
            .operation(PackageRequestV1::Run {
                scope_id: "qualified".into(),
                package_id: "denials.repeated".into(),
                export: None,
                evaluation_id: identity.into(),
                parameters: None,
            })
            .await?)
    }

    pub(super) async fn counts(&self, result_id: Option<String>) -> Result<serde_json::Value> {
        let response = self
            .operation(PackageRequestV1::Query {
                scope_id: "qualified".into(),
                package_id: "denials.repeated".into(),
                export: "repeated".into(),
                result_id,
                sql: "SELECT count FROM rows ORDER BY count".into(),
            })
            .await?;
        let rows = araphor_analysis::AnalysisPackageOwner::output_rows(
            &response.output.ok_or("query output is absent")?,
        )?;
        rows.get("query")
            .cloned()
            .ok_or_else(|| "query rows are absent".into())
    }
}

impl Worker {
    async fn check(&mut self) -> Result<()> {
        if self
            .task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            if let Some(task) = self.task.take() {
                task.await??;
            }
            return Err("automatic package worker stopped before replacement".into());
        }
        Ok(())
    }

    pub(super) async fn stop(mut self) -> Result<()> {
        self.stop.send_replace(true);
        if let Some(task) = self.task.as_mut() {
            tokio::time::timeout(Duration::from_secs(20), task).await???;
        }
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
