use araphor_analysis_sdk::{arrow_array::UInt64Array, Dataset};
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
    ContextSensitivityV1, InstanceStatusV1, ManagedReceipt,
};
use araphor_discovery_definition::Definition;
use erebor_runtime_client::AraphorClient;
use erebor_runtime_ipc::araphor::PackageOperationRequest;
use mithril_control::{ClientAuthConfig, ClientListenerConfig, ControlConfig};

use super::*;

fn configuration(tls: &MtlsFixture, auth: &ClientAuthConfig) -> Result<ControlConfig> {
    let mut config = tls.configuration()?;
    config.client = Some(ClientListenerConfig {
        listen: crate::control_fixture::free_address()?,
        tls_certificate_path: tls.files.server_certificate.clone(),
        tls_private_key_path: tls.files.server_key.clone(),
        auth: auth.clone(),
        administrative: None,
        investigation: Some(mithril_control::ClientGrpcConfig::default()),
        assets: None,
    });
    Ok(config)
}

async fn request(client: &AraphorClient, request: PackageRequestV1) -> Result<PackageResponseV1> {
    let reply = client
        .package_operation(PackageOperationRequest {
            definition: request.encode()?,
            selection: None,
        })
        .await?;
    Ok(PackageResponseV1::from_bytes(&reply.result)?)
}

fn instance(reply: PackageResponseV1) -> Result<InstanceStatusV1> {
    let PackageResponseV1::Instance(status) = reply else {
        return Err("instance response absent".into());
    };
    Ok(status)
}

fn input(fixture: &Fixture, revision: u64, count: u64) -> Result<()> {
    let mut rows = (0..count)
        .map(|event| AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "qualification-denials-v1".into(),
                entity_key: event.to_be_bytes().to_vec(),
                lifetime_key: b"subject".to_vec(),
                owner_revision: revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"resource".to_vec(),
        })
        .collect::<Vec<_>>();
    rows.push(AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "qualification-window-v1".into(),
            entity_key: b"window".to_vec(),
            lifetime_key: b"window".to_vec(),
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    });
    fixture
        .control
        .analysis_store()
        .ok_or("input store")?
        .commit_contexts(&rows)?;
    Ok(())
}

async fn progress(fixture: &Fixture, id: &str, after: u64) -> Result<ManagedReceipt> {
    let data = fixture.control.analysis_store().ok_or("progress store")?;
    let mut changes = data.subscribe_revision();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let next = data
                .managed_history(
                    &AnalysisSelectionV1::tenant([1; 16]),
                    id,
                    &Default::default(),
                )?
                .into_iter()
                .filter(|receipt| receipt.commit_revision > after)
                .max_by_key(|receipt| receipt.commit_revision);
            if let Some(receipt) = next {
                return Ok::<_, Box<dyn std::error::Error>>(receipt);
            }
            changes.changed().await?;
        }
    })
    .await?
}

fn values(data: &Dataset, column: &str) -> Result<Vec<u64>> {
    let mut result = Vec::new();
    for batch in &data.batches {
        let values = batch
            .column_by_name(column)
            .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
            .ok_or("unsigned result column")?;
        result.extend(values.values().iter().copied());
    }
    Ok(result)
}

fn checkpoint(fixture: &Fixture, receipt: &ManagedReceipt) -> Result<araphor_data::ManagedResult> {
    let data = fixture.control.analysis_store().ok_or("checkpoint store")?;
    let control = AnalysisReadControl::default();
    let current = data
        .managed_instance([1; 16], &receipt.instance, &control)?
        .ok_or("saved instance")?;
    let (call, _) = current
        .spec
        .manifest
        .calls
        .iter()
        .find(|(_, call)| {
            call.package.package_id == "denials.count"
                && call.package.revision == "1"
                && call.export == "count"
        })
        .ok_or("declared count call")?;
    let reference = receipt.results.get(call).ok_or("count call receipt")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        .try_into()?;
    Ok(data.managed_result(&current, &reference.result_id, now, &control)?)
}

#[tokio::test]
async fn public_instance_reacts() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let oidc = OidcFixture::start(&tls.files, "instance-operator").await?;
    let bundle = Denials::bundle("public-1", 2, false);
    let mut auth = oidc.auth(
        "https://localhost:44444",
        Some([1; 16]),
        tls.files.ca.clone(),
    );
    auth.package_managers = auth.investigators.clone();
    auth.package_trust = vec![PackageTrustPinV1 {
        tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        bundle_digest: bundle.digest()?,
    }];
    let config = configuration(&tls, &auth)?;
    let authority = Arc::new(ClientAuth::load(&auth).await?);
    let credential = tls.path().join("instance-token");
    fs::write(&credential, b"fixture-access")?;
    let outcome: Result<_> = async {
        let fixture = Fixture::configured(config.clone(), authority.clone())?;
        let (fixture, client, server) = fixture.connected(&tls, &auth, &credential).await?;
        let outcome: Result<_> = async {
            let PackageResponseV1::Image(image) = request(&client, PackageRequestV1::InstallImage { bundle: bundle.clone() }).await? else { return Err("installed image".into()); };
            assert_eq!(image, bundle.metadata()?);
            let path = tls.path().join("instance.yaml");
            fs::write(&path, "name: public-denials\ndescription: Count fixture denials.\nsql: 'SELECT * FROM \"denials.repeated\".\"public-1\".repeated()'\n")?;
            let PackageResponseV1::Definition(definition) = request(&client, PackageRequestV1::AdmitDefinition { definition: Definition::read(&path)? }).await? else { return Err("admitted definition".into()); };
            let admitted = instance(request(&client, PackageRequestV1::AdmitInstance { instance_id: "public-denials".into(), definition_name: definition.definition.name.clone(), definition_revision: definition.digest()? }).await?)?;
            assert!(!admitted.running);
            assert_eq!(admitted.progress, 0);
            let data = fixture.control.analysis_store().ok_or("admitted store")?;
            let stored = data.managed_instance([1; 16], &admitted.id, &Default::default())?.ok_or("admitted instance")?;
            assert_eq!(stored.spec.definition, definition);
            assert_eq!(stored.spec.manifest.calls.len(), 2);
            assert_eq!(stored.spec.definition.images[0].digest, bundle.digest()?);
            let (count, upstream) = stored.spec.manifest.calls.iter().find(|(_, call)| call.package.package_id == "denials.count").ok_or("count dependency")?;
            assert_eq!(upstream.package.revision, "1");
            assert_eq!(upstream.export, "count");
            let (_, downstream) = stored.spec.manifest.calls.iter().find(|(_, call)| call.package.package_id == "denials.repeated").ok_or("repeated caller")?;
            assert_eq!(downstream.package.revision, "public-1");
            assert_eq!(downstream.export, "repeated");
            assert_eq!(downstream.dependencies, std::collections::BTreeSet::from([*count]));
            assert!(data.managed_history(&AnalysisSelectionV1::tenant([1; 16]), &admitted.id, &Default::default())?.is_empty());
            input(&fixture, 1, 2)?;
            let running = instance(request(&client, PackageRequestV1::StartInstance { instance_id: admitted.id.clone(), expected_lifecycle: admitted.lifecycle }).await?)?;
            assert!(running.running);
            let first = progress(&fixture, &admitted.id, 0).await?;
            assert_eq!(first.results.len(), 2);
            assert_eq!(first.selected.commit_revision, first.commit_revision);
            assert!(first.results.values().all(|reference| reference.commit_revision == first.commit_revision));
            let saved = checkpoint(&fixture, &first)?;
            assert_eq!(saved.context.target, "sql");
            let initial = saved.context.clone();
            assert_eq!(saved.commit_revision, first.commit_revision);
            assert_eq!(values(&saved.output.datasets[0], "count")?, [2]);
            let state = saved.output.checkpoint.ok_or("first checkpoint")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets.len(), 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(values(&state.datasets[0], "runs")?, [1]);
            input(&fixture, 2, 3)?;
            let second = progress(&fixture, &admitted.id, first.commit_revision).await?;
            assert_eq!(second.results.len(), 2);
            assert_eq!(second.selected.commit_revision, second.commit_revision);
            assert!(second.results.values().all(|reference| reference.commit_revision == second.commit_revision));
            let saved = checkpoint(&fixture, &second)?;
            assert_eq!(saved.commit_revision, second.commit_revision);
            assert_ne!(saved.context.inputs, initial.inputs);
            assert_eq!(values(&saved.output.datasets[0], "count")?, [3]);
            let state = saved.output.checkpoint.ok_or("second checkpoint")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets.len(), 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(values(&state.datasets[0], "runs")?, [1]);
            let earlier = checkpoint(&fixture, &first)?;
            assert!(!earlier.current);
            assert_eq!(earlier.context, initial);
            assert_eq!(earlier.commit_revision, first.commit_revision);
            assert_eq!(values(&earlier.output.datasets[0], "count")?, [2]);
            let state = earlier.output.checkpoint.ok_or("retained checkpoint")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets.len(), 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(values(&state.datasets[0], "runs")?, [1]);
            let PackageResponseV1::Output(output) = request(&client, PackageRequestV1::ReadInstanceResult { instance_id: admitted.id.clone(), result_id: second.selected.result_id.clone() }).await? else { return Err("selected output".into()); };
            assert_eq!(values(&output.decode_any()?, "count")?, [3]);
            let stopped = instance(request(&client, PackageRequestV1::StopInstance { instance_id: admitted.id.clone(), expected_lifecycle: running.lifecycle }).await?)?;
            assert!(!stopped.running);
            assert_eq!(stopped.progress, second.commit_revision);
            input(&fixture, 3, 4)?;
            let inspected = instance(request(&client, PackageRequestV1::InspectInstance { instance_id: stopped.id.clone() }).await?)?;
            assert_eq!(inspected.progress, stopped.progress);
            let PackageResponseV1::History(history) = request(&client, PackageRequestV1::InspectInstanceHistory { instance_id: stopped.id.clone() }).await? else { return Err("stopped history".into()); };
            assert_eq!(history.len(), 2);
            assert!(history.contains(&first));
            assert!(history.contains(&second));
            Ok((stopped, second, history))
        }.await;
        drop(client);
        let network = server.shutdown().await;
        let host = fixture.shutdown().await;
        network?;
        host?;
        let (stopped, receipt, expected) = outcome?;
        let fixture = Fixture::configured(config, authority)?;
        let (fixture, client, server) = fixture.connected(&tls, &auth, &credential).await?;
        let outcome: Result<()> = async {
            let status = instance(request(&client, PackageRequestV1::InspectInstance { instance_id: stopped.id.clone() }).await?)?;
            assert!(!status.running);
            assert_eq!(status.lifecycle, stopped.lifecycle);
            assert_eq!(status.generation, stopped.generation);
            assert_eq!(status.progress, stopped.progress);
            let PackageResponseV1::History(history) = request(&client, PackageRequestV1::InspectInstanceHistory { instance_id: stopped.id }).await? else { return Err("reopened history".into()); };
            assert_eq!(history, expected);
            let saved = checkpoint(&fixture, &receipt)?;
            assert_eq!(values(&saved.output.datasets[0], "count")?, [3]);
            let state = saved.output.checkpoint.ok_or("reopened checkpoint")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets.len(), 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(values(&state.datasets[0], "runs")?, [1]);
            Ok(())
        }.await;
        drop(client);
        let network = server.shutdown().await;
        let host = fixture.shutdown().await;
        network?;
        host?;
        outcome
    }.await;
    oidc.shutdown().await?;
    outcome
}

#[tokio::test]
async fn public_receipt_reopens() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let oidc = OidcFixture::start(&tls.files, "receipt-operator").await?;
    let bundle = Denials::bundle("public-1", 2, false);
    let mut auth = oidc.auth(
        "https://localhost:44444",
        Some([1; 16]),
        tls.files.ca.clone(),
    );
    auth.package_managers = auth.investigators.clone();
    auth.package_trust = vec![PackageTrustPinV1 {
        tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        bundle_digest: bundle.digest()?,
    }];
    let config = configuration(&tls, &auth)?;
    let authority = Arc::new(ClientAuth::load(&auth).await?);
    let credential = tls.path().join("receipt-token");
    fs::write(&credential, b"fixture-access")?;
    let outcome: Result<()> = async {
        let fixture = Fixture::configured(config.clone(), authority.clone())?;
        let (fixture, client, server) = fixture.connected(&tls, &auth, &credential).await?;
        let outcome: Result<_> = async {
            request(&client, PackageRequestV1::InstallImage { bundle }).await?;
            let path = tls.path().join("receipt.yaml");
            fs::write(&path, "name: receipt-denials\nsql: 'SELECT * FROM \"denials.repeated\".\"public-1\".repeated()'\n")?;
            let PackageResponseV1::Definition(definition) = request(&client, PackageRequestV1::AdmitDefinition { definition: Definition::read(&path)? }).await? else { return Err("receipt definition".into()); };
            let admitted = instance(request(&client, PackageRequestV1::AdmitInstance { instance_id: "receipt-denials".into(), definition_name: definition.definition.name.clone(), definition_revision: definition.digest()? }).await?)?;
            input(&fixture, 1, 2)?;
            let run = PackageRequestV1::RunInstance { instance_id: admitted.id, expected_lifecycle: admitted.lifecycle, evaluation_id: "public-retry".into(), rebuild: false };
            let PackageResponseV1::History(receipts) = request(&client, run.clone()).await? else { return Err("finite receipts".into()); };
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].selected.commit_revision, receipts[0].commit_revision);
            assert_eq!(receipts[0].results.len(), 2);
            assert!(receipts[0].results.values().all(|reference| reference.commit_revision == receipts[0].commit_revision));
            let before = fixture.control.analysis_store().ok_or("retry store")?.meta()?;
            let PackageResponseV1::History(repeated) = request(&client, run.clone()).await? else { return Err("repeated receipts".into()); };
            assert_eq!(repeated, receipts);
            assert_eq!(fixture.control.analysis_store().ok_or("retry store")?.meta()?, before);
            let saved = checkpoint(&fixture, &receipts[0])?;
            assert_eq!(saved.commit_revision, receipts[0].commit_revision);
            assert_eq!(values(&saved.output.datasets[0], "count")?, [2]);
            let state = saved.output.checkpoint.ok_or("finite checkpoint")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets.len(), 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(values(&state.datasets[0], "runs")?, [1]);
            Ok((run, receipts))
        }.await;
        drop(client);
        let network = server.shutdown().await;
        let host = fixture.shutdown().await;
        network?;
        host?;
        let (run, receipts) = outcome?;
        let fixture = Fixture::configured(config, authority)?;
        let (fixture, client, server) = fixture.connected(&tls, &auth, &credential).await?;
        let outcome: Result<()> = async {
            let before = fixture.control.analysis_store().ok_or("reopened store")?.meta()?;
            let PackageResponseV1::History(repeated) = request(&client, run).await? else { return Err("reopened receipt".into()); };
            assert_eq!(repeated, receipts);
            assert_eq!(fixture.control.analysis_store().ok_or("reopened store")?.meta()?, before);
            let saved = checkpoint(&fixture, &receipts[0])?;
            assert_eq!(values(&saved.output.datasets[0], "count")?, [2]);
            let state = saved.output.checkpoint.ok_or("saved checkpoint")?;
            assert_eq!(state.version, 1);
            assert_eq!(state.datasets.len(), 1);
            assert_eq!(state.datasets[0].name, "state");
            assert_eq!(values(&state.datasets[0], "runs")?, [1]);
            Ok(())
        }.await;
        drop(client);
        let network = server.shutdown().await;
        let host = fixture.shutdown().await;
        network?;
        host?;
        outcome
    }.await;
    oidc.shutdown().await?;
    outcome
}
