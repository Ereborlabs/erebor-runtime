use std::{collections::BTreeMap, fs, sync::Arc, time::Duration};

use erebor_runtime_ipc::araphor::{
    araphor_administrative_service_client::AraphorAdministrativeServiceClient,
    GetNodeDecommissionRequest, SubmitNodeDecommissionRequest,
};
use mithril_control::{
    AdministrativeApprovalConfigV1, AdministrativeConfig, AdministrativeHttpOwner, ClientAuth,
    ClientListener, ClientListenerConfig, ControlStore, KubernetesNodeControlConfigV1,
    KubernetesNodeReadinessOwner,
};
use mithril_node::TrustCache;
use sha2::{Digest as _, Sha256};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

use super::OutagePolicyFixture;
use crate::control_fixture::{free_address, oidc::OidcFixture, ControlServerFixture, MtlsFixture};
use crate::platform::TestResult;

#[tokio::test]
async fn https_decommission_keeps_status() -> TestResult<()> {
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-store"))?;
    let fixture = OutagePolicyFixture::new(store.clone());
    let resource = fixture.resource(1)?;
    let kube = fixture.kubernetes_client(&resource)?;
    let control = tls.control_with_store(store, 1)?;
    let grpc_server = tls.start(control.clone()).await?;
    let connector = tls.connector(&grpc_server, "node-a", [1; 16]);
    let mut trust = TrustCache::load(&tls.path().join("node-trust"))?;
    let connection = connector
        .connect(
            OutagePolicyFixture::registration([1; 16], false),
            true,
            &mut trust,
        )
        .await?;
    let nodes = KubernetesNodeReadinessOwner::new(KubernetesNodeControlConfigV1 {
        daemon_set_namespace: "mithril-system".to_owned(),
        daemon_set_name: "mithril-node".to_owned(),
        session_ttl_seconds: 30,
        reconcile_interval_ms: 100,
    })?;
    let policy = ControlServerFixture::admission(
        &tls.files,
        kube.clone(),
        control.clone(),
        fixture.owner,
        nodes,
    )
    .await?;
    let oidc = OidcFixture::start(&tls.files, "operator").await?;
    let address = free_address()?;
    let origin = format!("https://localhost:{}", address.port());
    let key = tls.path().join("approval-key");
    let webhook = tls.path().join("webhook-token");
    fs::write(&key, "02".repeat(32))?;
    fs::write(&webhook, "03".repeat(32))?;
    let administrative = AdministrativeConfig {
        kubernetes_audience: "mithril-administrative-exec".into(),
        kubernetes_webhook_token_path: webhook,
        node_ids_by_kubernetes_name: BTreeMap::from([(
            "worker-a".into(),
            uuid::Uuid::from_bytes([4; 16]).to_string(),
        )]),
        request_lifetime_seconds: 60,
        approval: AdministrativeApprovalConfigV1 {
            state_directory: tls.path().join("approval-state"),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
            cluster_uid: "55555555-5555-4555-8555-555555555555".into(),
            trust_domain_id: uuid::Uuid::from_bytes([2; 16]).to_string(),
            issuer_id: uuid::Uuid::from_bytes([3; 16]).to_string(),
            key_id: "test-approval".into(),
            private_key_path: key,
            sequence_epoch: 1,
            authorization_lifetime_seconds: 60,
        },
    };
    let config = ClientListenerConfig {
        listen: address,
        tls_certificate_path: tls.files.server_certificate.clone(),
        tls_private_key_path: tls.files.server_key.clone(),
        auth: oidc.auth(&origin, None, tls.files.ca.clone()),
        administrative: Some(administrative.clone()),
        investigation: None,
        assets: None,
    };
    let auth = Arc::new(ClientAuth::load(&config.auth).await?);
    let owner =
        AdministrativeHttpOwner::from_client(&administrative, control, auth.oidc(), &origin, kube)?;
    let listener = ClientListener::new(config, auth, Some(Arc::new(owner)), None)?;
    let server = ControlServerFixture::client(listener, address).await?;
    let channel = Endpoint::from_shared(origin.clone())?
        .tls_config(
            ClientTlsConfig::new().ca_certificate(Certificate::from_pem(fs::read(&tls.files.ca)?)),
        )?
        .timeout(Duration::from_secs(2))
        .connect()
        .await?;
    let mut client = AraphorAdministrativeServiceClient::new(channel);
    let (_, artifact) = tls.decommission([1; 16])?;
    let digest = format!("{:x}", Sha256::digest(&artifact));
    let submitted = client
        .submit_node_decommission(SubmitNodeDecommissionRequest { artifact })
        .await?
        .into_inner();
    assert_eq!(submitted.state, "SUBMITTED");
    assert_eq!(submitted.artifact_sha256, digest);
    assert_eq!(
        client
            .get_node_decommission(GetNodeDecommissionRequest {
                artifact_sha256: digest,
            })
            .await?
            .into_inner(),
        submitted
    );
    let http = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&tls.files.ca)?)?)
        .timeout(Duration::from_secs(2))
        .build()?;
    for endpoint in [
        origin,
        format!("https://localhost:{}", policy.address().port()),
    ] {
        for path in [
            "/v1/node-decommissions",
            "/v1/node-decommissions/missing",
            "/v1/administrative-exec/requests",
            "/v1/administrative-exec/requests/missing",
            "/erebor.mithril.control.v1.UnknownService/Query",
            "/missing",
        ] {
            assert_eq!(
                http.post(format!("{endpoint}{path}"))
                    .send()
                    .await?
                    .status(),
                reqwest::StatusCode::NOT_FOUND,
                "old or unknown route remains: {path}"
            );
        }
    }
    server.shutdown().await?;
    oidc.shutdown().await?;
    policy.shutdown().await?;
    drop(connection);
    grpc_server.shutdown().await?;
    Ok(())
}
