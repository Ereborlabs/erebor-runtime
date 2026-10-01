use std::{fs, time::Duration};

use ed25519_dalek::SigningKey;
use mithril_control::{
    ControlStore, KubernetesNodeControlConfigV1, KubernetesNodeReadinessOwner,
    NodeDecommissionAuthorizationV1, NodeDecommissionStateV1, NodeDecommissionStatusV1,
    SignedNodeDecommissionV1,
};
use mithril_node::TrustCache;
use sha2::{Digest as _, Sha256};

use super::{OutagePolicyFixture, OUTAGE_CLUSTER_UID};
use crate::control_fixture::{ControlServerFixture, MtlsFixture};
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
    let server =
        ControlServerFixture::admission(&tls.files, kube, control, fixture.owner, nodes).await?;
    let url = format!(
        "https://localhost:{}/v1/node-decommissions",
        server.address().port()
    );

    let artifact = SignedNodeDecommissionV1::sign(
        &NodeDecommissionAuthorizationV1::new(
            OUTAGE_CLUSTER_UID,
            "node-a".to_owned(),
            &uuid::Uuid::from_bytes([1; 16]).hyphenated().to_string(),
            i64::MAX,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )?,
        "offline-decommission-v1".to_owned(),
        &SigningKey::from_bytes(&[9; 32]),
    )?
    .to_bytes()?;
    let digest = format!("{:x}", Sha256::digest(&artifact));
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&tls.files.ca)?)?)
        .timeout(Duration::from_secs(2))
        .build()?;
    let response = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(artifact)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::ACCEPTED);
    let submitted: NodeDecommissionStatusV1 = response.json().await?;
    assert_eq!(submitted.state, NodeDecommissionStateV1::Submitted);
    assert_eq!(submitted.artifact_sha256, digest);
    let response = client
        .get(format!("{url}/{}", submitted.artifact_sha256))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<NodeDecommissionStatusV1>().await?,
        submitted
    );

    server.shutdown().await?;
    drop(connection);
    grpc_server.shutdown().await?;
    Ok(())
}
