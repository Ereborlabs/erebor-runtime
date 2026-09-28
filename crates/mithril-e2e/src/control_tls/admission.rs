use std::{fs, time::Duration};

use erebor_interceptor_abi::EffectObservationV1;
use mithril_control::{
    AuthenticatedEvidenceNodeV1, ControlPlane, ControlStore, EvidenceIntakeOwner,
    KubernetesNodeControlConfigV1, KubernetesNodeReadinessOwner, TrustGenerationV1,
};
use mithril_node::{EvidenceIdV1, EvidenceWalLimits};
use zerocopy::IntoBytes as _;

use super::OutagePolicyFixture;
use crate::control_fixture::{ControlServerFixture, MtlsFixture};
use crate::platform::TestResult;

#[tokio::test]
async fn admission_keeps_retained_evidence() -> TestResult<()> {
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-store"))?;
    let wal = tls.wal(EvidenceWalLimits::default())?;
    let event = EffectObservationV1 {
        observed_boottime_ns: 1,
        source_sequence: 1,
        source_cpu_id: 0,
        task_cookie: 7,
        reason: 9,
        physical_result: 1,
        effect_family: 1,
        operation: 1,
        ..EffectObservationV1::default()
    };
    wal.record_bytes(event.as_bytes());
    let batch = wal
        .next_evidence_batch()
        .ok_or("missing retained admission evidence")?;
    let node = AuthenticatedEvidenceNodeV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id: [7; 16],
        label_epoch: 1,
    };
    let intake = EvidenceIntakeOwner::try_from(store.clone())?;
    let ack = intake.receive(&node, batch.clone().into())?;
    assert_eq!(ack.contiguous_cursor, 1);

    let fixture = OutagePolicyFixture::new(store.clone());
    let resource = fixture.resource(1)?;
    let kube = fixture.kubernetes_client(&resource)?;
    let review = fixture.protected_pod_admission_review();
    let control = ControlPlane::from_intake(
        Vec::new(),
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
        intake.clone(),
    )?
    .with_policy_desired_state(fixture.owner.clone());
    assert!(control.replace_kubernetes_workload_inventory(Vec::new())?);
    let nodes = KubernetesNodeReadinessOwner::new(KubernetesNodeControlConfigV1 {
        daemon_set_namespace: "mithril-system".to_owned(),
        daemon_set_name: "mithril-node".to_owned(),
        session_ttl_seconds: 30,
        reconcile_interval_ms: 100,
    })?;
    let server =
        ControlServerFixture::admission(&tls.files, kube, control, fixture.owner, nodes).await?;
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&tls.files.ca)?)?)
        .timeout(Duration::from_secs(2))
        .build()?;

    let response = client
        .post(format!(
            "https://localhost:{}/admit",
            server.address().port()
        ))
        .json(&review)
        .send()
        .await?;
    assert!(response.status().is_success());
    let review: serde_json::Value = response.json().await?;
    assert_eq!(review["response"]["uid"], "outage-admission-1");
    assert_eq!(review["response"]["allowed"], true);
    assert!(
        review["response"]["patch"]
            .as_array()
            .is_some_and(|patch| !patch.is_empty()),
        "protected Pod admission did not return a constraint patch: {review}"
    );
    let identity = tls.identity(super::batch_source_id(&batch)?);
    assert_eq!(intake.contiguous_cursor(&identity)?, 1);
    assert_eq!(
        intake
            .analysis_store()
            .read_page(&identity, 1)?
            .records
            .len(),
        1
    );
    assert_eq!(wal.pending_evidence_records(), 1);
    assert_eq!(wal.next_evidence_batch().as_ref(), Some(&batch));

    server.shutdown().await?;
    Ok(())
}
