use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use ed25519_dalek::SigningKey;
use kube::client::Body as KubeBody;
use kube::Client;
use mithril_control::{
    lower_kubernetes_policy, workload_target_fact_digest, CapabilityRecord, ContainerKindV1,
    ControlPlane, ControlStore, EvidenceIntakeIdentityV1, EvidenceIntakeOwner,
    KubernetesWorkloadIdentityV1, NodeDecommissionAuthorizationV1, NodeDecommissionStateV1,
    NodeRegistration, PolicyActivationAcknowledgement, PolicyBundleV1, PolicyDesiredStateConfigV1,
    PolicyDesiredStateOwner, PolicySignerConfigV1, PolicySourceRevisionV1, PolicySourceStateV1,
    ProfileSealRequestV1, RegistryDigestsV1, SignedNodeDecommissionV1, WorkloadProtectionPolicy,
    WorkloadTargetFactV1,
};
use mithril_node::{
    CoverageGapReasonV1, EffectObservationStore, EvidenceIdV1, EvidenceWalLimits,
    NodeControlConnector, NodeControlMessage, NodeDecommissionAcceptanceV1, NodeDecommissionConfig,
    NodeDecommissionOwner, ObservationCanonicalizer, PolicyControlPacingOwner, TrustCache,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{oneshot, watch};
use tower::service_fn;
use zerocopy::IntoBytes as _;

use crate::control_fixture::{Certificates, MtlsFixture};
use crate::physical::wait_for_async;

mod administrative;
mod admission;
mod backlog;
mod coverage;
mod decommission;
mod gap;
mod intake_budget;
mod readiness;
mod registration;
mod rejection;
mod replay;
mod retained;
mod retention;
mod storage;
mod transfer;
mod transfer_tests;

const OUTAGE_POLICY: &[u8] = include_bytes!("../fixtures/convergence/outage-policy-v1.json");
const OUTAGE_TENANT_ID: &str = "00000000-0000-0001-0000-000000000002";
const OUTAGE_CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
const OUTAGE_NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
const OUTAGE_POLICY_UID: &str = "30000000-0000-4000-8000-000000000001";
const OUTAGE_NOW: i64 = 1_800_000_000_000_000_000;

#[tokio::test]
async fn kubernetes_outage_pending_policy_transfer_preempts_evidence_ack_backlog(
) -> Result<(), Box<dyn StdError>> {
    let mut pacing = PolicyControlPacingOwner::default();
    pacing.mark_pending();
    let mut poll = tokio::time::interval(Duration::from_secs(60));
    let (sender, mut messages) = tokio::sync::mpsc::unbounded_channel();
    if sender.send(()).is_err() {
        return Err("the message receiver closed before the test started".into());
    }

    let selected_policy = tokio::select! {
        biased;
        () = pacing.wait_until_ready(&mut poll) => true,
        Some(()) = messages.recv() => false,
    };

    assert!(selected_policy);
    Ok(())
}

#[test]
#[ignore = "the startup budget requires the shipped release optimization level"]
fn kubernetes_outage_retained_control_store_starts_from_latest_state(
) -> Result<(), Box<dyn StdError>> {
    const FIXTURE_BATCHES: u64 = 3_204;
    const RECORDS_PER_BATCH: usize = 74;
    const LEGACY_BYTES_PER_RECORD: u64 = 16_776;
    const STARTUP_BUDGET: Duration = Duration::from_secs(5);

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("control-store");
    let store = ControlStore::open(&store_path)?;
    let stored_bytes =
        store.write_retained_evidence_for_test(FIXTURE_BATCHES, RECORDS_PER_BATCH)?;
    let commit_index = store.commit_index();
    drop(store);

    let started = Instant::now();
    let reopened = ControlStore::open(&store_path)?;
    let elapsed = started.elapsed();
    let record_count = FIXTURE_BATCHES * RECORDS_PER_BATCH as u64;
    eprintln!(
        "opened {record_count} retained records in {elapsed:?}; compact store uses {stored_bytes} bytes"
    );
    assert_eq!(reopened.commit_index(), commit_index);
    assert_eq!(reopened.health()?.evidence_cursors, 1);
    assert!(elapsed <= STARTUP_BUDGET);
    assert!(stored_bytes * 100 <= LEGACY_BYTES_PER_RECORD * record_count);
    assert!(store_path.join("state.bin").is_file());
    assert!(!store_path.join("commits").exists());
    let segment_count = fs::read_dir(store_path.join("evidence/segments-v2"))?.count() as u64;
    assert!(segment_count > 0 && segment_count < FIXTURE_BATCHES);
    Ok(())
}

struct OutagePolicyFixture {
    owner: PolicyDesiredStateOwner,
}

impl OutagePolicyFixture {
    fn new(store: ControlStore) -> Self {
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

    fn resource(&self, generation: i64) -> Result<WorkloadProtectionPolicy, Box<dyn StdError>> {
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

    fn inventory(
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

    fn active_acknowledgement(
        bundle: &PolicyBundleV1,
        profile_generation_ref_id: u64,
        observed_utc_ns: i64,
    ) -> PolicyActivationAcknowledgement {
        PolicyActivationAcknowledgement {
            tenant_id: bundle.candidate.tenant_id.clone(),
            candidate_content_id: bundle.candidate.candidate_content_id.clone(),
            policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
            target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
            state: "ACTIVE".to_owned(),
            node_bound_generation_digest: "1".repeat(64),
            profile_generation_ref_id,
            readback_digest: "2".repeat(64),
            probe_result_digest: "3".repeat(64),
            reason_code: String::new(),
            observed_utc_ns,
        }
    }

    fn kubernetes_client(
        &self,
        resource: &WorkloadProtectionPolicy,
    ) -> Result<Client, Box<dyn StdError>> {
        let policy = serde_json::to_value(resource)?;
        let service = service_fn(move |request: Request<KubeBody>| {
            let policy = policy.clone();
            async move {
                let value = match request.uri().path() {
                    "/api/v1/namespaces/tenant-a" => serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Namespace",
                        "metadata": {"name": "tenant-a", "uid": OUTAGE_NAMESPACE_UID}
                    }),
                    "/api/v1/namespaces/tenant-a/serviceaccounts/worker" => {
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "ServiceAccount",
                            "metadata": {
                                "name": "worker",
                                "namespace": "tenant-a",
                                "uid": "77777777-7777-4777-8777-777777777777"
                            }
                        })
                    }
                    "/apis/mithril.erebor.dev/v1alpha1/namespaces/tenant-a/workloadprotectionpolicies" => {
                        serde_json::json!({
                            "apiVersion": "mithril.erebor.dev/v1alpha1",
                            "kind": "WorkloadProtectionPolicyList",
                            "metadata": {"resourceVersion": "outage-list-1"},
                            "items": [policy]
                        })
                    }
                    "/apis/apps/v1/namespaces/mithril-system/daemonsets/mithril-node" => {
                        serde_json::json!({
                            "apiVersion": "apps/v1",
                            "kind": "DaemonSet",
                            "metadata": {"name": "mithril-node", "namespace": "mithril-system"},
                            "spec": {
                                "selector": {"matchLabels": {"app": "mithril-node"}},
                                "template": {
                                    "metadata": {"labels": {"app": "mithril-node"}},
                                    "spec": {
                                        "nodeSelector": {"kubernetes.io/os": "linux"},
                                        "containers": [{"name": "mithril-node", "image": "mithril-node:test"}]
                                    }
                                }
                            }
                        })
                    }
                    _ => {
                        let mut response = Response::new(Body::empty());
                        *response.status_mut() = StatusCode::NOT_FOUND;
                        return Ok::<_, Infallible>(response);
                    }
                };
                let mut response = Response::new(Body::from(value.to_string()));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                Ok::<_, Infallible>(response)
            }
        });
        Ok(Client::new(service, "default"))
    }

    fn protected_pod_admission_review(&self) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "outage-admission-1",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "name": "outage-a",
                "namespace": "tenant-a",
                "operation": "CREATE",
                "userInfo": {},
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "outage-a",
                        "namespace": "tenant-a",
                        "labels": {"app.kubernetes.io/name": "mithril-outage-worker"}
                    },
                    "spec": {
                        "serviceAccountName": "worker",
                        "runtimeClassName": "mithril-outage-recovery",
                        "nodeSelector": {"qualification.mithril.erebor.dev/node": "a"},
                        "containers": [{
                            "name": "worker",
                            "image": concat!(
                                "docker.io/library/busybox:1.36.1@sha256:",
                                "73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
                            )
                        }]
                    }
                }
            }
        })
    }

    fn registration(node_boot_id: [u8; 16], active_policy: bool) -> NodeRegistration {
        let mut registration = registration_for(node_boot_id, 1);
        registration.effect_prevention_claims_enabled = true;
        registration.kubernetes_node_name = "worker-a".to_owned();
        registration.policy_authority_absent = !active_policy;
        registration.startup_absence_proof_digest = mithril_control::startup_absence_proof_digest(
            "node-a",
            &node_boot_id,
            1,
            !active_policy,
            true,
        );
        registration
    }
}

#[tokio::test]
async fn signed_node_decommission_uses_the_same_durable_mtls_sequence_as_kubernetes(
) -> Result<(), Box<dyn StdError>> {
    let fixture = MtlsFixture::new(false)?;
    let control = fixture.control(4)?;
    let server = fixture.start(control.clone()).await?;
    let connector = fixture.connector(&server, "node-a", [7; 16]);
    let mut trust = TrustCache::load(fixture.path())?;
    let mut node = registration();
    node.kubernetes_node_name = "worker-a.example".to_owned();
    let mut connection = connector.connect(node, true, &mut trust).await?;
    control
        .bind_kubernetes_node_session("worker-a.example", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
    let session = control
        .ready_kubernetes_node_sessions(Duration::from_secs(2))
        .into_iter()
        .next()
        .ok_or("registered node has no ready Kubernetes session")?;

    let signing_key = SigningKey::from_bytes(&[9; 32]);
    let public_key = fixture.path().join("decommission-public-key");
    fs::write(&public_key, signing_key.verifying_key().to_bytes())?;
    let artifact = SignedNodeDecommissionV1::sign(
        &NodeDecommissionAuthorizationV1::new(
            "55555555-5555-4555-8555-555555555555",
            "node-a".to_owned(),
            &uuid::Uuid::from_bytes([7; 16]).hyphenated().to_string(),
            i64::MAX,
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )?,
        "offline-decommission-v1".to_owned(),
        &signing_key,
    )?
    .to_bytes()?;
    let submitted = control.submit_node_decommission(artifact.clone()).await?;
    let hash = &submitted.artifact_sha256;
    let NodeControlMessage::Decommission(prepare) = connection.next_message().await? else {
        return Err("Control did not deliver decommission preparation".into());
    };
    assert!(!prepare.execute);
    assert_eq!(prepare.artifact, artifact);

    let mut node_owner = NodeDecommissionOwner::load(
        &NodeDecommissionConfig {
            cluster_uid: "55555555-5555-4555-8555-555555555555".to_owned(),
            signing_key_id: "offline-decommission-v1".to_owned(),
            public_key_path: public_key,
            runtime_integration_owner: "mithril-system/mithril".to_owned(),
            runtime_hook_directory: fixture.path().join("host-hook-bin"),
            containerd_config_directory: fixture.path().join("host-containerd"),
            containerd_drop_in_directory: "conf.d".to_owned(),
            runtime_services: vec!["containerd".to_owned()],
        },
        &fixture.path().join("node-state"),
        "node-a".to_owned(),
        erebor_interceptor_abi::Id128V1::from([7; 16]),
    )?;
    assert_eq!(
        node_owner.accept(&prepare.artifact, 0, 1)?,
        NodeDecommissionAcceptanceV1::Accepted
    );
    let digest: [u8; 32] = Sha256::digest(&prepare.artifact).into();
    connection
        .send_decommission_result(digest, "ACCEPTED", String::new())
        .await?;
    wait_for_decommission_state(&control, hash, NodeDecommissionStateV1::Accepted).await?;
    let ready = || control.ready_kubernetes_node_sessions(Duration::from_secs(2));
    wait_for_async(
        fixture.path(),
        "the accepted node session to leave the ready set",
        Duration::from_secs(2),
        || Ok(ready().is_empty().then_some(())),
        || format!("last ready sessions: {:?}", ready()),
    )
    .await?;

    control
        .confirm_node_decommission_quarantine_for_test(&session)
        .await?;
    let NodeControlMessage::Decommission(execute) = connection.next_message().await? else {
        return Err("Control did not deliver quarantined decommission execution".into());
    };
    assert!(execute.execute);
    assert_eq!(
        node_owner.accept(&execute.artifact, 0, 1)?,
        NodeDecommissionAcceptanceV1::ResumeCleanup
    );
    node_owner.complete(&execute.artifact)?;
    connection
        .send_decommission_result(digest, "COMPLETED", String::new())
        .await?;
    wait_for_decommission_state(&control, hash, NodeDecommissionStateV1::Completed).await?;

    drop(connection);
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn kubernetes_outage_mtls_session_converges_policy_while_replaying_retained_evidence(
) -> Result<(), Box<dyn StdError>> {
    let tls = MtlsFixture::new(false)?;
    let intake_path = tls.path().join("control-evidence");
    let node_boot_id = [7; 16];

    let store = ControlStore::open(&intake_path)?;
    let restart_store = store.clone();
    let fixture = OutagePolicyFixture::new(store.clone());
    let first_resource = fixture.resource(1)?;
    let workload_inventory = fixture.inventory(&first_resource)?;
    let control = tls
        .control_with_store(store, 1)?
        .with_policy_desired_state(fixture.owner.clone());

    let first_server = tls.start(control.clone()).await?;
    let old_connector = tls.connector(&first_server, "node-a", node_boot_id);
    let mut trust = TrustCache::load(&tls.path().join("trust"))?;
    let mut old_connection = match old_connector
        .connect(
            OutagePolicyFixture::registration(node_boot_id, false),
            false,
            &mut trust,
        )
        .await
    {
        Ok(connection) => connection,
        Err(source) => {
            let server_result = first_server.shutdown().await;
            return Err(format!(
                "initial Control connection failed: {source}; server result: {server_result:?}"
            )
            .into());
        }
    };
    old_connection.report_readiness(true, true).await?;
    control.bind_kubernetes_node_session("worker-a", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
    assert!(control.replace_kubernetes_workload_inventory(workload_inventory.clone())?);
    let first = fixture.owner.reconcile(
        &first_resource,
        OUTAGE_NAMESPACE_UID,
        &workload_inventory,
        OUTAGE_NOW,
    )?;
    let first_bundle = first
        .bundles
        .first()
        .ok_or("missing initial policy bundle")?;
    let first_inventory = old_connection.policy_inventory(None, Vec::new()).await?;
    assert!(first_inventory.desired_inventory_complete);
    assert!(first_inventory.candidate_available);
    assert_eq!(
        first_inventory.candidate_content_id,
        first_bundle.candidate.candidate_content_id
    );
    assert_eq!(first_inventory.bundle_digest, first_bundle.bundle_digest);
    let accepted = old_connection
        .acknowledge_policy(OutagePolicyFixture::active_acknowledgement(
            first_bundle,
            1,
            OUTAGE_NOW + 1,
        ))
        .await?;
    assert_eq!(accepted.rollout_state, "ACTIVE");
    let active_first = fixture.owner.reconcile(
        &first_resource,
        OUTAGE_NAMESPACE_UID,
        &workload_inventory,
        OUTAGE_NOW + 2,
    )?;
    assert_eq!(active_first.status.rollout.active, 1);
    let first_candidate_id = first_bundle.candidate.candidate_content_id.clone();
    let first_bundle_digest = first_bundle.bundle_digest.clone();
    drop(old_connection);
    first_server.shutdown().await?;
    drop(control);
    drop(fixture);

    let observations = tls.wal(EvidenceWalLimits::default())?;
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: 1,
            source_sequence: 1,
            source_cpu_id: 0,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    let retained = observations
        .next_evidence_batch()
        .ok_or("missing retained evidence batch")?;
    let source_id = batch_source_id(&retained)?;

    let store = restart_store;
    let fixture = OutagePolicyFixture::new(store.clone());
    let second_resource = fixture.resource(2)?;
    let second = fixture.owner.reconcile(
        &second_resource,
        OUTAGE_NAMESPACE_UID,
        &workload_inventory,
        OUTAGE_NOW + 3,
    )?;
    let second_bundle = second
        .bundles
        .first()
        .ok_or("missing replacement policy bundle")?
        .clone();
    assert_ne!(
        second_bundle.candidate.candidate_content_id,
        first_candidate_id
    );
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let control = tls
        .control_with_store(store, 1)?
        .with_policy_desired_state(fixture.owner.clone());
    assert!(control.replace_kubernetes_workload_inventory(workload_inventory.clone())?);
    let second_server = tls.start(control.clone()).await?;
    let connector = tls.connector(&second_server, "node-a", node_boot_id);
    let mut connection = match connector
        .connect(
            OutagePolicyFixture::registration(node_boot_id, true),
            true,
            &mut trust,
        )
        .await
    {
        Ok(connection) => connection,
        Err(source) => {
            let server_result = second_server.shutdown().await;
            return Err(format!(
                "recovered Control connection failed: {source}; server result: {server_result:?}"
            )
            .into());
        }
    };
    connection.report_readiness(true, true).await?;
    control.bind_kubernetes_node_session("worker-a", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
    let coverage = observations
        .coverage_snapshot()
        .ok_or("missing retained evidence coverage")?;
    let current = coverage
        .current_intervals()
        .into_iter()
        .next()
        .ok_or("missing current evidence interval")?;
    connection.send_evidence_batch(retained.clone()).await?;
    let expected_coverage = connection.send_coverage_report(&coverage, &current).await?;
    let inventory = connection
        .policy_inventory(Some(&first_candidate_id), vec![first_bundle_digest.clone()])
        .await?;
    assert!(inventory.desired_inventory_complete);
    assert!(inventory.candidate_available);
    assert_eq!(
        inventory.candidate_content_id,
        second_bundle.candidate.candidate_content_id
    );
    assert_eq!(inventory.bundle_digest, second_bundle.bundle_digest);

    let mut delivered_bytes = Vec::with_capacity(usize::try_from(inventory.bundle_bytes)?);
    for chunk_index in 0..inventory.chunk_count {
        let chunk = connection
            .fetch_policy_chunk(
                inventory.candidate_content_id.clone(),
                inventory.bundle_digest.clone(),
                chunk_index,
            )
            .await?;
        assert_eq!(chunk.chunk_index, chunk_index);
        assert_eq!(chunk.chunk_count, inventory.chunk_count);
        delivered_bytes.extend_from_slice(&chunk.payload);
    }
    let delivered: PolicyBundleV1 = serde_json::from_slice(&delivered_bytes)?;
    assert_eq!(delivered, second_bundle);
    let accepted = connection
        .acknowledge_policy(OutagePolicyFixture::active_acknowledgement(
            &delivered,
            2,
            OUTAGE_NOW + 4,
        ))
        .await?;
    assert_eq!(accepted.rollout_state, "ACTIVE");
    let recovered = fixture.owner.reconcile(
        &second_resource,
        OUTAGE_NAMESPACE_UID,
        &workload_inventory,
        OUTAGE_NOW + 5,
    )?;
    assert_eq!(recovered.status.rollout.desired, 1);
    assert_eq!(recovered.status.rollout.active, 1);
    assert_eq!(recovered.status.rollout.updating, 0);
    assert_eq!(recovered.status.rollout.failed, 0);

    let mut evidence_acknowledged = false;
    let mut coverage_acknowledged = false;
    for _ in 0..2 {
        match connection.next_message().await? {
            NodeControlMessage::EvidenceAck(ack) => {
                observations.acknowledge_evidence(ack)?;
                evidence_acknowledged = true;
            }
            NodeControlMessage::CoverageAck(ack) => {
                assert_eq!(ack, expected_coverage);
                coverage_acknowledged = true;
            }
            NodeControlMessage::Administrative(_) => {
                return Err("Control returned an unrelated administrative request".into());
            }
            NodeControlMessage::Decommission(_) => {
                return Err("Control returned an unrelated decommission command".into());
            }
        }
    }
    assert!(evidence_acknowledged && coverage_acknowledged);
    assert!(observations.next_evidence_batch().is_none());

    let original_identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id,
        label_epoch: 1,
        source_id,
        source_epoch: 1,
    };
    assert_eq!(control.registered_nonce_count(), 1);
    assert_eq!(
        intake
            .store()
            .accepted_evidence_records(&original_identity)?,
        retained.decode_records()?
    );

    drop(connection);
    second_server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn kubernetes_outage_partitioned_node_reconnects_to_running_control_and_replaces_predecessor(
) -> Result<(), Box<dyn StdError>> {
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-store"))?;
    let fixture = OutagePolicyFixture::new(store.clone());
    let first_resource = fixture.resource(1)?;
    let inventory = fixture.inventory(&first_resource)?;
    let control = tls
        .control_with_store(store, 1)?
        .with_policy_desired_state(fixture.owner.clone());
    assert!(control.replace_kubernetes_workload_inventory(inventory.clone())?);
    let first = fixture.owner.reconcile(
        &first_resource,
        OUTAGE_NAMESPACE_UID,
        &inventory,
        OUTAGE_NOW,
    )?;
    let first_bundle = first.bundles.first().ok_or("missing first bundle")?;
    let first_candidate = first_bundle.candidate.candidate_content_id.clone();
    let first_digest = first_bundle.bundle_digest.clone();

    let server = tls.start(control.clone()).await?;
    let proxy = TcpBlackholeOwner::start(server.address()).await?;
    let connector = NodeControlConnector::new(
        tls.node_config(proxy.address()),
        "node-a".to_owned(),
        [7; 16],
    );
    let mut trust = TrustCache::load(&tls.path().join("trust"))?;
    let mut first_connection = connector
        .connect(
            OutagePolicyFixture::registration([7; 16], false),
            false,
            &mut trust,
        )
        .await?;
    first_connection.report_readiness(true, true).await?;
    control.bind_kubernetes_node_session("worker-a", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")?;
    let offered = first_connection.policy_inventory(None, Vec::new()).await?;
    assert_eq!(offered.candidate_content_id, first_candidate);
    let accepted = first_connection
        .acknowledge_policy(OutagePolicyFixture::active_acknowledgement(
            first_bundle,
            1,
            OUTAGE_NOW + 1,
        ))
        .await?;
    assert_eq!(accepted.rollout_state, "ACTIVE");
    proxy.block()?;

    let second_resource = fixture.resource(2)?;
    let second = fixture.owner.reconcile(
        &second_resource,
        OUTAGE_NAMESPACE_UID,
        &inventory,
        OUTAGE_NOW + 2,
    )?;
    let second_bundle = second.bundles.first().ok_or("missing replacement bundle")?;
    assert_ne!(
        second_bundle.candidate.candidate_content_id,
        first_candidate
    );

    match tokio::time::timeout(Duration::from_secs(30), first_connection.next_message()).await {
        Ok(Err(_closed)) => {}
        Ok(Ok(_message)) => return Err("the blackholed Control session returned a message".into()),
        Err(_elapsed) => {
            return Err("the blackholed Control session did not force a reconnect".into());
        }
    }
    drop(first_connection);
    proxy.unblock()?;

    let observations = EffectObservationStore::durable(
        4,
        tls.path().join("node-wal"),
        EvidenceWalLimits::default(),
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from([7; 16]),
        )?,
    )?;
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: 1,
            source_sequence: 1,
            source_cpu_id: 0,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    observations.mark_coverage_gapped(CoverageGapReasonV1::ControlDelay)?;
    let retained = observations
        .next_evidence_batch()
        .ok_or("missing partition evidence")?;
    let mut reconnected = connector
        .connect(
            OutagePolicyFixture::registration([7; 16], true),
            true,
            &mut trust,
        )
        .await?;
    reconnected.report_readiness(true, true).await?;
    reconnected.send_evidence_batch(retained).await?;
    let NodeControlMessage::EvidenceAck(acknowledgement) = reconnected.next_message().await? else {
        return Err("Control did not acknowledge retained partition evidence".into());
    };
    observations.acknowledge_evidence(acknowledgement)?;
    let coverage = observations
        .coverage_snapshot()
        .ok_or("missing partition coverage")?;
    let mut current_intervals = coverage.current_intervals();
    let interval = current_intervals
        .pop()
        .ok_or("partition coverage has no current interval")?;
    assert!(current_intervals.is_empty());

    let priority_entered = Arc::new(Barrier::new(2));
    let priority_release = Arc::new(Barrier::new(2));
    let evidence_entered = Arc::new(Barrier::new(2));
    let evidence_release = Arc::new(Barrier::new(2));
    let coordination_store = fixture.owner.store();
    assert!(coordination_store.pause_next_evidence_wait_for_test(
        Arc::clone(&evidence_entered),
        Arc::clone(&evidence_release),
    ));
    let priority_store = coordination_store.clone();
    let priority_task = tokio::task::spawn_blocking({
        let entered = Arc::clone(&priority_entered);
        let release = Arc::clone(&priority_release);
        move || priority_store.hold_priority_for_test(&entered, &release)
    });
    tokio::task::spawn_blocking({
        let entered = Arc::clone(&priority_entered);
        move || entered.wait()
    })
    .await?;
    let mut coverage_task = tokio::spawn(async move {
        let result = reconnected.send_coverage_report(&coverage, &interval).await;
        (reconnected, result)
    });
    tokio::task::spawn_blocking({
        let entered = Arc::clone(&evidence_entered);
        move || entered.wait()
    })
    .await?;
    tokio::task::spawn_blocking({
        let release = Arc::clone(&priority_release);
        move || release.wait()
    })
    .await?;
    tokio::task::spawn_blocking(move || evidence_release.wait()).await?;

    let completed_without_rescue =
        tokio::time::timeout(Duration::from_millis(500), &mut coverage_task).await;
    let needed_rescue = completed_without_rescue.is_err();
    let (mut reconnected, coverage_result) = match completed_without_rescue {
        Ok(result) => result?,
        Err(_elapsed) => {
            let rescue_store = coordination_store.clone();
            tokio::task::spawn_blocking(move || rescue_store.commit_index()).await?;
            coverage_task.await?
        }
    };
    priority_task.await??;
    assert!(
        !needed_rescue,
        "partition coverage slept after the final priority store operation completed"
    );
    let expected = coverage_result?;
    let NodeControlMessage::CoverageAck(actual) = reconnected.next_message().await? else {
        return Err("Control did not acknowledge partition coverage".into());
    };
    assert_eq!(actual, expected);
    let replacement = reconnected
        .policy_inventory(Some(&first_candidate), vec![first_digest])
        .await?;
    assert!(replacement.candidate_available);
    assert_eq!(
        replacement.candidate_content_id,
        second_bundle.candidate.candidate_content_id
    );

    drop(reconnected);
    proxy.stop().await?;
    server.shutdown().await?;
    Ok(())
}

fn batch_source_id(batch: &mithril_node::EvidenceBatchV1) -> Result<[u8; 16], Box<dyn StdError>> {
    let wire: mithril_control::EvidenceBatch = batch.clone().into();
    wire.source_id
        .as_slice()
        .try_into()
        .map_err(|_error| "evidence batch source identity is not Id128".into())
}

fn registration() -> NodeRegistration {
    registration_for([7; 16], 1)
}

fn registration_for(node_boot_id: [u8; 16], label_epoch: u64) -> NodeRegistration {
    NodeRegistration {
        platform_digest: "a".repeat(64),
        program_digest: "b".repeat(64),
        label_epoch,
        kernel_ready: true,
        effect_prevention_claims_enabled: false,
        kubernetes_node_name: String::new(),
        startup_absence_proof_digest: mithril_control::startup_absence_proof_digest(
            "node-a",
            &node_boot_id,
            label_epoch,
            true,
            true,
        ),
        policy_authority_absent: true,
        exception_authority_absent: true,
        capabilities: capabilities(),
        workload_targets: Vec::new(),
    }
}

fn capabilities() -> Vec<CapabilityRecord> {
    vec![CapabilityRecord {
        capability_id: "KERNEL_LSM_CHASSIS".to_owned(),
        state: "SUPPORTED".to_owned(),
        reason_code: "EXACT_ATTACH_READBACK".to_owned(),
    }]
}

async fn wait_for_decommission_state(
    control: &ControlPlane,
    artifact_sha256: &str,
    expected: NodeDecommissionStateV1,
) -> Result<(), Box<dyn StdError>> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if control
                .node_decommission_status(artifact_sha256)
                .is_ok_and(|status| status.state == expected)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_elapsed| format!("decommission did not reach {expected:?}"))?;
    Ok(())
}

fn control_store_lease_ready<T>(result: mithril_control::Result<T>) -> crate::Result<Option<T>> {
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

struct TcpBlackholeOwner {
    address: SocketAddr,
    blocked: watch::Sender<bool>,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl TcpBlackholeOwner {
    async fn start(upstream: SocketAddr) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (blocked, blocked_input) = watch::channel(false);
        let (shutdown, mut shutdown_input) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _result = &mut shutdown_input => break,
                    accepted = listener.accept() => {
                        let (downstream, _peer) = accepted?;
                        let upstream = tokio::net::TcpStream::connect(upstream).await?;
                        let blocked = blocked_input.clone();
                        connections.spawn(async move {
                            Self::relay(downstream, upstream, blocked).await
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            Ok(())
        });
        Ok(Self {
            address,
            blocked,
            shutdown,
            task,
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn block(&self) -> Result<(), watch::error::SendError<bool>> {
        self.blocked.send(true)
    }

    fn unblock(&self) -> Result<(), watch::error::SendError<bool>> {
        self.blocked.send(false)
    }

    async fn stop(self) -> Result<(), Box<dyn StdError>> {
        let _result = self.shutdown.send(());
        self.task.await??;
        Ok(())
    }

    async fn relay(
        downstream: tokio::net::TcpStream,
        upstream: tokio::net::TcpStream,
        blocked: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let (mut downstream_read, mut downstream_write) = downstream.into_split();
        let (mut upstream_read, mut upstream_write) = upstream.into_split();
        let client_to_control = async move {
            let mut bytes = [0_u8; 16 * 1_024];
            loop {
                let count = downstream_read.read(&mut bytes).await?;
                if count == 0 {
                    return Ok::<(), std::io::Error>(());
                }
                // This matches the K8s test rule: packets from Node to Control disappear.
                if !*blocked.borrow() {
                    upstream_write.write_all(&bytes[..count]).await?;
                }
            }
        };
        let control_to_client = tokio::io::copy(&mut upstream_read, &mut downstream_write);
        tokio::select! {
            result = client_to_control => result,
            result = control_to_client => result.map(|_bytes| ()),
        }
    }
}
