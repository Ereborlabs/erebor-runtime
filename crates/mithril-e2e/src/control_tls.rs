use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use ed25519_dalek::SigningKey;
use kube::client::Body as KubeBody;
use kube::Client;
use mithril_control::{
    lower_kubernetes_policy, serve, workload_target_fact_digest, AdministrativeExecArmResult,
    AdministrativeExecResolution, AllowedNodeIdentity, ArmAdministrativeExec,
    AuthenticatedEvidenceNodeV1, CapabilityRecord, ContainerKindV1, ControlPlane, ControlServerTls,
    ControlStore, EvidenceBatch, EvidenceConsumptionWatermarkV1, EvidenceIntakeIdentityV1,
    EvidenceIntakeOwner, EvidenceRecord, EvidenceRetentionOwner, EvidenceStoreCapacityPolicyV1,
    EvidenceStoreLimitsV1, EvidenceTemporalCoverage, KubernetesAdmissionHttpConfigV1,
    KubernetesAdmissionOwner, KubernetesNodeControlConfigV1, KubernetesNodeReadinessOwner,
    KubernetesWorkloadIdentityV1, NodeRegistration, PolicyActivationAcknowledgement,
    PolicyBundleV1, PolicyDesiredStateConfigV1, PolicyDesiredStateOwner, PolicySignerConfigV1,
    PolicySourceRevisionV1, PolicySourceStateV1, ProfileSealRequestV1, RegistryDigestsV1,
    ResolveAdministrativeExec, TrustGenerationV1, WorkloadProtectionPolicy, WorkloadTargetFactV1,
};
use mithril_node::{
    AdministrativeControlRequest, CoverageGapReasonV1, EffectObservationStore, EvidenceIdV1,
    EvidenceWalCapacityPolicyV1, EvidenceWalLimits, NodeControlConfig, NodeControlConnector,
    NodeControlMessage, ObservationCanonicalizer, PolicyControlPacingOwner, TrustCache,
};
use prost::Message as _;
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{
    Certificate as TonicCertificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request as TonicRequest, Response as TonicResponse, Status as TonicStatus};
use tower::service_fn;
use zerocopy::IntoBytes as _;

mod grpc_throughput_protocol {
    tonic::include_proto!("erebor.mithril.e2e.v1");
}

use grpc_throughput_protocol::grpc_throughput_client::GrpcThroughputClient;
use grpc_throughput_protocol::grpc_throughput_server::{GrpcThroughput, GrpcThroughputServer};
use grpc_throughput_protocol::{FileChunk, FileReceipt};

const OUTAGE_POLICY: &[u8] = include_bytes!("../fixtures/convergence/outage-policy-v1.json");
const OUTAGE_TENANT_ID: &str = "00000000-0000-0001-0000-000000000002";
const OUTAGE_CLUSTER_UID: &str = "55555555-5555-4555-8555-555555555555";
const OUTAGE_NAMESPACE_UID: &str = "66666666-6666-4666-8666-666666666666";
const OUTAGE_POLICY_UID: &str = "30000000-0000-4000-8000-000000000001";
const OUTAGE_NOW: i64 = 1_800_000_000_000_000_000;
const GRPC_THROUGHPUT_CHUNK_BYTES: usize = 3 * 1_024 * 1_024;
const GRPC_THROUGHPUT_MESSAGE_BYTES: usize = 4 * 1_024 * 1_024;
const GRPC_THROUGHPUT_WINDOW_BYTES: u32 = 16 * 1_024 * 1_024;

#[tokio::test]
async fn kubernetes_outage_pending_policy_transfer_preempts_evidence_ack_backlog() {
    let mut pacing = PolicyControlPacingOwner::default();
    pacing.mark_pending();
    let mut poll = tokio::time::interval(Duration::from_secs(60));
    let (sender, mut messages) = tokio::sync::mpsc::unbounded_channel();
    sender.send(()).expect("the message receiver is open");

    let selected_policy = tokio::select! {
        biased;
        () = pacing.wait_until_ready(&mut poll) => true,
        Some(()) = messages.recv() => false,
    };

    assert!(selected_policy);
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

#[test]
fn control_evidence_queue_reclaims_only_durably_consumed_segments() -> Result<(), Box<dyn StdError>>
{
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("control-store");
    let limits = EvidenceStoreLimitsV1 {
        maximum_retained_bytes: mithril_control::MAX_EVIDENCE_SEGMENT_BYTES as u64,
        maximum_retained_records: 2,
        capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
    };
    let store = ControlStore::open_with_evidence_limits(&store_path, limits)?;
    store.write_retained_evidence_for_test(2, 1)?;
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: [2; 16],
        node_id: "node-a".to_owned(),
        node_boot_id: [1; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let authenticated = AuthenticatedEvidenceNodeV1 {
        tenant_id: identity.tenant_id,
        node_id: identity.node_id.clone(),
        node_boot_id: identity.node_boot_id,
        label_epoch: identity.label_epoch,
    };
    let record = EvidenceRecord {
        observed_boottime_ns: 3,
        ingested_utc_ns: 3,
        coverage_interval_id: vec![4; 16].into(),
        task_cookie: 3,
        process_lineage_id: vec![5; 16].into(),
        authority_domain_id: vec![6; 16].into(),
        execution_set_id: vec![7; 16].into(),
        exact_object_id: vec![8; 16].into(),
        policy_rule_id: 1,
        reason: 1,
        decision: 1,
        effect_family: 1,
        operation: 1,
        configured_errno: -13,
        kernel_result: -13,
        temporal_coverage: EvidenceTemporalCoverage::Complete as i32,
        ..EvidenceRecord::default()
    };
    let payload = record.encode_to_vec();
    let mut framed_records = Vec::with_capacity(payload.len() + 8);
    framed_records.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed_records.extend_from_slice(&payload);
    let checksum = crc32c::crc32c(&framed_records);
    framed_records.extend_from_slice(&checksum.to_be_bytes());
    let third = EvidenceBatch {
        node_boot_id: identity.node_boot_id.to_vec(),
        source_id: identity.source_id.to_vec(),
        source_epoch: identity.source_epoch,
        cpu_id: 0,
        first_cursor: 3,
        framed_records: framed_records.into(),
        commit_group_tail: false,
    };
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    assert!(intake.receive(&authenticated, third.clone()).is_err());
    assert_eq!(
        fs::read_dir(store_path.join("evidence/segments-v2"))?.count(),
        1
    );

    let retention = EvidenceRetentionOwner::from_store(store.clone());
    retention.acknowledge(EvidenceConsumptionWatermarkV1 {
        identity: identity.clone(),
        evidence_cursor: 1,
        coverage_revision: 0,
    })?;
    assert_eq!(
        fs::read_dir(store_path.join("evidence/segments-v2"))?.count(),
        1
    );
    assert_eq!(retention.watermark(&identity)?.evidence_cursor, 1);
    assert!(intake.receive(&authenticated, third.clone()).is_err());
    retention.acknowledge(EvidenceConsumptionWatermarkV1 {
        identity: identity.clone(),
        evidence_cursor: 2,
        coverage_revision: 0,
    })?;
    assert_eq!(
        fs::read_dir(store_path.join("evidence/segments-v2"))?.count(),
        0
    );
    intake.receive(&authenticated, third)?;
    assert_eq!(store.accepted_evidence_records(&identity)?.len(), 1);
    assert_eq!(
        fs::read_dir(store_path.join("evidence/segments-v2"))?.count(),
        1
    );

    drop(retention);
    drop(intake);
    drop(store);
    let reopened = ControlStore::open_with_evidence_limits(&store_path, limits)?;
    let retention = EvidenceRetentionOwner::from_store(reopened.clone());
    assert_eq!(retention.watermark(&identity)?.evidence_cursor, 2);
    assert_eq!(reopened.evidence_cursor(&identity)?, 3);
    assert_eq!(reopened.accepted_evidence_records(&identity)?.len(), 1);
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
async fn mtls_registration_acknowledges_trust_and_reconnects_with_a_fresh_nonce(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 4,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
    );
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;

    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let first = connector.connect(registration(), true, &mut trust).await?;
    assert_eq!(trust.installed().generation, 4);
    let first_nonce = trust.installed().control_connection_nonce.clone();
    drop(first);
    let second = connector.connect(registration(), true, &mut trust).await?;
    assert_ne!(trust.installed().control_connection_nonce, first_nonce);
    for _ in 0..20 {
        if control.registered_nonce_count() == 2 && control.acknowledged_trust("node-a").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(control.registered_nonce_count(), 2);
    assert_eq!(
        control.acknowledged_trust("node-a"),
        Some(TrustGenerationV1 {
            generation: 4,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        })
    );
    drop(second);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_connection_renews_the_ready_session_while_its_owner_is_idle(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 4,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
    );
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;

    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let mut node = registration();
    node.kubernetes_node_name = "worker-a.example".to_owned();
    let connection = connector.connect(node, true, &mut trust).await?;
    control
        .bind_kubernetes_node_session("worker-a.example", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;

    // The initial report is older than this lease window. Only renewal can keep it ready.
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    let ready = control.ready_kubernetes_node_sessions(Duration::from_millis(1_500));
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].kubernetes_node_name, "worker-a.example");
    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_connection_reports_local_readiness_transitions_without_reconnect(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 4,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
    );
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;

    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let mut node = registration();
    node.kubernetes_node_name = "worker-a.example".to_owned();
    let connection = connector.connect(node, true, &mut trust).await?;
    control
        .bind_kubernetes_node_session("worker-a.example", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
    assert_eq!(control.registered_nonce_count(), 1);
    assert_eq!(
        control
            .ready_kubernetes_node_sessions(Duration::from_secs(2))
            .len(),
        1
    );

    connection.report_readiness(true, false).await?;
    assert!(control
        .ready_kubernetes_node_sessions(Duration::from_secs(2))
        .is_empty());
    connection.report_readiness(true, true).await?;
    assert_eq!(
        control
            .ready_kubernetes_node_sessions(Duration::from_secs(2))
            .len(),
        1
    );
    assert_eq!(control.registered_nonce_count(), 1);

    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_rejects_wrong_node_binding_and_expired_client_identity(
) -> Result<(), Box<dyn StdError>> {
    assert_rejected_identity(false, "node-b").await?;
    assert_rejected_identity(true, "node-a").await?;
    assert_wrong_ca_rejected().await
}

#[tokio::test]
async fn mtls_evidence_stream_replays_after_disconnect_and_reuses_one_registered_session(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let intake_path = directory.path().join("control-evidence");
    let store = ControlStore::open(&intake_path)?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let control = ControlPlane::with_control_store(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
        store,
    )?;
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
        EvidenceWalLimits {
            maximum_retained_records: 10,
            maximum_batch_records: 10,
            ..EvidenceWalLimits::default()
        },
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
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: 1,
            source_sequence: 1,
            source_cpu_id: 1,
            task_cookie: 8,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: 2,
            source_sequence: 2,
            source_cpu_id: 0,
            task_cookie: 9,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let mut first = connector.connect(registration(), false, &mut trust).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let first_batch = observations
        .next_evidence_batch()
        .ok_or("missing WAL batch")?;
    let first_source = batch_source_id(&first_batch)?;
    first.send_evidence_batch(first_batch.clone()).await?;
    drop(first);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(observations.next_evidence_batch().is_some());

    let mut second = connector.connect(registration(), false, &mut trust).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let replay = observations
        .next_evidence_batch()
        .ok_or("missing replay batch")?;
    assert_eq!(replay, first_batch);
    second.send_evidence_batch(replay).await?;
    let NodeControlMessage::EvidenceAck(ack) = second.next_message().await? else {
        return Err("Control did not acknowledge evidence".into());
    };
    observations.acknowledge_evidence(ack)?;
    let second_batch = observations
        .next_evidence_batch()
        .ok_or("missing second source batch")?;
    let second_source = batch_source_id(&second_batch)?;
    assert_ne!(second_source, first_source);
    second.send_evidence_batch(second_batch.clone()).await?;
    let NodeControlMessage::EvidenceAck(ack) = second.next_message().await? else {
        return Err("Control did not acknowledge the second evidence source".into());
    };
    observations.acknowledge_evidence(ack)?;
    assert_eq!(control.registered_nonce_count(), 2);
    assert!(observations.next_evidence_batch().is_none());
    for (source_id, batch) in [(first_source, first_batch), (second_source, second_batch)] {
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".to_owned(),
            node_boot_id: [7; 16],
            label_epoch: 1,
            source_id,
            source_epoch: 1,
        };
        assert_eq!(intake.contiguous_cursor(&identity)?, batch.last_cursor);
        assert_eq!(
            intake.store().accepted_evidence_records(&identity)?.len(),
            batch.record_count()
        );
    }

    drop(second);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_evidence_gap_survives_control_restart_and_closes_with_one_ack(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let store_path = directory.path().join("control-evidence");
    let control = |store| {
        ControlPlane::with_control_store(
            vec![AllowedNodeIdentity {
                node_id: "node-a".to_owned(),
                certificate_sha256: certificates.node_digest(),
                tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
            }],
            TrustGenerationV1 {
                generation: 1,
                bundle_digest: "d".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            },
            store,
        )
    };
    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
        EvidenceWalLimits {
            maximum_retained_records: 10,
            maximum_batch_records: 1,
            ..EvidenceWalLimits::default()
        },
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from([7; 16]),
        )?,
    )?;
    for source_sequence in 1..=3 {
        observations.record_bytes(
            erebor_interceptor_abi::EffectObservationV1 {
                observed_boottime_ns: source_sequence,
                source_sequence,
                source_cpu_id: 0,
                task_cookie: source_sequence,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 1,
                ..erebor_interceptor_abi::EffectObservationV1::default()
            }
            .as_bytes(),
        );
    }
    let batches = observations.next_evidence_batches();
    assert_eq!(
        batches
            .iter()
            .map(|batch| (batch.first_cursor, batch.last_cursor))
            .collect::<Vec<_>>(),
        vec![(1, 1), (2, 2), (3, 3)]
    );
    let source_id = batch_source_id(&batches[0])?;
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id: [7; 16],
        label_epoch: 1,
        source_id,
        source_epoch: 1,
    };
    let connector = |address| {
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16])
    };

    let initial_store = ControlStore::open(&store_path)?;
    let initial_intake = EvidenceIntakeOwner::from_store(initial_store.clone());
    let initial_control = control(initial_store.clone())?;
    let initial_address = free_address()?;
    let (initial_shutdown, initial_server) =
        start_server(initial_address, &files, initial_control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut trust = TrustCache::load(directory.path())?;
    let mut connection = connector(initial_address)
        .connect(registration(), false, &mut trust)
        .await?;
    connection.send_evidence_batch(batches[2].clone()).await?;
    if connection.next_message().await.is_ok() {
        return Err("Control acknowledged evidence across a cursor gap".into());
    }
    assert_eq!(initial_intake.contiguous_cursor(&identity)?, 0);
    assert_eq!(initial_store.health()?.pending_evidence_records, 1);
    assert_eq!(observations.pending_evidence_records(), 3);
    drop(connection);
    let _result = initial_shutdown.send(());
    initial_server.await??;
    drop(initial_control);
    drop(initial_intake);
    drop(initial_store);

    let reopened_store = ControlStore::open(&store_path)?;
    let reopened_intake = EvidenceIntakeOwner::from_store(reopened_store.clone());
    assert_eq!(reopened_intake.contiguous_cursor(&identity)?, 0);
    assert_eq!(reopened_store.health()?.pending_evidence_records, 1);
    let reopened_control = control(reopened_store.clone())?;
    let reopened_address = free_address()?;
    let (reopened_shutdown, reopened_server) =
        start_server(reopened_address, &files, reopened_control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut connection = connector(reopened_address)
        .connect(registration(), false, &mut trust)
        .await?;
    connection
        .send_evidence_group(batches[..2].to_vec())
        .await?;
    let NodeControlMessage::EvidenceAck(acknowledgement) = connection.next_message().await? else {
        return Err("Control returned no cumulative evidence acknowledgement".into());
    };
    assert_eq!(acknowledgement.contiguous_cursor, 3);
    assert_eq!(reopened_intake.contiguous_cursor(&identity)?, 3);
    assert_eq!(reopened_store.health()?.pending_evidence_records, 0);

    connection.send_evidence_group(batches.clone()).await?;
    let NodeControlMessage::EvidenceAck(duplicate_acknowledgement) =
        connection.next_message().await?
    else {
        return Err("Control returned no acknowledgement for an exact retry".into());
    };
    assert_eq!(duplicate_acknowledgement, acknowledgement);
    assert!(observations.acknowledge_evidence(acknowledgement)?);
    assert_eq!(observations.pending_evidence_records(), 0);
    assert_eq!(
        reopened_intake
            .store()
            .accepted_evidence_records(&identity)?
            .len(),
        3
    );
    drop(connection);
    let _result = reopened_shutdown.send(());
    reopened_server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_storage_failure_withholds_ack_until_replay_is_durable(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let store_path = directory.path().join("control-evidence");
    let limits = |maximum_retained_records| EvidenceStoreLimitsV1 {
        maximum_retained_bytes: mithril_control::MAX_EVIDENCE_SEGMENT_BYTES as u64,
        maximum_retained_records,
        capacity_policy: EvidenceStoreCapacityPolicyV1::Block,
    };
    let control = |store| {
        ControlPlane::with_control_store(
            vec![AllowedNodeIdentity {
                node_id: "node-a".to_owned(),
                certificate_sha256: certificates.node_digest(),
                tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
            }],
            TrustGenerationV1 {
                generation: 1,
                bundle_digest: "d".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            },
            store,
        )
    };
    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
        EvidenceWalLimits {
            maximum_retained_records: 10,
            maximum_batch_records: 10,
            ..EvidenceWalLimits::default()
        },
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from([7; 16]),
        )?,
    )?;
    for source_sequence in 1..=2 {
        observations.record_bytes(
            erebor_interceptor_abi::EffectObservationV1 {
                observed_boottime_ns: source_sequence,
                source_sequence,
                source_cpu_id: 0,
                task_cookie: source_sequence,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 1,
                ..erebor_interceptor_abi::EffectObservationV1::default()
            }
            .as_bytes(),
        );
    }

    let initial_store = ControlStore::open_with_evidence_limits(&store_path, limits(10))?;
    drop(initial_store);
    let retained_store_path = directory.path().join("retained-control-evidence");
    fs::rename(&store_path, &retained_store_path)?;
    fs::write(&store_path, [])?;
    assert!(ControlStore::open_with_evidence_limits(&store_path, limits(10)).is_err());
    assert_eq!(observations.pending_evidence_records(), 2);
    fs::remove_file(&store_path)?;
    fs::rename(retained_store_path, &store_path)?;

    let blocked_store = ControlStore::open_with_evidence_limits(&store_path, limits(1))?;
    let blocked_control = control(blocked_store.clone())?;
    let blocked_address = free_address()?;
    let (blocked_shutdown, blocked_server) =
        start_server(blocked_address, &files, blocked_control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut trust = TrustCache::load(directory.path())?;
    let mut connection = NodeControlConnector::new(
        files.node_config(blocked_address),
        "node-a".to_owned(),
        [7; 16],
    )
    .connect(registration(), false, &mut trust)
    .await?;
    connection
        .send_evidence_group(observations.next_evidence_batches())
        .await?;
    if connection.next_message().await.is_ok() {
        return Err("Control acknowledged evidence that exceeded durable capacity".into());
    }
    assert_eq!(observations.pending_evidence_records(), 2);
    assert_eq!(blocked_store.health()?.evidence_cursors, 0);
    drop(connection);
    let _result = blocked_shutdown.send(());
    blocked_server.await??;
    drop(blocked_control);
    drop(blocked_store);

    let restored_store = ControlStore::open_with_evidence_limits(&store_path, limits(10))?;
    let restored_control = control(restored_store.clone())?;
    let restored_address = free_address()?;
    let (restored_shutdown, restored_server) =
        start_server(restored_address, &files, restored_control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut connection = NodeControlConnector::new(
        files.node_config(restored_address),
        "node-a".to_owned(),
        [7; 16],
    )
    .connect(registration(), false, &mut trust)
    .await?;
    connection
        .send_evidence_group(observations.next_evidence_batches())
        .await?;
    let NodeControlMessage::EvidenceAck(acknowledgement) = connection.next_message().await? else {
        return Err("restored Control returned no evidence acknowledgement".into());
    };
    assert!(observations.acknowledge_evidence(acknowledgement)?);
    assert_eq!(observations.pending_evidence_records(), 0);
    assert_eq!(restored_store.health()?.evidence_cursors, 1);
    drop(connection);
    let _result = restored_shutdown.send(());
    restored_server.await??;
    Ok(())
}

#[tokio::test]
async fn kubernetes_outage_mtls_session_converges_policy_while_replaying_retained_evidence(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let intake_path = directory.path().join("control-evidence");
    let node_boot_id = [7; 16];
    let trust_generation = TrustGenerationV1 {
        generation: 1,
        bundle_digest: "d".repeat(64),
        policy_issuer_sequence_epoch: 0,
        policy_signers: Vec::new(),
    };
    let allowed = || {
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }]
    };

    let store = ControlStore::open(&intake_path)?;
    let restart_store = store.clone();
    let fixture = OutagePolicyFixture::new(store.clone());
    let first_resource = fixture.resource(1)?;
    let workload_inventory = fixture.inventory(&first_resource)?;
    let control = ControlPlane::with_control_store(allowed(), trust_generation.clone(), store)?
        .with_policy_desired_state(fixture.owner.clone());

    let address = free_address()?;
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let old_connector = NodeControlConnector::new(
        files.node_config(address),
        "node-a".to_owned(),
        node_boot_id,
    );
    let mut trust = TrustCache::load(&directory.path().join("trust"))?;
    let mut old_connection = old_connector
        .connect(
            OutagePolicyFixture::registration(node_boot_id, false),
            false,
            &mut trust,
        )
        .await?;
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
    let _result = shutdown.send(());
    server.await??;
    drop(control);
    drop(fixture);

    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
        EvidenceWalLimits::default(),
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from(node_boot_id),
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
    let control = ControlPlane::with_control_store(allowed(), trust_generation, store)?
        .with_policy_desired_state(fixture.owner.clone());
    assert!(control.replace_kubernetes_workload_inventory(workload_inventory.clone())?);
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let connector = NodeControlConnector::new(
        files.node_config(address),
        "node-a".to_owned(),
        node_boot_id,
    );
    let mut connection = connector
        .connect(
            OutagePolicyFixture::registration(node_boot_id, true),
            true,
            &mut trust,
        )
        .await?;
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
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn kubernetes_outage_partitioned_node_reconnects_to_running_control_and_replaces_predecessor(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let store = ControlStore::open(directory.path().join("control-store"))?;
    let fixture = OutagePolicyFixture::new(store.clone());
    let first_resource = fixture.resource(1)?;
    let inventory = fixture.inventory(&first_resource)?;
    let control = ControlPlane::with_control_store(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: OUTAGE_TENANT_ID.to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
        store,
    )?
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

    let control_address = free_address()?;
    let (shutdown, server) = start_server(control_address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let proxy = TcpBlackholeOwner::start(control_address).await?;
    let connector = NodeControlConnector::new(
        files.node_config(proxy.address()),
        "node-a".to_owned(),
        [7; 16],
    );
    let mut trust = TrustCache::load(&directory.path().join("trust"))?;
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
        directory.path().join("node-wal"),
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
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn kubernetes_outage_retained_evidence_allows_protected_pod_admission(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let store = ControlStore::open(directory.path().join("control-store"))?;
    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
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
    let retained = observations
        .next_evidence_batch()
        .ok_or("missing retained admission evidence")?;
    let retained: mithril_control::EvidenceBatch = retained.into();
    EvidenceIntakeOwner::from_store(store.clone()).receive(
        &AuthenticatedEvidenceNodeV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".to_owned(),
            node_boot_id: [7; 16],
            label_epoch: 1,
        },
        retained,
    )?;

    let fixture = OutagePolicyFixture::new(store.clone());
    let resource = fixture.resource(1)?;
    let kube = fixture.kubernetes_client(&resource)?;
    let review = fixture.protected_pod_admission_review();
    let control = ControlPlane::with_control_store(
        Vec::new(),
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
        store,
    )?
    .with_policy_desired_state(fixture.owner.clone());
    assert!(control.replace_kubernetes_workload_inventory(Vec::new())?);
    let nodes = KubernetesNodeReadinessOwner::new(KubernetesNodeControlConfigV1 {
        daemon_set_namespace: "mithril-system".to_owned(),
        daemon_set_name: "mithril-node".to_owned(),
        session_ttl_seconds: 30,
        reconcile_interval_ms: 100,
    })?;
    let address = free_address()?;
    let config = KubernetesAdmissionHttpConfigV1 {
        listen: address,
        tls_certificate_path: files.server_certificate.clone(),
        tls_private_key_path: files.server_key.clone(),
        maximum_request_bytes: 1024 * 1024,
        request_timeout_ms: 1_000,
    };
    let (shutdown, receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        KubernetesAdmissionOwner::serve_with_client(
            config,
            kube,
            control,
            fixture.owner,
            nodes,
            async move {
                let _result = receiver.await;
            },
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let ca = reqwest::Certificate::from_pem(&fs::read(&files.ca)?)?;
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(2))
        .build()?;

    let response = client
        .post(format!("https://localhost:{}/admit", address.port()))
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
        "protected Pod admission did not return a scheduler patch: {review}"
    );

    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_evidence_stream_retains_every_record_across_node_restart_beyond_the_soft_bound(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let intake_path = directory.path().join("control-evidence");
    let store = ControlStore::open(&intake_path)?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let control = ControlPlane::with_control_store(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
        store,
    )?;
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let wal_root = directory.path().join("node-wal");
    let wal_limits = EvidenceWalLimits {
        maximum_retained_records: 3,
        maximum_batch_records: 4_096,
        capacity_policy: EvidenceWalCapacityPolicyV1::Retain,
        ..EvidenceWalLimits::default()
    };
    let observations = EffectObservationStore::durable(
        4,
        wal_root.clone(),
        wal_limits,
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from([7; 16]),
        )?,
    )?;
    for source_sequence in 1..=2 {
        observations.record_bytes(
            erebor_interceptor_abi::EffectObservationV1 {
                observed_boottime_ns: source_sequence,
                source_sequence,
                source_cpu_id: 0,
                task_cookie: source_sequence,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 1,
                ..erebor_interceptor_abi::EffectObservationV1::default()
            }
            .as_bytes(),
        );
    }
    let before_restart = observations
        .next_evidence_batch()
        .ok_or("the Node retained no evidence before restart")?;
    assert_eq!(before_restart.record_count(), 2);
    assert_eq!(observations.pending_evidence_records(), 2);
    drop(observations);

    let observations = EffectObservationStore::durable(
        4,
        wal_root,
        wal_limits,
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from([7; 16]),
        )?,
    )?;
    assert_eq!(observations.pending_evidence_records(), 2);
    for source_sequence in 3..=303 {
        observations.record_bytes(
            erebor_interceptor_abi::EffectObservationV1 {
                observed_boottime_ns: source_sequence,
                source_sequence,
                source_cpu_id: 0,
                task_cookie: source_sequence,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 1,
                ..erebor_interceptor_abi::EffectObservationV1::default()
            }
            .as_bytes(),
        );
    }
    assert_eq!(observations.pending_evidence_records(), 303);
    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    let batches = observations.next_evidence_batches();
    let upload_records = batches
        .iter()
        .map(mithril_node::EvidenceBatchV1::record_count)
        .collect::<Vec<_>>();
    let mut delivered_source = None;
    let expected_cursor = batches
        .last()
        .map(|batch| batch.last_cursor)
        .ok_or("the Node did not prepare an evidence commit group")?;
    for batch in &batches {
        delivered_source = delivered_source.or(Some(batch_source_id(&batch)?));
    }
    connection.send_evidence_group(batches).await?;
    loop {
        let NodeControlMessage::EvidenceAck(acknowledgement) = connection.next_message().await?
        else {
            return Err("Control did not acknowledge the evidence commit group".into());
        };
        let complete = observations.acknowledge_evidence(acknowledgement)?;
        if complete {
            assert_eq!(acknowledgement.contiguous_cursor, expected_cursor);
            break;
        }
    }
    assert_eq!(upload_records.iter().sum::<usize>(), 303);
    assert_eq!(upload_records, vec![303]);
    assert_eq!(observations.pending_evidence_records(), 0);
    assert_eq!(control.registered_nonce_count(), 1);

    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id: [7; 16],
        label_epoch: 1,
        source_id: delivered_source.ok_or("the evidence stream had no source identity")?,
        source_epoch: 1,
    };
    assert_eq!(intake.contiguous_cursor(&identity)?, 303);
    assert_eq!(
        intake.store().accepted_evidence_records(&identity)?.len(),
        303
    );
    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
#[ignore = "the evidence throughput budget requires the shipped release optimization level"]
async fn mtls_evidence_backlog_exceeds_the_previous_baseline() -> Result<(), Box<dyn StdError>> {
    const BATCH_RECORDS: usize = 4_096;
    const QUALIFICATION_BYTES: u64 = 512 * 1_024 * 1_024;
    const PREVIOUS_MIB_PER_SECOND: f64 = 107.1;
    const TARGET_MIB_PER_SECOND: f64 = 300.0;

    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    fs::create_dir_all(&target)?;
    let directory = tempfile::tempdir_in(target)?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let store = ControlStore::open_with_evidence_limits(
        directory.path().join("control-evidence"),
        EvidenceStoreLimitsV1 {
            capacity_policy: EvidenceStoreCapacityPolicyV1::Retain,
            ..EvidenceStoreLimitsV1::default()
        },
    )?;
    let control = ControlPlane::with_control_store(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
        store.clone(),
    )?;
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;

    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
        EvidenceWalLimits {
            maximum_retained_records: BATCH_RECORDS,
            maximum_batch_records: BATCH_RECORDS,
            ..EvidenceWalLimits::default()
        },
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from([7; 16]),
        )?,
    )?;
    for source_sequence in 1..=BATCH_RECORDS as u64 {
        observations.record_bytes(
            erebor_interceptor_abi::EffectObservationV1 {
                observed_boottime_ns: source_sequence,
                source_sequence,
                source_cpu_id: 0,
                task_cookie: source_sequence,
                reason: 9,
                physical_result: 1,
                effect_family: 1,
                operation: 1,
                ..erebor_interceptor_abi::EffectObservationV1::default()
            }
            .as_bytes(),
        );
    }
    let template = observations
        .next_evidence_batch()
        .ok_or("the Node did not create a throughput batch template")?;
    assert_eq!(template.record_count(), BATCH_RECORDS);
    let encoded_batch_bytes = {
        let batch: EvidenceBatch = template.clone().into();
        batch.encoded_len() as u64
    };
    assert!(encoded_batch_bytes <= mithril_control::MAX_EVIDENCE_BATCH_PAYLOAD_BYTES as u64);
    let batch_count = QUALIFICATION_BYTES.div_ceil(encoded_batch_bytes);
    let accepted_bytes = encoded_batch_bytes * batch_count;
    let maximum_group_batches =
        (mithril_control::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES as u64 / encoded_batch_bytes).max(1);
    let (grpc_elapsed, grpc_mib_per_second) =
        measure_grpc_file_transfer(&files, accepted_bytes, None).await?;
    let (durable_grpc_elapsed, durable_grpc_mib_per_second) = measure_grpc_file_transfer(
        &files,
        accepted_bytes,
        Some(directory.path().join("grpc-received.bin")),
    )
    .await?;
    eprintln!(
        "raw mTLS gRPC transferred {accepted_bytes} bytes in {grpc_elapsed:?}: {grpc_mib_per_second:.1} MiB/s; durable receiver completed in {durable_grpc_elapsed:?}: {durable_grpc_mib_per_second:.1} MiB/s"
    );

    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(&directory.path().join("trust"))?;
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let direct_authenticated = AuthenticatedEvidenceNodeV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id: [7; 16],
        label_epoch: 1,
    };
    let direct_batch_count = maximum_group_batches;
    let mut direct_batches = Vec::new();
    for index in 0..direct_batch_count {
        let mut batch = template.clone();
        let first_cursor = index * BATCH_RECORDS as u64 + 1;
        batch.first_cursor = first_cursor;
        batch.last_cursor = first_cursor + BATCH_RECORDS as u64 - 1;
        let mut batch: EvidenceBatch = batch.into();
        batch.source_id = vec![9; 16];
        direct_batches.push((direct_authenticated.clone(), batch));
    }
    let direct_started = Instant::now();
    let direct_acknowledgement = intake.receive_group(direct_batches)?;
    let direct_elapsed = direct_started.elapsed();
    let direct_mib_per_second = encoded_batch_bytes as f64 * direct_batch_count as f64
        / 1_048_576.0
        / direct_elapsed.as_secs_f64();
    eprintln!(
        "direct Control intake completed in {direct_elapsed:?}: {direct_mib_per_second:.1} MiB/s"
    );
    assert_eq!(
        direct_acknowledgement.contiguous_cursor,
        direct_batch_count * BATCH_RECORDS as u64
    );
    let mut preparation_elapsed = Duration::ZERO;
    let mut enqueue_elapsed = Duration::ZERO;
    let mut acknowledgement_elapsed = Duration::ZERO;
    let mut acknowledgement_count = 0_u64;
    let started = Instant::now();
    let expected_acknowledgements = batch_count.div_ceil(maximum_group_batches);
    let mut index = 0_u64;
    while index < batch_count {
        let group_batches = maximum_group_batches.min(batch_count - index);
        let first_group_index = index;
        let mut batches = Vec::with_capacity(group_batches as usize);
        for _ in 0..group_batches {
            let phase_started = Instant::now();
            let mut batch = template.clone();
            let first_cursor = index * BATCH_RECORDS as u64 + 1;
            batch.first_cursor = first_cursor;
            batch.last_cursor = first_cursor + BATCH_RECORDS as u64 - 1;
            preparation_elapsed += phase_started.elapsed();
            batches.push(batch);
            index += 1;
        }
        let phase_started = Instant::now();
        connection.send_evidence_group(batches).await?;
        enqueue_elapsed += phase_started.elapsed();
        let expected_cursor = index * BATCH_RECORDS as u64;
        let minimum_cursor = first_group_index * BATCH_RECORDS as u64;
        let phase_started = Instant::now();
        loop {
            let NodeControlMessage::EvidenceAck(acknowledgement) =
                connection.next_message().await?
            else {
                return Err("Control did not acknowledge the throughput group".into());
            };
            acknowledgement_count += 1;
            if acknowledgement.contiguous_cursor <= minimum_cursor
                || acknowledgement.contiguous_cursor > expected_cursor
            {
                return Err("Control returned a cursor outside the throughput group".into());
            }
            if acknowledgement.contiguous_cursor == expected_cursor {
                break;
            }
        }
        acknowledgement_elapsed += phase_started.elapsed();
    }
    let elapsed = started.elapsed();
    let mib_per_second = accepted_bytes as f64 / 1_048_576.0 / elapsed.as_secs_f64();
    eprintln!(
        "durably acknowledged {accepted_bytes} evidence bytes in {elapsed:?}: {mib_per_second:.1} MiB/s (target {TARGET_MIB_PER_SECOND:.1}); acknowledgements={acknowledgement_count} prepare={preparation_elapsed:?} enqueue={enqueue_elapsed:?} control_ack={acknowledgement_elapsed:?}"
    );
    assert_eq!(acknowledgement_count, expected_acknowledgements);
    assert_eq!(store.health()?.pending_evidence_records, 0);
    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    assert!(mib_per_second > PREVIOUS_MIB_PER_SECOND);
    Ok(())
}

fn batch_source_id(batch: &mithril_node::EvidenceBatchV1) -> Result<[u8; 16], Box<dyn StdError>> {
    let wire: mithril_control::EvidenceBatch = batch.clone().into();
    wire.source_id
        .as_slice()
        .try_into()
        .map_err(|_error| "evidence batch source identity is not Id128".into())
}

#[tokio::test]
async fn mtls_coverage_upload_preserves_gap_truth_at_control() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let intake_path = directory.path().join("control-evidence");
    let store = ControlStore::open(&intake_path)?;
    let intake = EvidenceIntakeOwner::from_store(store.clone());
    let control = ControlPlane::with_control_store(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
        store,
    )?;
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
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
            observed_boottime_ns: 2,
            source_sequence: 2,
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
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: 3,
            source_sequence: 3,
            source_cpu_id: 1,
            task_cookie: 8,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let snapshot = observations
        .coverage_snapshot()
        .ok_or("missing coverage snapshot")?;
    let source_epoch = snapshot.source_epoch;
    let current = snapshot.current_intervals();
    let mut expected = Vec::new();
    for interval in &current {
        expected.push(connection.send_coverage_report(&snapshot, interval).await?);
    }
    assert_eq!(expected.len(), 2);
    for expected_ack in expected {
        let NodeControlMessage::CoverageAck(actual) = connection.next_message().await? else {
            return Err("Control did not acknowledge coverage".into());
        };
        assert_eq!(actual, expected_ack);
    }
    for interval in current {
        let coverage_identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".to_owned(),
            node_boot_id: [7; 16],
            label_epoch: 1,
            source_id: interval.source_id.to_be_bytes(),
            source_epoch,
        };
        let persisted = intake
            .latest_coverage_report(&coverage_identity)?
            .ok_or("Control did not persist coverage")?;
        assert_eq!(persisted.intervals.len(), 1);
        assert!(persisted.intervals[0].current);
        assert_ne!(persisted.intervals[0].state, "HEALTHY");
    }

    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_administrative_services_route_matching_results_and_cancel_waiters(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "d".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
    );
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let mut connection = connector.connect(registration(), true, &mut trust).await?;

    let resolution_request = ResolveAdministrativeExec {
        request_id: vec![1; 16],
        ..ResolveAdministrativeExec::default()
    };
    let resolution_control = control.clone();
    let resolution_task = tokio::spawn(async move {
        resolution_control
            .resolve_administrative_exec("node-a", resolution_request)
            .await
    });
    let AdministrativeControlRequest::Resolve(received) = tokio::time::timeout(
        Duration::from_secs(1),
        connection.next_administrative_request(),
    )
    .await??
    else {
        return Err("resolution request crossed into the arm service".into());
    };
    let resolution = AdministrativeExecResolution {
        request_id: received.request_id,
        resolved: true,
        ..AdministrativeExecResolution::default()
    };
    connection.send_resolution(resolution.clone()).await?;
    assert_eq!(resolution_task.await??, resolution);

    let arm_request = ArmAdministrativeExec {
        request_id: vec![2; 16],
        ..ArmAdministrativeExec::default()
    };
    let arm_control = control.clone();
    let arm_task = tokio::spawn(async move {
        arm_control
            .arm_administrative_exec("node-a", arm_request)
            .await
    });
    let AdministrativeControlRequest::Arm(received) = tokio::time::timeout(
        Duration::from_secs(1),
        connection.next_administrative_request(),
    )
    .await??
    else {
        return Err("arm request crossed into the resolution service".into());
    };
    let arm_result = AdministrativeExecArmResult {
        request_id: received.request_id,
        armed: true,
        ..AdministrativeExecArmResult::default()
    };
    connection.send_arm_result(arm_result.clone()).await?;
    assert_eq!(arm_task.await??, arm_result);

    let cancelled_request = ResolveAdministrativeExec {
        request_id: vec![3; 16],
        ..ResolveAdministrativeExec::default()
    };
    let cancelled_control = control;
    let cancelled_task = tokio::spawn(async move {
        cancelled_control
            .resolve_administrative_exec("node-a", cancelled_request)
            .await
    });
    let AdministrativeControlRequest::Resolve(cancelled) = tokio::time::timeout(
        Duration::from_secs(1),
        connection.next_administrative_request(),
    )
    .await??
    else {
        return Err("cancelled resolution crossed into the arm service".into());
    };
    cancelled_task.abort();
    let _cancelled = cancelled_task.await;
    connection
        .send_resolution(AdministrativeExecResolution {
            request_id: cancelled.request_id,
            resolved: true,
            ..AdministrativeExecResolution::default()
        })
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), connection.next_message())
            .await?
            .is_err()
    );

    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

async fn assert_wrong_ca_rejected() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let server_certificates = Certificates::issue(false)?;
    let files = server_certificates.write(directory.path())?;
    let wrong_ca_directory = directory.path().join("wrong-ca");
    fs::create_dir(&wrong_ca_directory)?;
    let wrong_ca = Certificates::issue(false)?.write(&wrong_ca_directory)?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: server_certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "f".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
    );
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut config = files.node_config(address);
    config.ca_path = wrong_ca.ca;
    let connector = NodeControlConnector::new(config, "node-a".to_owned(), [9; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    assert!(connector
        .connect(registration(), true, &mut trust)
        .await
        .is_err());
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

async fn assert_rejected_identity(
    expired: bool,
    registered_node_id: &str,
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(expired)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let control = ControlPlane::new(
        vec![AllowedNodeIdentity {
            node_id: "node-a".to_owned(),
            certificate_sha256: certificates.node_digest(),
            tenant_id: "00000000-0000-0001-0000-000000000002".to_owned(),
        }],
        TrustGenerationV1 {
            generation: 1,
            bundle_digest: "e".repeat(64),
            policy_issuer_sequence_epoch: 0,
            policy_signers: Vec::new(),
        },
    );
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let connector = NodeControlConnector::new(
        files.node_config(address),
        registered_node_id.to_owned(),
        [8; 16],
    );
    let mut trust = TrustCache::load(directory.path())?;
    assert!(connector
        .connect(registration(), true, &mut trust)
        .await
        .is_err());
    let _result = shutdown.send(());
    server.await??;
    Ok(())
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

fn start_server(
    address: SocketAddr,
    files: &CertificateFiles,
    control: ControlPlane,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<mithril_control::Result<()>>,
) {
    let tls = files.server_tls();
    let (shutdown, receiver) = oneshot::channel();
    let server = tokio::spawn(async move {
        serve(address, &tls, control, async move {
            let _result = receiver.await;
        })
        .await
    });
    (shutdown, server)
}

#[derive(Clone)]
struct GrpcThroughputReceiver {
    durable_path: Option<PathBuf>,
}

#[tonic::async_trait]
impl GrpcThroughput for GrpcThroughputReceiver {
    async fn upload(
        &self,
        request: TonicRequest<tonic::Streaming<FileChunk>>,
    ) -> Result<TonicResponse<FileReceipt>, TonicStatus> {
        let mut input = request.into_inner();
        let mut file = match &self.durable_path {
            Some(path) => Some(tokio::fs::File::create(path).await.map_err(|error| {
                TonicStatus::internal(format!(
                    "throughput receiver could not create its file: {error}"
                ))
            })?),
            None => None,
        };
        let mut received_bytes = 0_u64;
        while let Some(chunk) = input.message().await? {
            received_bytes = received_bytes
                .checked_add(chunk.payload.len() as u64)
                .ok_or_else(|| TonicStatus::out_of_range("throughput byte count is exhausted"))?;
            if let Some(file) = &mut file {
                file.write_all(&chunk.payload).await.map_err(|error| {
                    TonicStatus::internal(format!("throughput receiver write failed: {error}"))
                })?;
            }
        }
        if let Some(file) = file {
            file.sync_data().await.map_err(|error| {
                TonicStatus::internal(format!("throughput receiver sync failed: {error}"))
            })?;
        }
        Ok(TonicResponse::new(FileReceipt { received_bytes }))
    }
}

async fn measure_grpc_file_transfer(
    files: &CertificateFiles,
    total_bytes: u64,
    durable_path: Option<PathBuf>,
) -> Result<(Duration, f64), Box<dyn StdError>> {
    let address = free_address()?;
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            fs::read(&files.server_certificate)?,
            fs::read(&files.server_key)?,
        ))
        .client_ca_root(TonicCertificate::from_pem(fs::read(&files.ca)?));
    let receiver = GrpcThroughputReceiver { durable_path };
    let (shutdown, shutdown_input) = oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .initial_stream_window_size(GRPC_THROUGHPUT_WINDOW_BYTES)
            .initial_connection_window_size(GRPC_THROUGHPUT_WINDOW_BYTES)
            .tls_config(tls)?
            .add_service(
                GrpcThroughputServer::new(receiver)
                    .max_decoding_message_size(GRPC_THROUGHPUT_MESSAGE_BYTES)
                    .max_encoding_message_size(GRPC_THROUGHPUT_MESSAGE_BYTES),
            )
            .serve_with_shutdown(address, async move {
                let _result = shutdown_input.await;
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let client_tls = ClientTlsConfig::new()
        .ca_certificate(TonicCertificate::from_pem(fs::read(&files.ca)?))
        .identity(Identity::from_pem(
            fs::read(&files.node_certificate)?,
            fs::read(&files.node_key)?,
        ))
        .domain_name("localhost");
    let channel = Endpoint::from_shared(format!("https://{address}"))?
        .tls_config(client_tls)?
        .initial_stream_window_size(GRPC_THROUGHPUT_WINDOW_BYTES)
        .initial_connection_window_size(GRPC_THROUGHPUT_WINDOW_BYTES)
        .connect()
        .await?;
    let mut client = GrpcThroughputClient::new(channel)
        .max_decoding_message_size(GRPC_THROUGHPUT_MESSAGE_BYTES)
        .max_encoding_message_size(GRPC_THROUGHPUT_MESSAGE_BYTES);
    let (output, input) = mpsc::channel(8);
    let source = prost::bytes::Bytes::from(vec![0xa5; GRPC_THROUGHPUT_CHUNK_BYTES]);
    let started = Instant::now();
    let upload = tokio::spawn(async move {
        client
            .upload(TonicRequest::new(ReceiverStream::new(input)))
            .await
    });
    let mut remaining = total_bytes;
    while remaining > 0 {
        let chunk_bytes = remaining.min(GRPC_THROUGHPUT_CHUNK_BYTES as u64) as usize;
        output
            .send(FileChunk {
                payload: source.slice(..chunk_bytes),
            })
            .await
            .map_err(|_closed| "throughput receiver closed before the file completed")?;
        remaining -= chunk_bytes as u64;
    }
    drop(output);
    let receipt = upload.await??.into_inner();
    let elapsed = started.elapsed();
    if receipt.received_bytes != total_bytes {
        return Err(format!(
            "throughput receiver accepted {} of {total_bytes} bytes",
            receipt.received_bytes
        )
        .into());
    }
    let _result = shutdown.send(());
    server.await??;
    let mib_per_second = total_bytes as f64 / 1_048_576.0 / elapsed.as_secs_f64();
    Ok((elapsed, mib_per_second))
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

fn free_address() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.local_addr()
}

struct Certificates {
    ca: Certificate,
    server: Certificate,
    server_key: KeyPair,
    node: Certificate,
    node_key: KeyPair,
}

impl Certificates {
    fn issue(expired_node: bool) -> Result<Self, rcgen::Error> {
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

    fn node_digest(&self) -> String {
        format!("{:x}", Sha256::digest(self.node.der().as_ref()))
    }

    fn write(&self, directory: &Path) -> Result<CertificateFiles, std::io::Error> {
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

struct CertificateFiles {
    ca: PathBuf,
    server_certificate: PathBuf,
    server_key: PathBuf,
    node_certificate: PathBuf,
    node_key: PathBuf,
}

impl CertificateFiles {
    fn server_tls(&self) -> ControlServerTls {
        ControlServerTls {
            certificate_path: self.server_certificate.clone(),
            private_key_path: self.server_key.clone(),
            node_ca_path: self.ca.clone(),
        }
    }

    fn node_config(&self, address: SocketAddr) -> NodeControlConfig {
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
