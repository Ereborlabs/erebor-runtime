use std::convert::Infallible;
use std::error::Error as StdError;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use ed25519_dalek::SigningKey;
use kube::client::Body as KubeBody;
use kube::Client;
use mithril_control::{
    AllowedNodeIdentity, AuthenticatedEvidenceNodeV1, CapabilityRecord, ControlPlane, ControlStore,
    EvidenceBatch, EvidenceIntakeIdentityV1, EvidenceIntakeOwner, EvidenceRecord,
    EvidenceTemporalCoverage, NodeRegistration, TrustGenerationV1, WorkloadProtectionPolicy,
};
use mithril_node::{NodeControlConnector, PolicyControlPacingOwner, TrustCache};
use prost::Message as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{oneshot, watch, Notify};
use tower::service_fn;

use crate::control_fixture::{
    control_store_lease_ready, Certificates, ControlServerFixture, MtlsFixture,
    OutagePolicyFixture, OUTAGE_NAMESPACE_UID, OUTAGE_TENANT_ID,
};

mod administrative;
mod admission;
mod backlog;
mod coverage;
mod decommission;
mod decommission_order;
mod gap;
mod intake_budget;
mod partition;
mod readiness;
mod registration;
mod rejection;
mod replay;
mod restart;
mod retained;
mod storage;
mod transfer;
mod transfer_tests;

const OUTAGE_NOW: i64 = 1_800_000_000_000_000_000;

#[tokio::test]
async fn data_stream_flushes_without_tail() -> Result<(), Box<dyn StdError>> {
    use mithril_control::{
        node_evidence_client::NodeEvidenceClient, node_registry_client::NodeRegistryClient,
        node_trust_client::NodeTrustClient, EvidenceFloor, EvidenceFloorRequest,
        EvidenceStreamRequest, NodeRegistrationRequest, NodeSessionContext, TrustGenerationAck,
        TrustGenerationAckRequest,
    };
    use mithril_control::{EvidenceBatch, EvidenceIntakeIdentityV1};
    use mithril_node::{
        EffectObservationStore, EvidenceIdV1, EvidenceWalLimits, ObservationCanonicalizer,
    };
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::transport::{Certificate as TonicCertificate, ClientTlsConfig, Endpoint, Identity};
    use zerocopy::IntoBytes as _;
    let tls = MtlsFixture::new(false)?;
    let parts = tls.configuration()?.into_parts()?;
    if let Some(error) = parts.data_error {
        return Err(error.into());
    }
    let data = parts.control.analysis_store().ok_or("data owner absent")?;
    let trust = parts.control.trust_bundle_owner().current()?;
    let server = tls.start(parts.control).await?;
    ControlServerFixture::wait_context(
        &data,
        &araphor_data::AnalysisContextKeyV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            owner_id: "mithril-control/trust".into(),
            entity_key: b"trust".to_vec(),
            lifetime_key: trust.bundle_digest.into_bytes(),
            owner_revision: trust.generation,
        },
    )
    .await?;
    let baseline = data.meta()?.commit_revision;
    let client_tls = ClientTlsConfig::new()
        .ca_certificate(TonicCertificate::from_pem(fs::read(&tls.files.ca)?))
        .identity(Identity::from_pem(
            fs::read(&tls.files.node_certificate)?,
            fs::read(&tls.files.node_key)?,
        ))
        .domain_name("localhost");
    let channel = Endpoint::from_shared(format!("https://{}", server.address()))?
        .tls_config(client_tls)?
        .connect()
        .await?;
    let session = NodeSessionContext {
        node_id: "node-a".into(),
        node_boot_id: vec![7; 16],
        connection_nonce: uuid::Uuid::new_v4().as_bytes().to_vec(),
    };
    NodeRegistryClient::new(channel.clone())
        .register(NodeRegistrationRequest {
            session: Some(session.clone()),
            registration: Some(registration()),
        })
        .await?;
    assert!(NodeEvidenceClient::new(channel.clone())
        .report_floor(EvidenceFloorRequest {
            session: Some(session.clone()),
            floor: Some(EvidenceFloor {
                node_boot_id: vec![7; 16],
                source_id: vec![1; 16],
                source_epoch: 1,
                purged_cursor: 2,
            }),
        })
        .await
        .is_err());
    assert_eq!(data.meta()?.commit_revision, baseline);
    let mut trust_stream = NodeTrustClient::new(channel.clone())
        .watch(session.clone())
        .await?
        .into_inner();
    let trust = trust_stream.message().await?.ok_or("trust absent")?;
    drop(trust_stream);
    NodeTrustClient::new(channel.clone())
        .acknowledge(TrustGenerationAckRequest {
            session: Some(session.clone()),
            acknowledgement: Some(TrustGenerationAck {
                generation: trust.generation,
                bundle_digest: trust.bundle_digest,
            }),
        })
        .await?;
    let observations = EffectObservationStore::durable(
        4,
        tls.path().join("wal"),
        EvidenceWalLimits::default(),
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            [7; 16].into(),
        )?,
    )?;
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: 1,
            source_sequence: 1,
            task_cookie: 1,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..Default::default()
        }
        .as_bytes(),
    );
    let mut batch: EvidenceBatch = observations
        .next_evidence_batch()
        .ok_or("evidence absent")?
        .into();
    batch.commit_group_tail = false;
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".into(),
        node_boot_id: [7; 16],
        label_epoch: 1,
        source_id: batch.source_id.as_slice().try_into()?,
        source_epoch: batch.source_epoch,
    };
    let (output, input) = mpsc::channel(1);
    let mut client = NodeEvidenceClient::new(channel);
    let mut replies = client.open(ReceiverStream::new(input)).await?.into_inner();
    for _ in 0..3 {
        output
            .send(EvidenceStreamRequest {
                session: Some(session.clone()),
                batch: Some(batch.clone()),
            })
            .await?;
        let ack = tokio::time::timeout(Duration::from_secs(5), replies.message())
            .await??
            .ok_or("ACK absent while input remains open")?;
        assert_eq!(ack.contiguous_cursor, 1);
        assert_eq!(data.meta()?.commit_revision, baseline + 1);
    }
    let page = data.read_page(&identity, 1)?;
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].framed_record, batch.framed_records);
    drop(output);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), replies.message())
            .await??
            .is_none()
    );
    drop(replies);
    let floor = EvidenceFloor {
        node_boot_id: batch.node_boot_id.clone(),
        source_id: batch.source_id.clone(),
        source_epoch: batch.source_epoch,
        purged_cursor: 2,
    };
    let report = EvidenceFloorRequest {
        session: Some(session.clone()),
        floor: Some(floor.clone()),
    };
    let before = data.meta()?;
    let mut failures = vec![
        (
            EvidenceFloorRequest {
                session: None,
                ..report.clone()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            EvidenceFloorRequest {
                floor: None,
                ..report.clone()
            },
            tonic::Code::InvalidArgument,
        ),
    ];
    for foreign in [false, true] {
        let mut changed = session.clone();
        if foreign {
            changed.node_id = "node-b".into();
        } else {
            changed.connection_nonce = vec![9; 16];
        }
        failures.push((
            EvidenceFloorRequest {
                session: Some(changed),
                ..report.clone()
            },
            if foreign {
                tonic::Code::PermissionDenied
            } else {
                tonic::Code::Unauthenticated
            },
        ));
    }
    for (changed, code) in [
        (
            EvidenceFloor {
                node_boot_id: vec![9; 16],
                ..floor.clone()
            },
            tonic::Code::PermissionDenied,
        ),
        (
            EvidenceFloor {
                node_boot_id: vec![0; 16],
                ..floor.clone()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            EvidenceFloor {
                source_id: vec![1; 15],
                ..floor.clone()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            EvidenceFloor {
                source_epoch: 0,
                ..floor.clone()
            },
            tonic::Code::InvalidArgument,
        ),
    ] {
        failures.push((
            EvidenceFloorRequest {
                floor: Some(changed),
                ..report.clone()
            },
            code,
        ));
    }
    for (request, code) in failures {
        let status = client
            .report_floor(request)
            .await
            .err()
            .ok_or("invalid floor accepted")?;
        assert_eq!(status.code(), code);
        assert_eq!(data.meta()?, before);
        assert!(data.recovery_gaps(&identity, 0)?.is_empty());
    }
    client.report_floor(report.clone()).await?;
    let gaps = data.recovery_gaps(&identity, 0)?;
    assert_eq!(gaps.len(), 1);
    assert_eq!((gaps[0].first_cursor, gaps[0].last_cursor), (2, 2));
    assert_eq!(
        data.source_receipt(&identity)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        1
    );
    assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
    client.report_floor(report).await?;
    assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
    assert_eq!(data.read_page(&identity, 1)?.records, page.records);
    assert_eq!(observations.pending_evidence_records(), 1);
    let mut foreign = identity;
    foreign.tenant_id = [9; 16];
    assert!(data.recovery_gaps(&foreign, 0)?.is_empty());
    drop(client);
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn observability_recovery_mtls_reconnect_preserves_dispatch_and_output(
) -> Result<(), Box<dyn StdError>> {
    use mithril_control::{
        DiscoveryDigestV1, DiscoveryOwner, PolicySignerTrustV1, TraceAccessV1, TraceBatchV1,
        TraceCleanupV1, TraceExchangeV1, TraceFrameKindV1, TraceFrameV1, TraceRecipeV1,
        TraceRequestV1, TraceTargetV1, TraceTerminalReasonV1, TraceTerminalV1, TraceUploadV1,
    };
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-store"))?;
    let _discovery = DiscoveryOwner::open(store.clone())?;
    let fixture = OutagePolicyFixture::new(store.clone());
    let facts = fixture.inventory(&fixture.resource(1)?)?;
    let fact = facts.first().ok_or("missing workload fact")?.clone();
    let key = SigningKey::from_bytes(&[23; 32]);
    let trust = TrustGenerationV1 {
        generation: 1,
        bundle_digest: String::new(),
        policy_issuer_sequence_epoch: 1,
        policy_signers: vec![PolicySignerTrustV1 {
            signing_key_id: "trace-key".into(),
            ed25519_public_key_hex: hex::encode(key.verifying_key().as_bytes()),
            revoked: false,
        }],
    }
    .with_computed_bundle_digest();
    let control = ControlPlane::with_control_store(
        vec![AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: tls.node_digest(),
            tenant_id: OUTAGE_TENANT_ID.into(),
        }],
        trust,
        store,
    )?
    .with_trace_signer("trace-key".into(), 1, key.clone())?;
    control.replace_kubernetes_workload_inventory(facts)?;
    let server = tls.start(control.clone()).await?;
    let connector = tls.connector(&server, "node-a", [7; 16]);
    let mut cache = TrustCache::load(&tls.path().join("trace-trust"))?;
    let mut connection = connector.connect(registration(), true, &mut cache).await?;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )?;
    let tenant = *uuid::Uuid::parse_str(OUTAGE_TENANT_ID)?.as_bytes();
    let target = TraceTargetV1 {
        fact_digest: DiscoveryDigestV1::of(&fact)?,
        fact,
        runtime_container_id: "1".repeat(64),
        node_boot_id: [7; 16],
        cgroup_id: 17,
        binding_id: [3; 16],
        binding_nonce: [4; 16],
        root_cgroup_live_interval_id: [5; 16],
        container_generation: 1,
        label_epoch: 1,
    };
    let grant = TraceAccessV1 {
        tenant_id: tenant,
        principal: "operator".into(),
        valid_until_unix_ns: now + 120_000_000_000,
        revoked: false,
    };
    let request = TraceRequestV1 {
        selection: None,
        finding_reference: None,
        tenant_id: tenant,
        request_id: [6; 16],
        source: TraceRecipeV1::FailedOpens.manifest()?.source,
        targets: vec![target],
        unresolved: Vec::new(),
        collection_seconds: 30,
    };
    connection.report_readiness(true, false).await?;
    assert_eq!(
        control
            .accept_trace(request.clone(), grant.clone())
            .err()
            .ok_or("an unready node must reject new capture")?
            .code(),
        tonic::Code::Unavailable
    );
    connection.report_readiness(true, true).await?;
    control.accept_trace(request.clone(), grant)?;
    let dispatch = connection
        .exchange_diagnostics(&TraceExchangeV1::default())
        .await?
        .dispatch
        .ok_or("missing signed dispatch")?;
    dispatch.verify(
        &key.verifying_key(),
        tenant,
        "node-a",
        [7; 16],
        dispatch.accepted.accepted_unix_ns,
    )?;
    let id = dispatch.accepted.execution_id(0)?;
    let frame = TraceFrameV1 {
        execution_id: id,
        sequence: 1,
        kind: TraceFrameKindV1::Data,
        bytes: br#"{"type":"map","data":{"@errors":{"-2":7}}}"#.to_vec(),
    };
    let mut exchange = TraceExchangeV1 {
        retained: vec![id],
        resolved: None,
        output: Some(TraceUploadV1 {
            request_id: request.request_id,
            target_index: 0,
            original_node_boot_id: [7; 16],
            batch: TraceBatchV1 {
                execution_id: id,
                frames: vec![frame.clone()],
                terminal: None,
            },
        }),
    };
    let first = connection.exchange_diagnostics(&exchange).await?;
    assert_eq!(
        first
            .acknowledgement
            .as_ref()
            .ok_or("missing ack")?
            .last_sequence,
        1
    );
    assert!(first.dispatch.is_none());
    let mut replacement = connector.connect(registration(), true, &mut cache).await?;
    assert!(connection.exchange_diagnostics(&exchange).await.is_err());
    assert_eq!(replacement.exchange_diagnostics(&exchange).await?, first);
    let terminal = TraceTerminalV1 {
        execution_id: id,
        reason: TraceTerminalReasonV1::Deadline,
        last_sequence: 1,
        output_bytes: frame.bytes.len() as u64,
        output_incomplete: false,
        kernel_lost_events: None,
        ready_at_unix_ns: None,
        exit_code: Some(0),
        forced_kill: false,
        cleanup: TraceCleanupV1::Verified,
    };
    let upload = exchange.output.as_mut().ok_or("missing upload")?;
    upload.batch.frames.clear();
    upload.batch.terminal = Some(terminal.clone());
    let reply = replacement.exchange_diagnostics(&exchange).await?;
    assert_eq!(
        reply
            .acknowledgement
            .ok_or("missing terminal ack")?
            .terminal,
        Some(terminal)
    );
    assert!(replacement
        .exchange_diagnostics(&exchange)
        .await?
        .dispatch
        .is_none());
    drop(connection);
    drop(replacement);
    server.shutdown().await?;
    Ok(())
}

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
fn consumed_events_follow_retention() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("control-store");
    let store = ControlStore::open(&store_path)?;
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
    let mut batch = EvidenceBatch {
        node_boot_id: identity.node_boot_id.to_vec(),
        source_id: identity.source_id.to_vec(),
        source_epoch: identity.source_epoch,
        cpu_id: 0,
        first_cursor: 1,
        framed_records: framed_records.into(),
        commit_group_tail: false,
    };
    let intake = EvidenceIntakeOwner::try_from(store.clone())?;
    for cursor in 1..=3 {
        batch.first_cursor = cursor;
        assert_eq!(
            intake
                .receive(&authenticated, batch.clone())?
                .contiguous_cursor,
            cursor
        );
    }
    let data = intake.analysis_store();
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: "retention-test".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    data.register_processor(&scope, araphor_data::ProcessorClassV1::Required, 1)?;
    data.commit_result(&araphor_data::AnalysisResultCommitV1 {
        scope,
        expected_cursor: 0,
        consumed_cursor: 3,
        coverage_revision: 0,
        context_revision: 0,
        result_id: "processed".into(),
        body: vec![1],
        created_utc_ns: now,
        witnesses: Vec::new(),
        context_refs: Vec::new(),
    })?;
    assert_eq!(
        araphor_data::EvidenceRetentionOwner::new(&data)
            .retain(&identity, now)?
            .removed_records,
        0
    );
    assert_eq!(data.read_page(&identity, 1)?.records.len(), 3);
    assert_eq!(
        araphor_data::EvidenceRetentionOwner::new(&data)
            .retain(&identity, u64::MAX)?
            .removed_records,
        3
    );
    assert_eq!(intake.contiguous_cursor(&identity)?, 3);
    assert!(!store.root().join("evidence/segments-v2").exists());
    drop(data);
    drop(intake);
    drop(store);
    let reopened = EvidenceIntakeOwner::open(&store_path)?;
    assert_eq!(reopened.contiguous_cursor(&identity)?, 3);
    assert!(matches!(
        reopened.analysis_store().read_page(&identity, 1),
        Err(araphor_data::Error::RetainedRangeExpired {
            first_cursor: 1,
            last_cursor: 3,
            ..
        })
    ));
    assert_eq!(
        reopened
            .analysis_store()
            .read_result(identity.tenant_id, "processed")?,
        Some(vec![1])
    );
    Ok(())
}

impl OutagePolicyFixture {
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
}

#[tokio::test]
async fn observability_partition_tls_repair() -> Result<(), Box<dyn StdError>> {
    let fixture = MtlsFixture::new(false)?;
    let control = fixture.control(4)?;
    let server = fixture.start(control.clone()).await?;
    let proxy = TcpBlackholeOwner::start(server.address()).await?;
    let connector = NodeControlConnector::new(
        fixture.node_config(proxy.address()),
        "node-a".into(),
        [7; 16],
    );
    let mut trust = TrustCache::load(fixture.path())?;
    let mut node = registration();
    node.kubernetes_node_name = "worker-a.example".into();
    let connection = connector.connect(node.clone(), true, &mut trust).await?;
    control
        .bind_kubernetes_node_session("worker-a.example", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
    let sessions = control.ready_kubernetes_node_sessions(Duration::from_secs(10));
    assert_eq!(sessions.len(), 1);
    assert_eq!(control.registered_nonce_count(), 1);
    let first_nonce = trust.installed().control_connection_nonce.clone();
    let mut failures = Vec::new();

    let live = {
        let held = proxy.held_input.notified();
        tokio::pin!(held);
        held.as_mut().enable();
        proxy.block()?;
        let call = connection.report_readiness(true, true);
        tokio::pin!(call);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut call => {
                    return Err(format!("live readiness completed while blocked: {result:?}").into());
                }
                () = &mut held => {}
            }
            proxy.unblock()?;
            call.await?;
            Ok::<(), Box<dyn StdError>>(())
        })
        .await
    };
    proxy.unblock()?;
    if matches!(&live, Ok(Ok(()))) {
        assert_eq!(control.registered_nonce_count(), 1);
        assert_eq!(trust.installed().control_connection_nonce, first_nonce);
        assert_eq!(
            control.ready_kubernetes_node_sessions(Duration::from_secs(10)),
            sessions
        );
    } else {
        failures.push(format!("live readiness repair: {live:?}"));
    }
    drop(connection);
    proxy.stop().await?;

    let proxy = TcpBlackholeOwner::start(server.address()).await?;
    let connector = NodeControlConnector::new(
        fixture.node_config(proxy.address()),
        "node-a".into(),
        [7; 16],
    );
    let fresh = {
        let held = proxy.held_input.notified();
        tokio::pin!(held);
        held.as_mut().enable();
        proxy.block()?;
        let call = connector.connect(node, true, &mut trust);
        tokio::pin!(call);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut call => {
                    return Err(format!("fresh connection completed while blocked: {}", result.is_ok()).into());
                }
                () = &mut held => {}
            }
            proxy.unblock()?;
            Ok::<_, Box<dyn StdError>>(call.await?)
        })
        .await
    };
    proxy.unblock()?;
    match fresh {
        Ok(Ok(connection)) => {
            assert_eq!(trust.installed().generation, 4);
            assert_ne!(trust.installed().control_connection_nonce, first_nonce);
            assert_eq!(control.registered_nonce_count(), 2);
            control.bind_kubernetes_node_session(
                "worker-a.example",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            )?;
            assert_eq!(
                control.ready_kubernetes_node_sessions(Duration::from_secs(10)),
                sessions
            );
            drop(connection);
        }
        Ok(Err(error)) => failures.push(format!("fresh TLS repair: {error}")),
        Err(error) => failures.push(format!("fresh TLS repair: {error}")),
    }
    proxy.stop().await?;
    server.shutdown().await?;
    assert!(failures.is_empty(), "TLS repair failed: {failures:?}");
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

pub(crate) struct TcpBlackholeOwner {
    address: SocketAddr,
    blocked: watch::Sender<bool>,
    held_input: Arc<Notify>,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl TcpBlackholeOwner {
    pub(crate) async fn start(upstream: SocketAddr) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (blocked, blocked_input) = watch::channel(false);
        let held_input = Arc::new(Notify::new());
        let relay_input = held_input.clone();
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
                        let held_input = relay_input.clone();
                        connections.spawn(async move {
                            Self::relay(downstream, upstream, blocked, held_input).await
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
            held_input,
            shutdown,
            task,
        })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn block(&self) -> Result<(), watch::error::SendError<bool>> {
        self.blocked.send(true)
    }

    pub(crate) fn unblock(&self) -> Result<(), watch::error::SendError<bool>> {
        self.blocked.send(false)
    }

    pub(crate) async fn stop(self) -> Result<(), Box<dyn StdError>> {
        let _result = self.shutdown.send(());
        self.task.await??;
        Ok(())
    }

    async fn relay(
        downstream: tokio::net::TcpStream,
        upstream: tokio::net::TcpStream,
        mut blocked: watch::Receiver<bool>,
        held_input: Arc<Notify>,
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
                // Hold one input chunk until Node-to-Control transport is restored.
                while *blocked.borrow_and_update() {
                    held_input.notify_waiters();
                    blocked.changed().await.map_err(std::io::Error::other)?;
                }
                upstream_write.write_all(&bytes[..count]).await?;
            }
        };
        let control_to_client = tokio::io::copy(&mut upstream_read, &mut downstream_write);
        tokio::select! {
            result = client_to_control => result,
            result = control_to_client => result.map(|_bytes| ()),
        }
    }
}
