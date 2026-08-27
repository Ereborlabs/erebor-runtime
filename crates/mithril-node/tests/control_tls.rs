use std::error::Error as StdError;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mithril_control::{
    serve, AdministrativeExecArmResult, AdministrativeExecResolution, AllowedNodeIdentity,
    ArmAdministrativeExec, CapabilityRecord, ControlPlane, ControlServerTls,
    EvidenceIntakeIdentityV1, EvidenceIntakeOwner, NodeRegistration, ResolveAdministrativeExec,
    TrustGenerationV1,
};
use mithril_node::{
    AdministrativeControlRequest, EffectObservationStore, EvidenceIdV1,
    EvidenceWalCapacityPolicyV1, EvidenceWalLimits, NodeControlConfig, NodeControlConnector,
    NodeControlMessage, ObservationCanonicalizer, ObservationEnvelopeV1, TrustCache,
};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;
use zerocopy::IntoBytes as _;

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
    let control = ControlPlane::with_evidence_directory(
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
        &intake_path,
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
            source_sequence: 1,
            source_cpu_id: 0,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            source_sequence: 1,
            source_cpu_id: 1,
            task_cookie: 8,
            reason: 9,
            physical_result: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            source_sequence: 2,
            source_cpu_id: 0,
            task_cookie: 9,
            reason: 9,
            physical_result: 1,
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
    observations.acknowledge_evidence_upload(ack)?;
    let second_batch = observations
        .next_evidence_batch()
        .ok_or("missing second source batch")?;
    let second_source = batch_source_id(&second_batch)?;
    assert_ne!(second_source, first_source);
    second.send_evidence_batch(second_batch.clone()).await?;
    let NodeControlMessage::EvidenceAck(ack) = second.next_message().await? else {
        return Err("Control did not acknowledge the second evidence source".into());
    };
    observations.acknowledge_evidence_upload(ack)?;
    assert_eq!(control.registered_nonce_count(), 2);
    assert!(observations.next_evidence_batch().is_none());
    let intake = EvidenceIntakeOwner::open(&intake_path)?;
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
            batch.records.len()
        );
    }

    drop(second);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_retained_evidence_uses_its_original_session_after_boot_and_control_restart(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let intake_path = directory.path().join("control-evidence");
    let old_boot_id = [7; 16];
    let new_boot_id = [8; 16];
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

    let address = free_address()?;
    let control =
        ControlPlane::with_evidence_directory(allowed(), trust_generation.clone(), &intake_path)?;
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let old_connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), old_boot_id);
    let mut trust = TrustCache::load(&directory.path().join("trust"))?;
    let old_connection = old_connector
        .connect(registration_for(old_boot_id, 1), false, &mut trust)
        .await?;
    drop(old_connection);
    let _result = shutdown.send(());
    server.await??;

    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
        EvidenceWalLimits::default(),
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from(old_boot_id),
        )?,
    )?;
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            source_sequence: 1,
            source_cpu_id: 0,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    let retained = observations
        .next_evidence_batch()
        .ok_or("missing retained evidence batch")?;
    let source_id = batch_source_id(&retained)?;

    let control = ControlPlane::with_evidence_directory(allowed(), trust_generation, &intake_path)?;
    let (shutdown, server) = start_server(address, &files, control);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let new_connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), new_boot_id);
    let mut connection = new_connector
        .connect(registration_for(new_boot_id, 2), false, &mut trust)
        .await?;
    connection.send_evidence_batch(retained.clone()).await?;
    let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? else {
        return Err("Control did not acknowledge retained evidence".into());
    };
    observations.acknowledge_evidence_upload(ack)?;
    assert!(observations.next_evidence_batch().is_none());

    let intake = EvidenceIntakeOwner::open(&intake_path)?;
    let original_identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id: old_boot_id,
        label_epoch: 1,
        source_id,
        source_epoch: 1,
    };
    assert_eq!(
        intake
            .store()
            .accepted_evidence_records(&original_identity)?,
        retained
            .records
            .iter()
            .map(|record| record.payload.clone())
            .collect::<Vec<_>>()
    );

    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn mtls_evidence_stream_commits_a_rewrite_gap_before_later_records(
) -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let intake_path = directory.path().join("control-evidence");
    let control = ControlPlane::with_evidence_directory(
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
        &intake_path,
    )?;
    let (shutdown, server) = start_server(address, &files, control.clone());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let observations = EffectObservationStore::durable(
        4,
        directory.path().join("node-wal"),
        EvidenceWalLimits {
            maximum_retained_records: 3,
            maximum_batch_records: 1,
            capacity_policy: EvidenceWalCapacityPolicyV1::Rewrite,
            ..EvidenceWalLimits::default()
        },
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            EvidenceIdV1::from([7; 16]),
        )?,
    )?;
    for source_sequence in 1..=4 {
        observations.record_bytes(
            erebor_interceptor_abi::EffectObservationV1 {
                source_sequence,
                source_cpu_id: 0,
                task_cookie: source_sequence,
                reason: 9,
                physical_result: 1,
                ..erebor_interceptor_abi::EffectObservationV1::default()
            }
            .as_bytes(),
        );
    }
    assert_eq!(observations.health(None).wal_rewritten_records, 1);

    let connector =
        NodeControlConnector::new(files.node_config(address), "node-a".to_owned(), [7; 16]);
    let mut trust = TrustCache::load(directory.path())?;
    let mut connection = connector.connect(registration(), false, &mut trust).await?;
    let mut upload_count = 0;
    let mut delivered_source = None;
    while let Some(upload) = observations.next_evidence_upload() {
        if let mithril_node::EvidenceUploadV1::Batch(batch) = &upload {
            delivered_source = delivered_source.or(Some(batch_source_id(batch)?));
        }
        connection.send_evidence_upload(upload).await?;
        let NodeControlMessage::EvidenceAck(acknowledgement) = connection.next_message().await?
        else {
            return Err("Control did not acknowledge the evidence stream item".into());
        };
        observations.acknowledge_evidence_upload(acknowledgement)?;
        upload_count += 1;
    }
    assert_eq!(upload_count, 4);
    assert_eq!(control.registered_nonce_count(), 1);

    let intake = EvidenceIntakeOwner::open(&intake_path)?;
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".to_owned(),
        node_boot_id: [7; 16],
        label_epoch: 1,
        source_id: delivered_source.ok_or("the evidence stream had no source identity")?,
        source_epoch: 1,
    };
    assert_eq!(intake.contiguous_cursor(&identity)?, 4);
    assert_eq!(
        intake.store().accepted_evidence_records(&identity)?.len(),
        3
    );
    assert_eq!(intake.store().health()?.evidence_gap_ranges, 1);

    drop(connection);
    let _result = shutdown.send(());
    server.await??;
    Ok(())
}

fn batch_source_id(batch: &mithril_node::EvidenceBatchV1) -> Result<[u8; 16], Box<dyn StdError>> {
    let mut source_id = None;
    for record in &batch.records {
        let current = ObservationEnvelopeV1::from_wire_bytes(&record.payload)?
            .source_id
            .to_be_bytes();
        if source_id.is_some_and(|source_id| source_id != current) {
            return Err("one evidence batch crossed source identities".into());
        }
        source_id = Some(current);
    }
    source_id.ok_or_else(|| "evidence batch has no records".into())
}

#[tokio::test]
async fn mtls_coverage_upload_preserves_gap_truth_at_control() -> Result<(), Box<dyn StdError>> {
    let directory = tempfile::tempdir()?;
    let certificates = Certificates::issue(false)?;
    let files = certificates.write(directory.path())?;
    let address = free_address()?;
    let intake_path = directory.path().join("control-evidence");
    let control = ControlPlane::with_evidence_directory(
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
        &intake_path,
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
            source_sequence: 2,
            source_cpu_id: 0,
            task_cookie: 7,
            reason: 9,
            physical_result: 1,
            ..erebor_interceptor_abi::EffectObservationV1::default()
        }
        .as_bytes(),
    );
    observations.record_bytes(
        erebor_interceptor_abi::EffectObservationV1 {
            source_sequence: 3,
            source_cpu_id: 1,
            task_cookie: 8,
            reason: 9,
            physical_result: 1,
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
    let intake = EvidenceIntakeOwner::open(&intake_path)?;
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
        assert!(!persisted.negative_claim_eligible);
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
        }
    }
}
