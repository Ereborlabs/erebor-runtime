use std::os::unix::fs::DirBuilderExt as _;

use super::*;

#[derive(Clone, Copy)]
enum IntakeFault<'a> {
    Quota,
    FullDisk(&'a Path),
    CommitLimit,
    SegmentLimit,
}

#[tokio::test]
async fn data_load_contract() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("load");
    DataStoreQualification::new(output.clone())
        .load_tenants(2, 1)
        .await?;
    let result: serde_json::Value = serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
    assert_eq!(result["record_count"], 8192);
    assert_eq!(
        result["samples"].as_array().ok_or("samples absent")?.len(),
        2
    );
    assert!(result["input_bytes"].as_u64().ok_or("bytes absent")? > 0);
    Ok(())
}

#[tokio::test]
async fn data_context_bounds() -> Result<()> {
    use mithril_control::EVIDENCE_BATCH_BYTES;
    const CONTEXT_BYTES: usize = 16 * 1_024;
    use mithril_node::{EvidenceWal, TemporalCoverageV1};
    use prost::Message as _;
    use sha2::{Digest as _, Sha256};

    let tls = MtlsFixture::new(false)?;
    let case = DataStoreQualification::new(tls.path().join("proof"));
    let control = ControlStore::open(tls.path().join("control-store"))?;
    let boot = EvidenceIdV1::from([7; 16]);
    let prepared = super::super::roundtrip::signed_catalog(
        crate::control_fixture::OutagePolicyFixture::new(control.clone()).owner,
        tls.path(),
        boot,
        i64::try_from(START)?,
        None,
    )?;
    let (catalog, mut raw) = (prepared.catalog, prepared.raw);
    raw.source_sequence = 1;
    raw.source_cpu_id = 3;
    raw.observed_boottime_ns = 101;
    raw.task_cookie = 7;
    raw.process_instance_id = EvidenceIdV1::new(8, 9);
    raw.entry_instance_id = EvidenceIdV1::new(10, 11);
    raw.reason = 9;
    raw.physical_result = 1;
    let canonicalizer =
        ObservationCanonicalizer::new(EvidenceIdV1::new(1, 2), EvidenceIdV1::new(3, 4), 1, boot)?;
    let wal_root = tls.path().join("large-wal");
    let limits = EvidenceWalLimits {
        maximum_batch_records: 4096,
        ..Default::default()
    };
    let mut wal = EvidenceWal::open(&wal_root, limits)?;
    let mut last = None;
    for cursor in 1..=256 {
        raw.source_sequence = cursor;
        raw.observed_boottime_ns = cursor + 100;
        let mut observation = canonicalizer.normalize_kernel(
            raw,
            EvidenceIdV1::new(5, 6),
            TemporalCoverageV1::Complete,
            i64::try_from(START)?,
        )?;
        catalog.attach(&mut observation);
        let context = observation
            .decision_context
            .as_mut()
            .ok_or("decision context absent")?;
        let expected = mithril_control::EvidenceDecisionCatalogV1::from_context(context)?
            .ok_or("verified catalog absent")?;
        let padding = CONTEXT_BYTES
            .checked_sub(context.encoded_len())
            .ok_or("catalog exceeds context limit")?;
        // JSON whitespace changes encoded size, not catalog content.
        context
            .catalog_json
            .resize(context.catalog_json.len() + padding, b' ');
        assert_eq!(context.encoded_len(), CONTEXT_BYTES);
        assert_eq!(
            mithril_control::EvidenceDecisionCatalogV1::from_context(context)?,
            Some(expected)
        );
        assert_eq!(wal.append(&observation)?, cursor);
        last = Some(observation);
    }
    let mut oversized = last.ok_or("last observation absent")?;
    oversized.source_sequence = 257;
    let context = oversized
        .decision_context
        .as_mut()
        .ok_or("decision context absent")?;
    context.original_kernel_sequence = 257;
    context.catalog_json.resize(17 * 1_024 * 1_024, b' ');
    assert!(context.encoded_len() > 17 * 1_024 * 1_024);
    assert_eq!(wal.append(&oversized)?, 257);
    assert_eq!(wal.pending_records(), 257);
    drop(wal);
    let mut wal = EvidenceWal::open(&wal_root, limits)?;
    assert_eq!(wal.pending_records(), 257);
    let first = wal.next_batch().ok_or("first batch absent")?;
    assert!(first.record_count() < 256);
    let wire: mithril_control::EvidenceBatch = first.into();
    assert!(wire.encoded_len() <= EVIDENCE_BATCH_BYTES);
    assert!(wire.encoded_len() > EVIDENCE_BATCH_BYTES - 32 * 1024);
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".into(),
        node_boot_id: boot.to_be_bytes(),
        label_epoch: 1,
        source_id: wire.source_id.as_slice().try_into()?,
        source_epoch: wire.source_epoch,
    };
    let root = tls.path().join("analysis");
    let data = Arc::new(AnalysisStore::open(&root)?);
    let intake = EvidenceIntakeOwner::new(
        control,
        data.clone(),
        Arc::new(TestClock(AtomicU64::new(START))),
    )?;
    let server = tls.start(tls.control_from_intake(intake, 1)?).await?;
    let mut connection = case.connect(&tls, &server).await?;
    connection.report_readiness(true, true).await?;
    let mut expected = Sha256::new();
    let mut batches = 0;
    while let Some(batch) = wal.next_batch() {
        let end = batch.last_cursor;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        if wire.encoded_len() > EVIDENCE_BATCH_BYTES {
            assert_eq!((batch.first_cursor, batch.last_cursor), (257, 257));
            assert!(wire.encoded_len() > 17 * 1_024 * 1_024);
        }
        expected.update(&wire.framed_records);
        connection.send_evidence_batch(batch).await?;
        let ack = DataStoreQualification::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, end);
        assert_eq!(
            data.source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            end
        );
        wal.acknowledge(ack)?;
        batches += 1;
    }
    assert_eq!(batches, 3);
    assert_eq!(wal.pending_records(), 0);
    let receipt = data.source_receipt(&identity)?;
    drop(connection);
    server.shutdown().await?;
    drop(data);
    let data = DataStoreQualification::reopen_data(&root).await?;
    assert_eq!(data.source_receipt(&identity)?, receipt);
    let mut actual = Sha256::new();
    let mut cursor = 1;
    let mut count = 0;
    loop {
        let page = data.read_page(&identity, cursor)?;
        for record in page.records {
            actual.update(&record.framed_record);
            count += 1;
        }
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    assert_eq!(count, 257);
    assert_eq!(actual.finalize(), expected.finalize());
    Ok(())
}

#[tokio::test]
async fn data_tenant_load() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("tenants");
    let case = DataStoreQualification::new(output.clone());
    for (groups, tenants) in [(0, 2), (33, 2), (33, 10), (65, 1), (1, 0), (1, 11)] {
        assert!(case.load_tenants(groups, tenants).await.is_err());
        assert!(!output.exists());
    }
    tokio::time::timeout(Duration::from_secs(30), case.load_tenants(2, 2)).await??;
    let result: serde_json::Value = serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
    assert_eq!(result["tenant_count"], 2);
    assert_eq!(result["record_count"], 16384);
    let sources = result["sources"].as_array().ok_or("sources absent")?;
    assert_eq!(sources.len(), 2);
    assert_ne!(
        sources[0]["identity"]["tenant_id"],
        sources[1]["identity"]["tenant_id"]
    );
    for source in sources {
        assert_eq!(source["record_count"], 8192);
        assert_eq!(source["status"]["retained_event_count"], 8192);
    }
    let samples = result["samples"].as_array().ok_or("samples absent")?;
    assert_eq!(samples.len(), 4);
    for sample in samples {
        assert!(sample["node_us"].as_u64().ok_or("Node time absent")? > 0);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "subprocess helper; requires the parent's temporary data store"]
async fn data_commit_child() -> Result<()> {
    use rustix::process::{getrlimit, setrlimit, Resource};

    let root = PathBuf::from(std::env::var_os("ARAPHOR_COMMIT_ROOT").ok_or("root absent")?);
    let kind = std::env::var("ARAPHOR_COMMIT_KIND")?;
    let result = kind == "result";
    let data = AnalysisStore::open(root)?;
    let watch = data.subscribe_revision();
    let limit = std::env::var("ARAPHOR_COMMIT_LIMIT")?.parse()?;
    let _signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::from_raw(libc::SIGXFSZ))?;
    let prior = getrlimit(Resource::Fsize);
    match kind.as_str() {
        "segment" | "metadata" => {
            let stage = if kind == "segment" {
                araphor_data::AnalysisCommitStage::BeforeAppend
            } else {
                araphor_data::AnalysisCommitStage::AfterSync
            };
            data.set_commit_hook(stage, move || DataStoreQualification::limit_file(limit))?;
        }
        "result" => DataStoreQualification::limit_file(limit)?,
        _ => return Err("unknown commit kind".into()),
    }
    let failure = DataStoreQualification::native_commit(&data, result);
    let failure = if kind == "metadata" {
        failure?;
        assert!(watch.has_changed()?);
        assert_eq!(
            data.source_receipt(&DataStoreQualification::native_scope().identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        data.checkpoint()
    } else {
        failure
    };
    setrlimit(Resource::Fsize, prior)?;
    let error = failure
        .err()
        .ok_or("native commit unexpectedly succeeded")?;
    let expected = if result {
        "commit analysis result"
    } else {
        "commit raw catalogue publication"
    };
    if kind == "segment" {
        assert!(
            matches!(&error, araphor_data::Error::Io { path, source, .. }
            if path.extension().is_some_and(|extension| extension == "open")
                && source.raw_os_error() == Some(libc::EFBIG)),
            "{error}"
        );
    } else {
        assert!(
            matches!(&error,
        araphor_data::Error::AnalysisDatabase { operation, source, .. }
            if *operation == expected && source.to_string().contains("File too large")
                && source.to_string().contains("analysis.duckdb.wal")),
            "{error}"
        );
    }
    assert_eq!(watch.has_changed()?, kind == "metadata");
    std::process::exit(73);
}

#[tokio::test]
async fn data_commit_failure() -> Result<()> {
    for limit in [0, 64] {
        for kind in ["segment", "metadata", "result"] {
            let result = kind == "result";
            let directory = tempfile::tempdir()?;
            let root = directory.path().join("analysis");
            let data = AnalysisStore::open(&root)?;
            let scope = DataStoreQualification::native_scope();
            data.register_processor(&scope, ProcessorClassV1::Required, 1)?;
            data.accept_validated_batch(
                scope.identity.clone(),
                araphor_data::ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: START,
                    framed_records: b"prior".to_vec().into(),
                    frame_ends: vec![5],
                },
            )?;
            let before = data.meta()?;
            let status = data.source_status(&scope.identity)?;
            let records = data.read_page(&scope.identity, 1)?.records;
            drop(data);
            let mut child = tokio::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "discovery::data_store::tests::data_commit_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ARAPHOR_COMMIT_ROOT", &root)
                .env("ARAPHOR_COMMIT_LIMIT", limit.to_string())
                .env("ARAPHOR_COMMIT_KIND", kind)
                .kill_on_drop(true)
                .spawn()?;
            let exit = tokio::time::timeout(Duration::from_secs(10), child.wait()).await??;
            assert_eq!(exit.code(), Some(73));
            let data = AnalysisStore::open_with_limits(
                &root,
                araphor_data::RetentionLimitsV1 {
                    raw_max_age_ns: result.then_some(24 * HOUR),
                    ..Default::default()
                },
                Default::default(),
            )?;
            if kind == "metadata" {
                assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
                assert_eq!(data.read_page(&scope.identity, 1)?.records.len(), 2);
            } else {
                assert_eq!(data.meta()?, before);
                assert_eq!(data.source_status(&scope.identity)?, status);
                assert_eq!(data.read_page(&scope.identity, 1)?.records, records);
            }
            assert_eq!(
                data.read_result(scope.identity.tenant_id, "native-result")?,
                None
            );
            assert_eq!(
                data.processor_health(&scope)?
                    .ok_or("processor absent")?
                    .consumed_cursor,
                0
            );
            let mut watch = data.subscribe_revision();
            assert_eq!(
                *watch.borrow_and_update(),
                before.commit_revision + u64::from(kind == "metadata")
            );
            DataStoreQualification::native_commit(&data, result)?;
            let after = data.meta()?;
            assert_eq!(after.commit_revision, before.commit_revision + 1);
            assert_eq!(watch.has_changed()?, kind != "metadata");
            assert_eq!(*watch.borrow_and_update(), after.commit_revision);
            DataStoreQualification::native_commit(&data, result)?;
            assert!(!watch.has_changed()?);
            assert_eq!(data.meta()?, after);
            assert_eq!(
                data.processor_health(&scope)?
                    .ok_or("processor absent")?
                    .consumed_cursor,
                u64::from(result)
            );
            if result {
                assert_eq!(
                    data.read_result(scope.identity.tenant_id, "native-result")?,
                    Some(b"finding".to_vec())
                );
                let retained = EvidenceRetentionOwner::new(&data)
                    .retain(&scope.identity, START + 25 * HOUR)?;
                assert_eq!(retained.removed_records, 0);
            } else {
                assert_eq!(
                    data.source_receipt(&scope.identity)?
                        .ok_or("receipt absent")?
                        .contiguous_cursor,
                    2
                );
            }
            let final_meta = data.meta()?;
            drop(data);
            let data = AnalysisStore::open(&root)?;
            assert_eq!(data.meta()?, final_meta);
            let page = data.read_page(&scope.identity, 1)?;
            assert_eq!(page.records.len(), if result { 1 } else { 2 });
            assert_eq!(page.records[0], records[0]);
            assert_eq!(
                data.processor_health(&scope)?
                    .ok_or("processor absent")?
                    .consumed_cursor,
                u64::from(result)
            );
            assert_eq!(
                data.read_result(scope.identity.tenant_id, "native-result")?,
                result.then(|| b"finding".to_vec())
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "subprocess helper; requires the parent's temporary Control configuration"]
async fn data_control_child() -> Result<()> {
    let root = PathBuf::from(std::env::var_os("ARAPHOR_CONTROL_CRASH_ROOT").ok_or("root absent")?);
    let mut parts =
        mithril_control::ControlConfig::load(&root.join("control.json"))?.into_parts()?;
    if let Some(error) = parts.data_error {
        return Err(error.into());
    }
    parts
        .control
        .set_evidence_commit_hook(|| std::process::exit(73));
    let server = ControlServerFixture::start_tls(parts.tls, parts.control).await?;
    // The serial test harness can leave its test name on this line.
    println!("\nCONTROL_READY={}", server.address());
    std::future::pending::<()>().await;
    Ok(())
}

#[tokio::test]
async fn data_control_crash() -> Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncBufReadExt as _;

    let tls = MtlsFixture::new(false)?;
    let control_root = tls.path().join("control-store");
    let store = ControlStore::open(&control_root)?;
    let policy_id = {
        let fixture = OutagePolicyFixture::new(store.clone());
        let resource = fixture.resource(1)?;
        fixture
            .owner
            .reconcile(
                &resource,
                OUTAGE_NAMESPACE_UID,
                &fixture.inventory(&resource)?,
                i64::try_from(START)?,
            )?
            .source_revision
            .policy_source_revision_id
    };
    let policy = store.policy_document(&policy_id)?.ok_or("policy absent")?;
    drop(store);
    tls.configuration()?;
    let open_node = || {
        EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                [7; 16].into(),
            )?,
        )
    };
    let observations = open_node()?;
    DataStoreQualification::record(&observations, 1);
    let batch = observations
        .next_evidence_batch()
        .ok_or("Node batch absent")?;
    let wire: mithril_control::EvidenceBatch = batch.clone().into();
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        node_id: "node-a".into(),
        node_boot_id: [7; 16],
        label_epoch: 1,
        source_id: wire.source_id.as_slice().try_into()?,
        source_epoch: wire.source_epoch,
    };
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "discovery::data_store::tests::data_control_child",
            "--ignored",
            "--nocapture",
        ])
        .env("ARAPHOR_CONTROL_CRASH_ROOT", tls.path())
        .env("RUST_TEST_THREADS", "1")
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut output =
        tokio::io::BufReader::new(child.stdout.take().ok_or("child stdout absent")?).lines();
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(line) = output.next_line().await? {
            if let Some(value) = line.strip_prefix("CONTROL_READY=") {
                return Ok::<std::net::SocketAddr, Box<dyn StdError>>(value.parse()?);
            }
        }
        Err("Control child exited before readiness".into())
    })
    .await??;
    let case = DataStoreQualification::new(tls.path().join("result"));
    let mut connection = case.connect_at(&tls, address, "node-a", [7; 16]).await?;
    connection.report_readiness(true, true).await?;
    connection.policy_inventory(None, Vec::new()).await?;
    let mut invalid = batch.clone();
    invalid.first_cursor = 0;
    connection.send_evidence_batch(invalid).await?;
    let error = DataStoreQualification::ack(&mut connection)
        .await
        .err()
        .ok_or("invalid batch accepted")?;
    assert!(matches!(error.downcast_ref::<mithril_node::Error>(),
        Some(mithril_node::Error::ControlRpc { source, .. }) if source.code() == tonic::Code::InvalidArgument));
    assert!(child.try_wait()?.is_none());
    assert_eq!(observations.pending_evidence_records(), 1);
    drop(connection);
    let mut connection = case.connect_at(&tls, address, "node-a", [7; 16]).await?;
    connection.send_evidence_batch(batch).await?;
    assert!(
        DataStoreQualification::ack(&mut connection).await.is_err(),
        "Control sent an ACK before its injected exit"
    );
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
    assert_eq!(status.code(), Some(73));
    assert_eq!(observations.pending_evidence_records(), 1);
    drop(connection);
    drop(observations);
    let observations = open_node()?;
    let replay = observations
        .next_evidence_batch()
        .ok_or("Node replay absent")?;
    assert_eq!(mithril_control::EvidenceBatch::from(replay.clone()), wire);
    let data = Arc::new(AnalysisStore::open(tls.path().join("evidence/analysis"))?);
    let receipt = data
        .source_receipt(&identity)?
        .ok_or("committed receipt absent")?;
    assert_eq!(receipt.contiguous_cursor, 1);
    let committed = data.read_page(&identity, 1)?;
    assert_eq!(committed.records.len(), 1);
    assert_eq!(committed.records[0].framed_record, wire.framed_records);
    let store = ControlStore::open(&control_root)?;
    assert_eq!(store.policy_document(&policy_id)?, Some(policy.clone()));
    assert!(!store.root().join("evidence/segments-v2").exists());
    let intake = EvidenceIntakeOwner::new(
        store.clone(),
        data.clone(),
        Arc::new(mithril_control::SystemIntakeClock),
    )?;
    let control = tls.control_from_intake(intake, 1)?;
    let allowed: Vec<_> = control.allowed_nodes().values().cloned().collect();
    let mut projector =
        mithril_control::ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
    projector.reconcile()?;
    let before = data.meta()?;
    projector.reconcile()?;
    assert_eq!(data.meta()?, before);
    drop(projector);
    let server = tls.start(control).await?;
    let mut connection = case.connect(&tls, &server).await?;
    connection.send_evidence_batch(replay.clone()).await?;
    let ack = DataStoreQualification::ack(&mut connection).await?;
    assert_eq!(ack.contiguous_cursor, 1);
    assert_eq!(data.meta()?, before);
    assert_eq!(data.source_receipt(&identity)?, Some(receipt));
    assert_eq!(data.read_page(&identity, 1)?.records, committed.records);
    observations.acknowledge_evidence(ack)?;
    assert_eq!(observations.pending_evidence_records(), 0);
    connection.send_evidence_batch(replay).await?;
    assert_eq!(
        DataStoreQualification::ack(&mut connection)
            .await?
            .contiguous_cursor,
        1
    );
    assert_eq!(data.meta()?, before);
    DataStoreQualification::record(&observations, 2);
    connection
        .send_evidence_batch(
            observations
                .next_evidence_batch()
                .ok_or("new Node batch absent")?,
        )
        .await?;
    let ack = DataStoreQualification::ack(&mut connection).await?;
    assert_eq!(ack.contiguous_cursor, 2);
    observations.acknowledge_evidence(ack)?;
    assert_eq!(observations.pending_evidence_records(), 0);
    assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
    connection.report_readiness(true, true).await?;
    connection.policy_inventory(None, Vec::new()).await?;
    assert_eq!(store.policy_document(&policy_id)?, Some(policy));
    let after = data.meta()?;
    drop(connection);
    server.shutdown().await?;
    drop(data);
    let reopened =
        DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?;
    assert_eq!(reopened.meta()?, after);
    let page = reopened.read_page(&identity, 1)?;
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0], committed.records[0]);
    Ok(())
}

impl DataStoreQualification {
    fn limit_file(limit: u64) -> araphor_data::Result<()> {
        use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
        setrlimit(
            Resource::Fsize,
            Rlimit {
                current: Some(limit),
                ..getrlimit(Resource::Fsize)
            },
        )
        .map_err(|source| araphor_data::Error::Io {
            path: "<file-size-limit>".into(),
            source: source.into(),
            location: Default::default(),
        })
    }

    fn native_scope() -> ProcessorScopeV1 {
        ProcessorScopeV1 {
            processor_id: "native-processor".into(),
            method_version: 1,
            identity: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
        }
    }

    fn native_commit(data: &AnalysisStore, result: bool) -> araphor_data::Result<()> {
        let scope = Self::native_scope();
        if result {
            data.commit_result(&AnalysisResultCommitV1 {
                witnesses: vec![AnalysisWitnessV1 {
                    identity: scope.identity.clone().into(),
                    cursor: 1,
                    expires_utc_ns: START + 48 * HOUR,
                }],
                scope,
                expected_cursor: 0,
                consumed_cursor: 1,
                coverage_revision: 0,
                context_revision: 0,
                result_id: "native-result".into(),
                body: b"finding".to_vec(),
                created_utc_ns: START + 1,
                context_refs: Vec::new(),
            })?;
        } else {
            data.accept_validated_batch(
                scope.identity,
                araphor_data::ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 2,
                    last_cursor: 2,
                    intake_utc_ns: START + 1,
                    framed_records: b"next".to_vec().into(),
                    frame_ends: vec![4],
                },
            )?;
        }
        Ok(())
    }

    async fn wait_capacity(data: &AnalysisStore) -> Result<()> {
        let mut changes = data.subscribe_revision();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let health = data.storage_health()?;
                if health.write_ready && health.retention_healthy && health.intake_capacity {
                    break Ok::<_, Box<dyn StdError>>(());
                }
                changes.changed().await?;
            }
        })
        .await??;
        Ok(())
    }

    async fn capacity_recovery(&self, fault: IntakeFault<'_>) -> Result<()> {
        use rustix::process::{getrlimit, setrlimit, Resource};
        use std::io::{Seek as _, SeekFrom, Write as _};
        use std::os::unix::fs::MetadataExt as _;

        const GIB: u64 = 1024 * 1024 * 1024;
        let disk = match fault {
            IntakeFault::FullDisk(root) => Some(root),
            _ => None,
        };
        let native = matches!(fault, IntakeFault::CommitLimit | IntakeFault::SegmentLimit);
        let directory = match disk {
            Some(root) => {
                assert_eq!(root.parent(), Some(Path::new("/tmp")));
                assert!(root
                    .file_name()
                    .ok_or("filesystem name absent")?
                    .to_string_lossy()
                    .starts_with("araphor-data-disk-"));
                assert!(!fs::symlink_metadata(root)?.file_type().is_symlink());
                assert_eq!(rustix::fs::statfs(root)?.f_type, libc::TMPFS_MAGIC);
                let volume = rustix::fs::statvfs(root)?;
                assert_eq!(volume.f_blocks * volume.f_frsize, GIB);
                assert_eq!(fs::read_dir(root)?.count(), 0);
                tempfile::tempdir_in(root)?
            }
            None => tempfile::tempdir()?,
        };
        let tls = MtlsFixture::new(false)?;
        let mut config = tls.configuration()?;
        config.evidence_directory = directory.path().join("evidence");
        config.data_storage.disk_max_bytes = Some(GIB);
        let parts = config.into_parts()?;
        assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
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
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                [7; 16].into(),
            )?,
        )?;
        Self::record(&observations, 1);
        let first = observations.next_evidence_batch().ok_or("batch absent")?;
        let wire: mithril_control::EvidenceBatch = first.clone().into();
        let identity = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: [7; 16],
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let mut connection = self.connect(&tls, &server).await?;
        connection.report_readiness(true, true).await?;
        connection.send_evidence_batch(first).await?;
        let ack = Self::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, 1);
        observations.acknowledge_evidence(ack)?;
        let cancelled = araphor_data::AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            data.read_page_cancel(&identity, 1, &cancelled),
            Err(araphor_data::Error::AnalysisReadCancelled { .. })
        ));
        connection.policy_inventory(None, Vec::new()).await?;
        assert_eq!(data.read_page(&identity, 1)?.records.len(), 1);
        data.checkpoint()?;
        let backup_root = tls.path().join("backups");
        fs::DirBuilder::new().mode(0o700).create(&backup_root)?;
        let backup_path = backup_root.join("saved");
        let managed = directory.path().join("evidence/analysis/backups/saved");
        let manifest = data.backup(&managed)?;
        fs::DirBuilder::new().mode(0o700).create(&backup_path)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(backup_path.join("segments"))?;
        for file in ["analysis.duckdb", "manifest.json"] {
            fs::copy(managed.join(file), backup_path.join(file))?;
        }
        for segment in &manifest.segments {
            let file = format!("segments/{}", segment.file_name);
            fs::copy(managed.join(&file), backup_path.join(&file))?;
        }
        let saved = AnalysisStore::restore(&backup_path, &backup_root.join("source"))?;
        let saved_meta = saved.meta()?;
        let restore_root = directory.path().join("restore");
        fs::DirBuilder::new().mode(0o700).create(&restore_root)?;
        let before = data.meta()?;
        let status = data.source_status(&identity)?;
        let changed = data.subscribe_revision();
        Self::record(&observations, 2);
        let pending = observations.next_evidence_batch().ok_or("batch absent")?;
        let padding_file = if disk.is_some() {
            tempfile::NamedTempFile::new_in(directory.path())?
        } else {
            tempfile::NamedTempFile::new_in(directory.path().join("evidence/analysis"))?
        };
        let mut padding = padding_file.as_file();
        if disk.is_some() {
            let volume = rustix::fs::statvfs(directory.path())?;
            rustix::fs::fallocate(
                padding,
                rustix::fs::FallocateFlags::empty(),
                0,
                volume.f_bavail * volume.f_frsize,
            )?;
            assert_eq!(rustix::fs::statvfs(directory.path())?.f_bavail, 0);
            padding.seek(SeekFrom::End(0))?;
            assert!(matches!(padding.write_all(b"full"),
                Err(error) if error.raw_os_error() == Some(libc::ENOSPC)));
            assert!(matches!(
                EvidenceRetentionOwner::new(&data).step(START),
                Err(araphor_data::Error::StorageCapacity {
                    resource: "filesystem reserve",
                    ..
                })
            ));
            assert!(!data.retention_healthy());
        } else if !native {
            padding.set_len(GIB)?;
        }
        let full = data.storage_health()?;
        assert_eq!(full.intake_capacity, native);
        assert_eq!(full.maintenance_capacity, disk.is_none());
        let allocated = padding.metadata()?.blocks() * 512;
        if disk.is_some() {
            assert!(allocated > GIB / 2);
            let destination = directory.path().join("evidence/analysis/backups/blocked");
            assert!(matches!(
                data.backup(&destination),
                Err(araphor_data::Error::StorageCapacity {
                    resource: "filesystem reserve",
                    ..
                })
            ));
            assert!(!destination.exists());
            assert!(!destination.join("manifest.json").exists());
            assert_eq!(saved.meta()?, saved_meta);
            assert_eq!(saved.read_page(&identity, 1)?.records.len(), 1);
            assert!(matches!(
                AnalysisStore::restore(&backup_path, &restore_root),
                Err(araphor_data::Error::StorageCapacity {
                    resource: "copy reserve",
                    ..
                })
            ));
            assert!(restore_root.join("restore.pending").is_file());
            assert!(!restore_root.join("analysis.duckdb").exists());
            assert_eq!(fs::read_dir(&restore_root)?.count(), 2);
            assert!(restore_root.join("analysis.lock").is_file());
            assert!(matches!(
                AnalysisStore::open(&restore_root),
                Err(araphor_data::Error::AnalysisState { reason, .. })
                    if reason.contains("restore is incomplete")
            ));
            assert!(!restore_root.join("analysis.duckdb").exists());
        }
        let _signal = if native {
            Some(tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::from_raw(libc::SIGXFSZ),
            )?)
        } else {
            None
        };
        let prior = getrlimit(Resource::Fsize);
        if native {
            let stage = if matches!(fault, IntakeFault::SegmentLimit) {
                araphor_data::AnalysisCommitStage::BeforeAppend
            } else {
                araphor_data::AnalysisCommitStage::AfterSync
            };
            data.set_commit_hook(stage, || Self::limit_file(64))?;
        }
        let received: Result<_> = async {
            connection.send_evidence_batch(pending.clone()).await?;
            Ok(tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?)
        }
        .await;
        let catalogue = matches!(fault, IntakeFault::CommitLimit).then(|| data.checkpoint());
        if native {
            setrlimit(Resource::Fsize, prior)?;
        }
        if let Some(catalogue) = catalogue {
            let NodeControlMessage::EvidenceAck(ack) = received?? else {
                return Err("raw acceptance did not return its ACK".into());
            };
            assert_eq!(ack.contiguous_cursor, 2);
            observations.acknowledge_evidence(ack)?;
            assert_eq!(observations.pending_evidence_records(), 0);
            assert!(catalogue.is_err());
            assert!(changed.has_changed()?);
            assert_eq!(
                data.source_receipt(&identity)?
                    .ok_or("receipt absent")?
                    .contiguous_cursor,
                2
            );
            data.recover()?;
            assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
            assert_eq!(data.read_page(&identity, 1)?.records.len(), 2);
            Self::wait_capacity(&data).await?;
            connection.send_evidence_batch(pending).await?;
            assert_eq!(Self::ack(&mut connection).await?.contiguous_cursor, 2);
            assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
            drop(connection);
            server.shutdown().await?;
            let after = data.meta()?;
            drop(data);
            let data = Self::reopen_data(&directory.path().join("evidence/analysis")).await?;
            assert_eq!(data.meta()?, after);
            assert_eq!(data.read_page(&identity, 1)?.records.len(), 2);
            println!(
                "{}",
                serde_json::json!({
                    "case": "data-catalogue-recovery", "result": "PASS",
                    "raw_ack_before_catalogue": true, "contiguous_cursor": 2,
                    "proof_kind": "synthetic-mtls", "kernel_evidence": false,
                })
            );
            return Ok(());
        }
        let error = received?.err().ok_or("failed write received an ACK")?;
        let mithril_node::Error::ControlRpc { source, .. } = error else {
            return Err(error.into());
        };
        if native {
            assert_eq!(source.code(), tonic::Code::Unavailable);
            assert!(source.message().contains("File too large"), "{source}");
            if matches!(fault, IntakeFault::SegmentLimit) {
                assert!(source.message().contains(".open"), "{source}");
            } else {
                assert!(source.message().contains("commit evidence"), "{source}");
                assert!(source.message().contains("analysis.duckdb.wal"), "{source}");
            }
        } else {
            assert_eq!(source.code(), tonic::Code::ResourceExhausted);
        }
        assert_eq!(*changed.borrow(), before.commit_revision);
        assert_eq!(observations.pending_evidence_records(), 1);
        assert_eq!(data.storage_health()?.write_ready, !native);
        connection.policy_inventory(None, Vec::new()).await?;
        if native {
            data.recover()?;
            assert!(data.storage_health()?.write_ready);
            assert!(changed.has_changed()?);
        }
        assert_eq!(data.meta()?, before);
        assert_eq!(data.source_status(&identity)?, status);
        assert_eq!(
            data.read_page(&identity, 1)?.records[0].framed_record,
            wire.framed_records
        );
        connection.policy_inventory(None, Vec::new()).await?;
        padding.set_len(0)?;
        padding.sync_all()?;
        if disk.is_some() {
            data.recover()?;
        }
        let restored = AnalysisStore::restore(&backup_path, &backup_root.join("retry"))?;
        assert_eq!(restored.meta()?, saved_meta);
        assert_eq!(restored.meta()?.commit_revision, manifest.commit_revision);
        assert_eq!(
            restored.read_page(&identity, 1)?.records[0].framed_record,
            wire.framed_records
        );
        drop(connection);
        Self::wait_capacity(&data).await?;
        let mut connection = self.connect(&tls, &server).await?;
        connection.send_evidence_batch(pending.clone()).await?;
        let ack = Self::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, 2);
        observations.acknowledge_evidence(ack)?;
        assert_eq!(observations.pending_evidence_records(), 0);
        assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
        connection.send_evidence_batch(pending).await?;
        assert_eq!(Self::ack(&mut connection).await?.contiguous_cursor, 2);
        assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
        data.checkpoint()?;
        drop(connection);
        server.shutdown().await?;
        let after = data.meta()?;
        drop(data);
        let data = Self::reopen_data(&directory.path().join("evidence/analysis")).await?;
        assert_eq!(data.meta()?, after);
        assert_eq!(data.read_page(&identity, 1)?.records.len(), 2);
        assert_eq!(
            data.source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            2
        );
        println!(
            "{}",
            serde_json::json!({
                "case": "data-capacity-recovery", "result": "PASS",
                "filesystem_full": disk.is_some(), "padding_allocated_bytes": allocated,
                "native_commit_failure": native,
                "copy_reserve_rejected": disk.is_some(),
                "rejected_health": full, "recovered_usage": data.storage_usage()?,
                "source_identity": identity, "commit_revision": after.commit_revision,
                "contiguous_cursor": 2, "retained_count": 2,
                "proof_kind": "synthetic-mtls", "kernel_evidence": false,
            })
        );
        Ok(())
    }
}

#[tokio::test]
async fn data_capacity_recovery() -> Result<()> {
    let directory = tempfile::tempdir()?;
    DataStoreQualification::new(directory.path().join("result"))
        .capacity_recovery(IntakeFault::Quota)
        .await
}

#[tokio::test]
#[ignore = "requires the task-owned, empty 1 GiB tmpfs"]
async fn data_full_disk() -> Result<()> {
    let root = PathBuf::from(std::env::var("ARAPHOR_TEST_DATA_DISK")?);
    DataStoreQualification::new(root.join("result"))
        .capacity_recovery(IntakeFault::FullDisk(&root))
        .await
}

#[tokio::test]
async fn data_intake_failure() -> Result<()> {
    for kind in ["segment", "metadata"] {
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "discovery::data_store::tests::data_intake_child",
                "--ignored",
                "--nocapture",
            ])
            .env("ARAPHOR_INTAKE_KIND", kind)
            .kill_on_drop(true)
            .spawn()?;
        let status = tokio::time::timeout(Duration::from_secs(20), child.wait()).await??;
        assert!(status.success(), "{status}");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "subprocess helper; applies a process-wide native file-size limit"]
async fn data_intake_child() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let fault = match std::env::var("ARAPHOR_INTAKE_KIND")?.as_str() {
        "segment" => IntakeFault::SegmentLimit,
        "metadata" => IntakeFault::CommitLimit,
        _ => return Err("unknown intake fault".into()),
    };
    DataStoreQualification::new(directory.path().join("result"))
        .capacity_recovery(fault)
        .await
}

#[tokio::test]
async fn data_context_projection() -> Result<()> {
    use araphor_data::AnalysisContextKeyV1;
    use araphor_query::execution::{Engine, Limits};
    use araphor_query::follow::SystemClock;
    use futures_util::StreamExt as _;
    let tls = MtlsFixture::new(false)?;
    let store = ControlStore::open(tls.path().join("control-store"))?;
    let fixture = OutagePolicyFixture::new(store.clone());
    let resource = fixture.resource(1)?;
    let first = fixture.owner.reconcile(
        &resource,
        OUTAGE_NAMESPACE_UID,
        &fixture.inventory(&resource)?,
        i64::try_from(START)?,
    )?;
    let data = Arc::new(AnalysisStore::open(tls.path().join("analysis"))?);
    let intake = EvidenceIntakeOwner::new(
        store.clone(),
        data.clone(),
        Arc::new(TestClock(AtomicU64::new(START))),
    )?;
    let control = tls.control_from_intake(intake, 1)?;
    let authority = store.commit_index();
    let source = &first.source_revision;
    let source_key = AnalysisContextKeyV1 {
        tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
        owner_id: "mithril-control/policy".into(),
        entity_key: source.object_uid.as_bytes().to_vec(),
        lifetime_key: source.policy_source_revision_id.as_bytes().to_vec(),
        owner_revision: source.object_generation,
    };
    assert_eq!(data.context_version(&source_key)?, None);
    let engine = Engine::new(data.clone(), Limits::default())?;
    let mut subscription = engine
        .subscribe(
            "SELECT owner_id, entity_key, lifetime_key, owner_revision, body \
                FROM context_versions ORDER BY owner_id, entity_key, lifetime_key, owner_revision",
            Vec::new(),
            araphor_data::AnalysisSelectionV1::tenant(source_key.tenant_id),
            Arc::new(araphor_data::AnalysisReadControl::with_timeout(
                Duration::from_secs(60),
            )?),
            b"context-publication",
            None,
            Arc::new(SystemClock::default()),
            true,
        )
        .await?;
    let initial = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await?
        .ok_or("initial context capture absent")??;
    assert_eq!(initial.snapshot.contexts().count(), 0);
    let (fail, failed) = tokio::sync::oneshot::channel();
    data.set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeContextCommit,
        move || {
            let _sent = fail.send(());
            Err(araphor_data::PackageErrorCodeV1::Incomplete.error("injected context commit"))
        },
    )?;
    let server = tls.start(control.clone()).await?;
    tokio::time::timeout(Duration::from_secs(5), failed).await??;
    assert_eq!(data.meta()?, initial.snapshot.page.extraction.meta);
    assert!(data.context_version(&source_key)?.is_none());
    assert_eq!(store.commit_index(), authority);
    data.recover()?;
    assert_eq!(store.commit_index(), authority);
    let projected = ControlServerFixture::wait_context(&data, &source_key).await?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&projected.body)?,
        serde_json::json!({"source": source,
            "document": store.policy_document(&source.policy_source_revision_id)?})
    );
    assert_eq!(projected.valid_from_utc_ns, None);
    assert_eq!(projected.valid_until_utc_ns, None);
    let rollout = first.rollout_states.first().ok_or("rollout absent")?;
    assert_eq!(rollout.transition_version, 0);
    let rollout_key = AnalysisContextKeyV1 {
        tenant_id: source_key.tenant_id,
        owner_id: "mithril-control/rollout".into(),
        entity_key: rollout.target.node_id.as_bytes().to_vec(),
        lifetime_key: rollout.desired_candidate_content_id.as_bytes().to_vec(),
        owner_revision: rollout.transition_version,
    };
    let pending = ControlServerFixture::wait_context(&data, &rollout_key).await?;
    assert_eq!(pending.body, serde_json::to_vec(rollout)?);
    let captured = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await?
        .ok_or("published context capture absent")??;
    let source_ref = captured
        .snapshot
        .contexts()
        .find(|reference| reference.key == source_key)
        .ok_or("source receipt absent")?;
    let rollout_ref = captured
        .snapshot
        .contexts()
        .find(|reference| reference.key == rollout_key)
        .ok_or("rollout receipt absent")?;
    assert_eq!(source_ref.commit_revision, rollout_ref.commit_revision);
    assert_eq!(
        captured
            .batches
            .as_ref()
            .ok_or("context batches absent")?
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        captured.snapshot.contexts().count()
    );
    assert_eq!(store.commit_index(), authority);
    let mut foreign = source_key.clone();
    foreign.tenant_id = [9; 16];
    assert_eq!(data.context_version(&foreign)?, None);

    let resource = fixture.resource(2)?;
    let second = fixture.owner.reconcile(
        &resource,
        OUTAGE_NAMESPACE_UID,
        &fixture.inventory(&resource)?,
        i64::try_from(START + 1)?,
    )?;
    let source = &second.source_revision;
    let second_key = AnalysisContextKeyV1 {
        lifetime_key: source.policy_source_revision_id.as_bytes().to_vec(),
        owner_revision: source.object_generation,
        ..source_key.clone()
    };
    let second_copy = ControlServerFixture::wait_context(&data, &second_key).await?;
    let updated = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await?
        .ok_or("changed context capture absent")??;
    let changed = updated
        .snapshot
        .contexts()
        .find(|reference| reference.key == second_key)
        .ok_or("changed source receipt absent")?;
    assert!(changed.commit_revision > source_ref.commit_revision);
    assert!(captured
        .snapshot
        .contexts()
        .all(|reference| reference.key != second_key));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&second_copy.body)?,
        serde_json::json!({"source": source,
            "document": store.policy_document(&source.policy_source_revision_id)?})
    );
    assert_eq!(data.context_version(&source_key)?, Some(projected));
    assert_eq!(data.context_version(&rollout_key)?, Some(pending));
    subscription.cancel()?;
    server.shutdown().await?;
    let allowed: Vec<_> = control.allowed_nodes().values().cloned().collect();
    let mut projector =
        mithril_control::ControlContextOwner::new(store.clone(), data.clone(), &allowed)?;
    projector.reconcile()?;
    let before = data.meta()?;
    projector.reconcile()?;
    assert_eq!(data.meta()?, before);
    let server = tls.start(control).await?;
    let case = DataStoreQualification::new(tls.path().join("result"));
    let mut connection = case.connect(&tls, &server).await?;
    connection.report_readiness(true, true).await?;
    connection.policy_inventory(None, Vec::new()).await?;
    assert_eq!(data.meta()?, before);
    drop(connection);
    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn data_reopen_preserves_errors() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let reopening = DataStoreQualification::reopen_data(&root);
    tokio::pin!(reopening);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut reopening)
            .await
            .is_err()
    );
    drop(store);
    drop(reopening.await?);
    fs::write(root.join("analysis.duckdb"), b"invalid database")?;
    let error = DataStoreQualification::reopen_data(&root)
        .await
        .err()
        .ok_or("corrupt store accepted")?;
    assert!(matches!(
        error.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisDatabase { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn data_store_startup() -> Result<()> {
    let output = tempfile::tempdir()?;
    DataStoreQualification::new(output.path().join("result"))
        .startup()
        .await
}

#[tokio::test]
async fn data_store_recovery() -> Result<()> {
    let output = tempfile::tempdir()?;
    DataStoreQualification::new(output.path().join("result"))
        .recovery()
        .await
}

#[tokio::test]
async fn data_retirement_startup() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let case = DataStoreQualification::new(tls.path().join("result"));
    let parts = tls.configuration()?.into_parts()?;
    let data = parts.control.analysis_store().ok_or("data owner absent")?;
    let observations = EffectObservationStore::durable(
        8,
        tls.path().join("wal"),
        EvidenceWalLimits::default(),
        ObservationCanonicalizer::new(
            EvidenceIdV1::new(1, 2),
            EvidenceIdV1::new(3, 4),
            1,
            [7; 16].into(),
        )?,
    )?;
    DataStoreQualification::record(&observations, 1);
    let batch = observations.next_evidence_batch().ok_or("batch absent")?;
    let wire: mithril_control::EvidenceBatch = batch.clone().into();
    let request = araphor_data::ProcessorRetirementV1 {
        scope: ProcessorScopeV1 {
            processor_id: "security-fixture".into(),
            method_version: 1,
            identity: EvidenceIntakeIdentityV1 {
                tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
                node_id: "node-a".into(),
                node_boot_id: [7; 16],
                label_epoch: 1,
                source_id: wire.source_id.as_slice().try_into()?,
                source_epoch: wire.source_epoch,
            },
        },
        change_id: "operator-change-1".into(),
        reason: "Retire this fixture package.".into(),
        expected_cursor: 0,
        cutoff_cursor: 1,
    };
    data.register_processor(&request.scope, ProcessorClassV1::Required, 1)?;
    let server = tls.start(parts.control).await?;
    let mut connection = case.connect(&tls, &server).await?;
    connection.send_evidence_batch(batch).await?;
    observations.acknowledge_evidence(DataStoreQualification::ack(&mut connection).await?)?;
    let before = data.meta()?;
    let mut config = tls.configuration()?;
    let mut foreign = request.clone();
    foreign.scope.identity.tenant_id = [9; 16];
    config.data_retirements = vec![foreign];
    assert!(config.into_parts().is_err());
    let mut config = tls.configuration()?;
    config.data_retirements = vec![request.clone(), request.clone()];
    assert!(config.into_parts().is_err());
    let mut config = tls.configuration()?;
    config.data_retirements = vec![request.clone(); 33];
    assert!(config.into_parts().is_err());
    assert_eq!(data.meta()?, before);
    assert!(data.processor_retirement(&request.scope)?.is_none());
    drop(connection);
    server.shutdown().await?;
    drop(data);
    drop(DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?);
    drop(reopen_control_store(&tls.path().join("control-store")).await?);

    let mut config = tls.configuration()?;
    let mut stale = request.clone();
    stale.cutoff_cursor = 0;
    config.data_retirements = vec![stale];
    let parts = config.into_parts()?;
    assert!(parts.data_error.is_some());
    assert!(parts.control.analysis_store().is_none());
    let server = tls.start(parts.control).await?;
    let mut connection = case.connect(&tls, &server).await?;
    connection.report_readiness(true, true).await?;
    connection.policy_inventory(None, Vec::new()).await?;
    DataStoreQualification::record(&observations, 2);
    let pending = observations
        .next_evidence_batch()
        .ok_or("pending batch absent")?;
    connection.send_evidence_batch(pending.clone()).await?;
    let rejected = tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?;
    assert!(
        matches!(rejected, Err(mithril_node::Error::ControlRpc { source, .. }) if source.code() == tonic::Code::Unavailable)
    );
    assert_eq!(observations.pending_evidence_records(), 1);
    drop(connection);
    server.shutdown().await?;
    drop(reopen_control_store(&tls.path().join("control-store")).await?);

    let mut config = tls.configuration()?;
    config.data_retirements = vec![request.clone()];
    let parts = config.into_parts()?;
    assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
    let data = parts.control.analysis_store().ok_or("data owner absent")?;
    let retirement = data
        .processor_retirement(&request.scope)?
        .ok_or("retirement absent")?;
    assert_eq!(retirement.0, request);
    let health = data
        .processor_health(&request.scope)?
        .ok_or("health absent")?;
    assert_eq!(health.state, ProcessorStateV1::Retired);
    assert_eq!(health.consumed_cursor, 0);
    assert!(health.incomplete);
    let server = tls.start(parts.control).await?;
    let mut connection = case.connect(&tls, &server).await?;
    connection.send_evidence_batch(pending).await?;
    let ack = DataStoreQualification::ack(&mut connection).await?;
    assert_eq!(ack.contiguous_cursor, 2);
    observations.acknowledge_evidence(ack)?;
    assert_eq!(observations.pending_evidence_records(), 0);
    let before = data.meta()?;
    drop(connection);
    server.shutdown().await?;
    drop(data);
    drop(DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?);
    drop(reopen_control_store(&tls.path().join("control-store")).await?);
    let mut config = tls.configuration()?;
    config.data_retirements = vec![request.clone()];
    let parts = config.into_parts()?;
    assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
    let data = parts.control.analysis_store().ok_or("data owner absent")?;
    assert_eq!(data.meta()?, before);
    assert_eq!(data.processor_retirement(&request.scope)?, Some(retirement));
    Ok(())
}

#[tokio::test]
async fn data_capacity_retry() -> Result<()> {
    for seeded in [false, true] {
        let tls = MtlsFixture::new(false)?;
        let case = DataStoreQualification::new(tls.path().join("result"));
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                [7; 16].into(),
            )?,
        )?;
        if seeded {
            let parts = tls.configuration()?.into_parts()?;
            assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
            let server = tls.start(parts.control).await?;
            let mut connection = case.connect(&tls, &server).await?;
            DataStoreQualification::record(&observations, 1);
            connection
                .send_evidence_batch(observations.next_evidence_batch().ok_or("batch absent")?)
                .await?;
            let ack = DataStoreQualification::ack(&mut connection).await?;
            assert_eq!(ack.contiguous_cursor, 1);
            observations.acknowledge_evidence(ack)?;
            drop(connection);
            server.shutdown().await?;
            drop(DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?);
            drop(reopen_control_store(&tls.path().join("control-store")).await?);
        }
        let mut config = tls.configuration()?;
        config.data_storage.policy_reserve_bytes = Some(u64::MAX / 4);
        if seeded {
            config.data_retention.raw_max_age_ns = Some(24 * HOUR);
        }
        let parts = config.into_parts()?;
        assert!(parts.data_error.is_none());
        let data = parts.control.analysis_store().ok_or("data owner absent")?;
        if seeded {
            assert!(matches!(
                EvidenceRetentionOwner::new(&data).step(START),
                Err(araphor_data::Error::StorageCapacity {
                    resource: "filesystem reserve",
                    ..
                })
            ));
            assert!(!data.retention_healthy());
        }
        let before = data.meta()?;
        let changed = data.subscribe_revision();
        let server = tls.start(parts.control).await?;
        let cursor = if seeded { 2 } else { 1 };
        DataStoreQualification::record(&observations, cursor);
        let batch = observations.next_evidence_batch().ok_or("batch absent")?;
        let mut connection = case.connect(&tls, &server).await?;
        connection.report_readiness(true, true).await?;
        connection.send_evidence_batch(batch.clone()).await?;
        let rejected =
            tokio::time::timeout(Duration::from_secs(5), connection.next_message()).await?;
        assert!(
            matches!(rejected, Err(mithril_node::Error::ControlRpc { source, .. }) if source.code() == tonic::Code::ResourceExhausted)
        );
        if seeded {
            let snapshot = observations.coverage_snapshot().ok_or("coverage absent")?;
            let interval = snapshot
                .current_intervals()
                .into_iter()
                .next()
                .ok_or("source coverage absent")?;
            let coverage = connection.send_coverage_report(&snapshot, &interval).await;
            assert!(
                matches!(coverage, Err(mithril_node::Error::ControlRpc { source, .. })
                    if source.code() == tonic::Code::ResourceExhausted)
            );
        }
        assert_eq!(observations.pending_evidence_records(), 1);
        assert_eq!(data.meta()?, before);
        assert_eq!(*changed.borrow(), before.commit_revision);
        connection.policy_inventory(None, Vec::new()).await?;
        drop(connection);
        server.shutdown().await?;
        drop(data);
        drop(DataStoreQualification::reopen_data(&tls.path().join("evidence/analysis")).await?);
        drop(reopen_control_store(&tls.path().join("control-store")).await?);

        let parts = tls.configuration()?.into_parts()?;
        assert!(parts.data_error.is_none(), "{:?}", parts.data_error);
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
        let mut connection = case.connect(&tls, &server).await?;
        connection.send_evidence_batch(batch).await?;
        let ack = DataStoreQualification::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, cursor);
        observations.acknowledge_evidence(ack)?;
        assert_eq!(observations.pending_evidence_records(), 0);
        assert_eq!(data.meta()?.commit_revision, baseline + 1);
        drop(connection);
        server.shutdown().await?;
    }
    Ok(())
}
