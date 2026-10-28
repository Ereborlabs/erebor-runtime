use super::*;

#[tokio::test]
async fn retained_floor_is_gapped() -> TestResult {
    const INPUT: usize = 32 * 1024 * 1024;
    let mut records = records(1, [[7; 16]; 3])?;
    let source = records[0].id.stream.clone();
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            ..Default::default()
        },
        Default::default(),
    )?);
    for record in &records[..2] {
        store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: record.id.durable_cursor,
                last_cursor: record.id.durable_cursor,
                intake_utc_ns: record.id.durable_cursor,
                frame_ends: vec![record.wire_record.len()],
                framed_records: record.wire_record.clone().into(),
            },
        )?;
    }
    let expired = araphor_data::EvidenceRetentionOwner::new(&store).retain(&source, 10)?;
    assert_eq!(expired.removed_records, 2);
    assert_eq!(expired.retained_floor, 2);
    assert!(!store.graph_enabled());
    let mut fixture = Fixture::stored(Target::Sql, records.split_off(2), directory, store)?;
    fixture.query = Engine::new(
        Arc::clone(fixture.query.store()),
        araphor_query::execution::Limits {
            input_capacity: Some(INPUT),
            global_evaluations: Some(1),
            ..Default::default()
        },
    )?;
    report(&fixture, 1, &[([7; 16], 11, "HEALTHY")])?;
    let (facts, _) = Facts::default().facts(&[], &fixture.records)?;
    let owner = payload(
        &fixture,
        GraphReplayInputV1 {
            source: source.clone(),
            records: fixture.records.clone(),
            coverage: vec![range(
                &fixture,
                1,
                0,
                [7; 16],
                DiscoveryCoverageStateV1::Healthy,
                Vec::new(),
            )],
            coverage_keys: vec![GraphCoverageKeyV1 {
                source: source.clone(),
                cpu_id: fixture.records[0].id.cpu_id,
                report_revision: 1,
                interval_id: [7; 16],
                interval_revision: 11,
                state: DiscoveryCoverageStateV1::Healthy,
                gap_reasons: Vec::new(),
            }],
            facts,
            missing_ranges: vec![(1, 2)],
        },
        sdk::CoverageState::Gapped,
        "graph:retained-floor",
        "",
    )
    .await?;
    let (id, _, _) = fixture
        .query
        .store()
        .graph_window_headers(&source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 3)
        .ok_or("retained-floor Graph window")?;
    let graph = fixture
        .query
        .store()
        .graph_result(source.tenant_id, &id)?
        .ok_or("retained-floor graph")?;
    let scope = graph.scope.clone();
    assert_eq!(graph.missing_ranges, vec![(1, 2)]);
    assert_eq!(graph.input_manifest.missing_ranges, vec![(1, 2)]);
    assert_eq!(
        graph.input_manifest.evidence,
        vec![fixture.records[0].id.clone()]
    );
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("graph progress")?
            .consumed_cursor,
        graph.last_cursor
    );
    assert_eq!(graph.last_cursor, 3);
    let before_domain = fixture.graph_history()?;
    let before_heads = fixture.query.store().graph_window_headers(&source, None)?;
    let before_head = fixture.query.store().processor_result(&scope)?;
    let before_health = fixture.query.store().processor_health(&scope)?;
    let before_instance = fixture
        .query
        .store()
        .managed_instance(
            source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control,
        )?
        .ok_or("retained-floor instance")?;
    let before_history = fixture.query.store().managed_history(
        &owner.admitted().grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    let before = fixture.query.store().meta()?;
    let repeated = owner
        .run(managed::request("repeat")?, &fixture.control)
        .await?;
    let (next, _, _) = fixture
        .query
        .store()
        .graph_window_headers(&source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 3)
        .ok_or("repeated retained-floor window")?;
    assert_eq!(next, id);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(source.tenant_id, &next)?,
        Some(graph)
    );
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        fixture.query.store().graph_window_headers(&source, None)?,
        before_heads
    );
    assert_eq!(fixture.query.store().processor_result(&scope)?, before_head);
    assert_eq!(
        repeated.commit_revision,
        before
            .commit_revision
            .checked_add(2)
            .ok_or("retained-floor revision overflow")?
    );
    let mut expected_meta = before;
    expected_meta.commit_revision = repeated.commit_revision;
    assert_eq!(fixture.query.store().meta()?, expected_meta);
    let expected_health = before_health.map(|mut health| {
        health.read_revision = repeated.commit_revision;
        health
    });
    assert_eq!(
        fixture.query.store().processor_health(&scope)?,
        expected_health
    );
    let mut expected_instance = before_instance;
    expected_instance.progress = repeated.commit_revision;
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance(
                source.tenant_id,
                &owner.admitted().spec.id,
                &fixture.control
            )?
            .ok_or("repeated retained-floor instance")?,
        expected_instance
    );
    let mut expected_history = before_history;
    expected_history.push(repeated);
    assert_eq!(
        fixture.query.store().managed_history(
            &owner.admitted().grant.selection,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        expected_history
    );
    drop(owner);
    drop(fixture.query.reserve_evaluation(source.tenant_id)?);
    drop(fixture.query.memory().reserve_input(INPUT)?);
    Ok(())
}

#[tokio::test]
async fn frozen_keys_preserve_source() -> TestResult {
    let fixture = Fixture::with_records(Target::Sql, records(1, [[7; 16], [8; 16], [7; 16]])?)?;
    report(&fixture, 1, &[([8; 16], 11, "HEALTHY")])?;
    let publication = fixture.prepare("").await?;
    let first_grant = publication.grant.clone();
    let first_definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&first_grant, &first_definition)?;
    drop(publication);
    let first_owner = fixture
        .managed_graph(
            &first_grant,
            &first_definition,
            "unselected-history",
            "SELECT * FROM events",
        )
        .await?;
    let first_receipt = first_owner
        .run(managed::request("evaluate")?, &fixture.control)
        .await?;
    let (first, _, revision) = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("original target Graph window")?;
    assert_eq!(revision, first_receipt.commit_revision);
    let target_scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let consumed = fixture
        .query
        .store()
        .processor_health(&target_scope)?
        .ok_or("target native progress")?
        .consumed_cursor;
    assert_eq!(consumed, 3);
    drop(first_owner);
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("original target graph")?;
    assert!(original
        .input_manifest
        .coverage
        .iter()
        .any(|key| { key.interval_id == [8; 16] && key.report_revision == 1 }));
    let mut other = fixture.source.clone();
    other.source_id = [99; 16];
    let record = &fixture.records[0];
    fixture.query.store().accept_validated_batch(
        other.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: record.id.durable_cursor,
            last_cursor: record.id.durable_cursor,
            intake_utc_ns: 1,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    fixture.query.store().register_graph(&other)?;
    fixture
        .query
        .store()
        .accept_validated_coverage(ValidatedCoverageV1 {
            identity: other.clone(),
            cpu_id: record.id.cpu_id,
            revision: 101,
            encoded_report: CoverageReport {
                source_id: other.source_id.to_vec(),
                source_epoch: other.source_epoch,
                cpu_id: record.id.cpu_id,
                revision: 101,
                intervals: vec![CoverageInterval {
                    interval_id: vec![7; 16],
                    source_epoch: other.source_epoch,
                    revision: 101,
                    state: "GAPPED".into(),
                    first_sequence: 1,
                    last_sequence: Some(1),
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
        })?;
    let publication = fixture
        .prepare("WHERE source_id = decode(repeat('63', 16), 'hex')")
        .await?;
    let foreign_grant = publication.grant.clone();
    let foreign_definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&foreign_grant, &foreign_definition)?;
    drop(publication);
    let foreign_owner = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        foreign_grant.clone(),
        "foreign-history".into(),
        other.clone(),
        "SELECT * FROM events WHERE source_id = decode(repeat('63', 16), 'hex')".into(),
        foreign_definition,
        &fixture.control,
    )
    .await?;
    let foreign_receipt = foreign_owner
        .run(managed::request("evaluate")?, &fixture.control)
        .await?;
    let (foreign, _, revision) = fixture
        .query
        .store()
        .graph_window_headers(&other, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("foreign native Graph window")?;
    assert_eq!(revision, foreign_receipt.commit_revision);
    drop(foreign_owner);
    let retained = fixture
        .query
        .store()
        .graph_result(other.tenant_id, &foreign)?
        .ok_or("foreign graph")?;
    assert_eq!(retained.scope.identity, other);
    assert!(retained.input_manifest.coverage.iter().any(|key| {
        key.source == other && key.report_revision == 101 && key.interval_id == [7; 16]
    }));
    let mut frozen = original.clone();
    frozen.previous_result_id = Some(first.clone());
    frozen
        .input_manifest
        .coverage
        .extend(retained.input_manifest.coverage.clone());
    frozen.input_manifest.coverage.sort();
    frozen.input_manifest.coverage.dedup();
    let before = fixture.query.store().meta()?;
    let contexts = frozen
        .input_manifest
        .context
        .iter()
        .map(|key| {
            fixture
                .query
                .store()
                .context_version(key)?
                .ok_or_else(|| Code::Invalid.error("retained graph fact fixture"))
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let references = fixture.query.store().commit_contexts(&contexts)?;
    assert_eq!(fixture.query.store().meta()?, before);
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let checkpoint = "graph:foreign-frozen-key";
    fixture.query.store().commit_graph_snapshot(
        araphor_data::AnalysisResultCommitV1 {
            scope: frozen.scope.clone(),
            expected_cursor: consumed,
            consumed_cursor: consumed,
            coverage_revision: 1,
            context_revision: references
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id: checkpoint.into(),
            body: Vec::new(),
            created_utc_ns: now,
            witnesses: frozen
                .input_manifest
                .evidence
                .iter()
                .map(|id| araphor_data::AnalysisWitnessV1 {
                    identity: id.stream.clone().into(),
                    cursor: id.durable_cursor,
                    expires_utc_ns: frozen.witness_deadline_utc_ns,
                })
                .collect(),
            context_refs: references,
        },
        araphor_data::analysis::CanonicalGraph::bounded(frozen.clone(), usize::MAX)?,
        &[],
        &[],
        &[],
        false,
        || Ok(()),
    )?;
    report(&fixture, 101, &[([7; 16], 101, "GAPPED")])?;
    report(&fixture, 102, &[([7; 16], 22, "HEALTHY")])?;
    let selected = [fixture.records[0].clone(), fixture.records[2].clone()];
    let (facts, _) = Facts::default().facts(&[], &selected)?;
    drop(
        payload(
            &fixture,
            GraphReplayInputV1 {
                source: fixture.source.clone(),
                records: selected.to_vec(),
                coverage: [0, 2]
                    .into_iter()
                    .map(|index| {
                        range(
                            &fixture,
                            102,
                            index,
                            [7; 16],
                            DiscoveryCoverageStateV1::Healthy,
                            Vec::new(),
                        )
                    })
                    .collect(),
                coverage_keys: vec![GraphCoverageKeyV1 {
                    source: fixture.source.clone(),
                    cpu_id: record.id.cpu_id,
                    report_revision: 102,
                    interval_id: [7; 16],
                    interval_revision: 22,
                    state: DiscoveryCoverageStateV1::Healthy,
                    gap_reasons: Vec::new(),
                }],
                facts,
                missing_ranges: Vec::new(),
            },
            sdk::CoverageState::Complete,
            "graph:selected-source-keys",
            "WHERE source_id <> decode(repeat('63', 16), 'hex') AND source_cursor <> 2",
        )
        .await?,
    );
    let selected_id = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("selected target Graph window")?
        .0;
    let selected = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &selected_id)?
        .ok_or("selected graph")?;
    assert_eq!(selected.previous_result_id.as_deref(), Some(checkpoint));
    assert!(selected.input_manifest.coverage.iter().all(|key| {
        key.source == fixture.source && key.interval_id == [7; 16] && key.report_revision == 102
    }));
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &first)?,
        Some(original)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(other.tenant_id, &foreign)?,
        Some(retained)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, checkpoint)?,
        Some(frozen)
    );
    Ok(())
}
