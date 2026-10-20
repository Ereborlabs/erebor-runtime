use super::*;

#[tokio::test]
async fn recorded_matches_corpus() -> TestResult {
    let fixture = Fixture::new()?;
    let manifest = Fixture::input()?;
    let original = fixture.recorded(&manifest).await?;
    let mut missing = manifest;
    missing.contexts.clear();
    let missing = fixture.recorded(&missing).await?;
    assert_eq!(
        serde_json::json!({"original":original,"missing_context":missing}),
        serde_json::from_slice::<serde_json::Value>(include_bytes!(
            "../../../../../araphor-data/src/discovery/validation/tests/fixtures/atoms.json"
        ))?
    );
    Ok(())
}

#[tokio::test]
async fn merge_matches_corpus() -> TestResult {
    let fixture = Fixture::new()?;
    let manifest = Fixture::input()?;
    let mut first = manifest.clone();
    first.records.retain(|record| record.id.durable_cursor == 1);
    first
        .contexts
        .retain(|context| context.record_id.durable_cursor == 1);
    first.coverage[0].last_cursor = 1;
    first.coverage[0].expected_records = 1;
    let mut second = manifest;
    second
        .records
        .retain(|record| record.id.durable_cursor != 1);
    second
        .contexts
        .retain(|context| context.record_id.durable_cursor != 1);
    second.coverage[0].first_cursor = 2;
    second.coverage[0].expected_records = 2;
    let first = fixture.recorded(&first).await?.snapshot;
    let second = fixture.recorded(&second).await?.snapshot;
    let merged = fixture.merged(&first, &second).await?;
    let groups = fixture.groups(&merged).await?;
    assert_eq!(
        serde_json::json!({"merged":merged,"groups":groups}),
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/merge.json"))?
    );
    Ok(())
}

#[tokio::test]
async fn comparison_matches_corpus() -> TestResult {
    let fixture = Fixture::new()?;
    let original = Fixture::input()?;
    let snapshot = fixture.recorded(&original).await?.snapshot;
    let baseline = DiscoveryReviewedBaselineV1 {
        reviewer: "operator".into(),
        reviewed_utc_ns: 3000,
        forbidden: vec![snapshot.atoms[0].key.static_key.clone()],
        snapshot,
    };
    let mut changed = original.clone();
    changed
        .records
        .retain(|record| record.id.durable_cursor != 2);
    changed
        .contexts
        .retain(|context| context.record_id.durable_cursor != 2);
    changed.coverage[0].expected_records = 2;
    let counts = fixture
        .comparison(&fixture.recorded(&changed).await?.snapshot, &baseline)
        .await?;
    let mut changed = original.clone();
    let mut wire = changed.records[1].decode()?;
    wire.kernel_result = -1;
    changed.records[1].wire_record = Vec::<u8>::try_from(&wire)?;
    let outcomes = fixture
        .comparison(&fixture.recorded(&changed).await?.snapshot, &baseline)
        .await?;
    let mut changed = original;
    changed.contexts[0].image_digest = "replacement-image".into();
    changed.contexts[1].image_digest = "replacement-image".into();
    let identities = fixture
        .comparison(&fixture.recorded(&changed).await?.snapshot, &baseline)
        .await?;
    assert_eq!(
        serde_json::json!({"counts":counts,"outcomes":outcomes,"identities":identities}),
        serde_json::from_slice::<serde_json::Value>(include_bytes!("baseline/compare.json"))?
    );
    Ok(())
}

#[tokio::test]
async fn recorded_crosses_old_boundary() -> TestResult {
    let fixture = Fixture::new()?;
    let mut input = Fixture::input()?;
    let record = input.records[0].clone();
    let context = input.contexts[0].clone();
    input.records = (1..=129)
        .map(|cursor| {
            let mut record = record.clone();
            record.id.durable_cursor = cursor;
            record
        })
        .collect();
    input.contexts = input.records[..128]
        .iter()
        .map(|record| {
            let mut context = context.clone();
            context.record_id = record.id.clone();
            context
        })
        .collect();
    input.coverage[0].last_cursor = 129;
    input.coverage[0].expected_records = 129;
    input.exclusions = vec![DiscoveryUnresolvedV1 {
        record_id: input.records[127].id.clone(),
        reason: "EXPLICIT_EXCLUSION".into(),
    }];
    input.lifecycle = vec![DiscoveryLifecycleEntryV1 {
        case: DiscoveryLifecycleCaseV1::Startup,
        state: DiscoveryLifecycleStateV1::Recorded {
            records: vec![input.records[0].id.clone(), input.records[128].id.clone()],
        },
    }];
    let unique = fixture.recorded(&input).await?;
    input.records.extend(input.records.clone());
    input.records.reverse();
    input.contexts.reverse();
    let complete = fixture.recorded(&input).await?;
    assert_eq!(complete.snapshot, unique.snapshot);
    assert_eq!(unique.duplicate_deliveries, 0);
    assert_eq!(complete.duplicate_deliveries, 129);
    assert_eq!(complete.snapshot.accepted_records, 129);
    assert_eq!(complete.snapshot.included_records, 127);
    assert_eq!(complete.snapshot.excluded_records, 1);
    assert_eq!(complete.snapshot.unresolved_records, 1);
    assert_eq!(complete.snapshot.coverage, input.coverage);
    assert_eq!(complete.snapshot.excluded, input.exclusions);
    assert_eq!(
        complete.snapshot.unresolved[0].record_id.durable_cursor,
        129
    );
    assert_eq!(
        complete.snapshot.atoms[0]
            .evidence_sample
            .iter()
            .map(|id| id.durable_cursor)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(complete.snapshot.lifecycle[0], input.lifecycle[0]);
    assert_eq!(complete.snapshot.tenant_id, input.tenant_id);
    assert_eq!(complete.snapshot.source_revision, input.source_revision);
    assert_eq!(complete.snapshot.proof_kind, input.proof_kind);
    Ok(())
}

#[tokio::test]
async fn duplicates_keep_context_projection() -> TestResult {
    let fixture = Fixture::new()?;
    let mut input = Fixture::input()?;
    input.records.truncate(1);
    input.contexts.truncate(1);
    input.coverage[0].last_cursor = 1;
    input.coverage[0].expected_records = 1;
    let text = "\\\"".repeat(2048);
    input.contexts[0].subject_revision = text.clone();
    input.contexts[0].image_digest = text.clone();
    input.contexts[0].configuration_digest = text.clone();
    input.contexts[0].static_key.object_selector = text;
    let single = fixture.recorded(&input).await?;
    let record = input.records[0].clone();
    input.records.extend(std::iter::repeat_n(record, 1023));
    let (call, result) = fixture.atoms(&input).await?;
    let repeated = DiscoveryOwner::recorded_result(&input, &call, &result)?;
    assert_eq!(repeated.snapshot, single.snapshot);
    assert_eq!(repeated.duplicate_deliveries, 1023);
    assert_eq!(repeated.snapshot.included_records, 1);
    let records = &result.evaluation().input("records")?.data;
    assert_eq!(records.rows(), 1024);
    for batch in &records.batches {
        let projected: Vec<builtin::Record<'_>> = serde_arrow::from_record_batch(batch)?;
        for record in projected {
            assert!(!serde_json::to_string(&record)?.contains("subject_revision"));
        }
    }
    Ok(())
}
