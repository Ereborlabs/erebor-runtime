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
