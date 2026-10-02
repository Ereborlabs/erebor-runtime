use std::sync::mpsc;
use std::time::Duration;

use super::tests::QueryFixture;
use super::*;
use crate::{
    AnalysisCommitStage, AnalysisResultCommitV1, AnalysisWitnessV1, EvidenceRetentionOwner,
    ProcessorClassV1, ProcessorScopeV1,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn while_held<T: Send>(
    held: QueryResult,
    work: impl FnOnce() -> TestResult<T> + Send,
) -> TestResult<T> {
    let digest = held.digest()?;
    let meta = held.meta.clone();
    let sources = held.sources.to_vec();
    let (done, completed) = mpsc::channel();
    let (completed, unchanged, result) = std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let result = work();
            let _sent = done.send(());
            result
        });
        let completed = completed.recv_timeout(Duration::from_secs(5));
        let unchanged = held.digest().map(|current| {
            current == digest && held.meta == meta && &**held.sources == sources.as_slice()
        });
        // Release held output before join, also when the worker did not finish.
        drop(held);
        (completed, unchanged, worker.join())
    });
    assert!(
        completed.is_ok(),
        "held query output blocked store maintenance"
    );
    assert!(unchanged?, "store maintenance changed held query output");
    result.map_err(|_| "store maintenance worker panicked")?
}

#[test]
fn query_scope_reader_release() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 100, 7)?;
    let owner = fixture.owner(QueryLimits::default())?;
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let held = owner.query_at(&plan, 100)?;
    let before = held.meta.clone();
    assert_eq!(held.rows.len(), 1);
    assert_eq!(held.sources[0].receipt.contiguous_cursor, 1);
    let (rotated, rotation) = mpsc::channel();
    fixture
        .store
        .set_commit_hook(AnalysisCommitStage::BeforeRotation, move || {
            rotated
                .send(())
                .map_err(|_| crate::AnalysisReadCancelledSnafu.build())
        })?;
    while_held(held, || {
        fixture
            .store
            .backup(&fixture.root().join("backups/query_held"))?;
        fixture.event(2, 200, 8)?;
        Ok(())
    })?;
    rotation.try_recv()?;

    let later = owner.query_at(&plan, 200)?;
    assert_eq!(later.meta.commit_revision, before.commit_revision + 1);
    assert_eq!(later.sources[0].receipt.contiguous_cursor, 2);
    let cursor = later
        .columns
        .iter()
        .position(|name| name == "source_cursor")
        .ok_or("source cursor column absent")?;
    let operation = later
        .columns
        .iter()
        .position(|name| name == "operation")
        .ok_or("operation column absent")?;
    assert_eq!(later.rows.len(), 2);
    assert_eq!(later.rows[0][cursor], Value::UBigInt(1));
    assert_eq!(later.rows[0][operation], Value::UInt(7));
    assert_eq!(later.rows[1][cursor], Value::UBigInt(2));
    assert_eq!(later.rows[1][operation], Value::UInt(8));
    Ok(())
}

#[test]
fn query_scope_pin_deletion() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 100, 7)?;
    fixture
        .store
        .backup(&fixture.root().join("backups/query_pin"))?;
    fixture.event(2, 200, 8)?;
    let floor = fixture.store.read_page(&fixture.source, 2)?.records[0].position;
    let expires = 3 * 24 * 60 * 60 * 1_000_000_000_u64;
    let scope = ProcessorScopeV1 {
        processor_id: "query-witness".into(),
        method_version: 1,
        identity: fixture.source.clone(),
    };
    fixture
        .store
        .register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    fixture.store.commit_result(&AnalysisResultCommitV1 {
        scope,
        expected_cursor: 0,
        consumed_cursor: 2,
        coverage_revision: 0,
        context_revision: 0,
        result_id: "query-held-witness".into(),
        body: b"witness".to_vec(),
        created_utc_ns: 300,
        witnesses: vec![AnalysisWitnessV1 {
            identity: fixture.source.clone(),
            cursor: 1,
            expires_utc_ns: expires,
        }],
        context_refs: Vec::new(),
    })?;
    let owner = fixture.owner(QueryLimits::default())?;
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let held = owner.query_at(&plan, expires - 1)?;
    let before = held.meta.commit_revision;
    assert_eq!(held.rows.len(), 2);
    let removed = while_held(held, || {
        Ok(EvidenceRetentionOwner::new(&fixture.store).retain(&fixture.source, expires - 1)?)
    })?;
    assert_eq!(removed.removed_records, 1);
    assert_eq!(
        fixture.store.replay_floor(fixture.source.tenant_id)?,
        Some(floor)
    );

    let retained = owner.query_at(&plan, expires - 1)?;
    assert_eq!(retained.meta.commit_revision, before + 1);
    assert_eq!(retained.rows.len(), 1);
    let cursor = retained
        .columns
        .iter()
        .position(|name| name == "source_cursor")
        .ok_or("source cursor column absent")?;
    assert_eq!(retained.rows[0][cursor], Value::UBigInt(1));
    assert_eq!(retained.sources[0].receipt.contiguous_cursor, 2);
    assert_eq!(retained.sources[0].state, QueryCoverageState::Gapped);
    assert_eq!(
        retained.sources[0].expired,
        vec![crate::AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 2,
            commit_revision: before + 1,
        }]
    );
    let before = retained.meta.commit_revision;
    let removed = while_held(retained, || {
        Ok(EvidenceRetentionOwner::new(&fixture.store).retain(&fixture.source, expires)?)
    })?;
    assert_eq!(removed.removed_records, 1);
    assert_eq!(
        fixture.store.replay_floor(fixture.source.tenant_id)?,
        Some(floor)
    );
    let expired = owner.query_at(&plan, expires)?;
    assert!(expired.rows.is_empty());
    assert_eq!(expired.meta.commit_revision, before + 1);
    assert_eq!(expired.sources[0].receipt.contiguous_cursor, 2);
    assert_eq!(expired.sources[0].state, QueryCoverageState::Gapped);
    Ok(())
}
