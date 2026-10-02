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

#[test]
fn query_scope_pin_race() -> TestResult {
    for pin_first in [true, false] {
        let fixture = QueryFixture::new()?;
        fixture.event(1, 100, 7)?;
        let position = fixture.store.read_page(&fixture.source, 1)?.records[0].position;
        let scope = ProcessorScopeV1 {
            processor_id: "query-race".into(),
            method_version: 1,
            identity: fixture.source.clone(),
        };
        fixture
            .store
            .register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let expires = 3 * 24 * 60 * 60 * 1_000_000_000_u64;
        let input = AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "query-pin-race".into(),
            body: b"witness".to_vec(),
            created_utc_ns: 200,
            witnesses: vec![AnalysisWitnessV1 {
                identity: fixture.source.clone(),
                cursor: 1,
                expires_utc_ns: expires,
            }],
            context_refs: Vec::new(),
        };
        let owner = fixture.owner(QueryLimits::default())?;
        let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
        let held = owner.query_at(&plan, expires - 1)?;
        let before = held.meta.commit_revision;
        assert_eq!(held.rows.len(), 1);
        let (paused, first_ready) = mpsc::channel();
        let (release, resumed) = mpsc::channel();
        fixture.store.set_commit_hook(
            if pin_first {
                AnalysisCommitStage::BeforeResultCommit
            } else {
                AnalysisCommitStage::BeforeRetentionCommit
            },
            move || {
                paused
                    .send(())
                    .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                resumed
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| crate::AnalysisReadCancelledSnafu.build())
            },
        )?;
        let (entered, second_ready) = mpsc::channel();
        let store = &fixture.store;
        let source = &fixture.source;
        let commit = &input;
        let (pin, deletion) = while_held(held, move || {
            std::thread::scope(|scope| -> TestResult<_> {
                if pin_first {
                    let pin = scope.spawn(|| store.commit_result(commit));
                    first_ready.recv_timeout(Duration::from_secs(5))?;
                    let deletion = scope.spawn(move || {
                        entered
                            .send(())
                            .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                        EvidenceRetentionOwner::new(store).retain(source, expires - 1)
                    });
                    second_ready.recv_timeout(Duration::from_secs(5))?;
                    release.send(())?;
                    Ok((
                        pin.join().map_err(|_| "pin worker panicked")?,
                        deletion.join().map_err(|_| "retention worker panicked")?,
                    ))
                } else {
                    let deletion = scope
                        .spawn(|| EvidenceRetentionOwner::new(store).retain(source, expires - 1));
                    first_ready.recv_timeout(Duration::from_secs(5))?;
                    let pin = scope.spawn(move || {
                        entered
                            .send(())
                            .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                        store.commit_result(commit)
                    });
                    second_ready.recv_timeout(Duration::from_secs(5))?;
                    release.send(())?;
                    Ok((
                        pin.join().map_err(|_| "pin worker panicked")?,
                        deletion.join().map_err(|_| "retention worker panicked")?,
                    ))
                }
            })
        })?;
        let deletion = deletion?;
        assert_eq!(deletion.removed_records, u32::from(!pin_first));
        assert_eq!(deletion.commit_revision, before + 1);
        let stored = fixture
            .store
            .read_result(fixture.source.tenant_id, &input.result_id)?;
        let progress = fixture
            .store
            .processor_health(&input.scope)?
            .ok_or("progress absent")?;
        assert_eq!(progress.resume_floor, 0);
        if pin_first {
            let pin = pin?;
            assert_eq!(pin.commit_revision, before + 1);
            assert_eq!(pin.consumed_cursor, 1);
            assert_eq!(stored, Some(input.body));
            assert_eq!(progress.consumed_cursor, 1);
        } else {
            assert!(matches!(pin, Err(crate::Error::AnalysisState { .. })));
            assert!(stored.is_none());
            assert_eq!(progress.consumed_cursor, 0);
        }
        let later = owner.query_at(&plan, expires - 1)?;
        assert_eq!(later.meta.commit_revision, before + 1);
        assert_eq!(later.rows.len(), usize::from(pin_first));
        assert_eq!(later.sources[0].receipt.contiguous_cursor, 1);
        assert_eq!(
            later.sources[0].receipt.retained_floor,
            u64::from(!pin_first)
        );
        assert_eq!(later.sources[0].expired.len(), usize::from(!pin_first));
        if pin_first {
            let cursor = later
                .columns
                .iter()
                .position(|name| name == "source_cursor")
                .ok_or("source cursor column absent")?;
            assert_eq!(later.rows[0][cursor], Value::UBigInt(1));
        } else {
            assert_eq!(
                later.sources[0].expired[0],
                crate::AnalysisGapV1 {
                    first_cursor: 1,
                    last_cursor: 1,
                    commit_revision: before + 1,
                }
            );
        }
        assert_eq!(
            fixture.store.replay_floor(fixture.source.tenant_id)?,
            (!pin_first).then_some(position),
        );
    }
    Ok(())
}

#[test]
fn query_scope_native_cancel() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 100, 7)?;
    let capacity = 64 * 1024;
    let owner = fixture.owner(QueryLimits {
        input_bytes: capacity,
        output_bytes: capacity,
        input_capacity: capacity,
        output_capacity: capacity,
        global_evaluations: 1,
        extract_timeout: Duration::from_secs(30),
        evaluate_timeout: Duration::from_secs(30),
        ..Default::default()
    })?;
    let plan = fixture.plan(QueryTemplate::OperationCounts)?;
    let before = fixture.store.meta()?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let (entered, ready) = mpsc::channel();
    let (release, resumed) = mpsc::channel();
    *owner.scan_gate.lock().map_err(|_| "scan gate poisoned")? = Some((entered, resumed));
    std::thread::scope(|scope| -> TestResult {
        let worker = scope.spawn(|| owner.query_cancel(&plan, 100, &control));
        let checks = (|| -> TestResult {
            ready.recv_timeout(Duration::from_secs(5))?;
            {
                let inputs = owner
                    .input_refs
                    .lock()
                    .map_err(|_| "input references poisoned")?;
                assert!(!inputs.is_empty());
                assert!(inputs.iter().all(|input| input.upgrade().is_some()));
            }
            assert!(owner.budget.evaluate(fixture.source.tenant_id).is_err());
            assert!(owner.budget.output(1).is_err());
            control.cancel()?;
            release.send(())?;
            ready.recv_timeout(Duration::from_secs(5))?;
            Ok(())
        })();
        // Release the scan on error before the worker is joined.
        drop(release);
        let result = worker.join().map_err(|_| "query worker panicked")?;
        checks?;
        assert!(owner
            .native_failed
            .load(std::sync::atomic::Ordering::Acquire));
        assert!(
            matches!(result, Err(crate::Error::AnalysisReadCancelled { .. })),
            "{result:?}"
        );
        Ok(())
    })?;
    {
        let inputs = owner
            .input_refs
            .lock()
            .map_err(|_| "input references poisoned")?;
        assert!(!inputs.is_empty());
        assert!(inputs.iter().all(|input| input.upgrade().is_none()));
    }
    drop(owner.budget.evaluate(fixture.source.tenant_id)?);
    drop(owner.budget.output(capacity)?);
    assert_eq!(fixture.store.meta()?, before);
    fixture.event(2, 200, 7)?;
    let result = owner.query_at(&plan, 200)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(7), Value::BigInt(2)]]);
    assert_eq!(result.sources[0].receipt.contiguous_cursor, 2);
    assert_eq!(result.meta.commit_revision, before.commit_revision + 1);
    drop(result);
    drop(owner.budget.evaluate(fixture.source.tenant_id)?);
    drop(owner.budget.output(capacity)?);
    Ok(())
}
