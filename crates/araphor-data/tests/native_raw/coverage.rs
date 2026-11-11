use super::*;
use araphor_data::{CoverageRecord, CoverageReportRef, Selection};
#[cfg(feature = "test-fixtures")]
use std::sync::Arc;

fn position(revision: u64) -> StorePositionV1 {
    StorePositionV1 {
        commit_revision: revision,
        ordinal: u32::MAX,
    }
}

fn report(source: &EvidenceIntakeIdentityV1, revision: u64) -> ValidatedCoverageV1 {
    let mut report = coverage(source, revision);
    report.encoded_report = revision.to_be_bytes().to_vec();
    report
}

fn replace_report(
    store: &NativeStore,
    key: &CoverageReportRef,
    value: &CoverageRecord,
) -> TestResult {
    let key = [
        b"\0data/coverage/report/".as_slice(),
        &key.source.key(),
        &key.revision.to_be_bytes(),
    ]
    .concat();
    let mut bytes = vec![0];
    serde::Serialize::serialize(
        &(&value.reference, &value.encoded_report),
        &mut rmp_serde::Serializer::new(&mut bytes)
            .with_bytes(rmp_serde::config::BytesMode::ForceIterables),
    )?;
    let mut write = store.write()?;
    write.native().insert(key, bytes);
    write.commit([])?;
    Ok(())
}

#[test]
fn receipt_history_survives_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let limits = araphor_data::RetentionLimitsV1 {
        raw_max_age_ns: Some(50),
        ..Default::default()
    };
    let store = NativeStore::open_with_limits(&root, limits, Default::default())?;
    let source = identity();
    let registration = store.register_processor(
        &araphor_data::ProcessorScopeV1 {
            processor_id: "source-history".into(),
            method_version: 1,
            identity: source.clone(),
        },
        araphor_data::ProcessorClassV1::Optional,
        1,
    )?;
    assert!(registration > 0);
    store.accept_validated_coverage(report(&source, 7))?;
    let covered = store.meta()?.commit_revision;
    assert!(covered > registration);
    store.accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 7,
            first_cursor: 1,
            last_cursor: 2,
            intake_utc_ns: 100,
            framed_records: b"ab".to_vec().into(),
            frame_ends: vec![1, 2],
        },
    )?;
    let accepted = store.meta()?.commit_revision;
    store.accept_validated_coverage(report(&source, 9))?;
    let updated = store.meta()?.commit_revision;
    store.accept_validated_coverage(report(&source, 9))?;
    assert_eq!(store.meta()?.commit_revision, updated);
    store.checkpoint()?;
    let expired = araphor_data::EvidenceRetentionOwner::new(&store).step(201)?;
    assert_eq!(expired.removed_records, 2);
    assert_eq!(
        store
            .source_receipt(&source)?
            .ok_or("expired receipt")?
            .retained_floor,
        2
    );
    assert!(expired.read_revision > updated);
    assert!(matches!(
        store.read_page(&source, 1),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    let check = |store: &NativeStore| -> TestResult {
        for (revision, expected) in [
            (registration, None),
            (covered, Some((7, 0, 7, 0))),
            (accepted, Some((7, 2, 7, 0))),
            (updated, Some((7, 2, 9, 0))),
            (expired.read_revision, Some((7, 2, 9, 2))),
        ] {
            let view = store.read_at(revision)?;
            assert_eq!(view.meta().commit_revision, revision);
            assert_eq!(
                view.source_receipt(&source)?.map(|row| (
                    row.cpu_id,
                    row.contiguous_cursor,
                    row.coverage_revision,
                    row.retained_floor
                )),
                expected,
                "revision {revision}"
            );
        }
        Ok(())
    };
    check(&store)?;
    drop(store);
    let store = NativeStore::open_with_limits(&root, limits, Default::default())?;
    check(&store)?;
    assert_eq!(
        store
            .source_receipt(&source)?
            .ok_or("source receipt")?
            .retained_floor,
        2
    );
    Ok(())
}

#[test]
#[cfg(feature = "test-fixtures")]
fn coverage_keeps_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = Arc::new(NativeStore::open(&root)?);
    let source = identity();
    let scope = selection(&source);
    for revision in 1..=16 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let after = position(store.meta()?.commit_revision);
    for revision in 17..=22 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let before = store.meta()?;
    let control = AnalysisReadControl::default();
    let writer = Arc::clone(&store);
    let arrival = source.clone();
    control.on_read_step(move || {
        writer.accept_validated_coverage(report(&arrival, 23))?;
        Ok(())
    })?;
    let first = store.coverage_changes(&scope, after, &control)?;
    assert_eq!(first.meta, before);
    assert_eq!(
        first
            .reports
            .iter()
            .map(|row| row.reference.revision)
            .collect::<Vec<_>>(),
        (17..=22).collect::<Vec<_>>()
    );
    for row in &first.reports {
        assert_eq!(row.reference.source, source);
        assert!(row.reference.position > after);
        assert!(row.reference.position.commit_revision <= before.commit_revision);
        assert_eq!(row.encoded_report, row.reference.revision.to_be_bytes());
        assert_eq!(
            store.coverage_report(&scope, &row.reference, &control)?,
            *row
        );
    }
    let next = store.coverage_changes(&scope, position(first.meta.commit_revision), &control)?;
    assert_eq!(next.reports.len(), 1);
    assert_eq!(next.reports[0].reference.revision, 23);
    let current = store.meta()?;
    store.accept_validated_coverage(report(&source, 23))?;
    assert_eq!(store.meta()?, current);
    assert!(store
        .coverage_changes(&scope, position(current.commit_revision), &control)?
        .reports
        .is_empty());
    let reference = &first.reports[0].reference;
    assert_eq!(
        rmp_serde::from_slice::<CoverageReportRef>(&rmp_serde::to_vec_named(reference)?)?,
        *reference
    );
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.coverage_changes(&scope, position(first.meta.commit_revision), &control)?,
        next
    );
    assert_eq!(
        store.coverage_report(&scope, reference, &control)?,
        first.reports[0]
    );
    let backup = root.join("backups/saved");
    store.backup(&backup)?;
    let restored = NativeStore::restore(&backup, &directory.path().join("restored"))?;
    assert_eq!(
        restored.coverage_report(&scope, reference, &control)?,
        first.reports[0]
    );
    assert_eq!(
        restored
            .coverage_changes(&scope, position(first.meta.commit_revision), &control)?
            .reports,
        next.reports
    );
    Ok(())
}

#[test]
fn coverage_keeps_scope() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let alpha = identity();
    let beta = EvidenceIntakeIdentityV1 {
        node_id: "node-b".into(),
        source_epoch: 2,
        ..alpha.clone()
    };
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [2; 16],
        ..alpha.clone()
    };
    for source in [&alpha, &beta, &foreign] {
        store.accept_validated_coverage(report(source, 1))?;
    }
    let control = AnalysisReadControl::default();
    let mut damaged = Vec::new();
    for source in [&beta, &foreign] {
        let record = store
            .coverage_changes(&selection(source), position(0), &control)?
            .reports
            .remove(0);
        let mut invalid = record.clone();
        invalid.encoded_report.clear();
        replace_report(&store, &record.reference, &invalid)?;
        damaged.push(record);
    }
    let mut scope = selection(&alpha);
    let selected = store.coverage_changes(&scope, position(0), &control)?;
    assert_eq!(selected.reports.len(), 1);
    assert_eq!(selected.reports[0].reference.source, alpha);
    assert!(store
        .coverage_report(&selection(&beta), &selected.reports[0].reference, &control)
        .is_err());
    scope.sources = Selection::Exact(Vec::new());
    assert!(store
        .coverage_changes(&scope, position(0), &control)?
        .reports
        .is_empty());
    replace_report(&store, &damaged[0].reference, &damaged[0])?;
    scope.sources = Selection::All;
    let all = store.coverage_changes(&scope, position(0), &control)?;
    assert_eq!(
        all.reports
            .iter()
            .map(|row| &row.reference.source)
            .collect::<Vec<_>>(),
        [&alpha, &beta]
    );
    scope.nodes = vec![beta.node_id.clone()];
    assert_eq!(
        store
            .coverage_changes(&scope, position(0), &control)?
            .reports,
        all.reports[1..]
    );
    Ok(())
}

#[test]
fn coverage_rejects_corruption() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let source = identity();
    let scope = selection(&source);
    let control = AnalysisReadControl::default();
    store.accept_validated_coverage(report(&source, 1))?;
    let record = store
        .coverage_changes(&scope, position(0), &control)?
        .reports
        .remove(0);
    let held = store.view()?;
    for case in 0..4 {
        let mut invalid = record.reference.clone();
        match case {
            0 => invalid.source.node_id = "another-node".into(),
            1 => invalid.revision += 1,
            2 => invalid.position.ordinal += 1,
            _ => invalid.position.commit_revision += 100,
        }
        assert!(
            store.coverage_report(&scope, &invalid, &control).is_err(),
            "reference {case}"
        );
    }
    for case in 0..5 {
        let mut invalid = record.clone();
        match case {
            0 => invalid.encoded_report.clear(),
            1 => invalid.reference.revision = 0,
            2 => invalid.reference.position.ordinal = 1,
            3 => invalid.reference.position.commit_revision = store.meta()?.commit_revision + 100,
            _ => invalid.reference.source.node_id = "another-node".into(),
        }
        replace_report(&store, &record.reference, &invalid)?;
        let before = store.meta()?;
        let head = store.database().inner().journal_head()?;
        assert!(
            store
                .coverage_changes(&scope, position(0), &control)
                .is_err(),
            "record {case}"
        );
        assert!(
            store
                .coverage_report(&scope, &record.reference, &control)
                .is_err(),
            "record {case}"
        );
        assert_eq!(
            held.coverage_report(&scope, &record.reference, &control)?,
            record
        );
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, head);
    }
    replace_report(&store, &record.reference, &record)?;
    assert_eq!(
        store
            .coverage_changes(&scope, position(0), &control)?
            .reports,
        vec![record]
    );
    Ok(())
}

#[test]
#[cfg(feature = "test-fixtures")]
fn coverage_keeps_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let source = identity();
    let scope = selection(&source);
    for revision in 1..=3 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let before = store.meta()?;
    let receipt = store.source_receipt(&source)?;
    let head = store.database().inner().journal_head()?;
    let control = Arc::new(AnalysisReadControl::default());
    let cancel = Arc::clone(&control);
    control.on_read_step(move || cancel.cancel())?;
    assert!(store
        .coverage_changes(&scope, position(0), &control)
        .is_err());
    for after in [
        StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        position(before.commit_revision + 1),
    ] {
        assert!(store
            .coverage_changes(&scope, after, &AnalysisReadControl::default())
            .is_err());
    }
    assert_eq!(store.meta()?, before);
    assert_eq!(store.source_receipt(&source)?, receipt);
    assert_eq!(store.database().inner().journal_head()?, head);
    assert_eq!(
        store
            .coverage_changes(&scope, position(0), &AnalysisReadControl::default())?
            .reports
            .len(),
        3
    );
    Ok(())
}
