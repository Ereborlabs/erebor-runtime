use super::*;

#[test]
fn query_input_pending_positions() -> TestResult {
    use prost::Message as _;

    let directory = tempfile::tempdir()?;
    let store = std::sync::Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let identity = identity(1);
    store.accept_validated_batch(identity.clone(), batch(11, 10, 10)?)?;
    let report = crate::CoverageReport {
        source_id: identity.source_id.to_vec(),
        source_epoch: identity.source_epoch,
        revision: 1,
        ..Default::default()
    }
    .encode_to_vec();
    store.accept_validated_coverage(crate::ValidatedCoverageV1 {
        identity: identity.clone(),
        cpu_id: 0,
        revision: 1,
        encoded_report: report.clone(),
    })?;
    assert!(store.read_page(&identity, 1)?.records.is_empty());
    let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    let fields = [(
        "events",
        &[
            "source_cursor",
            "received_utc_ns",
            "commit_revision",
            "ordinal",
        ][..],
    )];
    let complete = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(row_count(&complete, "events"), 10);
    assert!(complete.exhausted);
    let before = store.meta()?;
    let control = AnalysisReadControl::default();
    let writer = std::sync::Arc::clone(&store);
    let source = identity.clone();
    control.on_read_step(move || {
        writer.accept_validated_batch(source, batch(1, 10, 20)?)?;
        Ok(())
    })?;
    let first = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(None),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(first.extraction.meta, before);
    assert!(first.exhausted);
    assert_eq!(first.extraction.sources[0].receipt.contiguous_cursor, 0);
    assert_eq!(
        first.extraction.sources[0].coverage_report.as_deref(),
        Some(report.as_slice())
    );
    assert_eq!(first.extraction.sources[0].pending.len(), 1);
    assert_eq!(
        (
            first.extraction.sources[0].pending[0].first_cursor,
            first.extraction.sources[0].pending[0].last_cursor
        ),
        (1, 10)
    );
    assert_eq!(
        unsigned(&first, "events", "source_cursor")?,
        (11..=20).collect::<Vec<_>>()
    );
    assert_eq!(unsigned(&first, "events", "received_utc_ns")?, vec![10; 10]);
    let mut ordered_positions = positions(&first)?;
    let next = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(Some(first.scanned_through)),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(next.exhausted);
    assert_eq!(next.extraction.sources[0].receipt.contiguous_cursor, 20);
    assert!(next.extraction.sources[0].pending.is_empty());
    assert_eq!(
        unsigned(&next, "events", "source_cursor")?,
        (1..=10).collect::<Vec<_>>()
    );
    assert_eq!(unsigned(&next, "events", "received_utc_ns")?, vec![20; 10]);
    assert!(positions(&next)?
        .iter()
        .all(|position| *position > first.scanned_through));
    ordered_positions.extend(positions(&next)?);
    assert!(ordered_positions.windows(2).all(|pair| pair[0] < pair[1]));
    let ordered = store.read_page(&identity, 1)?;
    assert_eq!(
        ordered
            .records
            .iter()
            .map(|record| record.cursor)
            .collect::<Vec<_>>(),
        (1..=20).collect::<Vec<_>>()
    );
    assert_eq!(ordered.records[10].position, ordered_positions[0]);
    assert_eq!(ordered.records[0].position, ordered_positions[10]);
    let meta = store.meta()?;
    store.accept_validated_batch(identity.clone(), batch(11, 10, 10)?)?;
    assert_eq!(store.meta()?, meta);
    let retry = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(Some(next.scanned_through)),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(retry.exhausted && row_count(&retry, "events") == 0);
    assert_eq!(retry.scanned_through, next.scanned_through);
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}

#[test]
fn query_scope_position_pages() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    let other = EvidenceIntakeIdentityV1 {
        source_epoch: 2,
        ..identity.clone()
    };
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [2; 16],
        ..identity.clone()
    };
    store.accept_validated_batch(identity.clone(), batch(1, 257, 10)?)?;
    let first_revision = store.meta()?.commit_revision;
    store.accept_validated_batch(foreign, batch(1, 1, 10)?)?;
    store.accept_validated_batch(other.clone(), batch(1, 1, 20)?)?;
    let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![other, identity.clone()]);
    let first = read(
        &store,
        &selection,
        &[("events", &[])],
        AnalysisReadModeV1::Page(None),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(!first.exhausted);
    assert_eq!(row_count(&first, "events"), 256);
    assert!(first.tables["events"]
        .iter()
        .all(|batch| batch.num_columns() == 0));
    assert_eq!(
        first.scanned_through,
        StorePositionV1 {
            commit_revision: first_revision,
            ordinal: 255
        }
    );
    let next = read(
        &store,
        &selection,
        &[(
            "events",
            &[
                "source_epoch",
                "source_cursor",
                "commit_revision",
                "ordinal",
            ],
        )],
        AnalysisReadModeV1::Page(Some(first.scanned_through)),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(next.exhausted);
    assert_eq!(unsigned(&next, "events", "source_epoch")?, vec![1, 2]);
    assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![257, 1]);
    let seen = positions(&next)?;
    assert!(seen[0] > first.scanned_through);
    assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        next.scanned_through.commit_revision,
        store.meta()?.commit_revision
    );
    assert_eq!(next.scanned_through.ordinal, u32::MAX);
    Ok(())
}

#[test]
fn query_input_sparse_positions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    for cursor in [3, 7] {
        store.accept_validated_batch(identity.clone(), batch(cursor, 1, 1)?)?;
    }
    store.accept_validated_batch(identity.clone(), batch(1, 10, 2)?)?;
    let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    let fields = [(
        "events",
        &["source_cursor", "commit_revision", "ordinal"][..],
    )];
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(None),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let expected = [3, 7, 1, 2, 4, 5, 6, 8, 9, 10];
    assert!(page.exhausted);
    assert_eq!(page.scanned_through.ordinal, u32::MAX);
    assert_eq!(unsigned(&page, "events", "source_cursor")?, expected);
    for (index, position) in positions(&page)?.into_iter().enumerate() {
        let next = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(Some(position)),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(next.exhausted);
        assert_eq!(
            unsigned(&next, "events", "source_cursor")?,
            expected[index + 1..]
        );
    }
    assert_eq!(
        store
            .source_receipt(&identity)?
            .ok_or("source absent")?
            .contiguous_cursor,
        10
    );
    Ok(())
}

#[test]
fn query_input_page_resume() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    store.accept_validated_batch(
        identity.clone(),
        records(
            1,
            1,
            (1..=3).map(|cursor| EvidenceRecord {
                observed_boottime_ns: cursor,
                decision_context: Some(crate::EvidenceDecisionContext {
                    binding_id: vec![if cursor == 2 { 2 } else { 1 }; 16],
                    catalog_json: vec![cursor as u8; 768],
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )?,
    )?;
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity]);
    selection.binding_ids.push([1; 16]);
    let fields = [(
        "events",
        &[
            "source_cursor",
            "catalog_json",
            "commit_revision",
            "ordinal",
        ][..],
    )];
    let limits = AnalysisExtractLimits {
        page_bytes: 1024,
        ..Default::default()
    };
    let first = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(None),
        limits,
        &AnalysisReadControl::default(),
    )?;
    assert!(!first.exhausted);
    assert_eq!(unsigned(&first, "events", "source_cursor")?, vec![1]);
    assert_eq!(
        binary(&first, "events", "catalog_json")?,
        vec![vec![1; 768]]
    );
    let first_position = positions(&first)?[0];
    assert_eq!(
        first.scanned_through,
        StorePositionV1 {
            ordinal: 1,
            ..first_position
        }
    );
    let next = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(Some(first.scanned_through)),
        limits,
        &AnalysisReadControl::default(),
    )?;
    assert!(next.exhausted);
    assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![3]);
    assert_eq!(binary(&next, "events", "catalog_json")?, vec![vec![3; 768]]);
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(None),
            AnalysisExtractLimits {
                page_bytes: 767,
                ..limits
            },
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "projected row bytes",
            ..
        })
    ));
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}

#[test]
fn analysis_extract_range_pages() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    for cursor in 1..=257 {
        store.accept_validated_batch(identity.clone(), batch(cursor, 1, 10)?)?;
    }
    let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    let fields = [("events", &["source_cursor"][..])];
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        page.extraction.scanned_bytes,
        stored_batches(&store)?
            .iter()
            .map(|entry| entry.bytes)
            .sum::<usize>()
    );
    assert!(page.exhausted);
    assert_eq!(
        unsigned(&page, "events", "source_cursor")?,
        (1..=257).collect::<Vec<_>>()
    );
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits {
                input_bytes: page.extraction.projected_bytes,
                ..Default::default()
            },
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    let mut selection = AnalysisSelectionV1::new(
        identity.tenant_id,
        (1..=KEY_LIMIT)
            .map(|epoch| EvidenceIntakeIdentityV1 {
                source_epoch: epoch as u64,
                ..identity.clone()
            })
            .collect(),
    );
    assert!(selection.valid());
    selection
        .sources
        .exact_mut()
        .ok_or("exact sources absent")?
        .push(EvidenceIntakeIdentityV1 {
            source_epoch: KEY_LIMIT as u64 + 1,
            ..identity
        });
    assert!(selection.valid());
    assert!(AnalysisExtractLimits {
        keys: Some(KEY_LIMIT),
        ..Default::default()
    }
    .check_keys(&selection)
    .is_err());
    Ok(())
}
