use super::*;

#[test]
fn recovery_headers() -> TestResult {
    let fixture = Fixture::new()?;
    let source = identity("a");
    fixture.append(&source, 1, 1, 10)?;
    let before = fixture.native.view()?;
    assert_eq!(
        fixture.native.record_recovery_floor(&source, 4)?,
        araphor_data::AnalysisRecoveryStatusV1::Partial {
            first_cursor: 2,
            last_cursor: 4
        },
    );
    assert_eq!(fixture.native.view()?.revision(), 2);
    let first = fixture.native.view()?;
    fixture.append(&source, 5, 1, 20)?;
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let requests = requests(&[("events", &["source_cursor"])])?;
    let control = AnalysisReadControl::default();
    let native = fixture.native.read_tables(
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_table(
        &native,
        "events",
        vec![("source_cursor", Arc::new(UInt64Array::from(vec![1, 5])))],
    )?;
    assert_witnesses(&native, vec![(source.clone(), 1), (source.clone(), 5)]);
    assert_contexts(&native, &[]);
    assert!(
        native.extraction.missing_contexts.is_empty()
            && native.extraction.missing_results.is_empty()
    );
    assert_eq!(native.received_min, Some(10));
    assert_eq!(
        native.scanned_through,
        StorePositionV1 {
            commit_revision: 3,
            ordinal: u32::MAX
        }
    );
    assert!(native.exhausted);
    assert_eq!(native.extraction.sources.len(), 1);
    let header = &native.extraction.sources[0];
    assert_eq!(
        header.receipt,
        araphor_data::AnalysisSourceReceiptV1 {
            identity: source.clone(),
            cpu_id: 0,
            contiguous_cursor: 1,
            coverage_revision: 0,
            retained_floor: 0,
        }
    );
    assert_eq!(
        header.recovery,
        [araphor_data::AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 4,
            commit_revision: 2
        }]
    );
    assert_eq!(
        header.pending,
        [araphor_data::AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 4,
            commit_revision: 3
        }]
    );
    assert!(header.expired.is_empty());
    assert_eq!(header.coverage_report, None);
    assert_eq!(header.receipt.contiguous_cursor, 1);
    assert_eq!(header.recovery[0].first_cursor, 2);
    assert_eq!(header.recovery[0].last_cursor, 4);
    assert_eq!(header.commit_revision, fixture.native.view()?.revision());
    fixture.native.record_recovery_floor(&source, 6)?;
    let newest = fixture.native.view()?.revision();
    let native = fixture.native.read_tables(
        &selection,
        read(&requests, AnalysisReadModeV1::Metadata),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert!(native.tables.is_empty());
    assert_witnesses(&native, Vec::new());
    assert_contexts(&native, &[]);
    assert_eq!(native.received_min, None);
    assert_eq!(
        native.scanned_through,
        StorePositionV1 {
            commit_revision: 4,
            ordinal: u32::MAX
        }
    );
    assert!(native.exhausted);
    let header = &native.extraction.sources[0];
    assert_eq!(
        header.recovery,
        [
            araphor_data::AnalysisGapV1 {
                first_cursor: 2,
                last_cursor: 4,
                commit_revision: 2
            },
            araphor_data::AnalysisGapV1 {
                first_cursor: 5,
                last_cursor: 6,
                commit_revision: 4
            },
        ]
    );
    assert_eq!(
        header.pending,
        [araphor_data::AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 4,
            commit_revision: 4
        }]
    );
    assert_eq!(header.receipt.contiguous_cursor, 1);
    assert_eq!(native.extraction.sources[0].commit_revision, newest);
    for (view, count) in [(&before, 0), (&first, 1)] {
        let page = fixture.native.read_tables_at(
            view,
            &selection,
            read(&requests, AnalysisReadModeV1::Metadata),
            AnalysisExtractLimits::default(),
            &control,
            None,
        )?;
        assert!(page.tables.is_empty());
        assert_witnesses(&page, Vec::new());
        assert_contexts(&page, &[]);
        assert_eq!(page.received_min, None);
        assert!(page.exhausted);
        assert!(page.extraction.sources[0].pending.is_empty());
        assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 1);
        assert_eq!(page.extraction.sources[0].recovery.len(), count);
        assert_eq!(page.extraction.sources[0].commit_revision, view.revision());
    }
    Ok(())
}

#[test]
fn recovery_budget() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let source = identity("a");
    store.accept_validated_batch(source.clone(), batch(1, 1, 10)?)?;
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let requests = requests(&[("events", &["source_cursor"])])?;
    let control = AnalysisReadControl::default();
    let baseline = store.read_tables(
        &selection,
        read(&requests, AnalysisReadModeV1::Metadata),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    for last in 2..=259 {
        store.record_recovery_floor(&source, last)?;
    }
    let page = store.read_tables(
        &selection,
        read(&requests, AnalysisReadModeV1::Metadata),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(page.extraction.sources[0].recovery.len(), 258);
    assert!(page.extraction.sources[0].pending.is_empty());
    assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 1);
    let limits = AnalysisExtractLimits {
        input_bytes: baseline.extraction.input_bytes
            + 257 * size_of::<araphor_data::AnalysisGapV1>(),
        ..AnalysisExtractLimits::default()
    };
    assert!(matches!(
        store.read_tables(
            &selection,
            read(&requests, AnalysisReadModeV1::Metadata),
            limits,
            &control
        ),
        Err(Error::AnalysisInputTooLarge { .. })
    ));
    control.cancel()?;
    assert!(matches!(
        store.read_tables(
            &selection,
            read(&requests, AnalysisReadModeV1::Metadata),
            AnalysisExtractLimits::default(),
            &control
        ),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}
