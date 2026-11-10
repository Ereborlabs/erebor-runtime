use super::*;

#[test]
fn recovery_headers() -> TestResult {
    let pair = Pair::new()?;
    let source = identity("a");
    pair.append(&source, 1, 1, 10)?;
    let before = pair.native.view()?;
    assert_eq!(
        pair.native.record_recovery_floor(&source, 4)?,
        pair.old.record_recovery_floor(&source, 4)?
    );
    let first = pair.native.view()?;
    pair.append(&source, 5, 1, 20)?;
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let requests = requests(&[("events", &["source_cursor"])])?;
    let control = AnalysisReadControl::default();
    let native = pair.native.read_tables(
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    let old = pair.old.read_tables(
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    let header = &native.extraction.sources[0];
    assert_eq!(header.receipt, old.extraction.sources[0].receipt);
    assert_eq!(header.recovery, old.extraction.sources[0].recovery);
    assert_eq!(header.pending, old.extraction.sources[0].pending);
    assert_eq!(header.receipt.contiguous_cursor, 1);
    assert_eq!(header.recovery[0].first_cursor, 2);
    assert_eq!(header.recovery[0].last_cursor, 4);
    assert_eq!(header.commit_revision, pair.native.view()?.revision());
    assert_eq!(native.tables, old.tables);
    pair.native.record_recovery_floor(&source, 6)?;
    let newest = pair.native.view()?.revision();
    let native = pair.native.read_tables(
        &selection,
        read(&requests, AnalysisReadModeV1::Metadata),
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(native.extraction.sources[0].commit_revision, newest);
    for (view, count) in [(&before, 0), (&first, 1)] {
        let page = pair.native.read_tables_at(
            view,
            &selection,
            read(&requests, AnalysisReadModeV1::Metadata),
            AnalysisExtractLimits::default(),
            &control,
            None,
        )?;
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
