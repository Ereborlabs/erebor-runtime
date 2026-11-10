use super::*;
use araphor_data::AnalysisAppendRead;

fn cursors(page: &AnalysisPositionPageV1) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    page.tables["events"]
        .iter()
        .map(|batch| {
            Ok(batch
                .column_by_name("source_cursor")
                .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
                .ok_or("source cursor")?
                .values()
                .to_vec())
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()
        .map(|chunks| chunks.into_iter().flatten().collect())
}

#[test]
fn append_pages_keep_the_original_cut_after_later_intake() -> TestResult {
    let pair = Pair::new()?;
    let source = identity("append");
    pair.append(&source, 1, 6, 10)?;
    let requests = requests(&[("events", &["source_cursor", "task_cookie"])])?;
    let selection = AnalysisSelectionV1::new([1; 16], vec![source.clone()]);
    let control = AnalysisReadControl::default();
    let limits = AnalysisExtractLimits {
        page_rows: 2,
        ..Default::default()
    };
    let mut native_cursor = AnalysisAppendRead::default();
    let mut old_cursor = AnalysisAppendRead::default();
    let cut = pair.native.view()?.revision();
    let mut after = None;
    for expected in [vec![1, 2], vec![3, 4], vec![5, 6]] {
        let (native, current) = pair.native.read_append_tables_filtered(
            &selection,
            &selection,
            read(&requests, AnalysisReadModeV1::Complete),
            after,
            limits,
            &control,
            &mut native_cursor,
            &mut |_| Ok(()),
        )?;
        let (old, old_current) = pair.old.read_append_tables_filtered(
            &selection,
            &selection,
            read(&requests, AnalysisReadModeV1::Complete),
            after,
            limits,
            &control,
            &mut old_cursor,
            &mut |_| Ok(()),
        )?;
        assert_eq!(cursors(&native)?, expected);
        assert_eq!(native.tables, old.tables);
        assert_eq!(native.scanned_through, old.scanned_through);
        assert_eq!(native.exhausted, old.exhausted);
        assert_eq!(native.extraction.meta.commit_revision, cut);
        assert_eq!(current.commit_revision, old_current.commit_revision);
        assert_eq!(current.commit_revision, pair.native.view()?.revision());
        after = Some(native.scanned_through);
        if expected[0] == 1 {
            pair.append(&source, 7, 1, 20)?;
        } else {
            assert!(current.commit_revision > cut);
        }
        assert_eq!(native.exhausted, expected[0] == 5);
    }
    assert_eq!(
        after,
        Some(StorePositionV1 {
            commit_revision: cut,
            ordinal: u32::MAX
        })
    );
    let (page, current) = pair.native.read_append_tables_filtered(
        &selection,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        after,
        limits,
        &control,
        &mut native_cursor,
        &mut |_| Ok(()),
    )?;
    assert_eq!(cursors(&page)?, [7]);
    assert!(page.exhausted);
    assert_eq!(page.extraction.meta, current);
    assert!(current.commit_revision > cut);
    Ok(())
}

#[test]
fn append_scope_and_failed_capture_keep_cursor_charges_correct() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let source = identity("append");
    store.accept_validated_batch(source.clone(), batch(1, 4, 10)?)?;
    let requests = requests(&[("events", &["source_cursor", "task_cookie"])])?;
    let selection = AnalysisSelectionV1::new([1; 16], vec![source]);
    let control = AnalysisReadControl::default();
    let limits = AnalysisExtractLimits {
        page_rows: 1,
        ..Default::default()
    };
    let mut cursor = AnalysisAppendRead::default();
    let mut charges = Vec::new();
    let (first, _) = store.read_append_tables_filtered(
        &selection,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        None,
        limits,
        &control,
        &mut cursor,
        &mut |bytes| {
            charges.push(bytes);
            Ok(())
        },
    )?;
    assert_eq!(charges[0], 0);
    assert!(charges[1] > 0);
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.read_append_tables_filtered(
            &selection,
            &selection,
            read(&requests, AnalysisReadModeV1::Complete),
            Some(first.scanned_through),
            limits,
            &cancelled,
            &mut cursor,
            &mut |bytes| {
                charges.push(bytes);
                Ok(())
            },
        ),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(charges.len(), 2);
    let (second, _) = store.read_append_tables_filtered(
        &selection,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        Some(first.scanned_through),
        limits,
        &control,
        &mut cursor,
        &mut |bytes| {
            charges.push(bytes);
            Ok(())
        },
    )?;
    assert_eq!(cursors(&second)?, [2]);
    assert_eq!(charges.len(), 2);
    let mut changed = selection.clone();
    changed.cursor_from = Bound::Included(3);
    let failure = store.read_append_tables_filtered(
        &changed,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        Some(second.scanned_through),
        limits,
        &control,
        &mut cursor,
        &mut |bytes| {
            charges.push(bytes);
            if bytes == 0 {
                Ok(())
            } else {
                Err(Code::Limit.error("append retained budget"))
            }
        },
    );
    assert!(failure.is_err());
    assert_eq!(charges.last(), Some(&0));
    let offset = charges.len();
    let (third, _) = store.read_append_tables_filtered(
        &changed,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        Some(second.scanned_through),
        limits,
        &control,
        &mut cursor,
        &mut |bytes| {
            charges.push(bytes);
            Ok(())
        },
    )?;
    assert_eq!(cursors(&third)?, [3]);
    assert_eq!(charges[offset], 0);
    assert!(charges[offset + 1] > 0);
    let result = store.read_append_tables_filtered(
        &changed,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        Some(third.scanned_through),
        AnalysisExtractLimits {
            input_bytes: 1,
            ..limits
        },
        &control,
        &mut cursor,
        &mut |_| Ok(()),
    );
    assert!(matches!(result, Err(Error::AnalysisInputTooLarge { .. })));
    Ok(())
}
