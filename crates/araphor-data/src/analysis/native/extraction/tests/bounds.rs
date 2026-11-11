use super::*;

#[test]
fn query_input_allocation_bounds() -> TestResult {
    use prost::Message as _;

    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    store.accept_validated_batch(identity.clone(), batch(11, 4, 10)?)?;
    store.accept_validated_coverage(crate::ValidatedCoverageV1 {
        identity: identity.clone(),
        cpu_id: 0,
        revision: 1,
        encoded_report: crate::CoverageReport {
            source_id: identity.source_id.to_vec(),
            source_epoch: identity.source_epoch,
            revision: 1,
            ..Default::default()
        }
        .encode_to_vec(),
    })?;
    store.record_recovery_floor(&identity, 5)?;
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    for revision in 0..4 {
        selection
            .contexts
            .exact_mut()
            .ok_or("exact contexts absent")?
            .push(AnalysisContextKeyV1 {
                tenant_id: identity.tenant_id,
                owner_id: "missing".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision,
            });
        selection.results.push(format!("missing-{revision}"));
    }
    let fields = [
        ("events", &["source_cursor"][..]),
        ("context_versions", &["body"][..]),
    ];
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(page.extraction.input_bytes >= owned_bytes(&page));
    assert_eq!(
        unsigned(&page, "events", "source_cursor")?,
        vec![11, 12, 13, 14]
    );
    assert_eq!(page.extraction.sources[0].pending.len(), 1);
    assert_eq!(page.extraction.sources[0].recovery.len(), 1);
    assert_eq!(page.extraction.missing_contexts.len(), 4);
    assert_eq!(page.extraction.missing_results.len(), 4);
    let before = store.meta()?;
    let mut rejected = 0;
    let mut admitted = INPUT_BYTES;
    while rejected + 1 < admitted {
        let limit = rejected + (admitted - rejected) / 2;
        match read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits {
                input_bytes: limit,
                ..Default::default()
            },
            &AnalysisReadControl::default(),
        ) {
            Ok(page) => {
                assert!(page.extraction.input_bytes <= limit);
                assert!(page.extraction.input_bytes >= owned_bytes(&page));
                assert_eq!(row_count(&page, "events"), 4);
                admitted = limit;
            }
            Err(crate::Error::AnalysisInputTooLarge { .. }) => rejected = limit,
            Err(error) => return Err(error.into()),
        }
    }
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits {
            input_bytes: admitted,
            ..Default::default()
        },
        &AnalysisReadControl::default(),
    )?;
    assert!(page.extraction.input_bytes <= admitted);
    assert!(page.extraction.input_bytes >= owned_bytes(&page));
    assert_eq!(
        unsigned(&page, "events", "source_cursor")?,
        vec![11, 12, 13, 14]
    );
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits {
                input_bytes: admitted - 1,
                ..Default::default()
            },
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert!(store.maintenance.try_write().is_ok());
    let recovered = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        unsigned(&recovered, "events", "source_cursor")?,
        vec![11, 12, 13, 14]
    );
    Ok(())
}

#[test]
fn analysis_extract_limits() -> TestResult {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    store.accept_validated_batch(identity.clone(), batch(1, 257, 1)?)?;
    let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    let fields = [("events", &["source_cursor"][..])];
    let before = store.meta()?;
    let complete = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        unsigned(&complete, "events", "source_cursor")?,
        (1..=257).collect::<Vec<_>>()
    );
    assert!(complete.exhausted);
    let first = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(None),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(row_count(&first, "events"), 256);
    assert!(!first.exhausted);
    let next = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(Some(first.scanned_through)),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![257]);
    assert!(next.exhausted);
    assert!(next.scanned_through > first.scanned_through);
    assert_eq!(
        complete.extraction.scanned_bytes,
        store
            .raw
            .lock()
            .map_err(|_| "raw lock poisoned")?
            .index
            .entries
            .values()
            .map(|entry| entry.frame_bytes)
            .sum::<usize>()
    );
    let control = Arc::new(AnalysisReadControl::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let cancel = Arc::clone(&control);
    control.on_read_step(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        cancel.cancel()
    })?;
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let empty = read(
        &store,
        &AnalysisSelectionV1::new(identity.tenant_id, vec![]),
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(row_count(&empty, "events"), 0);
    let first = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Page(None),
        AnalysisExtractLimits {
            page_bytes: 9,
            ..Default::default()
        },
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(unsigned(&first, "events", "source_cursor")?, vec![1]);
    assert_eq!(first.extraction.projected_bytes, 9);
    assert!(!first.exhausted);
    let next = read(
        &store,
        &selection,
        &[("events", &[])],
        AnalysisReadModeV1::Page(Some(first.scanned_through)),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(row_count(&next, "events"), 256);
    assert!(next.tables["events"]
        .iter()
        .all(|batch| batch.num_columns() == 0));
    assert!(next.exhausted);
    assert!(next.scanned_through > first.scanned_through);
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(None),
            AnalysisExtractLimits {
                page_bytes: 8,
                ..Default::default()
            },
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "projected row bytes",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    assert!(store.maintenance.try_write().is_ok());
    store.checkpoint()?;
    Ok(())
}
