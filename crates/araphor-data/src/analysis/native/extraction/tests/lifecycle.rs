use super::*;

#[test]
fn analysis_extract_rotation() -> TestResult {
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::tempdir()?;
    let store = std::sync::Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let first = identity(1);
    let rotating = EvidenceIntakeIdentityV1 {
        source_epoch: 2,
        ..first.clone()
    };
    store.accept_validated_batch(first.clone(), batch(1, 1, 10)?)?;
    for cursor in [1, 33, 65] {
        store.accept_validated_batch(rotating.clone(), padded_batch(cursor, 32, 10, 128 * 1024))?;
    }
    let before = store.meta()?;
    let selection = AnalysisSelectionV1::new(first.tenant_id, vec![first, rotating.clone()]);
    let (start, started) = mpsc::channel();
    let (rotate, rotation) = mpsc::channel();
    store.set_commit_hook(crate::AnalysisCommitStage::BeforeRotation, move || {
        rotate
            .send(())
            .map_err(|_| crate::AnalysisReadCancelledSnafu.build())
    })?;
    let fields = [("events", &["source_epoch", "source_cursor"][..])];
    std::thread::scope(|scope| -> TestResult {
        let writer_store = std::sync::Arc::clone(&store);
        let writer = scope.spawn(move || {
            started.recv_timeout(Duration::from_secs(2)).map_err(|_| {
                crate::NativeStateSnafu {
                    field: "rotation fixture barrier",
                }
                .build()
            })?;
            writer_store.accept_validated_batch(rotating, padded_batch(97, 32, 10, 128 * 1024))
        });
        let control = AnalysisReadControl::default();
        control.on_read_step(move || {
            start
                .send(())
                .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
            rotation
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
            Ok(())
        })?;
        let output = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control,
        );
        assert_eq!(
            writer.join().map_err(|_| "writer panicked")??,
            crate::EvidenceStoreOutcomeV1::Accepted
        );
        let output = output?;
        assert_eq!(output.extraction.meta, before);
        assert_eq!(output.extraction.sources[1].receipt.contiguous_cursor, 96);
        let cursors = unsigned(&output, "events", "source_cursor")?;
        assert_eq!(
            cursors,
            std::iter::once(1).chain(1..=96).collect::<Vec<_>>()
        );
        assert_eq!(
            unsigned(&output, "events", "source_epoch")?,
            std::iter::once(1)
                .chain(std::iter::repeat_n(2, 96))
                .collect::<Vec<_>>()
        );
        Ok(())
    })?;
    let later = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        later.extraction.meta.commit_revision,
        before.commit_revision + 1
    );
    assert_eq!(later.extraction.sources[1].receipt.contiguous_cursor, 128);
    assert_eq!(
        unsigned(&later, "events", "source_cursor")?,
        std::iter::once(1).chain(1..=128).collect::<Vec<_>>()
    );
    assert_eq!(
        unsigned(&later, "events", "source_epoch")?,
        std::iter::once(1)
            .chain(std::iter::repeat_n(2, 128))
            .collect::<Vec<_>>()
    );
    assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 3);
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}

#[test]
fn analysis_extract_lock_waits() -> TestResult {
    use std::sync::mpsc;
    use std::time::Duration;
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    store.accept_validated_batch(identity.clone(), batch(1, 1, 1)?)?;
    let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
    let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    let fields = [("events", &["source_cursor"][..])];
    for access in 0..3 {
        for cancelled in [false, true] {
            let (ready, held) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let (waiting, blocked) = mpsc::channel();
            let control = if cancelled {
                AnalysisReadControl::default()
            } else {
                AnalysisReadControl::with_timeout(Duration::from_millis(50))?
            };
            *control
                .wait_signal
                .lock()
                .map_err(|_| "wait signal poisoned")? = Some(waiting);
            std::thread::scope(|scope| -> TestResult {
                let store = &store;
                let control = &control;
                let selection = &selection;
                let receipt = &receipt;
                let identity = &identity;
                let holder = scope.spawn(move || -> Result<()> {
                    let _raw = if access == 2 {
                        None
                    } else {
                        Some(store.raw.lock().map_err(|_| {
                            crate::NativeStateSnafu {
                                field: "raw fixture lock",
                            }
                            .build()
                        })?)
                    };
                    let _maintenance = if access == 2 {
                        Some(store.maintenance.write().map_err(|_| {
                            crate::NativeStateSnafu {
                                field: "maintenance fixture lock",
                            }
                            .build()
                        })?)
                    } else {
                        None
                    };
                    assert_eq!(
                        store.view()?.source_receipt(identity)?.as_ref(),
                        Some(receipt)
                    );
                    if access != 2 {
                        let metadata = read(
                            store,
                            selection,
                            &fields,
                            AnalysisReadModeV1::Metadata,
                            Default::default(),
                            &AnalysisReadControl::with_timeout(Duration::from_millis(50))?,
                        )?;
                        assert_eq!(metadata.extraction.sources[0].receipt, *receipt);
                    }
                    ready
                        .send(())
                        .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                    blocked
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                    if cancelled {
                        control.cancel()?;
                    }
                    released
                        .recv_timeout(Duration::from_secs(3))
                        .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                    Ok(())
                });
                held.recv_timeout(Duration::from_secs(2))?;
                let result = match access {
                    0 => store.raw.until(control).map(|_| ()),
                    1 => read(
                        store,
                        selection,
                        &fields,
                        AnalysisReadModeV1::Complete,
                        Default::default(),
                        control,
                    )
                    .map(|_| ()),
                    _ => store.maintenance.read_until(control).map(|_| ()),
                };
                let _sent = release.send(());
                holder.join().map_err(|_| "lock holder panicked")??;
                assert!(match result {
                    Err(crate::Error::AnalysisReadCancelled { .. }) => cancelled,
                    Err(crate::Error::AnalysisReadDeadline { .. }) => !cancelled,
                    _ => false,
                });
                Ok(())
            })?;
        }
    }
    store.accept_validated_batch(identity.clone(), batch(2, 1, 2)?)?;
    assert_eq!(store.read_page(&identity, 1)?.records.len(), 2);
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}

#[test]
fn analysis_extract_file_faults() -> TestResult {
    use std::os::unix::fs::FileExt as _;

    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    store.accept_validated_batch(identity.clone(), batch(1, 1, 1)?)?;
    let (path, offset) = {
        let view = store.view()?;
        let entry = view.raw.entries.values().next().ok_or("batch absent")?;
        let span = entry.commit.spans.first().ok_or("span absent")?;
        (
            SegmentRange::path(&store.root, entry.reference.id),
            entry.body_start + u64::from(span.start),
        )
    };
    let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity]);
    let fields = [("events", &["source_cursor"][..])];
    let hidden = directory.path().join("hidden.seg");
    std::fs::rename(&path, &hidden)?;
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::Io { .. })
    ));
    std::fs::rename(&hidden, &path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)?;
    let mut original = [0];
    file.read_exact_at(&mut original, offset)?;
    file.write_all_at(&[original[0] ^ 0xff], offset)?;
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        ),
        Err(crate::Error::AnalysisState { .. })
    ));
    file.write_all_at(&original, offset)?;
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(unsigned(&page, "events", "source_cursor")?, vec![1]);
    assert!(page.exhausted);
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}

#[test]
fn analysis_extract_gaps() -> TestResult {
    let directory = tempfile::tempdir()?;
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: Some(1024),
    };
    let store = AnalysisStore::open_with_retention(directory.path().join("analysis"), limits)?;
    let identity = identity(1);
    store.accept_validated_batch(identity.clone(), batch(1, 1, 1)?)?;
    store.backup(&store.root.join("backups/sealed"))?;
    store.accept_validated_batch(identity.clone(), batch(2, 1, 100)?)?;
    EvidenceRetentionOwner::new(&store).retain(&identity, 3)?;
    store.record_recovery_floor(&identity, 4)?;
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    selection.received_from = Bound::Included(99);
    let fields = [("events", &["source_cursor"][..])];
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(page.extraction.input_bytes >= owned_bytes(&page));
    assert_eq!(unsigned(&page, "events", "source_cursor")?, vec![2]);
    assert_eq!(
        page.extraction.scanned_bytes,
        store
            .raw
            .lock()
            .map_err(|_| "raw lock poisoned")?
            .index
            .entries
            .values()
            .filter(|entry| entry.commit.intake == 20 || entry.commit.intake == 100)
            .map(|entry| entry.frame_bytes)
            .sum::<usize>()
    );
    assert_eq!(page.extraction.sources[0].expired.len(), 1);
    assert_eq!(
        (
            page.extraction.sources[0].expired[0].first_cursor,
            page.extraction.sources[0].expired[0].last_cursor
        ),
        (1, 1)
    );
    assert_eq!(
        (
            page.extraction.sources[0].recovery[0].first_cursor,
            page.extraction.sources[0].recovery[0].last_cursor
        ),
        (3, 4)
    );
    let mut damaged = store.view()?.as_ref().clone();
    damaged.raw.ranges.remove_mut(&(identity.key(), 2));
    let requests = AnalysisTableRequests::from([(
        "events".into(),
        Some(BTreeSet::from([
            AnalysisStore::table_schemas()["events"].index_of("source_cursor")?
        ])),
    )]);
    assert!(store
        .read_tables_at(
            &damaged,
            &selection,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 0
            },
            Default::default(),
            &AnalysisReadControl::default(),
            None,
        )
        .is_err());
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}

#[test]
#[ignore = "release history scan qualification"]
fn analysis_extract_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: Some(1),
    };
    let store = AnalysisStore::open_with_retention(directory.path().join("analysis"), limits)?;
    let identity = identity(1);
    let frame_bytes = 128 * 1024;
    for group in 0..18 {
        store.accept_validated_batch(
            identity.clone(),
            padded_batch(
                group * 32 + 1,
                32,
                if group == 17 { 20 } else { 10 },
                frame_bytes,
            ),
        )?;
    }
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    selection.received_from = Bound::Included(20);
    let fields = [("events", &["source_cursor"][..])];
    let recent = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        recent.extraction.scanned_bytes,
        store
            .raw
            .lock()
            .map_err(|_| "raw lock poisoned")?
            .index
            .entries
            .values()
            .filter(|entry| entry.commit.intake == 20)
            .map(|entry| entry.frame_bytes)
            .sum::<usize>()
    );
    assert_eq!(row_count(&recent, "events"), 32);
    assert_eq!(recent.extraction.projected_bytes, 32 * 9);
    selection.received_from = Bound::Unbounded;
    let sparse = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        sparse.extraction.scanned_bytes,
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
    let cursors = unsigned(&sparse, "events", "source_cursor")?;
    assert_eq!(cursors, (1..=576).collect::<Vec<_>>());
    assert_eq!(
        cursors
            .iter()
            .copied()
            .filter(|cursor| cursor % 32 == 1)
            .collect::<Vec<_>>(),
        (0..18).map(|group| group * 32 + 1).collect::<Vec<_>>()
    );
    assert_eq!(sparse.extraction.projected_bytes, 576 * 9);
    let full = read(
        &store,
        &selection,
        &[("events", &["catalog_json"])],
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits {
            input_bytes: INPUT_BYTES,
            ..Default::default()
        },
        &AnalysisReadControl::default(),
    );
    assert!(
        matches!(
            full,
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input bytes",
                ..
            })
        ),
        "{:?}",
        full.as_ref().map(|page| &page.extraction)
    );
    assert!(store.maintenance.try_write().is_ok());
    let scope = ProcessorScopeV1 {
        processor_id: "history".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    store.commit_result(&AnalysisResultCommitV1 {
        consumed_cursor: 18 * 32,
        body: vec![1],
        created_utc_ns: 21,
        witnesses: (0..18)
            .map(|group| crate::AnalysisWitnessV1 {
                identity: identity.clone().into(),
                cursor: group * 32 + 1,
                expires_utc_ns: 100,
            })
            .collect(),
        ..crate::analysis::tests::result(scope, "sparse-history".into())
    })?;
    let usage = store.witness_usage(identity.tenant_id, 22)?;
    let header_bytes = crate::analysis::SegmentFile::encode_identity(&identity)?.len() as u64;
    assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 6);
    assert_eq!(
        usage.segment_bytes,
        sparse.extraction.scanned_bytes as u64 + 6 * header_bytes
    );
    assert_eq!(usage.referenced_bytes, 18 * frame_bytes as u64);
    assert_eq!(
        usage.extra_segment_bytes,
        usage.segment_bytes - usage.referenced_bytes
    );
    assert_eq!(usage.charged_bytes, usage.segment_bytes);
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&identity, 50)?
            .removed_records,
        0
    );
    Ok(())
}
