use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::*;
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisExtractionV1, AnalysisReadControl,
    AnalysisReadModeV1, AnalysisSelectionV1, AnalysisTableRead, ContextSensitivityV1,
    EvidenceIntakeIdentityV1, Selection, ValidatedEvidenceBatchV1,
};

fn control() -> crate::Result<AnalysisReadControl> {
    AnalysisReadControl::with_timeout(Duration::from_secs(30))
}

fn capture(
    store: &AnalysisStore,
    selection: &AnalysisSelectionV1,
    raw: bool,
) -> crate::Result<AnalysisExtractionV1> {
    let columns = if raw {
        BTreeMap::from([("events".to_owned(), Some(BTreeSet::new()))])
    } else {
        BTreeMap::new()
    };
    Ok(store
        .read_tables(
            selection,
            AnalysisTableRead {
                requests: &columns,
                event_ranges: None,
                inputs: None,
                mode: if raw {
                    AnalysisReadModeV1::Complete
                } else {
                    AnalysisReadModeV1::Metadata
                },
                now: 1,
            },
            Default::default(),
            &control()?,
        )?
        .extraction)
}

fn append(store: &AnalysisStore, identity: EvidenceIntakeIdentityV1) -> crate::Result<()> {
    let bytes = Vec::<u8>::try_from(&crate::EvidenceRecord {
        operation: 7,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        identity,
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![bytes.len()],
            framed_records: bytes.into(),
        },
    )?;
    Ok(())
}

#[test]
fn input_checks_global_notices() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let identity = crate::analysis::tests::identity();
    append(&store, identity.clone())?;
    let selection = AnalysisSelectionV1::new([1; 16], vec![identity.clone()]);
    let mut extraction = capture(&store, &selection, true)?;
    let mut witnesses = std::mem::take(&mut extraction.witnesses);
    assert_eq!(witnesses.len(), 1);
    witnesses[0].expires_utc_ns = 100;
    assert_eq!(
        store.package_input_current(
            &active,
            &selection,
            &extraction,
            witnesses.iter(),
            1,
            &control()?
        )?,
        Some(100)
    );
    let mut foreign = identity;
    foreign.tenant_id = [2; 16];
    append(&store, foreign)?;
    assert_eq!(
        store.package_input_current(
            &active,
            &selection,
            &extraction,
            witnesses.iter(),
            1,
            &control()?
        )?,
        None
    );
    Ok(())
}

#[test]
fn controlled_registration_reads() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let first = start(&store, "first")?;
    start(&store, "second")?;
    assert_eq!(
        store.package_activation_page(None)?,
        store.package_activation_page_until(None, &control()?)?
    );
    assert_eq!(
        store.package_activation_page(Some(&first.key))?,
        store.package_activation_page_until(Some(&first.key), &control()?)?
    );
    assert_eq!(
        store.package_revision([1; 16], "first", "v1")?,
        store.package_revision_until([1; 16], "first", "v1", &control()?)?
    );
    for package in [None, Some("first")] {
        assert_eq!(
            store.package_activations([1; 16], "scope", package)?,
            store.package_activations_until([1; 16], "scope", package, &control()?)?
        );
    }
    let cancelled = control()?;
    cancelled.cancel()?;
    assert!(matches!(
        store.package_activation_page_until(None, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(matches!(
        store.package_revision_until([1; 16], "first", "v1", &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(matches!(
        store.package_activations_until([1; 16], "scope", None, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.read_slots.available_permits(), 16);
    Ok(())
}

#[test]
fn input_checks_capture_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    let mut extraction = capture(&store, &selection, false)?;
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        Some(u64::MAX)
    );
    extraction.meta.recovery_epoch += 1;
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        None
    );
    extraction.meta.recovery_epoch -= 1;
    extraction.meta.store_uuid = uuid::Uuid::new_v4();
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        None
    );
    let extraction = capture(&store, &selection, false)?;
    let renewed = store.renew_package(&active, b"{\"renewed\":true}", "grant2", || Ok(()))?;
    assert_eq!(
        store.package_activation_until(&active.key, &control()?)?,
        Some(renewed)
    );
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        None
    );
    Ok(())
}

#[test]
fn input_checks_exact_references() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let upstream = start(&store, "upstream")?;
    let active = start(&store, "downstream")?;
    store.commit_package(&commit(upstream.clone(), "upstream-1"), || Ok(()))?;
    let key = AnalysisContextKeyV1 {
        tenant_id: [1; 16],
        owner_id: "input".into(),
        entity_key: vec![1],
        lifetime_key: vec![2],
        owner_revision: 1,
    };
    store.commit_context(&AnalysisContextVersionV1 {
        key: key.clone(),
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"{}".to_vec(),
    })?;
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.contexts = Selection::Exact(vec![key]);
    selection.results = vec!["upstream-1".into()];
    let mut extraction = capture(&store, &selection, false)?;
    assert_eq!(extraction.references.len(), 2);
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        Some(u64::MAX)
    );
    for reference in &mut extraction.references {
        if let crate::AnalysisReferenceV1::Context { reference, .. } = reference {
            reference.commit_revision -= 1;
        }
    }
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        None
    );
    for reference in &mut extraction.references {
        if let crate::AnalysisReferenceV1::Context { reference, .. } = reference {
            reference.commit_revision += 1;
        }
    }
    let upstream = store
        .package_activation(&upstream.key)?
        .ok_or("activation")?;
    store.commit_package(&commit(upstream, "upstream-2"), || Ok(()))?;
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        None
    );
    Ok(())
}

#[test]
fn input_checks_witness_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_limits(
        directory.path().join("store"),
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            ..Default::default()
        },
        Default::default(),
    )?;
    let active = start(&store, "first")?;
    let identity = crate::analysis::tests::identity();
    append(&store, identity.clone())?;
    let selection = AnalysisSelectionV1::new([1; 16], vec![identity.clone()]);
    let mut extraction = capture(&store, &selection, true)?;
    let mut witnesses = std::mem::take(&mut extraction.witnesses);
    assert_eq!(witnesses.len(), 1);
    witnesses[0].expires_utc_ns = 100;
    assert_eq!(
        store.package_input_current(
            &active,
            &selection,
            &extraction,
            witnesses.iter(),
            100,
            &control()?
        )?,
        None
    );
    witnesses[0].cursor += 1;
    assert_eq!(
        store.package_input_current(
            &active,
            &selection,
            &extraction,
            witnesses.iter(),
            1,
            &control()?
        )?,
        None
    );
    witnesses[0].cursor -= 1;
    assert_eq!(
        store.package_input_current(
            &active,
            &selection,
            &extraction,
            witnesses.iter(),
            1,
            &control()?
        )?,
        Some(100)
    );
    store.raw.lock().map_err(|_| "raw lock")?.seal_all()?;
    let retired = crate::EvidenceRetentionOwner::new(&store).retain(&identity, u64::MAX)?;
    assert_eq!(retired.removed_records, 1);
    let extraction = capture(&store, &selection, false)?;
    assert_eq!(
        store.package_input_current(
            &active,
            &selection,
            &extraction,
            witnesses.iter(),
            1,
            &control()?
        )?,
        None
    );
    Ok(())
}

#[test]
fn input_checks_trace_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let intent = crate::analysis::raw::tests::trace_intent()?;
    let mut state = store.accept_trace(&intent)?;
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.traces = Selection::Exact(vec![intent.bindings[0].identity.clone()]);
    let extraction = capture(&store, &selection, false)?;
    assert_eq!(extraction.trace_reads(), &[intent.request_id]);
    assert_eq!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?)?,
        Some(u64::MAX)
    );
    state.cancel_requested = true;
    state.read_revoked = true;
    store.update_trace(&state)?;
    assert!(matches!(
        store.package_input_current(&active, &selection, &extraction, [].iter(), 1, &control()?),
        Err(crate::Error::AnalysisReadDenied { .. })
    ));
    Ok(())
}

#[test]
fn completion_requires_actual_commit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let mut input = commit(active.clone(), "first-1");
    input.metadata = b"{\"actual\":true}".to_vec();
    let receipt = store.commit_package(&input, || Ok(()))?;
    let after = store.package_activation(&active.key)?.ok_or("activation")?;
    assert_eq!(
        store.package_completed(&active, &receipt, &control()?)?,
        Some((after, input.metadata))
    );
    let mut forged = receipt.clone();
    forged.commit_revision += 1;
    assert!(store
        .package_completed(&active, &forged, &control()?)?
        .is_none());
    forged = receipt.clone();
    forged.result_id = "absent".into();
    assert!(store
        .package_completed(&active, &forged, &control()?)?
        .is_none());
    let mut wrong = active.clone();
    wrong.generation += 1;
    assert!(store
        .package_completed(&wrong, &receipt, &control()?)?
        .is_none());
    wrong = active;
    wrong.metadata = b"{\"different\":true}".to_vec();
    assert!(store
        .package_completed(&wrong, &receipt, &control()?)?
        .is_none());
    wrong.metadata = input.activation.metadata;
    wrong.result_id = Some("not-the-precondition".into());
    assert!(store
        .package_completed(&wrong, &receipt, &control()?)?
        .is_none());
    Ok(())
}

#[test]
fn activation_watch_excludes_sources() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut activations = store.subscribe_activations();
    let active = start(&store, "first")?;
    assert!(activations.has_changed()?);
    activations.borrow_and_update();
    append(&store, crate::analysis::tests::identity())?;
    assert!(!activations.has_changed()?);
    store.commit_package(&commit(active.clone(), "first-1"), || Ok(()))?;
    assert!(!activations.has_changed()?);
    let active = store.package_activation(&active.key)?.ok_or("activation")?;
    store.mark_package_stale(&active)?;
    assert!(!activations.has_changed()?);
    let active = store.renew_package(&active, b"{\"renewed\":true}", "grant2", || Ok(()))?;
    assert!(activations.has_changed()?);
    activations.borrow_and_update();
    store.renew_package(&active, &active.metadata, &active.grant_id, || Ok(()))?;
    assert!(!activations.has_changed()?);
    store.update_package_metadata(&active.key, active.generation, b"{\"ready\":true}", || {
        Ok(())
    })?;
    assert!(activations.has_changed()?);
    activations.borrow_and_update();
    store.suspend_package(&active.key, active.generation, || Ok(()))?;
    assert!(activations.has_changed()?);
    Ok(())
}

#[test]
fn activation_watch_reconciles_recovery() -> TestResult {
    for applied in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let active = start(&store, "first")?;
        let mut activations = store.subscribe_activations();
        let mut writer = store.writer()?;
        let transaction = writer.get_mut()?.transaction()?;
        let revision = store.package_next(&transaction)?;
        let mut stopped = active.clone();
        stopped.active = false;
        stopped.generation = revision;
        AnalysisStore::write_activation(&transaction, &stopped)?;
        AnalysisStore::record_revision(&transaction, revision, &["package_activations"])?;
        transaction.execute_batch(if applied { "COMMIT" } else { "ROLLBACK" })?;
        assert!(store
            .commit_metadata(transaction, "test uncertain activation commit")
            .is_err());
        drop(writer);
        assert!(!activations.has_changed()?);
        store.recover()?;
        assert_eq!(activations.has_changed()?, applied);
        assert_eq!(
            store.package_activation(&active.key)?,
            Some(if applied { stopped } else { active })
        );
        activations.borrow_and_update();
        store.recover()?;
        assert!(!activations.has_changed()?);
        append(&store, crate::analysis::tests::identity())?;
        assert!(!activations.has_changed()?);
    }
    Ok(())
}

#[test]
fn reader_release_wakes_capacity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let identity = crate::analysis::tests::identity();
    append(&store, identity.clone())?;
    store.meta()?;
    let mut capacity = store.subscribe_capacity();
    let mut permits = (0..16)
        .map(|_| store.reserve_trace_read())
        .collect::<crate::Result<Vec<_>>>()?;
    assert!(matches!(
        store.reserve_trace_read(),
        Err(crate::Error::AnalysisBusy { .. })
    ));
    assert!(!capacity.has_changed()?);
    drop(permits.pop());
    assert_eq!(store.read_slots.available_permits(), 1);
    assert!(capacity.has_changed()?);
    capacity.borrow_and_update();
    let reader = store.reader_until(&control()?)?;
    assert!(!capacity.has_changed()?);
    drop(reader);
    assert!(capacity.has_changed()?);
    assert_eq!(store.read_slots.available_permits(), 1);
    drop(permits);
    assert_eq!(store.read_slots.available_permits(), 16);
    capacity.borrow_and_update();
    assert_eq!(store.read_page(&identity, 1)?.records.len(), 1);
    assert!(capacity.has_changed()?);
    Ok(())
}

#[tokio::test]
async fn cancellation_ignores_stage_deadline() -> TestResult {
    let control = AnalysisReadControl::with_timeout(Duration::from_nanos(1))?;
    let wait = control.cancelled();
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    assert!(matches!(
        control.check(),
        Err(crate::Error::AnalysisReadDeadline { .. })
    ));
    control.cancel()?;
    tokio::time::timeout(Duration::from_secs(1), wait).await?;
    control.cancelled().await;
    assert!(matches!(
        control.check(),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn capacity_checks_reader_gate() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut permits = (0..16)
        .map(|_| store.reserve_trace_read())
        .collect::<crate::Result<Vec<_>>>()?;
    let wait = store.wait_capacity();
    tokio::pin!(wait);
    assert!(futures_util::poll!(&mut wait).is_pending());
    store.capacity.send_replace(());
    assert!(futures_util::poll!(&mut wait).is_pending());
    drop(permits.pop());
    tokio::time::timeout(Duration::from_secs(1), wait).await??;
    assert_eq!(store.read_slots.available_permits(), 1);
    drop(permits);
    store.wait_capacity().await?;
    Ok(())
}
