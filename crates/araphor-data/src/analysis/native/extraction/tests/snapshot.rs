use super::*;

#[test]
fn analysis_tenant_snapshot() -> TestResult {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let first = identity(1);
    store.accept_validated_batch(first.clone(), batch(1, 1, 10)?)?;
    store.accept_validated_batch(identity(2), batch(1, 1, 10)?)?;
    let next = EvidenceIntakeIdentityV1 {
        source_id: [4; 16],
        node_boot_id: [5; 16],
        ..first.clone()
    };
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: first.tenant_id,
            owner_id: "policy".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![42],
    };
    let selection = AnalysisSelectionV1::tenant(first.tenant_id);
    let fields = [
        ("events", &["source_id"][..]),
        ("context_versions", &["body"][..]),
    ];
    let before = store.meta()?;
    let control = AnalysisReadControl::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let writer = Arc::clone(&store);
    let late = next.clone();
    control.on_read_step(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        writer.accept_validated_batch(late, batch(1, 1, 20)?)?;
        writer.commit_context(&context)?;
        Ok(())
    })?;
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(page.extraction.meta, before);
    assert_eq!(page.extraction.sources.len(), 1);
    assert_eq!(
        binary(&page, "events", "source_id")?,
        vec![first.source_id.to_vec()]
    );
    assert_eq!(row_count(&page, "context_versions"), 0);
    assert!(page.extraction.missing_contexts.is_empty());
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(page.extraction.sources.len(), 2);
    assert_eq!(
        binary(&page, "events", "source_id")?,
        vec![first.source_id.to_vec(), next.source_id.to_vec()]
    );
    assert_eq!(binary(&page, "context_versions", "body")?, vec![vec![42]]);
    let empty = read(
        &store,
        &AnalysisSelectionV1::new(first.tenant_id, vec![]),
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(
        row_count(&empty, "events") + row_count(&empty, "context_versions"),
        0
    );
    Ok(())
}

#[test]
fn analysis_extract_snapshot() -> TestResult {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let identity = identity(1);
    store.accept_validated_batch(identity.clone(), batch(1, 1, 10)?)?;
    let scope = ProcessorScopeV1 {
        processor_id: "p".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: identity.tenant_id,
            owner_id: "policy".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 0,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![42],
    };
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    selection.contexts = Selection::Exact(vec![context.key.clone()]);
    selection.results.push("late".into());
    let key = context.key.clone();
    let before = store.meta()?;
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let writer = Arc::clone(&store);
    let source = identity.clone();
    control.on_read_step(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        writer.accept_validated_batch(source, batch(2, 1, 5)?)?;
        writer.commit_context(&context)?;
        writer.commit_result(&AnalysisResultCommitV1 {
            body: vec![43],
            created_utc_ns: 20,
            ..crate::analysis::tests::result(scope, "late".into())
        })?;
        Ok(())
    })?;
    let fields = [
        ("events", &["source_cursor"][..]),
        ("context_versions", &["body"][..]),
    ];
    let first = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.extraction.meta, before);
    assert_eq!(first.extraction.sources[0].receipt.contiguous_cursor, 1);
    assert_eq!(first.extraction.missing_contexts, vec![key]);
    assert_eq!(first.extraction.missing_results, vec!["late"]);
    assert_eq!(unsigned(&first, "events", "source_cursor")?, vec![1]);
    assert_eq!(row_count(&first, "context_versions"), 0);
    assert!(first
        .extraction
        .references
        .iter()
        .all(|entry| entry.result().is_none()));
    let result_revision = store.meta()?.commit_revision;
    let next = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert!(
        next.extraction.missing_contexts.is_empty() && next.extraction.missing_results.is_empty()
    );
    assert_eq!(next.extraction.meta, store.meta()?);
    assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![1, 2]);
    assert_eq!(binary(&next, "context_versions", "body")?, vec![vec![42]]);
    let reference = next
        .extraction
        .references
        .iter()
        .find(|entry| entry.result().is_some())
        .ok_or("result reference absent")?;
    let result = reference.result().ok_or("result reference absent")?;
    assert_eq!(result.result_id, "late");
    assert_eq!(result.commit_revision, result_revision);
    assert_eq!(
        reference.origins(),
        &[AnalysisReferenceOriginV1::ExplicitResult]
    );
    assert_eq!(
        store.read_result(identity.tenant_id, "late")?,
        Some(vec![43])
    );
    selection.received_from = Bound::Included(100);
    let later = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(later.extraction.scanned_bytes, 0);
    assert_eq!(row_count(&later, "events"), 0);
    assert_eq!(binary(&later, "context_versions", "body")?, vec![vec![42]]);
    let reference = later
        .extraction
        .references
        .iter()
        .find_map(AnalysisReferenceV1::result)
        .ok_or("result reference absent")?;
    assert_eq!(reference.result_id, "late");
    assert_eq!(reference.commit_revision, result_revision);
    assert!(
        later.extraction.missing_contexts.is_empty() && later.extraction.missing_results.is_empty()
    );
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}
