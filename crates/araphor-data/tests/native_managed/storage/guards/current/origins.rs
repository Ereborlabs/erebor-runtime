use super::*;
use araphor_data::{AnalysisContextRefV1, AnalysisReferenceOriginV1 as Origin, AnalysisWitnessV1};

fn evidence(
    store: &AnalysisStore,
    ids: &[String],
) -> TestResult<(Vec<AnalysisWitnessV1>, Vec<AnalysisContextRefV1>)> {
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.results = ids.to_vec();
    let requests = AnalysisTableRequests::new();
    let before = store.meta()?;
    let page = store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Metadata,
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(page.tables.is_empty());
    assert!(page.extraction.missing_results.is_empty());
    assert_eq!(
        page.extraction
            .references
            .iter()
            .filter_map(|reference| reference.result())
            .map(|reference| reference.result_id.clone())
            .collect::<BTreeSet<_>>(),
        ids.iter().cloned().collect()
    );
    let contexts = page
        .extraction
        .references
        .iter()
        .filter_map(|reference| reference.context())
        .cloned()
        .collect();
    assert_eq!(store.meta()?, before);
    Ok((page.extraction.witnesses, contexts))
}

#[test]
fn retained_origins_merge_refs() -> TestResult {
    let saved = Saved::new()?;
    let requests = AnalysisTableRequests::new();
    let page = saved.store.read_tables(
        &AnalysisSelectionV1::tenant([1; 16]),
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Metadata,
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(page.tables.is_empty());
    assert!(page.extraction.references.is_empty());
    assert!(page.extraction.witnesses.is_empty());
    let source = super::super::super::source::identity();
    let reference = &saved.receipt.results[&10];
    let (witnesses, contexts) = evidence(&saved.store, std::slice::from_ref(&reference.result_id))?;
    assert_eq!(witnesses.len(), 1);
    assert_eq!(
        witnesses[0].identity,
        araphor_data::AnalysisStreamIdentityV1::from(source.clone())
    );
    assert_eq!(witnesses[0].cursor, 1);
    assert_eq!(witnesses[0].expires_utc_ns, 100);
    assert_eq!(contexts, std::slice::from_ref(&saved.context));
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: "saved-origins".into(),
        method_version: 1,
        identity: source.clone(),
    };
    saved
        .store
        .register_processor(&scope, araphor_data::ProcessorClassV1::Optional, 1)?;
    let mut earliest = witnesses[0].clone();
    earliest.expires_utc_ns = 50;
    let generic = saved
        .store
        .commit_result(&araphor_data::AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: saved.context.commit_revision,
            result_id: "saved-origins-proof".into(),
            body: b"proof".to_vec(),
            created_utc_ns: 10,
            witnesses: vec![earliest.clone()],
            context_refs: vec![saved.context.clone()],
        })?;
    assert_eq!(
        evidence(&saved.store, &["saved-origins-proof".into()])?,
        (vec![earliest.clone()], vec![saved.context.clone()])
    );
    assert_eq!(
        evidence(&saved.store, std::slice::from_ref(&reference.result_id))?,
        (witnesses, contexts)
    );
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source]);
    selection.contexts = araphor_data::Selection::Exact(vec![saved.context.key.clone()]);
    selection.results = vec![reference.result_id.clone(), "saved-origins-proof".into()];
    let requests = AnalysisTableRequests::new();
    let page = saved.store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Metadata,
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(page.extraction.references.len(), 3);
    let context = page
        .extraction
        .references
        .iter()
        .find(|entry| entry.context().is_some())
        .ok_or("context reference absent")?;
    assert_eq!(context.context(), Some(&saved.context));
    assert_eq!(
        context.origins(),
        &[Origin::Context, Origin::ExplicitResult,]
    );
    let managed = page
        .extraction
        .references
        .iter()
        .find(|entry| entry.result().is_some_and(|result| result == reference))
        .ok_or("managed reference absent")?;
    assert_eq!(managed.result(), Some(reference));
    assert_eq!(managed.origins(), &[Origin::ExplicitResult]);
    let generic_entry = page
        .extraction
        .references
        .iter()
        .find(|entry| {
            entry
                .result()
                .is_some_and(|result| result.result_id == "saved-origins-proof")
        })
        .ok_or("generic reference absent")?;
    assert_eq!(
        generic_entry.result(),
        Some(&araphor_data::analysis::PackageResultRefV1 {
            result_id: "saved-origins-proof".into(),
            commit_revision: generic.commit_revision,
        })
    );
    assert_eq!(generic_entry.origins(), &[Origin::ExplicitResult]);
    assert_eq!(page.extraction.witnesses, vec![earliest]);
    Ok(())
}
