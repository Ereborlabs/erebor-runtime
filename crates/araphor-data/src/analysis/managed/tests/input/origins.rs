use super::*;
use crate::AnalysisReferenceOriginV1 as Origin;

#[test]
fn retained_origins_merge_refs() -> TestResult {
    let saved = Saved::new()?;
    let source = crate::analysis::tests::identity();
    let reference = &saved.receipt.results[&10];
    let (witnesses, contexts) = saved
        .store
        .package_evidence([1; 16], std::slice::from_ref(&reference.result_id))?;
    assert_eq!(witnesses.len(), 1);
    assert_eq!(
        witnesses[0].identity,
        crate::AnalysisStreamIdentityV1::from(source.clone())
    );
    assert_eq!(witnesses[0].cursor, 1);
    assert_eq!(witnesses[0].expires_utc_ns, 100);
    assert_eq!(contexts, std::slice::from_ref(&saved.context));
    let scope = crate::ProcessorScopeV1 {
        processor_id: "saved-origins".into(),
        method_version: 1,
        identity: source.clone(),
    };
    saved
        .store
        .register_processor(&scope, crate::ProcessorClassV1::Optional, 1)?;
    let mut earliest = witnesses[0].clone();
    earliest.expires_utc_ns = 50;
    let generic = saved.store.commit_result(&crate::AnalysisResultCommitV1 {
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
        saved
            .store
            .package_evidence([1; 16], &["saved-origins-proof".into()])?,
        (vec![earliest.clone()], vec![saved.context.clone()])
    );
    assert_eq!(
        saved
            .store
            .package_evidence([1; 16], std::slice::from_ref(&reference.result_id))?,
        (witnesses, contexts)
    );
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![source]);
    selection.contexts = crate::Selection::Exact(vec![saved.context.key.clone()]);
    selection.results = vec![reference.result_id.clone(), "saved-origins-proof".into()];
    let outputs = [saved.inputs[0].clone(), saved.inputs[0].clone()];
    let requests = AnalysisTableRequests::new();
    let page = saved.store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            inputs: Some(crate::AnalysisInputTables {
                authorized: &saved.fixture.instance.grant.selection,
                outputs: &outputs,
            }),
            mode: AnalysisReadModeV1::Metadata,
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(page.packages.is_empty());
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
        &[
            Origin::Context,
            Origin::ExplicitResult,
            Origin::Package(0),
            Origin::Package(1),
        ]
    );
    let managed = page
        .extraction
        .references
        .iter()
        .find(|entry| entry.result().is_some_and(|result| result == reference))
        .ok_or("managed reference absent")?;
    assert_eq!(managed.result(), Some(reference));
    assert_eq!(
        managed.origins(),
        &[
            Origin::ExplicitResult,
            Origin::Package(0),
            Origin::Package(1),
        ]
    );
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
        Some(&crate::analysis::PackageResultRefV1 {
            result_id: "saved-origins-proof".into(),
            commit_revision: generic.commit_revision,
        })
    );
    assert_eq!(generic_entry.origins(), &[Origin::ExplicitResult]);
    assert_eq!(page.extraction.witnesses, vec![earliest]);
    saved.permits()?;
    Ok(())
}
