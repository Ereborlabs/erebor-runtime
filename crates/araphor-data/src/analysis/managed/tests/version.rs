use super::*;

pub(super) fn target(
    store: &AnalysisStore,
    current: &ManagedInstance,
    description: &str,
) -> TestResult<ManagedSpec> {
    let mut spec = current.spec.clone();
    spec.definition.definition.description = description.into();
    spec.manifest.definition = store.admit_definition(spec.tenant, &spec.definition, || Ok(()))?;
    Ok(spec)
}

pub(super) fn capture(
    store: &AnalysisStore,
    current: &ManagedInstance,
    target: &ManagedInstance,
    rebuild: bool,
) -> TestResult<ManagedCapture> {
    let requests = AnalysisTableRequests::new();
    let selection = current.grant.selection.project(&requests)?;
    Ok(store
        .read_managed_tables_filtered(
            &selection,
            &ManagedRead {
                source: None,
                execution: None,
                follow: false,
                instance: target.clone(),
                expected: Some(current.clone()),
                rebuild,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state)
}
