use super::*;

#[derive(Default)]
struct RecoveryInputs {
    failed: std::sync::atomic::AtomicBool,
    inner: Inputs,
}

impl GraphContextProvider for RecoveryInputs {
    fn facts(&self, record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        if self.failed.load(std::sync::atomic::Ordering::Acquire) {
            return GraphInvalidSnafu {
                field: "fixture recovery failure",
            }
            .fail();
        }
        self.inner.facts(record)
    }
}

#[test]
fn control_graph_evidence_recovery() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let provider = Arc::new(RecoveryInputs::default());
    let owner = GraphAndFindingOwner::new(store.clone(), provider.clone())?;
    let records = (1..=257)
        .map(|cursor| record(cursor, &wire(cursor, DeniedBeforeEffect, 2, 2, [20; 16])))
        .collect::<Result<Vec<_>>>()?;
    for batch in records.chunks(128) {
        accept(&store, batch)?;
    }
    coverage(&store, 257, 1, "HEALTHY")?;
    super::window_expiry::process_to(&owner, &store, 257, 10)?;
    let original = owner
        .current_findings(source().tenant_id)?
        .into_iter()
        .find(|(_, finding)| finding.evidence[0].durable_cursor == 1)
        .ok_or("original finding")?;
    provider
        .failed
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(owner.refresh(&source(), 11).is_err());
    accept(
        &store,
        &[record(258, &wire(258, DeniedBeforeEffect, 2, 2, [20; 16]))?],
    )?;
    coverage(&store, 258, 2, "HEALTHY")?;
    assert_eq!(owner.process(12)?, 0);
    assert!(owner.process(12).is_err());
    let scope = GraphAndFindingOwner::scope(&source());
    let failed = store.processor_health(&scope)?.ok_or("failed health")?;
    assert_eq!(failed.state, ProcessorStateV1::ProcessingFailed);
    assert_eq!(failed.consumed_cursor, 257);
    provider
        .inner
        .0
        .lock()
        .map_err(|_| "provider")?
        .extend([policy(&records[0], 1)?, activation(&records[0])?]);
    provider
        .failed
        .store(false, std::sync::atomic::Ordering::Release);
    super::window_expiry::process_to(&owner, &store, 258, 13)?;
    let revised = owner
        .current_finding(source().tenant_id, &original.1.finding_id)?
        .ok_or("revised finding")?;
    assert_ne!(revised.0, original.0);
    assert!(!revised.1.revision.context.is_empty());
    assert_eq!(
        owner.finding_result(source().tenant_id, &original.0, &original.1.finding_id)?,
        Some(original.1)
    );
    let recovered = store.processor_health(&scope)?.ok_or("recovered health")?;
    assert_eq!(recovered.state, ProcessorStateV1::Current);
    assert!(!recovered.incomplete);
    Ok(())
}
