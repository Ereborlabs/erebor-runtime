use super::*;

struct SelectiveFailure;

impl GraphContextProvider for SelectiveFailure {
    fn facts(&self, record: &DiscoveryRecordV1) -> Result<Vec<AnalysisContextVersionV1>> {
        if record.id.stream.source_id == source().source_id {
            return GraphInvalidSnafu {
                field: "fixture source failure",
            }
            .fail();
        }
        Ok(Vec::new())
    }
}

#[test]
fn control_graph_source_recovery() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let owner = GraphAndFindingOwner::new(store.clone(), Arc::new(SelectiveFailure))?;
    let observation = record(1, &wire(1, DeniedBeforeEffect, 2, 2, [20; 16]))?;
    accept(&store, std::slice::from_ref(&observation))?;
    let mut other = source();
    other.source_id = [4; 16];
    assert_eq!(
        store.accept_validated_batch(
            other.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 1,
                framed_records: observation.wire_record.clone().into(),
                frame_ends: vec![observation.wire_record.len()],
            },
        )?,
        EvidenceStoreOutcomeV1::Accepted
    );
    assert_eq!(
        store.source_page(source().tenant_id, None)?,
        vec![source(), other.clone()]
    );
    for now in [10, 11] {
        assert!(matches!(
            owner.process(now),
            Err(Error::GraphInvalid {
                field: "fixture source failure",
                ..
            })
        ));
        let failed = store
            .processor_health(&GraphAndFindingOwner::scope(&source()))?
            .ok_or("failed health")?;
        assert_eq!(failed.state, ProcessorStateV1::ProcessingFailed);
        assert_eq!(failed.consumed_cursor, 0);
        assert!(failed.incomplete);
        let healthy = store
            .processor_health(&GraphAndFindingOwner::scope(&other))?
            .ok_or("healthy health")?;
        assert_eq!(healthy.consumed_cursor, 1);
        assert_ne!(healthy.state, ProcessorStateV1::ProcessingFailed);
        assert!(owner.snapshot(&other)?.is_some());
        assert_eq!(owner.process(now)?, 0);
    }
    Ok(())
}
