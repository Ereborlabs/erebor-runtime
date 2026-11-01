use super::*;
use sdk::arrow_array::{Array as _, BooleanArray, UInt64Array};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn states(
    store: &AnalysisStore,
    receipt: &AnalysisSourceReceiptV1,
    revision: u64,
) -> TestResult<AnalysisPositionPageV1> {
    let selection =
        AnalysisSelectionV1::new(receipt.identity.tenant_id, vec![receipt.identity.clone()]);
    let requests = ["graph_state", "discovery_state"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                Some((0..AnalysisStore::table_schemas()[name].fields().len()).collect()),
            )
        })
        .collect();
    let control = AnalysisReadControl::default();
    let mut output = store
        .read_tables(
            &selection,
            AnalysisTableRead {
                requests: &BTreeMap::new(),
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 100,
            },
            AnalysisExtractLimits::default(),
            &control,
        )?
        .extraction;
    output.meta.commit_revision = revision;
    let read = AnalysisTableRead {
        requests: &requests,
        event_ranges: None,
        mode: AnalysisReadModeV1::Complete,
        now: 100,
    };
    Ok(store.read_snapshot(|reader| {
        let mut capture = tables::Capture::new(&read, &selection);
        store.extract_graph_state(reader, receipt, &read, &mut output, &mut capture, &control)?;
        store.extract_discovery_state(
            reader,
            receipt,
            &mut output,
            &mut capture,
            None,
            &control,
        )?;
        capture.finish(
            output,
            StorePositionV1 {
                commit_revision: revision,
                ordinal: u32::MAX,
            },
            true,
            &control,
        )
    })?)
}

fn boolean(page: &AnalysisPositionPageV1, table: &str, column: &str) -> TestResult<Option<bool>> {
    let batch = &page.tables[table][0];
    let values = batch
        .column_by_name(column)
        .ok_or("state column")?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or("boolean state column")?;
    Ok((!values.is_null(0)).then(|| values.value(0)))
}

fn cursor(page: &AnalysisPositionPageV1, table: &str, column: &str) -> TestResult<Option<u64>> {
    let batch = &page.tables[table][0];
    let values = batch
        .column_by_name(column)
        .ok_or("state column")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("cursor state column")?;
    Ok((!values.is_null(0)).then(|| values.value(0)))
}

#[test]
fn processor_state_uses_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = crate::RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: None,
    };
    let store = Arc::new(AnalysisStore::open_with_limits(
        &root,
        limits,
        Default::default(),
    )?);
    let source = crate::analysis::tests::identity();
    store.accept_validated_batch(source.clone(), crate::analysis::tests::batch(1, &[b"one"]))?;
    let receipt = store.source_receipt(&source)?.ok_or("source receipt")?;
    let initial = store.meta()?.commit_revision;
    store.register_graph(&source)?;
    let graph = store.meta()?.commit_revision;
    let discovery = crate::ProcessorScopeV1 {
        processor_id: crate::DISCOVERY_PROCESSOR.into(),
        method_version: u64::from(crate::DISCOVERY_SCHEMA_VERSION),
        identity: source.clone(),
    };
    let registered = store.register_processor(&discovery, crate::ProcessorClassV1::Optional, 1)?;
    let retired = store.retire_required(&crate::ProcessorRetirementV1 {
        scope: crate::ProcessorScopeV1 {
            processor_id: crate::GRAPH_PROCESSOR.into(),
            method_version: u64::from(crate::GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        },
        change_id: "historical-state".into(),
        reason: "Stop the Graph processor.".into(),
        expected_cursor: 0,
        cutoff_cursor: 1,
    })?;
    assert_eq!(
        crate::EvidenceRetentionOwner::new(&store)
            .retain(&source, 10_000_000_000)?
            .removed_records,
        1
    );
    let expired = store.meta()?.commit_revision;
    let resumed = store
        .resume_optional(&discovery)?
        .ok_or("optional resume")?;
    let before = store.meta()?;
    assert_eq!(store.resume_optional(&discovery)?, None);
    assert_eq!(store.meta()?, before);
    let graph_owner = store.lease_graph(vec![AnalysisSelectionV1::new(
        source.tenant_id,
        vec![source.clone()],
    )])?;
    store.register_discovery_owner();
    for revision in [
        initial,
        graph,
        registered,
        retired,
        expired,
        resumed.commit_revision,
    ] {
        let page = states(&store, &receipt, revision)?;
        assert_eq!(
            boolean(&page, "graph_state", "processor_present")?,
            Some(revision >= graph)
        );
        assert_eq!(
            boolean(&page, "graph_state", "retired")?,
            (revision >= graph).then_some(revision >= retired)
        );
        assert_eq!(
            cursor(&page, "graph_state", "consumed_cursor")?,
            (revision >= graph).then_some(0)
        );
        assert_eq!(
            boolean(&page, "discovery_state", "processor_present")?,
            Some(revision >= registered)
        );
        assert_eq!(
            cursor(&page, "discovery_state", "resume_floor")?,
            (revision >= registered).then_some(u64::from(revision >= resumed.commit_revision))
        );
        let rows: Vec<crate::DiscoveryStateRowV1> =
            serde_arrow::from_record_batch(&page.tables["discovery_state"][0])?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].gaps,
            Some(if revision >= resumed.commit_revision {
                vec![resumed]
            } else {
                Vec::new()
            })
        );
    }
    AnalysisStore::validate_state(store.writer()?.get()?, &root)?;
    drop(graph_owner);
    drop(store);
    let store = Arc::new(AnalysisStore::open_with_limits(
        &root,
        limits,
        Default::default(),
    )?);
    let _graph_owner = store.lease_graph(vec![AnalysisSelectionV1::new(
        source.tenant_id,
        vec![source],
    )])?;
    store.register_discovery_owner();
    let page = states(&store, &receipt, registered)?;
    assert_eq!(boolean(&page, "graph_state", "retired")?, Some(false));
    assert_eq!(cursor(&page, "discovery_state", "resume_floor")?, Some(0));
    Ok(())
}
