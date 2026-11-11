use super::*;

fn selected(
    store: &NativeStore,
) -> Result<araphor_data::ManagedReceipt, Box<dyn std::error::Error>> {
    let instance = instance(store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(store, 1)?;
    let page = super::super::super::attempts::capture(store, &instance, false)?;
    select(store, &page, &[1], None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::super::attempts::request("first", true),
        || Ok(()),
    )?;
    Ok(publish(store, &attempt, false)?)
}

#[test]
fn source_header_winner_damage() -> TestResult {
    for prefix in [
        b"\0data/@source/header/".as_slice(),
        b"\0data/@source/winner/",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let receipt = selected(&store)?;
        let view = store.view()?;
        let (key, _) = view
            .snapshot()
            .prefix(prefix)
            .next()
            .ok_or("source index")??;
        let mut write = store.write()?;
        write.native().remove(key);
        write.commit([])?;
        let mut exact = AnalysisSelectionV1::tenant([1; 16]);
        exact.select_graphs(
            Selection::Exact(vec![receipt.selected.result_id.clone()]),
            None,
        )?;
        if prefix == b"\0data/@source/header/" {
            assert!(page(&store, None, &exact).is_err());
            assert!(store
                .graph_finding_batch(
                    [1; 16],
                    &[NotificationFindingRefV1 {
                        result_id: receipt.selected.result_id,
                        finding_id: "absent".into()
                    }]
                )
                .is_err());
        }
        drop(view);
        drop(store);
        assert!(NativeStore::open(&root).is_err());
    }
    Ok(())
}

#[test]
fn source_rebound_graph_publication() -> TestResult {
    for missing in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let (_, model, source, observation) =
            super::super::super::domain::fixture_source(&store, true)?;
        let scope = ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: source,
        };
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        super::super::super::domain::commit(&store, &model, &observation, 0)?;
        let view = store.view()?;
        let (_, prior) = view
            .snapshot()
            .prefix(b"\0data/graph/publication/")
            .next()
            .ok_or("first publication")??;
        super::super::super::domain::commit(&store, &model, &observation, 1)?;
        let selection = AnalysisSelectionV1::tenant([1; 16]);
        let current = page(&store, None, &selection)?;
        let manifest = manifests(&current)?.remove(0);
        let finding_id = values(&current, "finding_id")?.remove(0);
        let latest = store.view()?;
        let mut target = None;
        for entry in latest.snapshot().prefix(b"\0data/graph/publication/") {
            let (key, bytes) = entry?;
            let publication: araphor_data::analysis::native::GraphPublication =
                rmp_serde::from_slice(&bytes[1..])?;
            if publication.reference.result_id == manifest.graph_result_id {
                target = Some(key);
            }
        }
        let target = target.ok_or("current publication")?;
        let mut write = store.write()?;
        if missing {
            let prefix = b"\0data/@source/header/";
            write
                .native()
                .remove([prefix.as_slice(), &target[target.len() - 8..]].concat());
        } else {
            write.native().insert(target, prior);
        }
        write.commit([])?;
        let mut exact = selection;
        exact.select_graphs(
            Selection::Exact(vec![manifest.graph_result_id.clone()]),
            None,
        )?;
        assert!(page(&store, None, &exact).is_err());
        let reference = NotificationFindingRefV1 {
            result_id: manifest.graph_result_id,
            finding_id,
        };
        assert!(store
            .graph_finding_batch([1; 16], &[reference.clone()])
            .is_err());
        let control = AnalysisReadControl::default();
        let budget = super::super::super::graph::Budget;
        let batch =
            store.prepare_notifications([1; 16], &[reference.clone()], &[], &control, &budget)?;
        assert!(batch.finding(&reference).is_err());
        drop(batch);
        drop((view, latest));
        drop(store);
        assert!(NativeStore::open(&root).is_err());
    }
    Ok(())
}

#[test]
fn source_scalar_scope_budget() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let receipt = selected(&store)?;
    let schemas = araphor_data::AnalysisStore::table_schemas();
    let fields = [
        "graph_result_id",
        "first_cursor",
        "last_cursor",
        "notice_context_revision",
        "subject_count",
        "relationship_count",
    ];
    let requests: AnalysisTableRequests = [(
        "graph_manifest".into(),
        Some(
            schemas["graph_manifest"]
                .fields()
                .iter()
                .enumerate()
                .filter_map(|(index, field)| {
                    fields.contains(&field.name().as_str()).then_some(index)
                })
                .collect(),
        ),
    )]
    .into();
    let read = AnalysisTableRead {
        requests: &requests,
        mode: AnalysisReadModeV1::Complete,
        now: 1000,
        event_ranges: None,
    };
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let control = AnalysisReadControl::default();
    let scalar = store.read_tables(&selection, read, AnalysisExtractLimits::default(), &control)?;
    assert!(scalar
        .extraction
        .graph_coverage(&receipt.selected.result_id)
        .is_some());
    let full = page(&store, None, &selection)?;
    assert!(full.extraction.input_bytes > scalar.extraction.input_bytes);
    let finite = AnalysisExtractLimits {
        input_bytes: scalar.extraction.input_bytes,
        ..Default::default()
    };
    assert!(store
        .read_tables(&selection, read, finite, &control)
        .is_ok());
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(store
        .read_tables(
            &selection,
            read,
            AnalysisExtractLimits::default(),
            &cancelled
        )
        .is_err());
    let mut narrow = AnalysisSelectionV1::new([1; 16], vec![]);
    narrow.select_graphs(Selection::All, None)?;
    let hidden = store.read_tables(
        &narrow,
        read,
        AnalysisExtractLimits {
            keys: Some(0),
            ..Default::default()
        },
        &control,
    )?;
    assert!(hidden
        .tables
        .get("graph_manifest")
        .is_none_or(|batches| batches.iter().all(|batch| batch.num_rows() == 0)));
    let unsupported: AnalysisTableRequests = [(
        "graph_manifest".into(),
        Some([schemas["graph_manifest"].index_of("snapshot")?].into()),
    )]
    .into();
    let result = store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &unsupported,
            ..read
        },
        AnalysisExtractLimits::default(),
        &control,
    );
    assert!(
        matches!(
            &result,
            Err(Error::Package {
                code: Code::Missing,
                field: "Source Graph snapshot",
                ..
            })
        ),
        "snapshot projection: {:?}",
        result
            .as_ref()
            .map(|page| page.tables.keys().collect::<Vec<_>>())
    );
    Ok(())
}
