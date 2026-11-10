use super::*;
use sdk::arrow_array::Array as _;
use std::time::Duration;

#[test]
fn graph_state_bootstrap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    append(&store, 1)?;
    let control = AnalysisReadControl::default();
    let selection = AnalysisSelectionV1::new([1; 16], vec![identity()]);
    let requests = state_requests();
    let read = araphor_data::AnalysisTableRead {
        requests: &requests,
        mode: araphor_data::AnalysisReadModeV1::Metadata,
        now: 1000,
        event_ranges: None,
    };
    let page = store.read_tables(&selection, read, AnalysisExtractLimits::default(), &control)?;
    assert_eq!(page.tables["graph_state"][0].num_rows(), 1);
    assert_eq!(head(&page.tables["graph_state"][0])?.null_count(), 1);
    let requests = araphor_data::AnalysisTableRequests::from([("graph_subjects".into(), None)]);
    let error = store
        .read_tables(
            &selection,
            araphor_data::AnalysisTableRead {
                requests: &requests,
                ..read
            },
            AnalysisExtractLimits::default(),
            &control,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Package {
            code: Code::Unsupported,
            field: "native table owner",
            ..
        }
    ));
    Ok(())
}

#[tokio::test]
async fn source_log_and_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    let page = super::super::attempts::capture(&store, &instance, false)?;
    select(&store, &page, &[1], None)?;
    let control = AnalysisReadControl::default();
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::attempts::request("first", true),
        || Ok(()),
    )?;
    let before = store.view()?;
    let requests = araphor_data::AnalysisTableRequests::from([("graph_manifest".into(), None)]);
    let selection = AnalysisSelectionV1::new([1; 16], vec![identity()]);
    let budget = super::super::graph::Budget;
    let mut matched =
        store.subscribe_inputs_at(&before, &selection, &requests, None, &control, &budget)?;
    let mut other = identity();
    other.source_id = [8; 16];
    let other = AnalysisSelectionV1::new([1; 16], vec![other]);
    let mut unrelated =
        store.subscribe_inputs_at(&before, &other, &requests, None, &control, &budget)?;
    let receipt = publish(&store, &attempt, false)?;
    let position = tokio::time::timeout(Duration::from_secs(5), matched.changed()).await??;
    assert_eq!(position.commit_revision, receipt.commit_revision);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), unrelated.changed())
            .await
            .is_err()
    );
    let requests = state_requests();
    let read = araphor_data::AnalysisTableRead {
        requests: &requests,
        mode: araphor_data::AnalysisReadModeV1::Metadata,
        now: 1000,
        event_ranges: None,
    };
    let old = store.read_tables_at(
        &before,
        &selection,
        read,
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    let current =
        store.read_tables(&selection, read, AnalysisExtractLimits::default(), &control)?;
    let old = &old.tables["graph_state"][0];
    let current = &current.tables["graph_state"][0];
    assert_eq!(head(old)?.null_count(), 1);
    assert_eq!(head(current)?.value(0), receipt.selected.result_id);
    let consumed = current
        .column_by_name("consumed_cursor")
        .ok_or("consumed")?
        .as_any()
        .downcast_ref::<sdk::arrow_array::UInt64Array>()
        .ok_or("consumed type")?;
    assert_eq!(consumed.value(0), 1);
    drop((page, attempt, matched, unrelated, before));
    drop(store);
    let store = NativeStore::open(&root)?;
    let current = store.view()?;
    let mut resumed = store.subscribe_inputs_at(
        &store.read_at(receipt.commit_revision - 1)?,
        &selection,
        &araphor_data::AnalysisTableRequests::from([("graph_manifest".into(), None)]),
        None,
        &control,
        &budget,
    )?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), resumed.changed())
            .await??
            .commit_revision,
        receipt.commit_revision
    );
    assert!(current.revision() >= receipt.commit_revision);
    Ok(())
}

fn head(
    batch: &sdk::RecordBatch,
) -> Result<&sdk::arrow_array::StringArray, Box<dyn std::error::Error>> {
    Ok(batch
        .column_by_name("current_result_id")
        .ok_or("head")?
        .as_any()
        .downcast_ref::<sdk::arrow_array::StringArray>()
        .ok_or("head type")?)
}

fn state_requests() -> araphor_data::AnalysisTableRequests {
    araphor_data::AnalysisTableRequests::from([(
        "graph_state".into(),
        Some(
            (0..araphor_data::AnalysisStore::table_schemas()["graph_state"]
                .fields()
                .len())
                .collect(),
        ),
    )])
}
