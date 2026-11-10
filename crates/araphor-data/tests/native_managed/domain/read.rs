use super::*;
use araphor_data::{AnalysisPositionPageV1, Selection};
use sdk::arrow_array::{StringArray, UInt64Array};

fn requests() -> AnalysisTableRequests {
    ["findings", "graph_manifest"]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                Some(
                    (0..araphor_data::AnalysisStore::table_schemas()[name]
                        .fields()
                        .len())
                        .collect(),
                ),
            )
        })
        .collect()
}

fn value(
    page: &AnalysisPositionPageV1,
    table: &str,
    field: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let batch = page.tables[table]
        .iter()
        .find(|batch| batch.num_rows() != 0)
        .ok_or("table row")?;
    Ok(batch
        .column_by_name(field)
        .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
        .ok_or("integer field")?
        .value(0))
}

fn result(page: &AnalysisPositionPageV1) -> Result<&str, Box<dyn std::error::Error>> {
    let batch = page.tables["findings"]
        .iter()
        .find(|batch| batch.num_rows() != 0)
        .ok_or("finding row")?;
    Ok(batch
        .column_by_name("graph_result_id")
        .and_then(|array| array.as_any().downcast_ref::<StringArray>())
        .ok_or("result field")?
        .value(0))
}

#[test]
fn native_finding_reads_keep_saved_cuts_and_live_producer_authority() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (instance, model, _, observation) = fixture(&store)?;
    let control = AnalysisReadControl::default();
    let requests = requests();
    let read = AnalysisTableRead {
        requests: &requests,
        mode: AnalysisReadModeV1::Complete,
        now: 1000,
        event_ranges: None,
    };
    let scope = AnalysisSelectionV1::tenant([1; 16]);
    let other = AnalysisSelectionV1::tenant([2; 16]);
    let empty = store.read_tables(&other, read, AnalysisExtractLimits::default(), &control)?;
    let finite = AnalysisExtractLimits {
        input_bytes: empty.extraction.input_bytes,
        ..Default::default()
    };
    commit(&store, &model, &observation, 0)?;
    let held = store.view()?;
    let first = store.read_tables_at(
        &held,
        &scope,
        read,
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert_eq!(
        first.tables["findings"]
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    assert_eq!(value(&first, "graph_manifest", "subject_count")?, 3);
    assert_eq!(value(&first, "graph_manifest", "relationship_count")?, 1);
    let token = value(&first, "findings", "finding_value_id")?;
    let original = result(&first)?.to_owned();
    commit(&store, &model, &observation, 1)?;
    let second = store.read_tables(&scope, read, AnalysisExtractLimits::default(), &control)?;
    assert_ne!(result(&second)?, original);
    assert_eq!(value(&second, "findings", "finding_value_id")?, token);
    assert_eq!(value(&second, "graph_manifest", "subject_count")?, 3);
    let replay = store.read_tables_at(
        &held,
        &scope,
        read,
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert_eq!(result(&replay)?, original);
    let selected = scope.project(&requests)?;
    let filtered = store.read_tables_filtered(
        &selected,
        &scope,
        read,
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert_eq!(result(&filtered)?, result(&second)?);
    assert_eq!(value(&filtered, "findings", "finding_value_id")?, token);
    let mut invalid = selected.clone();
    invalid.select_graphs(Selection::Exact(vec![original.clone()]), None)?;
    invalid.sources = Selection::Exact(Vec::new());
    assert!(matches!(
        store.read_tables_filtered(
            &invalid,
            &scope,
            read,
            AnalysisExtractLimits::default(),
            &control,
            None
        ),
        Err(Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    let narrow = AnalysisSelectionV1::new([1; 16], Vec::new());
    let denied = store.read_tables_filtered(
        &narrow.project(&requests)?,
        &narrow,
        read,
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert!(denied
        .tables
        .get("findings")
        .is_none_or(|rows| rows.iter().all(|batch| batch.num_rows() == 0)));
    let absent = store.read_tables(&other, read, finite, &control)?;
    assert!(absent
        .tables
        .get("findings")
        .is_none_or(|rows| rows.iter().all(|batch| batch.num_rows() == 0)));
    let rollback = Fixture::with_model(&store, [2; 16], "rollback", model.clone())?;
    let mut tx = store.write()?;
    tx.admit_managed(&rollback.spec, &rollback.grant)?;
    tx.rollback();
    assert!(store
        .view()?
        .managed_graph([2; 16], "rollback", &control)?
        .is_none());
    let absent = store.read_tables(&other, read, finite, &control)?;
    assert!(absent
        .tables
        .get("findings")
        .is_none_or(|rows| rows.iter().all(|batch| batch.num_rows() == 0)));
    let later = Fixture::with_model(&store, [1; 16], "later", model.clone())?;
    later.admit(&store)?;
    let before = store.database().inner().journal_head()?;
    let bounded = store.read_tables_filtered(
        &selected,
        &scope,
        read,
        AnalysisExtractLimits {
            keys: Some(0),
            ..Default::default()
        },
        &control,
        None,
    );
    assert!(bounded.is_err());
    assert_eq!(store.database().inner().journal_head()?, before);
    commit(&store, &model, &observation, 2)?;
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(held);
    drop(store);
    let store = NativeStore::open(&root)?;
    let latest = store.read_tables(&scope, read, AnalysisExtractLimits::default(), &control)?;
    assert_eq!(value(&latest, "findings", "finding_value_id")?, token);
    let historical = store.read_tables_at(
        &store.read_at(first.extraction.meta.commit_revision)?,
        &scope,
        read,
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert_eq!(result(&historical)?, original);
    let absent = store.read_tables(&other, read, finite, &control)?;
    assert!(absent
        .tables
        .get("findings")
        .is_none_or(|rows| rows.iter().all(|batch| batch.num_rows() == 0)));
    assert_eq!(
        store
            .managed_resume([1; 16], &instance.spec.id, &control)?
            .instance
            .progress,
        latest
            .extraction
            .references
            .iter()
            .filter_map(|entry| entry.result())
            .map(|reference| reference.commit_revision)
            .max()
            .ok_or("result reference")?
    );
    Ok(())
}
