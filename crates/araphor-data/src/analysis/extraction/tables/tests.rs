use std::collections::BTreeSet;
use std::time::Duration;

use sdk::arrow_array::{BinaryArray, UInt64Array};
use serde::{Serialize, Serializer};

use super::*;
use crate::{AnalysisExtractLimits, AnalysisReadModeV1};

mod native;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn extraction() -> TestResult<(AnalysisExtractionV1, AnalysisReadControl)> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("data"))?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    let relations = BTreeSet::new();
    let columns = BTreeMap::new();
    let page = store.read_tables(
        &selection,
        AnalysisTableRead {
            relations: &relations,
            columns: &columns,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Metadata,
            now: 1,
        },
        AnalysisExtractLimits::default(),
        &control,
    )?;
    Ok((page.extraction, control))
}

fn columns(relation: &str, names: &[&str]) -> TestResult<BTreeMap<String, BTreeSet<usize>>> {
    let schema = AnalysisStore::table_schemas()
        .get(relation)
        .ok_or("the native source schema is missing")?;
    Ok(BTreeMap::from([(
        relation.into(),
        names
            .iter()
            .map(|name| schema.index_of(name))
            .collect::<std::result::Result<_, _>>()?,
    )]))
}

#[test]
fn row_preflight_keeps_existing_native_builders() -> TestResult {
    let (mut output, control) = extraction()?;
    let relations = BTreeSet::from(["events".into()]);
    let columns = columns("events", &["tenant_id", "source_cursor"])?;
    let read = AnalysisTableRead {
        relations: &relations,
        columns: &columns,
        event_ranges: None,
        inputs: None,
        mode: AnalysisReadModeV1::Complete,
        now: 1,
    };
    let scope = AnalysisSelectionV1::new([1; 16], Vec::new());
    let mut capture = Capture::new(&read, &scope);
    let mut budget = output.sink(&control);
    assert!(table_row!(&mut capture,"events",&mut budget;
        tenant_id=>Binary:Some([1u8;16].as_slice()),source_cursor=>UInt64:Some(1u64)
    )?);
    assert!(matches!(
        table_row!(&mut capture,"events",&mut budget;
            tenant_id=>Binary:Some([2u8;16].as_slice()),source_cursor=>UInt64:None::<u64>
        ),
        Err(crate::Error::AnalysisState { .. })
    ));
    let table = capture
        .tables
        .get_mut("events")
        .ok_or("the events table is missing")?;
    assert_eq!(table.total_rows, 1);
    table.finish(&mut budget)?;
    assert_eq!(table.batches[0].num_rows(), 1);
    let tenants = table.batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("the tenant column is not Binary")?;
    let cursors = table.batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("the cursor column is not UInt64")?;
    assert_eq!(tenants.value(0), [1u8; 16]);
    assert_eq!(cursors.value(0), 1);
    Ok(())
}

#[test]
fn empty_projection_retains_native_row_count() -> TestResult {
    let (mut output, control) = extraction()?;
    let relations = BTreeSet::from(["events".into()]);
    let columns = columns("events", &[])?;
    let read = AnalysisTableRead {
        relations: &relations,
        columns: &columns,
        event_ranges: None,
        inputs: None,
        mode: AnalysisReadModeV1::Complete,
        now: 1,
    };
    let scope = AnalysisSelectionV1::new([1; 16], Vec::new());
    let mut capture = Capture::new(&read, &scope);
    let mut budget = output.sink(&control);
    for cursor in 1..=3u64 {
        assert!(table_row!(&mut capture,"events",&mut budget;
            source_cursor=>UInt64:Some(cursor)
        )?);
    }
    let table = capture
        .tables
        .get_mut("events")
        .ok_or("the events table is missing")?;
    table.finish(&mut budget)?;
    assert_eq!(table.batches.len(), 1);
    assert_eq!(table.batches[0].num_columns(), 0);
    assert_eq!(table.batches[0].num_rows(), 3);
    Ok(())
}

#[test]
fn page_prefix_and_fanout_do_not_append_denied_rows() -> TestResult {
    for fanout in [false, true] {
        let (mut output, control) = extraction()?;
        output.limits.page_bytes = 17;
        let relations = BTreeSet::from(["events".into()]);
        let columns = columns("events", &["source_cursor"])?;
        let read = AnalysisTableRead {
            relations: &relations,
            columns: &columns,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Page(None),
            now: 1,
        };
        let scope = AnalysisSelectionV1::new([1; 16], Vec::new());
        let mut capture = Capture::new(&read, &scope);
        let mut used = 0;
        let mut budget = ReadBudget {
            output: &mut output,
            control: &control,
            row_bytes: Some(&mut used),
            emitted: 0,
        };
        assert!(table_row!(&mut capture,"events",&mut budget;source_cursor=>UInt64:Some(1u64))?);
        if !fanout {
            budget.emitted = 0;
        }
        let next = table_row!(&mut capture,"events",&mut budget;source_cursor=>UInt64:Some(2u64));
        if fanout {
            assert!(matches!(
                next,
                Err(crate::Error::AnalysisInputTooLarge {
                    resource: "projected row bytes",
                    ..
                })
            ));
        } else {
            assert!(!next?);
        }
        let table = capture
            .tables
            .get_mut("events")
            .ok_or("the events table is missing")?;
        assert_eq!(table.total_rows, 1);
        table.finish(&mut budget)?;
        assert_eq!(table.batches[0].num_rows(), 1);
        assert_eq!(budget.output.projected_bytes, 9);
    }
    Ok(())
}

struct RefuseSerialization;
impl Serialize for RefuseSerialization {
    fn serialize<S: Serializer>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "the unrequested JSON field was evaluated",
        ))
    }
}

#[test]
fn unrequested_json_is_not_serialized() -> TestResult {
    let (mut output, control) = extraction()?;
    let relations = BTreeSet::from(["context_versions".into()]);
    let columns = columns("context_versions", &["owner_revision"])?;
    let read = AnalysisTableRead {
        relations: &relations,
        columns: &columns,
        event_ranges: None,
        inputs: None,
        mode: AnalysisReadModeV1::Complete,
        now: 1,
    };
    let scope = AnalysisSelectionV1::new([1; 16], Vec::new());
    let mut capture = Capture::new(&read, &scope);
    let mut budget = output.sink(&control);
    assert!(table_row!(&mut capture,"context_versions",&mut budget;
        owner_revision=>UInt64:Some(1u64),body=>Json:Some(&RefuseSerialization)
    )?);
    assert_eq!(capture.tables["context_versions"].total_rows, 1);
    Ok(())
}

#[test]
fn capacity_is_admitted_before_native_buffer_mutation() -> TestResult {
    let (mut output, control) = extraction()?;
    let relations = BTreeSet::from(["events".into()]);
    let columns = columns("events", &["source_cursor"])?;
    let read = AnalysisTableRead {
        relations: &relations,
        columns: &columns,
        event_ranges: None,
        inputs: None,
        mode: AnalysisReadModeV1::Complete,
        now: 1,
    };
    let scope = AnalysisSelectionV1::new([1; 16], Vec::new());
    let mut capture = Capture::new(&read, &scope);
    let mut budget = output.sink(&control);
    capture.table("events", &["source_cursor"], &mut budget)?;
    budget.output.limits.input_bytes = budget.output.input_bytes;
    assert!(matches!(
        table_row!(&mut capture,"events",&mut budget;source_cursor=>UInt64:Some(1u64)),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    let table = &capture.tables["events"];
    assert_eq!(table.total_rows, 0);
    assert!(table.batches.is_empty());
    assert_eq!(budget.output.projected_bytes, 0);
    Ok(())
}

#[test]
fn mapping_keeps_native_projection_order() -> TestResult {
    let (mut output, control) = extraction()?;
    let relations = BTreeSet::from(["events".into()]);
    let columns = columns("events", &["source_cursor", "tenant_id"])?;
    let read = AnalysisTableRead {
        relations: &relations,
        columns: &columns,
        event_ranges: None,
        inputs: None,
        mode: AnalysisReadModeV1::Complete,
        now: 1,
    };
    let scope = AnalysisSelectionV1::new([1; 16], Vec::new());
    let mut capture = Capture::new(&read, &scope);
    let mut budget = output.sink(&control);
    for cursor in 1..=2u64 {
        assert!(table_row!(&mut capture, "events", &mut budget;
            source_cursor => UInt64: Some(cursor),
            tenant_id => Binary: Some([7u8; 16].as_slice()),
        )?);
    }
    let table = capture
        .tables
        .get_mut("events")
        .ok_or("the events table is missing")?;
    assert_eq!(table.mapping, vec![Some(1), Some(0)]);
    table.finish(&mut budget)?;
    let batch = &table.batches[0];
    assert_eq!(batch.schema().field(0).name(), "tenant_id");
    assert_eq!(batch.schema().field(1).name(), "source_cursor");
    let tenants = batch
        .column(0)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("the tenant column is not Binary")?;
    let cursors = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("the cursor column is not UInt64")?;
    assert_eq!(tenants.value(0), [7u8; 16]);
    assert_eq!(tenants.value(1), [7u8; 16]);
    assert_eq!(cursors.values().as_ref(), &[1, 2]);
    Ok(())
}
