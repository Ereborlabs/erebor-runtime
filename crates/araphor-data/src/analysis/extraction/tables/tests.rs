use std::time::Duration;

use sdk::arrow_array::{BinaryArray, UInt64Array};
use serde::{Serialize, Serializer};

use super::*;
use crate::{AnalysisExtractLimits, AnalysisReadModeV1};

mod native;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn schema_contract() -> TestResult {
    use sha2::{Digest, Sha256};

    let mut hashes = BTreeMap::new();
    for (name, schema) in AnalysisStore::table_schemas() {
        let mut value = serde_json::to_value(schema.as_ref())?;
        value.sort_all_objects();
        let bytes = serde_json::to_vec(&value)?;
        hashes.insert(name.clone(), format!("{:x}", Sha256::digest(bytes)));
    }
    let expected = [
        (
            "behaviors",
            "951aa953789bcc90117265499c8e10ed917646007d38d0a6ecfb8ce379dc17c9",
        ),
        (
            "catalog",
            "c0327a34b237d15874de33e8b47518cd2b6981e1717d4757ee3bb68ad70cfe0a",
        ),
        (
            "context",
            "9bedf8f1dbd69eecff2bf1d24b6b19889f10683d763ac8ff40ea34f916367e2d",
        ),
        (
            "context_versions",
            "f8bd877560d97083e6a1b5684ef8014a9c494f2fcb6842ae36a464a7e45ab2dd",
        ),
        (
            "correlation_packages",
            "b6244d9d0f578e2b413dca4e790c192d27b212ae930206f89eef30597167e344",
        ),
        (
            "coverage",
            "3a9401f56d9fb017ad8b7344dc5affacaee3cebdd9fa8016ea05870cb0c1a879",
        ),
        (
            "events",
            "0a18c5edf190bfb425009eebb679e4c672eb070308781f1285de9634f502ab39",
        ),
        (
            "findings",
            "f6ee0fe520df06f0eaf4afc4bbc4decf3f129ee9398a3f3dafc45806379b7a59",
        ),
        (
            "graph_branches",
            "a38f863f769c36713df2596d5a31cae38cb66341aa743a222a0a3dceae049811",
        ),
        (
            "graph_manifest",
            "0cbea412d4f3ed7b138fda4c1543a4548f0be7a4d168f85b447446f84da20c89",
        ),
        (
            "graph_subjects",
            "334ed1146be637e6cc919e3c11949c359099cfb4a1b1ca4b584ea0a1c199d463",
        ),
        (
            "notifications",
            "06eb20a7b37e359810924a690d60fa19299f611796703fa39aa1483184b6932d",
        ),
        (
            "policy_observations",
            "9a62677cf9dd189693ae9585476b0de6cab5522e9f51a0496f8663803c53bd41",
        ),
        (
            "relationships",
            "edac9469333632cafc96d2e7889873bade30ee1650fec92549f6b51243aeaf19",
        ),
        (
            "targets",
            "da55132a187680344db38a1760db3e1473cf0fa09970ec4ff813d8913e054224",
        ),
        (
            "trace_measurements",
            "715f549324319e2276d24865d8814b4016aff668bb669b68d19044f0511ce7f7",
        ),
        (
            "trace_output",
            "807c46e42c7afcabc7304f932e680c1ed01f3523f0cd434471e5b66d3d39b1fe",
        ),
        (
            "trace_recipes",
            "f06ce8f5f3397cc8a025d9dccdab07c91e23b1b6dd31a143e3bb1bc737fe32b3",
        ),
        (
            "traces",
            "0b992ee04842a6da96ceff1793fc078ee7aa0db7335e38a27a41c1ecacd73061",
        ),
    ];
    assert_eq!(
        hashes,
        expected
            .into_iter()
            .map(|(name, hash)| (name.to_owned(), hash.to_owned()))
            .collect()
    );
    Ok(())
}

fn extraction() -> TestResult<(AnalysisExtractionV1, AnalysisReadControl)> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("data"))?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    let columns = BTreeMap::new();
    let page = store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &columns,
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

fn columns(relation: &str, names: &[&str]) -> TestResult<crate::AnalysisTableRequests> {
    let schema = AnalysisStore::table_schemas()
        .get(relation)
        .ok_or("the native source schema is missing")?;
    Ok(BTreeMap::from([(
        relation.into(),
        Some(
            names
                .iter()
                .map(|name| schema.index_of(name))
                .collect::<std::result::Result<_, _>>()?,
        ),
    )]))
}

#[test]
fn row_preflight_keeps_existing_native_builders() -> TestResult {
    let (mut output, control) = extraction()?;
    let columns = columns("events", &["tenant_id", "source_cursor"])?;
    let read = AnalysisTableRead {
        requests: &columns,
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
    let columns = columns("events", &[])?;
    let read = AnalysisTableRead {
        requests: &columns,
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
        let columns = columns("events", &["source_cursor"])?;
        let read = AnalysisTableRead {
            requests: &columns,
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

impl Capture<'_> {
    table_row! {
        fn declared_row(
            &mut self,
            cursor: u64,
            accepted: &mut bool,
            budget: &mut ReadBudget<'_>,
        );
        schema declared_fields;
        row(self, "events", budget);
        setup {}
        fields {
            source_cursor => UInt64(false): Some(cursor),
            catalog_json => Json(true): Some(&RefuseSerialization),
        }
        then {
            *accepted = true;
            Ok(true)
        }
    }
}

#[test]
fn declared_row_admission() -> TestResult {
    assert_eq!(
        Capture::declared_fields(),
        vec![
            sdk::Field::new("source_cursor", sdk::DataType::UInt64, false),
            sdk::Field::new("catalog_json", sdk::DataType::Binary, true),
        ]
    );
    let (mut output, control) = extraction()?;
    output.limits.page_bytes = 17;
    let columns = columns("events", &["source_cursor"])?;
    let read = AnalysisTableRead {
        requests: &columns,
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
    let mut accepted = false;
    assert!(capture.declared_row(1, &mut accepted, &mut budget)?);
    assert!(accepted);
    accepted = false;
    budget.emitted = 0;
    assert!(!capture.declared_row(2, &mut accepted, &mut budget)?);
    assert!(!accepted);
    let table = capture.tables.get_mut("events").ok_or("events missing")?;
    assert_eq!(table.total_rows, 1);
    table.finish(&mut budget)?;
    assert_eq!(table.batches[0].num_rows(), 1);
    assert_eq!(budget.output.projected_bytes, 9);
    Ok(())
}

#[test]
fn unrequested_json_is_not_serialized() -> TestResult {
    let (mut output, control) = extraction()?;
    let columns = columns("context_versions", &["owner_revision"])?;
    let read = AnalysisTableRead {
        requests: &columns,
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
    let columns = columns("events", &["source_cursor"])?;
    let read = AnalysisTableRead {
        requests: &columns,
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
    let columns = columns("events", &["source_cursor", "tenant_id"])?;
    let read = AnalysisTableRead {
        requests: &columns,
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

#[test]
fn catalog_preflight_is_atomic() -> TestResult {
    let (mut output, control) = extraction()?;
    let columns = columns("catalog", &["relation", "ordinal", "data_type", "nullable"])?;
    let read = AnalysisTableRead {
        requests: &columns,
        event_ranges: None,
        inputs: None,
        mode: AnalysisReadModeV1::Metadata,
        now: 1,
    };
    let scope = AnalysisSelectionV1::tenant([1; 16]);
    let mut capture = Capture::new(&read, &scope);
    for (relation, schema) in Capture::schemas() {
        for (ordinal, field) in schema.fields().iter().enumerate() {
            capture.catalog_size(
                relation,
                ordinal,
                field,
                (false, false, false),
                &mut output.sink(&control),
            )?;
        }
    }
    let original_limit = output.limits.input_bytes;
    output.limits.input_bytes = output.input_bytes;
    let table = capture.tables.get_mut("catalog").ok_or("catalog table")?;
    assert!(matches!(
        table.reserve(&mut output.sink(&control)),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input bytes",
            ..
        })
    ));
    assert_eq!(table.total_rows, 0);
    assert!(table.batches.is_empty());
    assert_eq!(output.projected_bytes, 0);
    output.limits.input_bytes = original_limit;
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        table.reserve(&mut output.sink(&cancelled)),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(table.total_rows, 0);
    assert!(table.batches.is_empty());
    table.reserve(&mut output.sink(&control))?;
    let mut expected = 0;
    for (relation, schema) in Capture::schemas() {
        for (ordinal, field) in schema.fields().iter().enumerate() {
            capture.catalog_row(
                relation,
                ordinal,
                field,
                (false, false, false),
                &mut output.sink(&control),
            )?;
            expected += 1;
        }
    }
    let table = capture.tables.get_mut("catalog").ok_or("catalog table")?;
    table.finish(&mut output.sink(&control))?;
    assert_eq!(table.batches.len(), 1);
    assert_eq!(table.batches[0].num_rows(), expected);
    Ok(())
}

#[test]
fn omitted_display_is_unevaluated() -> TestResult {
    struct RefuseDisplay(std::cell::Cell<bool>);
    impl std::fmt::Display for RefuseDisplay {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.set(true);
            Err(std::fmt::Error)
        }
    }
    let (mut output, control) = extraction()?;
    let columns = columns("catalog", &["ordinal"])?;
    let read = AnalysisTableRead {
        requests: &columns,
        event_ranges: None,
        inputs: None,
        mode: AnalysisReadModeV1::Metadata,
        now: 1,
    };
    let scope = AnalysisSelectionV1::tenant([1; 16]);
    let mut capture = Capture::new(&read, &scope);
    let mut budget = output.sink(&control);
    let display = RefuseDisplay(std::cell::Cell::new(false));
    assert!(table_row!(&mut capture, "catalog", &mut budget;
        ordinal=>UInt32:Some(0), data_type=>Display:Some(&display)
    )?);
    assert!(!display.0.get());
    Ok(())
}

#[test]
fn bulk_boolean_reservation() -> TestResult {
    use std::mem::size_of;

    use sdk::arrow_array::{builder::BooleanBuilder, Array, ArrayRef, BooleanArray, RecordBatch};

    let (mut output, control) = extraction()?;
    let schema = Arc::new(sdk::Schema::new(vec![
        sdk::Field::new("value", sdk::DataType::Boolean, false),
        sdk::Field::new("optional", sdk::DataType::Boolean, true),
    ]));
    let mut table = Table::new(
        Arc::clone(&schema),
        &["value", "optional"],
        &mut output.sink(&control),
    )?;
    for row in 0..600usize {
        table.cell(0, &sdk::DataType::Boolean, false, 0)?;
        table.cell(1, &sdk::DataType::Boolean, row.is_multiple_of(3), 0)?;
        table.measure()?;
    }
    let bitmap = BooleanBuilder::with_capacity(600).capacity() / 8;
    assert_eq!(bitmap, 128);
    let charge = size_of::<RecordBatch>() + 2 * (size_of::<ArrayRef>() + 512) + 3 * bitmap;
    let before = output.input_bytes;
    let original_limit = output.limits.input_bytes;
    output.limits.input_bytes = before + charge - 1;
    assert!(matches!(
        table.reserve(&mut output.sink(&control)),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input bytes",
            ..
        })
    ));
    assert_eq!(output.input_bytes, before);
    assert_eq!(table.total_rows, 0);
    assert!(table.batches.is_empty());
    output.limits.input_bytes += 1;
    table.reserve(&mut output.sink(&control))?;
    assert_eq!(output.input_bytes - before, charge);
    output.limits.input_bytes = original_limit;
    let before = output.input_bytes;
    for row in 0..600usize {
        table.cell(0, &sdk::DataType::Boolean, false, 0)?;
        table.cell(1, &sdk::DataType::Boolean, row.is_multiple_of(3), 0)?;
        let mut budget = output.sink(&control);
        assert!(table.admit(&mut budget, 4)?);
        table
            .builder::<BooleanBuilder>(0)?
            .append_value(row.is_multiple_of(2));
        table
            .builder::<BooleanBuilder>(1)?
            .append_option((!row.is_multiple_of(3)).then_some(row.is_multiple_of(5)));
        table.appended(&mut budget, 4);
    }
    assert_eq!(output.input_bytes, before);
    assert_eq!(output.projected_bytes, 2400);
    table.finish(&mut output.sink(&control))?;
    assert_eq!(table.total_rows, 600);
    assert_eq!(table.batches.len(), 1);
    let batch = &table.batches[0];
    assert_eq!(batch.num_rows(), 600);
    assert_eq!(batch.schema(), schema);
    let values = batch
        .column(0)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or("Boolean values")?;
    let optional = batch
        .column(1)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or("nullable Boolean values")?;
    assert_eq!(values.null_count(), 0);
    assert_eq!(optional.null_count(), 200);
    assert_eq!(values.get_buffer_memory_size(), bitmap);
    assert_eq!(optional.get_buffer_memory_size(), 2 * bitmap);
    for row in 0..600usize {
        assert_eq!(values.value(row), row.is_multiple_of(2));
        assert_eq!(optional.is_null(row), row.is_multiple_of(3));
        if !row.is_multiple_of(3) {
            assert_eq!(optional.value(row), row.is_multiple_of(5));
        }
    }
    Ok(())
}
