#![cfg(test)]

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
use datafusion::arrow::array::Int64Array;

use super::*;
use crate::execution::{Engine, Limits};
use crate::parser::Parser;
use crate::sources::SourceSnapshot;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    engine: Arc<Engine>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let engine = Engine::new(
            store,
            Limits {
                input_bytes: 4096,
                input_capacity: Some(4096),
                ..Default::default()
            },
        )?;
        Ok(Self {
            engine,
            _directory: directory,
        })
    }

    fn session(&self) -> TestResult<Session> {
        Ok(self.engine.session(
            AnalysisSelectionV1::tenant([1; 16]),
            &AnalysisReadControl::with_timeout(Duration::from_secs(10))?,
            1,
        )?)
    }
}

#[test]
fn indexed_schema_keeps_metadata() -> TestResult {
    let field = Field::new(
        "ReceivedAt",
        DataType::Timestamp(
            datafusion::arrow::datatypes::TimeUnit::Nanosecond,
            Some("UTC".into()),
        ),
        false,
    )
    .with_metadata(HashMap::from([("source".into(), "events".into())]));
    let schema = Schema::new_with_metadata(
        vec![field],
        HashMap::from([("owner".into(), "model".into())]),
    );
    let actual = Session::indexed_schema(&schema)?;
    assert_eq!(actual.metadata(), schema.metadata());
    assert!(Arc::ptr_eq(&actual.fields()[0], &schema.fields()[0]));
    assert_eq!(actual.fields().len(), 2);
    assert_eq!(
        actual.field(1),
        &Field::new("__row_index", DataType::UInt64, false)
    );
    let empty = Schema::new_with_metadata(Vec::<Field>::new(), schema.metadata().clone());
    let actual = Session::indexed_schema(&empty)?;
    assert_eq!(actual.metadata(), empty.metadata());
    assert_eq!(actual.fields().len(), 1);
    assert_eq!(
        actual.field(0),
        &Field::new("__row_index", DataType::UInt64, false)
    );
    for names in [vec!["value", "value"], vec!["__row_index"]] {
        let schema = Schema::new(
            names
                .into_iter()
                .map(|name| Field::new(name, DataType::Int64, true))
                .collect::<Vec<_>>(),
        );
        assert!(Session::indexed_schema(&schema).is_err());
    }
    Ok(())
}

#[test]
fn builtin_has_no_index() -> TestResult {
    let fixture = Fixture::new()?;
    let native = fixture.engine.catalog(SourceSnapshot::providers())?;
    assert!(fixture
        .engine
        .plan(
            &native,
            Parser::default().parse("SELECT events.__row_index FROM events")?,
            Vec::new()
        )
        .is_err());
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let table = crate::sources::SourceProvider::local("events", Session::indexed_schema(&schema)?);
    let native = fixture
        .engine
        .catalog(BTreeMap::from([("events".into(), table)]))?;
    let plan = fixture.engine.plan(
        &native,
        Parser::default().parse("SELECT * FROM events")?,
        Vec::new(),
    )?;
    assert_eq!(plan.schema().as_arrow().field(1).name(), "__row_index");
    Ok(())
}

#[test]
fn prepaid_indices_keep_aliases() -> TestResult {
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    let batches = [vec![10, 20], vec![], vec![30]]
        .into_iter()
        .map(|values| {
            RecordBatch::try_new(
                Arc::clone(&schema),
                vec![Arc::new(Int64Array::from(values))],
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let memory = fixture.engine.memory().reserve_input(
        fixture
            .engine
            .limits()
            .input_capacity
            .expect("configured input capacity"),
    )?;
    let schema = Session::indexed_schema(&schema)?;
    let indexed = session.index_batches(Arc::clone(&schema), &batches, &memory, 128)?;
    assert!(memory.size() >= 128);
    for (batch, expected) in indexed.iter().zip([vec![0, 1], vec![], vec![2]]) {
        let indices = batch
            .column(1)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("row indices")?;
        assert_eq!(indices.values().as_ref(), expected);
    }
    for (original, indexed) in batches.iter().zip(&indexed) {
        assert!(Arc::ptr_eq(original.column(0), indexed.column(0)));
        assert_eq!(indexed.schema(), schema);
    }
    session.register("events", Arc::clone(&schema), &indexed)?;
    let alias = indexed[2].column(1).slice(0, 1);
    drop(indexed);
    drop(batches);
    drop(memory);
    drop(session);
    assert!(fixture
        .engine
        .memory()
        .reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity")
        )
        .is_err());
    assert_eq!(
        alias
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("index alias")?
            .value(0),
        2
    );
    drop(alias);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity"),
        )?,
    );
    Ok(())
}

#[test]
fn claimed_inputs_skip_prepayment() -> TestResult {
    let fixture = Fixture::new()?;
    let session = fixture.session()?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    let batches = vec![RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(Int64Array::from_iter_values(0..200))],
    )?];
    let memory = fixture.engine.memory().reserve_input(0)?;
    fixture.engine.memory().retain_input(&batches[0], &memory)?;
    let bytes = session.check_input(batches.iter())?;
    assert!(fixture.engine.memory().reserve_input(bytes).is_err());
    let indexed = session.index_batches(Session::indexed_schema(&schema)?, &batches, &memory, 0)?;
    assert!(Arc::ptr_eq(batches[0].column(0), indexed[0].column(0)));
    assert_eq!(
        indexed[0]
            .column(1)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("row indices")?
            .value(199),
        199
    );
    drop(indexed);
    drop(batches);
    drop(memory);
    drop(
        fixture.engine.memory().reserve_input(
            fixture
                .engine
                .limits()
                .input_capacity
                .expect("configured input capacity"),
        )?,
    );
    Ok(())
}

#[test]
fn empty_index_keeps_schema() -> TestResult {
    let fixture = Fixture::new()?;
    let mut session = fixture.session()?;
    let schema = Session::indexed_schema(&Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]))?;
    let memory = fixture.engine.memory().reserve_input(128)?;
    let batches = session.index_batches(Arc::clone(&schema), &[], &memory, 128)?;
    assert!(batches.is_empty());
    assert_eq!(memory.size(), 128);
    session.register("empty", Arc::clone(&schema), &batches)?;
    let table = crate::sources::SourceProvider::local("empty", Arc::clone(&schema));
    let native = fixture
        .engine
        .catalog(BTreeMap::from([("empty".into(), table)]))?;
    let plan = fixture.engine.plan(
        &native,
        Parser::default().parse("SELECT * FROM empty")?,
        Vec::new(),
    )?;
    let output = session.collect_local(Arc::new(plan))?;
    assert!(output.iter().all(|batch| batch.num_rows() == 0));
    assert_eq!(schema.fields().len(), 2);
    Ok(())
}

#[test]
fn zero_columns_keep_indices() -> TestResult {
    let fixture = Fixture::new()?;
    let session = fixture.session()?;
    let source = Arc::new(Schema::new_with_metadata(
        Vec::<Field>::new(),
        HashMap::from([("owner".into(), "model".into())]),
    ));
    let schema = Session::indexed_schema(&source)?;
    let batches = [0, 2, 1]
        .into_iter()
        .map(|rows| {
            RecordBatch::try_new_with_options(
                Arc::clone(&source),
                Vec::new(),
                &datafusion::arrow::array::RecordBatchOptions::new().with_row_count(Some(rows)),
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let memory = fixture.engine.memory().reserve_input(128)?;
    let indexed = session.index_batches(Arc::clone(&schema), &batches, &memory, 128)?;
    assert_eq!(indexed.len(), 3);
    let mut offset = 0;
    for (batch, rows) in indexed.iter().zip([0, 2, 1]) {
        assert_eq!(batch.schema(), schema);
        assert_eq!(batch.num_columns(), 1);
        assert_eq!(batch.num_rows(), rows);
        let indices = batch
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("row indices")?;
        for row in 0..rows {
            assert_eq!(indices.value(row), offset);
            offset += 1;
        }
    }
    assert_eq!(offset, 3);
    Ok(())
}
