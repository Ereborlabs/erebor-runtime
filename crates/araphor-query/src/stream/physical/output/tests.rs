use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, StorePositionV1};
use datafusion::arrow::array::{
    builder::{Int64Builder, ListViewBuilder},
    Int64Array, RecordBatchOptions,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::physical_plan::memory::MemoryStream;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use futures_util::{stream, StreamExt as _};

use super::*;
use crate::execution::{Engine, Limits};
use crate::sources::ArrowSnapshot;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn owner() -> TestResult<(tempfile::TempDir, Session, Arc<ArrowSnapshot>)> {
    let directory = tempfile::tempdir()?;
    let engine = Engine::new(
        Arc::new(AnalysisStore::open(directory.path().join("data"))?),
        Limits {
            extract_timeout: Duration::from_secs(30),
            evaluate_timeout: Duration::from_secs(30),
            ..Limits::default()
        },
    )?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let snapshot = engine
        .session(selection.clone(), &control, 1)?
        .metadata(&BTreeMap::new())
        .await?;
    let session = engine.session(selection, &control, 1)?;
    Ok((directory, session, snapshot))
}

fn output(session: &Session, snapshot: Arc<ArrowSnapshot>) -> Result<Output> {
    let engine = session.engine();
    Ok(Output {
        snapshot,
        batches: None,
        positions: Vec::new(),
        position: StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        limited: false,
        _memory: engine
            .memory()
            .prepare_output(engine.limits().output_bytes)
            .context(SqlSnafu)?,
        _permit: Some(Arc::new(engine.reserve_evaluation([1; 16])?)),
        _control: Arc::clone(session.control()),
    })
}

#[tokio::test]
async fn logical_rows_ignore_batches() -> TestResult {
    let (_directory, session, snapshot) = owner().await?;
    let schema = Arc::new(Schema::new_with_metadata(
        vec![Field::new("value", DataType::Int64, true)],
        HashMap::from([("contract".into(), "replacement".into())]),
    ));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(Int64Array::from(vec![Some(1), None, Some(3)]))],
    )?;
    let mut previous = None;
    let first = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![batch.clone()],
                Arc::clone(&schema),
                None,
            )?),
            Some(&mut previous),
        )
        .await?;
    assert!(Arc::ptr_eq(&first.snapshot, &snapshot));
    assert_eq!(
        first.batches.as_ref().ok_or("first result")?,
        std::slice::from_ref(&batch)
    );
    drop(first);
    let split = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![
                    RecordBatch::new_empty(Arc::clone(&schema)),
                    batch.slice(0, 1),
                    RecordBatch::new_empty(Arc::clone(&schema)),
                    batch.slice(1, 2),
                ],
                Arc::clone(&schema),
                None,
            )?),
            Some(&mut previous),
        )
        .await?;
    assert!(split.batches.is_none());
    assert_eq!(split._memory.size(), 0);
    assert!(split._permit.is_none());
    drop(split);
    let changed = Arc::new(Schema::new_with_metadata(
        schema.fields().clone(),
        HashMap::from([("contract".into(), "changed".into())]),
    ));
    let empty = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![RecordBatch::new_empty(Arc::clone(&changed)); 1000],
                Arc::clone(&changed),
                None,
            )?),
            Some(&mut previous),
        )
        .await?;
    assert!(empty
        .batches
        .as_ref()
        .ok_or("empty replacement")?
        .is_empty());
    assert_eq!(empty._memory.size(), 0);
    drop(empty);
    let empty = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(Vec::new(), changed, None)?),
            Some(&mut previous),
        )
        .await?;
    assert!(empty.batches.is_none());
    drop(empty);
    let schema_change = output(&session, snapshot)?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(Vec::new(), schema, None)?),
            Some(&mut previous),
        )
        .await?;
    assert!(schema_change
        .batches
        .as_ref()
        .ok_or("schema-only replacement")?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn zero_columns_keep_rows() -> TestResult {
    let (_directory, session, snapshot) = owner().await?;
    let schema = Arc::new(Schema::empty());
    let batch = RecordBatch::try_new_with_options(
        Arc::clone(&schema),
        Vec::new(),
        &RecordBatchOptions::new().with_row_count(Some(3)),
    )?;
    let mut previous = None;
    let first = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![batch.clone()],
                Arc::clone(&schema),
                None,
            )?),
            Some(&mut previous),
        )
        .await?;
    let batches = first.batches.as_ref().ok_or("zero-column result")?;
    assert_eq!(batches[0].num_columns(), 0);
    assert_eq!(batches[0].num_rows(), 3);
    drop(first);
    let same = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![batch.slice(0, 1), batch.slice(1, 2)],
                Arc::clone(&schema),
                None,
            )?),
            Some(&mut previous),
        )
        .await?;
    assert!(same.batches.is_none());
    drop(same);
    let changed = output(&session, snapshot)?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![batch.slice(0, 2)],
                schema,
                None,
            )?),
            Some(&mut previous),
        )
        .await?;
    assert_eq!(
        changed.batches.as_ref().ok_or("changed row count")?[0].num_rows(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn finite_keeps_native_arrays() -> TestResult {
    let (_directory, session, snapshot) = owner().await?;
    let mut builder = ListViewBuilder::new(Int64Builder::new());
    builder.values().append_value(7);
    builder.append(true);
    let array: ArrayRef = Arc::new(builder.finish());
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        array.data_type().clone(),
        false,
    )]));
    let batch = RecordBatch::try_new(Arc::clone(&schema), vec![Arc::clone(&array)])?;
    assert!(ScalarValue::try_from_array(array.as_ref(), 0).is_err());
    let completed = output(&session, snapshot)?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(vec![batch.clone()], schema, None)?),
            None,
        )
        .await?;
    let batches = completed.batches.as_ref().ok_or("finite output absent")?;
    assert_eq!(batches, &[batch]);
    assert!(Arc::ptr_eq(batches[0].column(0), &array));
    Ok(())
}

#[tokio::test]
async fn later_error_releases_output() -> TestResult {
    let (_directory, mut session, snapshot) = owner().await?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    let producer = Arc::new(());
    let active = Arc::clone(&producer);
    let stream = stream::iter(vec![
        Ok(RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(Int64Array::from(vec![1]))],
        )?),
        Err(DataFusionError::Execution("later batch failed".into())),
    ])
    .map(move |batch| {
        let _active = &active;
        batch
    });
    let mut previous = None;
    let error = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(RecordBatchStreamAdapter::new(Arc::clone(&schema), stream)),
            Some(&mut previous),
        )
        .await
        .err()
        .ok_or("later batch must fail")?;
    assert!(matches!(&error, crate::Error::Sql { source }
        if matches!(source.find_root(), DataFusionError::Execution(message)
            if message == "later batch failed")));
    assert_eq!(
        crate::Failure::from(&error),
        crate::Failure::EvaluationFailed
    );
    assert_eq!(previous, None);
    assert_eq!(Arc::strong_count(&producer), 1);
    drop(session.engine().reserve_evaluation([1; 16])?);
    drop(
        session
            .engine()
            .memory()
            .reserve_output(session.engine().limits().output_capacity)?,
    );
    session.set_output(1, session.engine().limits().output_bytes)?;
    let error = output(&session, snapshot)?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![RecordBatch::try_new(
                    Arc::clone(&schema),
                    vec![Arc::new(Int64Array::from(vec![1, 2]))],
                )?],
                schema,
                None,
            )?),
            Some(&mut previous),
        )
        .await
        .err()
        .ok_or("logical row limit must fail")?;
    assert!(matches!(
        error,
        crate::Error::Sql {
            source: DataFusionError::ResourcesExhausted(_)
        }
    ));
    assert_eq!(previous, None);
    drop(session.engine().reserve_evaluation([1; 16])?);
    drop(
        session
            .engine()
            .memory()
            .reserve_output(session.engine().limits().output_capacity)?,
    );
    Ok(())
}

#[tokio::test]
async fn borrowed_output_keeps_charge() -> TestResult {
    let (_directory, session, snapshot) = owner().await?;
    let engine = Arc::clone(session.engine());
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    let completed = output(&session, Arc::clone(&snapshot))?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![RecordBatch::try_new(
                    Arc::clone(&schema),
                    vec![Arc::new(Int64Array::from(vec![7]))],
                )?],
                schema,
                None,
            )?),
            Some(&mut None),
        )
        .await?;
    let array = Arc::clone(
        completed
            .batches
            .as_ref()
            .ok_or("completed batches")?
            .first()
            .ok_or("completed batch")?
            .column(0),
    );
    drop(completed);
    drop(snapshot);
    drop(session);
    drop(engine.reserve_evaluation([1; 16])?);
    drop(
        engine
            .memory()
            .reserve_input(engine.limits().input_capacity)?,
    );
    assert!(engine
        .memory()
        .reserve_output(engine.limits().output_capacity)
        .is_err());
    assert_eq!(
        array
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or("native Int64 array")?
            .value(0),
        7
    );
    drop(array);
    drop(
        engine
            .memory()
            .reserve_output(engine.limits().output_capacity)?,
    );
    Ok(())
}

#[tokio::test]
async fn empty_prefix_yields_cancel() -> TestResult {
    let (_directory, session, snapshot) = owner().await?;
    let engine = Arc::clone(session.engine());
    tokio::spawn(async move {
        let schema = Arc::new(Schema::empty());
        let active = Arc::new(());
        let producer = Arc::clone(&active);
        let empty = RecordBatch::new_empty(Arc::clone(&schema));
        let stream = stream::repeat_with(move || {
            let _producer = &producer;
            Ok::<_, DataFusionError>(empty.clone())
        });
        let stream = Box::pin(RecordBatchStreamAdapter::new(schema, stream));
        let mut previous = None;
        let error = {
            let pending =
                output(&session, snapshot)?.complete(&session, stream, Some(&mut previous));
            tokio::pin!(pending);
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            session.control().cancel()?;
            pending.await.err().ok_or("empty source must cancel")?
        };
        assert_eq!(crate::Failure::from(&error), crate::Failure::Cancelled);
        assert_eq!(previous, None);
        assert_eq!(Arc::strong_count(&active), 1);
        drop(engine.reserve_evaluation([1; 16])?);
        drop(
            engine
                .memory()
                .reserve_output(engine.limits().output_capacity)?,
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn empty_backing_obeys_limit() -> TestResult {
    let (_directory, mut session, snapshot) = owner().await?;
    session.set_output(1, 8)?;
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(Int64Array::from(vec![1; 2048]))],
    )?;
    let mut previous = None;
    let error = output(&session, snapshot)?
        .complete(
            &session,
            Box::pin(MemoryStream::try_new(
                vec![batch.slice(0, 0)],
                schema,
                None,
            )?),
            Some(&mut previous),
        )
        .await
        .err()
        .ok_or("empty native backing must obey output limit")?;
    assert!(matches!(
        error,
        crate::Error::Sql {
            source: DataFusionError::ResourcesExhausted(_)
        }
    ));
    assert_eq!(previous, None);
    drop(session.engine().reserve_evaluation([1; 16])?);
    drop(
        session
            .engine()
            .memory()
            .reserve_output(session.engine().limits().output_capacity)?,
    );
    Ok(())
}
