use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use araphor_query::datafusion::catalog::streaming::StreamingTable;
use araphor_query::datafusion::common::DataFusionError;
use araphor_query::datafusion::execution::TaskContext;
use araphor_query::datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use araphor_query::datafusion::physical_plan::streaming::PartitionStream;
use araphor_query::datafusion::physical_plan::SendableRecordBatchStream;
use sdk::arrow_array::BinaryArray;
use tokio::sync::Notify;

use super::*;

#[derive(Debug)]
struct ConversionGate {
    schema: Arc<sdk::Schema>,
    first_polls: Arc<AtomicUsize>,
    later_polls: Arc<AtomicUsize>,
    later_entered: Arc<Notify>,
    release_error: Arc<Notify>,
    dropped: Arc<AtomicBool>,
}

struct ProducerGuard(Arc<AtomicBool>);

impl Drop for ProducerGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl PartitionStream for ConversionGate {
    fn schema(&self) -> &Arc<sdk::Schema> {
        &self.schema
    }

    fn execute(&self, context: Arc<TaskContext>) -> SendableRecordBatchStream {
        let rows = context.session_config().batch_size();
        let array = BinaryArray::from_iter_values(std::iter::repeat_n([7u8], rows));
        let first = sdk::RecordBatch::try_new(Arc::clone(&self.schema), vec![Arc::new(array)])
            .map_err(DataFusionError::from);
        let first_polls = Arc::clone(&self.first_polls);
        let later_polls = Arc::clone(&self.later_polls);
        let later_entered = Arc::clone(&self.later_entered);
        let release_error = Arc::clone(&self.release_error);
        let guard = ProducerGuard(Arc::clone(&self.dropped));
        let stream = futures_util::stream::unfold((Some(first), guard), move |(first, guard)| {
            let first_polls = Arc::clone(&first_polls);
            let later_polls = Arc::clone(&later_polls);
            let later_entered = Arc::clone(&later_entered);
            let release_error = Arc::clone(&release_error);
            async move {
                let batch = match first {
                    Some(batch) => {
                        first_polls.fetch_add(1, Ordering::SeqCst);
                        batch
                    }
                    None => {
                        later_polls.fetch_add(1, Ordering::SeqCst);
                        later_entered.notify_one();
                        release_error.notified().await;
                        Err(DataFusionError::Execution("later native failure".into()))
                    }
                };
                Some((batch, (None, guard)))
            }
        });
        Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        ))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn conversion_stops_native_polling() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(Limits {
        global_evaluations: 1,
        tenant_evaluations: 1,
        evaluate_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    })?;
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Binary, false)]);
    let input = sdk::Port::new("input", schema.clone());
    let model = sdk::Model::new(
        "evaluate",
        vec![input.clone()],
        vec![sdk::Port::new(
            "rows",
            sdk::Schema::new(vec![sdk::Field::new(
                "value",
                sdk::DataType::FixedSizeBinary(2),
                false,
            )]),
        )],
    );
    let package = sdk::Package::new("stream-conversion", "1", vec![model.clone()]);
    let program = SqlModelV1 {
        outputs: BTreeMap::from([("rows".into(), "SELECT value FROM input".into())]),
        ..Default::default()
    };
    let mut admitted = AdmittedExport::admit(&owner, &model, Some(&program))?;
    let gate = Arc::new(ConversionGate {
        schema: Arc::new(schema.clone()),
        first_polls: Arc::new(AtomicUsize::new(0)),
        later_polls: Arc::new(AtomicUsize::new(0)),
        later_entered: Arc::new(Notify::new()),
        release_error: Arc::new(Notify::new()),
        dropped: Arc::new(AtomicBool::new(false)),
    });
    let partition = Arc::clone(&gate);
    let provider: Arc<dyn TableProvider> = Arc::new(StreamingTable::try_new(
        Arc::clone(&gate.schema),
        vec![partition],
    )?);
    let state = owner.catalog(BTreeMap::from([("gate".into(), provider)]))?;
    admitted.model.as_mut().ok_or("admitted model")?.outputs[0] =
        AdmittedModel::plan(&owner, &state, "SELECT value FROM gate")?;
    let evaluation = sdk::Evaluation {
        export: model.name.clone(),
        inputs: vec![sdk::Input {
            data: sdk::Dataset {
                name: input.name,
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(schema),
                    vec![Arc::new(BinaryArray::from_iter_values([[0u8, 1]]))],
                )?],
            },
            revision: sdk::Revision {
                owner: "fixture".into(),
                id: "1".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        }],
        parameters: None,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: "stream-conversion".into(),
            time_utc_ns: 1_000,
            seed: None,
            limits: model.limits,
        },
    };
    let admitted = Arc::new(admitted);
    let engine = Arc::clone(&owner);
    let control = control()?;
    let mut worker = tokio::task::spawn_blocking(move || {
        evaluate(
            &engine,
            [1; 16],
            &control,
            &package,
            &admitted,
            &evaluation,
            None,
        )
    });
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut worker => result,
            _ = gate.later_entered.notified() => {
                gate.release_error.notify_one();
                (&mut worker).await
            }
        }
    })
    .await??;
    let error = result
        .err()
        .ok_or("invalid fixed-width output was accepted")?;
    assert!(matches!(
        error,
        crate::Error::AnalysisContract {
            source: sdk::Error::Batch { .. },
            ..
        }
    ));
    assert_eq!(gate.first_polls.load(Ordering::SeqCst), 1);
    assert_eq!(gate.later_polls.load(Ordering::SeqCst), 0);
    assert!(gate.dropped.load(Ordering::SeqCst));
    drop(owner.reserve_evaluation([1; 16])?);
    drop(
        owner.memory().reserve_input(
            owner
                .limits()
                .input_capacity
                .ok_or("configured input capacity")?,
        )?,
    );
    drop(
        owner.memory().reserve_output(
            owner
                .limits()
                .output_capacity
                .ok_or("configured output capacity")?,
        )?,
    );
    Ok(())
}
