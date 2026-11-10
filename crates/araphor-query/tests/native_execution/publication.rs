use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};

use super::*;
use araphor_data::{
    analysis::native::{ManagedCommit, ManagedReturn},
    ManagedAttempt, ManagedFrontier, ManagedRead, ManagedRequest, StorePositionV1,
};
use araphor_query::{
    definition::{ExecutionReceipt, Invocation},
    follow::ManagedPublication,
    sources::ArrowSnapshot,
};
use async_trait::async_trait;
use datafusion::{
    catalog::{Session, TableProvider},
    common::{DataFusionError, Result as NativeResult},
    datasource::sink::{DataSink, DataSinkExec},
    execution::TaskContext,
    logical_expr::{dml::InsertOp, Expr, TableType},
    physical_plan::{DisplayAs, DisplayFormatType, ExecutionPlan, SendableRecordBatchStream},
};
use futures_util::TryStreamExt as _;
use serde::Deserialize;

#[derive(Clone)]
pub(super) struct Publication {
    engine: Arc<Engine>,
    schema: sdk::arrow_schema::SchemaRef,
    selected: Arc<Mutex<Vec<sdk::RecordBatch>>>,
    attempt: Arc<Mutex<Option<Arc<ManagedAttempt>>>>,
    receipt: Arc<Mutex<Option<araphor_data::ManagedReceipt>>>,
    pub(super) reject: Arc<AtomicBool>,
    pub(super) later: Arc<AtomicU64>,
}

impl Publication {
    pub(super) fn new(engine: &Arc<Engine>, schema: sdk::arrow_schema::SchemaRef) -> Arc<Self> {
        Arc::new(Self {
            engine: engine.clone(),
            schema,
            selected: Arc::new(Mutex::new(Vec::new())),
            attempt: Arc::new(Mutex::new(None)),
            receipt: Arc::new(Mutex::new(None)),
            reject: Arc::new(AtomicBool::new(false)),
            later: Arc::new(AtomicU64::new(0)),
        })
    }

    pub(super) fn selected(&self) -> Vec<sdk::RecordBatch> {
        self.selected.lock().unwrap().clone()
    }

    pub(super) fn receipt(&self) -> araphor_data::ManagedReceipt {
        self.receipt.lock().unwrap().clone().unwrap()
    }

    pub(super) fn finish_cancelled(&self) -> araphor_data::Result<()> {
        let attempt = self.attempt.lock().unwrap().clone().unwrap();
        self.engine.store().finish_managed(
            &attempt,
            araphor_data::ManagedExit::Cancelled,
            || Ok(()),
        )?;
        Ok(())
    }

    pub(super) fn assert_consumed(&self, position: StorePositionV1) -> TestResult {
        #[derive(Deserialize)]
        struct Consumer {
            completed_through: StorePositionV1,
        }
        let view = self.engine.store().view()?;
        let (_, value) = view
            .snapshot()
            .prefix(b"\0data/input/")
            .next()
            .ok_or("consumer")??;
        let consumer: Consumer = rmp_serde::from_slice(&value[1..])?;
        assert_eq!(consumer.completed_through, position);
        Ok(())
    }
}

impl fmt::Debug for Publication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativePublication")
    }
}

impl DisplayAs for Publication {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativePublication")
    }
}

#[async_trait]
impl TableProvider for Publication {
    fn schema(&self) -> sdk::arrow_schema::SchemaRef {
        self.schema.clone()
    }
    fn table_type(&self) -> TableType {
        TableType::Base
    }
    async fn scan(
        &self,
        _: &dyn Session,
        _: Option<&Vec<usize>>,
        _: &[Expr],
        _: Option<usize>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        Err(DataFusionError::Plan("publication is a sink".into()))
    }
    async fn insert_into(
        &self,
        _: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        operation: InsertOp,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        assert_eq!(operation, InsertOp::Append);
        Ok(Arc::new(DataSinkExec::new(
            input,
            Arc::new(self.clone()),
            None,
        )))
    }
}

impl ManagedPublication for Publication {
    fn begin(
        &self,
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<(Invocation, ManagedRead)> {
        let resume = self
            .engine
            .store()
            .managed_resume(TENANT, "native-query", control)?;
        Ok((
            Invocation {
                id: uuid::Uuid::new_v4().to_string(),
                ..Default::default()
            },
            ManagedRead {
                instance: resume.instance,
                source: None,
                execution: None,
                follow: true,
                expected: None,
                rebuild: false,
                completed: Some(resume.completed),
            },
        ))
    }

    fn admit(
        &self,
        snapshot: &ArrowSnapshot,
        invocation: &Invocation,
        frontier: &ManagedFrontier,
        control: &AnalysisReadControl,
    ) -> araphor_query::Result<Option<Arc<ManagedAttempt>>> {
        let attempt = self.engine.store().register_managed_attempt(
            snapshot
                .managed()
                .ok_or_else(|| Code::Missing.error("managed snapshot"))?,
            &ManagedRequest {
                id: invocation.id.clone(),
                time_utc_ns: snapshot.managed().unwrap().time_utc_ns(),
                seed: invocation.seed,
                rebuild: false,
                witness_expiry: u64::MAX,
                frontier: Some(frontier.clone()),
            },
            || control.check(),
        )?;
        let attempt = Arc::new(attempt);
        let later = self.later.swap(0, Ordering::SeqCst);
        if later != 0 {
            event(self.engine.store(), TENANT, later)?;
        }
        *self.attempt.lock().unwrap() = Some(attempt.clone());
        Ok(Some(attempt))
    }
}

#[async_trait]
impl DataSink for Publication {
    fn schema(&self) -> &sdk::arrow_schema::SchemaRef {
        &self.schema
    }
    async fn write_all(
        &self,
        mut stream: SendableRecordBatchStream,
        context: &Arc<TaskContext>,
    ) -> NativeResult<u64> {
        let mut batches = Vec::new();
        while let Some(batch) = stream.try_next().await? {
            assert_eq!(batch.schema(), self.schema);
            batches.push(batch);
        }
        let rows = batches.iter().map(|batch| batch.num_rows() as u64).sum();
        let receipt = ExecutionReceipt::from_context(context)?;
        receipt.prepare_ack(context)?;
        let engine = self.engine.clone();
        let returned = receipt.clone();
        let selected = batches.clone();
        let schema = self.schema.clone();
        let attempt = self
            .attempt
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| DataFusionError::Internal("managed attempt".into()))?;
        let reject = self.reject.swap(false, Ordering::SeqCst);
        let published = receipt
            .clone()
            .blocking(context, (), move |control| {
                let returns = returned
                    .calls()
                    .iter()
                    .map(|(id, call)| ManagedReturn {
                        call: *id,
                        evaluation: call.evaluation(),
                        output: call.output(),
                        changes: call.changes(),
                        graph: call.graph(),
                        retained: call.retained(),
                    })
                    .collect::<Vec<_>>();
                let budget = engine
                    .memory()
                    .managed_budget(control, engine.limits().input_bytes);
                let selected = sdk::Dataset {
                    name: "selected".into(),
                    batches: selected,
                };
                let input = ManagedCommit {
                    control,
                    budget: budget.as_ref(),
                    attempt: &attempt,
                    completed: true,
                    now_utc_ns: attempt.request().time_utc_ns,
                    returns: &returns,
                    selected: &selected,
                    selected_schema: &schema,
                };
                let prepared = engine.store().prepare_managed(&input)?;
                Ok(engine.store().commit_managed(prepared, || {
                    if reject {
                        Err(Code::Denied.error("test publication guard"))
                    } else {
                        control.check()
                    }
                })?)
            })
            .await?;
        receipt.acknowledge(context, published.commit_revision, true, Some(&published))?;
        *self.receipt.lock().unwrap() = Some(published);
        *self.selected.lock().unwrap() = batches;
        Ok(rows)
    }
}
