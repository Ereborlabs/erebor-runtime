use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisReadControl, ManagedAttempt, ManagedCommit, ManagedReceipt, ManagedReturn,
    PackageErrorCodeV1 as Code,
};
use araphor_query::definition::{ExecutionReceipt, PackageCall};
use async_trait::async_trait;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{DataFusionError, Result};
use datafusion::datasource::sink::{DataSink, DataSinkExec};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{dml::InsertOp, Expr, TableType};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, SendableRecordBatchStream,
};
use futures_util::TryStreamExt as _;

use super::Instance;

#[derive(Default)]
pub(super) struct Step {
    pub(super) completed: u64,
    pub(super) attempt: Option<Arc<ManagedAttempt>>,
    pub(super) publishing: bool,
    pub(super) receipt: Option<ManagedReceipt>,
}

#[derive(Clone)]
pub(super) struct Publication {
    pub(super) owner: Arc<Instance>,
    pub(super) schema: sdk::arrow_schema::SchemaRef,
    pub(super) state: Arc<Mutex<Step>>,
    pub(super) witness_expiry: u64,
    pub(super) lifecycle: Option<u64>,
}

impl fmt::Debug for Publication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedPublication")
    }
}

impl DisplayAs for Publication {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedPublication")
    }
}

#[async_trait]
impl TableProvider for Publication {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> sdk::arrow_schema::SchemaRef {
        Arc::clone(&self.schema)
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
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Err(DataFusionError::External(Box::new(
            Code::Unsupported.error("managed publication scan"),
        )))
    }

    async fn insert_into(
        &self,
        _: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        operation: InsertOp,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if operation != InsertOp::Append || input.schema() != self.schema {
            return Err(DataFusionError::External(Box::new(
                Code::Invalid.error("managed publication input"),
            )));
        }
        Ok(Arc::new(DataSinkExec::new(
            input,
            Arc::new(self.clone()),
            None,
        )))
    }
}

#[async_trait]
impl DataSink for Publication {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn schema(&self) -> &sdk::arrow_schema::SchemaRef {
        &self.schema
    }

    async fn write_all(
        &self,
        mut data: SendableRecordBatchStream,
        context: &Arc<TaskContext>,
    ) -> Result<u64> {
        let control = context
            .session_config()
            .get_extension::<AnalysisReadControl>()
            .ok_or_else(|| {
                DataFusionError::External(Box::new(
                    Code::Incomplete.error("managed execution control"),
                ))
            })?;
        let limits = self.owner.query.limits();
        let memory = self.owner.query.memory();
        let reservation = memory.reserve_output(0)?;
        let (mut rows, mut bytes) = (0usize, 0usize);
        let mut batches = Vec::new();
        while let Some(batch) = data.try_next().await? {
            control
                .check()
                .map_err(|source| DataFusionError::External(Box::new(source)))?;
            rows = rows.checked_add(batch.num_rows()).ok_or_else(|| {
                DataFusionError::ResourcesExhausted("managed selected rows".into())
            })?;
            bytes = bytes
                .checked_add(batch.get_array_memory_size())
                .ok_or_else(|| {
                    DataFusionError::ResourcesExhausted("managed selected bytes".into())
                })?;
            if rows > limits.output_rows || bytes > limits.output_bytes {
                return Err(DataFusionError::ResourcesExhausted(
                    "managed selected relation exceeds output limits".into(),
                ));
            }
            memory.retain_output(&batch, &reservation)?;
            batches.push(batch);
        }
        if batches.is_empty() {
            batches.push(sdk::RecordBatch::new_empty(Arc::clone(&self.schema)));
        }
        let receipt = ExecutionReceipt::from_context(context)?;
        for (id, returned) in receipt.calls() {
            if self
                .owner
                .calls
                .get(id)
                .and_then(|plan| match plan {
                    datafusion::logical_expr::LogicalPlan::Extension(extension) => {
                        extension.node.as_any().downcast_ref::<PackageCall>()
                    }
                    _ => None,
                })
                .is_none_or(|call| !returned.belongs_to(call))
            {
                return Err(DataFusionError::External(Box::new(
                    Code::Denied.error("managed returned call identity"),
                )));
            }
        }
        let attempt = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .attempt
            .clone()
            .ok_or_else(|| {
                DataFusionError::External(Box::new(
                    Code::Incomplete.error("managed execution attempt"),
                ))
            })?;
        let calls = receipt.calls().clone();
        let owner = Arc::clone(&self.owner);
        let state = Arc::clone(&self.state);
        let schema = Arc::clone(&self.schema);
        let selected = sdk::Dataset {
            name: "selected".into(),
            batches,
        };
        let selected_limits = sdk::Limits {
            max_rows: limits.output_rows as u64,
            max_bytes: limits.output_bytes as u64,
            max_batches: u32::MAX,
            max_checkpoint_bytes: u64::MAX,
        };
        receipt
            .blocking(context, reservation, move |control| {
                let returns = calls
                    .iter()
                    .map(|(call, returned)| ManagedReturn {
                        call: *call,
                        evaluation: returned.evaluation(),
                        output: returned.output(),
                    })
                    .collect::<Vec<_>>();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|time| u64::try_from(time.as_nanos()).ok())
                    .ok_or_else(|| Code::Incomplete.error("managed publication time"))?;
                state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .publishing = true;
                Instance::authorize(
                    owner.authority.as_ref(),
                    &owner.admitted.grant,
                    &owner.prepared,
                    || {
                        control.check()?;
                        let receipt = owner.query.store().commit_managed(
                            &ManagedCommit {
                                attempt: &attempt,
                                now_utc_ns: now,
                                returns: &returns,
                                selected: &selected,
                                selected_schema: schema.as_ref(),
                                selected_limits,
                            },
                            || control.check(),
                        )?;
                        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                        state.attempt = None;
                        state.completed = receipt.commit_revision;
                        state.receipt = Some(receipt);
                        Ok(())
                    },
                )
                .map_err(araphor_query::Error::from)
            })
            .await?;
        Ok(rows as u64)
    }
}
