use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex};

use araphor_analysis_sdk as sdk;
use araphor_data::{AnalysisResultReceiptV1, PackageErrorCodeV1 as Code};
use araphor_query::definition::ExecutionReceipt;
use async_trait::async_trait;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::Result;
use datafusion::datasource::sink::{DataSink, DataSinkExec};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{dml::InsertOp, Expr, TableType};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, SendableRecordBatchStream,
};
use futures_util::TryStreamExt as _;

use super::{GraphPublication, Projection};

pub(super) type Receipt = (String, AnalysisResultReceiptV1);

mod expiry;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Publish(bool),
    Expire,
}

#[derive(Clone)]
pub(super) struct Publication {
    pub(super) owner: Arc<GraphPublication>,
    pub(super) schema: sdk::arrow_schema::SchemaRef,
    pub(super) result_id: Option<String>,
    pub(super) kind: Kind,
    pub(super) receipt: Arc<Mutex<Option<Receipt>>>,
}
impl fmt::Debug for Publication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GraphPublication")
    }
}
impl DisplayAs for Publication {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("GraphPublication")
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
        Err(Projection::invalid("graph publication scan"))
    }
    async fn insert_into(
        &self,
        _: &dyn Session,
        input: Arc<dyn ExecutionPlan>,
        operation: InsertOp,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if operation != InsertOp::Append || input.schema() != self.schema {
            return Err(Projection::invalid("graph publication input"));
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
        if matches!(self.kind, Kind::Expire) {
            return self.expire(data, context).await;
        }
        let mut rows = 0usize;
        let mut bytes = 0usize;
        while let Some(batch) = data.try_next().await? {
            rows = rows
                .checked_add(batch.num_rows())
                .ok_or_else(|| Projection::invalid("graph selected rows overflow"))?;
            bytes = bytes
                .checked_add(batch.get_array_memory_size())
                .ok_or_else(|| Projection::invalid("graph selected bytes overflow"))?;
            if rows > self.owner.session.engine().limits().output_rows
                || bytes > self.owner.session.engine().limits().output_bytes
            {
                return Err(Projection::external(
                    Code::Limit.error("graph selected relation"),
                ));
            }
        }
        let receipt = ExecutionReceipt::from_context(context)?;
        let owner = Arc::clone(&self.owner);
        let result_id = self
            .result_id
            .clone()
            .unwrap_or_else(|| format!("graph:{}", uuid::Uuid::new_v4()));
        let advance = matches!(self.kind, Kind::Publish(true));
        let state = Arc::clone(&self.receipt);
        let captured = receipt.clone();
        let operation = Arc::clone(context);
        let acknowledgement = receipt.clone();
        let acknowledged = receipt
            .blocking(context, (), move |control| {
                let converted = owner.convert_graph(
                    &operation,
                    &captured,
                    result_id.clone(),
                    advance,
                    control,
                )?;
                let completed = converted.completed;
                let deadline = converted.deadline;
                let previous = &converted.previous;
                let packet = converted.packet;
                let mut prepared = Some(packet.graph);
                let mut output = None;
                owner.authorize(control, &mut || {
                    owner.grant.remaining()?;
                    owner.session.control().check()?;
                    control.check()?;
                    Projection::check_deadline(deadline)?;
                    let receipt = owner.session.engine().store().commit_graph_snapshot(
                        packet.request.clone(),
                        prepared
                            .take()
                            .ok_or_else(|| Code::Invalid.error("graph publication callback"))?,
                        &packet.contexts,
                        &packet.proofs,
                        &packet.sources,
                        packet.advance,
                        || {
                            owner.grant.remaining()?;
                            owner.session.control().check()?;
                            control.check()?;
                            Projection::check_deadline(deadline)
                        },
                    )?;
                    let id = previous
                        .as_ref()
                        .filter(|(_, revision)| *revision == receipt.commit_revision)
                        .map_or_else(|| result_id.clone(), |(id, _)| id.clone());
                    output = Some((id, receipt));
                    Ok(())
                })?;
                let output =
                    output.ok_or_else(|| Code::Denied.error("graph publication authority"))?;
                let revision = output.1.commit_revision;
                *state.lock().unwrap_or_else(|error| error.into_inner()) = Some(output);
                Ok(completed.then_some(revision))
            })
            .await?;
        if let Some(revision) = acknowledged {
            acknowledgement.acknowledge(context, revision)?;
        }
        Ok(rows as u64)
    }
}
