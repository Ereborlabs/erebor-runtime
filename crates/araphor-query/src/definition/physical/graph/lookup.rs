use std::fmt;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use async_trait::async_trait;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{tree_node::TreeNodeRecursion, Result};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{Expr, TableType};
use datafusion::physical_expr::{EquivalenceProperties, PhysicalExpr};
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures_util::{stream, TryStreamExt};

use super::super::{external, internal, CallContext};
use crate::sources::{SourceOrigin, SourceProvider, SourceSnapshot};

#[derive(Debug)]
pub(crate) struct GraphProvider {
    pub(crate) family: usize,
    call: u64,
    relation: String,
    schema: Arc<sdk::Schema>,
}

#[derive(Clone, Debug)]
pub(crate) struct GraphExec {
    pub(crate) family: usize,
    pub(crate) read: usize,
    call: u64,
    relation: String,
    projection: Option<Vec<usize>>,
    properties: Arc<PlanProperties>,
}

impl GraphProvider {
    pub(crate) fn new(call: u64, relation: &sdk::GraphRelation) -> crate::Result<Self> {
        Ok(Self {
            family: SourceProvider::identity()?,
            call,
            relation: relation.name.clone(),
            schema: Arc::new(relation.engine().read_schema()),
        })
    }
}

impl GraphExec {
    pub(super) fn call_id(&self) -> u64 {
        self.call
    }
}

#[async_trait]
impl TableProvider for GraphProvider {
    fn schema(&self) -> Arc<sdk::Schema> {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _session: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let schema = match projection {
            Some(columns) => Arc::new(self.schema.project(columns)?),
            None => Arc::clone(&self.schema),
        };
        Ok(Arc::new(GraphExec {
            family: self.family,
            read: SourceProvider::identity().map_err(external)?,
            call: self.call,
            relation: self.relation.clone(),
            projection: projection.cloned(),
            properties: Arc::new(PlanProperties::new(
                EquivalenceProperties::new(schema),
                Partitioning::UnknownPartitioning(1),
                EmissionType::Final,
                Boundedness::Bounded,
            )),
        }))
    }
}

impl DisplayAs for GraphExec {
    fn fmt_as(&self, _kind: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GraphLookupExec: {}", self.relation)
    }
}

impl ExecutionPlan for GraphExec {
    fn name(&self) -> &str {
        "GraphLookupExec"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        Vec::new()
    }

    fn apply_expressions(
        &self,
        _f: &mut dyn FnMut(&Arc<dyn PhysicalExpr>) -> Result<TreeNodeRecursion>,
    ) -> Result<TreeNodeRecursion> {
        Ok(TreeNodeRecursion::Continue)
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if !children.is_empty() {
            return Err(internal("Graph lookup children differ"));
        }
        Ok(self)
    }

    fn reset_state(self: Arc<Self>) -> Result<Arc<dyn ExecutionPlan>> {
        Ok(Arc::new(Self {
            read: SourceProvider::identity().map_err(external)?,
            ..self.as_ref().clone()
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(internal("Graph lookup partition differs"));
        }
        let owner = context
            .session_config()
            .get_extension::<CallContext>()
            .ok_or_else(|| internal("Graph lookup invocation is absent"))?;
        let host = owner.graph(self.call)?;
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| internal("Graph lookup snapshot is absent"))?;
        let relation = self.relation.clone();
        let projection = self.projection.clone();
        let read = self.read;
        let family = self.family;
        let stream = stream::once(async move {
            host.check_inputs()?;
            let schema = Arc::new(
                host.transaction
                    .spec()
                    .read_schema("owned", &relation)
                    .map_err(external)?,
            );
            let reader = Arc::clone(&host);
            let captured = Arc::clone(&source);
            let task = Arc::clone(&context);
            let output = Arc::clone(&schema);
            let bind = async move {
                let input = reader.owned(&relation, &captured, &task).await?;
                captured.bind_port(read, output, input.data.batches.clone(), Some(&input))
            };
            source
                .bind_shared(
                    (family, None, None),
                    None,
                    read,
                    Arc::clone(&schema),
                    &context,
                    bind,
                )
                .await?;
            host.check_inputs()?;
            let input = source
                .captured_input(&SourceOrigin::Port(read))?
                .ok_or_else(|| internal("Graph lookup input is absent"))?;
            let batches = input
                .data
                .batches
                .iter()
                .map(|batch| match &projection {
                    Some(columns) => batch.project(columns).map_err(Into::into),
                    None => Ok(batch.clone()),
                })
                .collect::<Vec<Result<_>>>();
            Ok::<_, datafusion::common::DataFusionError>(stream::iter(batches))
        })
        .try_flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            stream,
        )))
    }
}
