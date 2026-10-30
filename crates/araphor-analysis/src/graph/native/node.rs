use std::any::Any;
use std::fmt;
use std::sync::Arc;

use araphor_query::sources::{PortSource, SourceDependenciesExec, SourceSnapshot};
use datafusion::common::Result;
use datafusion::execution::TaskContext;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, Distribution, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures_util::{stream, TryStreamExt as _};

use super::Projection;

pub(super) struct Port {
    pub(super) owner: Arc<Projection>,
    pub(super) index: usize,
}

impl fmt::Debug for Port {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphPort")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl PortSource for Port {
    fn reusable(&self) -> bool {
        true
    }
    fn plan(
        &self,
        slot: usize,
        inputs: &[Arc<dyn ExecutionPlan>],
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let schema = Arc::new(self.owner.ports[self.index].schema.clone());
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(schema),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Final,
            Boundedness::Bounded,
        ));
        let port: Arc<dyn ExecutionPlan> = Arc::new(PortExec {
            owner: Arc::clone(&self.owner),
            index: self.index,
            slot,
            children: if self.owner.prepared.is_some() {
                Vec::new()
            } else {
                inputs.to_vec()
            },
            properties,
        });
        Ok(if let Some(prepared) = &self.owner.prepared {
            Arc::new(SourceDependenciesExec::new(port, prepared.clone()))
        } else {
            port
        })
    }
}

#[derive(Clone)]
struct PortExec {
    owner: Arc<Projection>,
    index: usize,
    slot: usize,
    children: Vec<Arc<dyn ExecutionPlan>>,
    properties: Arc<PlanProperties>,
}

impl fmt::Debug for PortExec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphPortExec")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl DisplayAs for PortExec {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GraphPortExec: {}",
            self.owner.ports[self.index].name
        )
    }
}

impl ExecutionPlan for PortExec {
    fn name(&self) -> &str {
        "GraphPortExec"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }
    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        self.children.iter().collect()
    }
    fn required_input_distribution(&self) -> Vec<Distribution> {
        vec![Distribution::SinglePartition; self.children.len()]
    }
    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if children.len() != self.children.len() {
            return Err(Projection::invalid("graph physical inputs"));
        }
        Ok(Arc::new(Self {
            children,
            ..self.as_ref().clone()
        }))
    }
    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(Projection::invalid("graph input partition"));
        }
        let plan = self.clone();
        let stream = stream::once(async move {
            let captured = plan.owner.capture(&plan.children, &context).await?;
            let input = &captured.inputs[plan.index];
            let source = context
                .session_config()
                .get_extension::<SourceSnapshot>()
                .ok_or_else(|| Projection::invalid("graph captured source"))?;
            source.bind_port(
                plan.slot,
                Arc::new(plan.owner.ports[plan.index].schema.clone()),
                input.data.batches.clone(),
                Some(input),
            )?;
            let batches = input.data.batches.clone();
            Ok::<_, datafusion::common::DataFusionError>(stream::iter(batches.into_iter().map(
                move |batch| {
                    let _held = &captured;
                    Ok(batch)
                },
            )))
        })
        .try_flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            stream,
        )))
    }
}
