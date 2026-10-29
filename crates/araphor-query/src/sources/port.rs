use std::any::Any;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DFSchema, DFSchemaRef, Result};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{Expr, LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
};

use super::{SourceOrigin, SourceProvider};

pub trait PortSource: fmt::Debug + Send + Sync {
    /// Return true only when the physical plan supports DataFusion state reset.
    /// The plan must read each capture from the current TaskContext.
    fn reusable(&self) -> bool {
        false
    }

    fn plan(
        &self,
        slot: usize,
        inputs: &[Arc<dyn ExecutionPlan>],
    ) -> Result<Arc<dyn ExecutionPlan>>;
}

#[derive(Debug)]
pub struct SourceDependenciesExec {
    input: Arc<dyn ExecutionPlan>,
    sources: Vec<Arc<dyn ExecutionPlan>>,
}

impl SourceDependenciesExec {
    pub fn new(input: Arc<dyn ExecutionPlan>, sources: Vec<Arc<dyn ExecutionPlan>>) -> Self {
        Self { input, sources }
    }

    pub(crate) fn sources(&self) -> &[Arc<dyn ExecutionPlan>] {
        &self.sources
    }
}

impl DisplayAs for SourceDependenciesExec {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SourceDependenciesExec: {}", self.sources.len())
    }
}

impl ExecutionPlan for SourceDependenciesExec {
    fn name(&self) -> &str {
        "SourceDependenciesExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        self.input.properties()
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let [input] = <[Arc<dyn ExecutionPlan>; 1]>::try_from(children).map_err(|_| {
            datafusion::common::DataFusionError::Internal("source port child count changed".into())
        })?;
        Ok(Arc::new(Self {
            input,
            sources: self.sources.clone(),
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        self.input.execute(partition, context)
    }
}

#[derive(Clone)]
pub struct SourcePort {
    pub(crate) slot: usize,
    role: String,
    schema: DFSchemaRef,
    inputs: Vec<LogicalPlan>,
    origins: BTreeSet<SourceOrigin>,
    source: Arc<dyn PortSource>,
}

impl SourcePort {
    pub(crate) fn reusable(&self) -> bool {
        self.source.reusable()
    }

    pub(crate) fn origins(&self) -> &BTreeSet<SourceOrigin> {
        &self.origins
    }

    pub fn new(
        role: String,
        schema: SchemaRef,
        inputs: Vec<LogicalPlan>,
        source: Arc<dyn PortSource>,
    ) -> crate::Result<Self> {
        Ok(Self {
            slot: SourceProvider::identity()?,
            role,
            schema: Arc::new(
                DFSchema::try_from(schema.as_ref().clone())
                    .map_err(|source| crate::Error::Sql { source })?,
            ),
            inputs,
            origins: BTreeSet::new(),
            source,
        })
    }

    pub fn prepared(
        role: String,
        schema: SchemaRef,
        inputs: &[LogicalPlan],
        source: Arc<dyn PortSource>,
    ) -> crate::Result<Self> {
        let mut port = Self::new(role, schema, Vec::new(), source)?;
        for input in inputs {
            port.origins
                .extend(crate::planner::Planner::dependencies(input)?);
        }
        Ok(port)
    }

    pub(crate) fn plan(&self, inputs: &[Arc<dyn ExecutionPlan>]) -> Result<Arc<dyn ExecutionPlan>> {
        if inputs.len() != self.inputs.len() {
            return datafusion::common::internal_err!("bound source input count changed");
        }
        let plan = self.source.plan(self.slot, inputs)?;
        if plan.schema().as_ref() != self.schema.as_arrow() {
            return datafusion::common::internal_err!("bound source schema changed");
        }
        Ok(plan)
    }
}

impl fmt::Debug for SourcePort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourcePort")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}
impl PartialEq for SourcePort {
    fn eq(&self, other: &Self) -> bool {
        self.slot == other.slot
            && self.inputs == other.inputs
            && self.origins == other.origins
            && self.schema == other.schema
    }
}
impl Eq for SourcePort {}
impl Hash for SourcePort {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.role.hash(state);
        self.inputs.hash(state);
        self.origins.hash(state);
        self.schema.hash(state);
    }
}
impl PartialOrd for SourcePort {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.slot.cmp(&other.slot) {
            Ordering::Equal => {
                (&self.inputs, &self.origins).partial_cmp(&(&other.inputs, &other.origins))
            }
            order => Some(order),
        }
        .filter(|order| *order != Ordering::Equal || self == other)
    }
}
impl UserDefinedLogicalNodeCore for SourcePort {
    fn name(&self) -> &str {
        "SourcePort"
    }
    fn inputs(&self) -> Vec<&LogicalPlan> {
        self.inputs.iter().collect()
    }
    fn schema(&self) -> &DFSchemaRef {
        &self.schema
    }
    fn expressions(&self) -> Vec<Expr> {
        Vec::new()
    }
    fn necessary_children_exprs(&self, _: &[usize]) -> Option<Vec<Vec<usize>>> {
        Some(
            self.inputs
                .iter()
                .map(|input| (0..input.schema().fields().len()).collect())
                .collect(),
        )
    }
    fn fmt_for_explain(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SourcePort: {}", self.slot)
    }
    fn with_exprs_and_inputs(
        &self,
        expressions: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> Result<Self> {
        if !expressions.is_empty() || inputs.len() != self.inputs.len() {
            return datafusion::common::internal_err!("bound source inputs changed");
        }
        Ok(Self {
            inputs,
            ..self.clone()
        })
    }
}

#[cfg(test)]
mod tests;
