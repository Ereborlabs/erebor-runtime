use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DFSchema, DFSchemaRef, Result};
use datafusion::logical_expr::{Expr, LogicalPlan, UserDefinedLogicalNodeCore};
use datafusion::physical_plan::ExecutionPlan;

use super::SourceProvider;

pub trait PortSource: fmt::Debug + Send + Sync {
    fn plan(
        &self,
        slot: usize,
        inputs: &[Arc<dyn ExecutionPlan>],
    ) -> Result<Arc<dyn ExecutionPlan>>;
}

#[derive(Clone)]
pub struct SourcePort {
    pub(crate) slot: usize,
    schema: DFSchemaRef,
    inputs: Vec<LogicalPlan>,
    source: Arc<dyn PortSource>,
}

impl SourcePort {
    pub fn new(
        schema: SchemaRef,
        inputs: Vec<LogicalPlan>,
        source: Arc<dyn PortSource>,
    ) -> crate::Result<Self> {
        Ok(Self {
            slot: SourceProvider::identity()?,
            schema: Arc::new(
                DFSchema::try_from(schema.as_ref().clone())
                    .map_err(|source| crate::Error::Sql { source })?,
            ),
            inputs,
            source,
        })
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
        self.slot == other.slot && self.inputs == other.inputs && self.schema == other.schema
    }
}
impl Eq for SourcePort {}
impl Hash for SourcePort {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.slot.hash(state);
        self.inputs.hash(state);
        self.schema.hash(state);
    }
}
impl PartialOrd for SourcePort {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.slot.cmp(&other.slot) {
            Ordering::Equal => self.inputs.partial_cmp(&other.inputs),
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
