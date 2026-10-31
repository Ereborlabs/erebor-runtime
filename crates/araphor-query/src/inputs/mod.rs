use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::catalog::TableProvider;
use datafusion::common::TableReference;
use datafusion::datasource::{provider_as_source, source_as_provider};
use datafusion::logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder};
use snafu::ResultExt as _;

use crate::follow::Window;
use crate::sources::{SourceOrigin, SourceProvider};
use crate::{InvalidSnafu, Result, SqlSnafu};

mod receipt;

#[derive(Debug)]
pub struct Inputs {
    ports: Vec<sdk::Port>,
    plans: Vec<PortPlan>,
}

#[derive(Debug)]
struct PortPlan {
    slot: usize,
    changes: bool,
    window: Option<Window>,
    plan: Arc<LogicalPlan>,
    origins: BTreeSet<SourceOrigin>,
    identity: Option<SourceOrigin>,
}

impl Inputs {
    pub(crate) fn from_plans(
        model: &sdk::Model,
        plans: &[LogicalPlan],
        origins: Vec<BTreeSet<SourceOrigin>>,
    ) -> Result<Self> {
        if plans.len() != model.inputs.len() || origins.len() != plans.len() {
            return InvalidSnafu {
                field: "package input plans",
            }
            .fail();
        }
        let plans = plans
            .iter()
            .zip(origins)
            .enumerate()
            .map(|(slot, (plan, origins))| {
                let identity = Self::identity(plan).filter(|origin| {
                    origins.len() == 1
                        && origins.contains(origin)
                        && (matches!(origin, SourceOrigin::Port(_))
                            || matches!(
                                &model.inputs[slot].source,
                                sdk::InputSource::Table(sdk::TableRef::Named(_))
                            ))
                });
                Ok(PortPlan {
                    slot,
                    changes: model.change_inputs.as_ref().is_some_and(|changes| {
                        changes
                            .ports
                            .iter()
                            .any(|pair| pair.after == model.inputs[slot].port.name)
                    }),
                    window: Window::infer(plan)?,
                    plan: Arc::new(plan.clone()),
                    origins,
                    identity,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            ports: model
                .inputs
                .iter()
                .map(|input| input.port.clone())
                .collect(),
            plans,
        })
    }

    pub(crate) fn origins(&self) -> impl Iterator<Item = &SourceOrigin> {
        self.plans.iter().flat_map(|port| &port.origins)
    }

    pub(crate) fn bind_ports(
        &self,
        model: &sdk::Model,
        plans: &[LogicalPlan],
        bindings: &BTreeMap<usize, &BTreeSet<SourceOrigin>>,
    ) -> Result<Option<Self>> {
        if !self
            .origins()
            .any(|origin| matches!(origin, SourceOrigin::Port(id) if bindings.contains_key(id)))
        {
            return Ok(None);
        }
        let origins = self
            .plans
            .iter()
            .map(|port| {
                let mut origins = port.origins.clone();
                for (&id, resolved) in bindings {
                    if origins.remove(&SourceOrigin::Port(id)) {
                        origins.extend(resolved.iter().cloned());
                    }
                }
                origins
            })
            .collect();
        Self::from_plans(model, plans, origins).map(Some)
    }

    fn identity(plan: &LogicalPlan) -> Option<SourceOrigin> {
        match plan {
            LogicalPlan::Extension(extension) => extension.node.as_any()
                .downcast_ref::<crate::sources::SourcePort>().map(|source| SourceOrigin::Port(source.slot)),
            LogicalPlan::TableScan(scan) if scan.filters.is_empty() && scan.fetch.is_none() => {
                let provider = source_as_provider(&scan.source).ok()?;
                let provider = provider.as_any().downcast_ref::<SourceProvider>()?;
                let source = provider.retained_source()?;
                let expected = &source.schema;
                let indices = scan.projection.as_deref();
                if scan.projected_schema.as_arrow() != expected.as_ref()
                    || indices.is_some_and(|indices| indices.iter().copied().ne(0..expected.fields().len())) {
                    return None;
                }
                Some(SourceOrigin::Package(source.slot))
            }
            LogicalPlan::Projection(projection) if projection.schema.as_arrow() == projection.input.schema().as_arrow()
                && projection.expr.iter().enumerate().all(|(index, expr)| {
                    matches!(expr, Expr::Column(column) if projection.input.schema().index_of_column(column).ok() == Some(index))
                }) => Self::identity(&projection.input),
            LogicalPlan::SubqueryAlias(alias) => Self::identity(&alias.input),
            _ => None,
        }
    }

    pub(crate) fn scan(
        name: &str,
        provider: Arc<dyn TableProvider>,
        schema: &sdk::Schema,
    ) -> Result<LogicalPlan> {
        let native = provider.schema();
        let projection = schema
            .fields()
            .iter()
            .map(|field| native.index_of(field.name()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(datafusion::common::DataFusionError::from)
            .context(SqlSnafu)?;
        LogicalPlanBuilder::scan(
            TableReference::bare(name),
            provider_as_source(provider),
            Some(projection),
        )
        .and_then(LogicalPlanBuilder::build)
        .context(SqlSnafu)
    }

    pub fn allocated_bytes(&self) -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            .saturating_add(self.ports.capacity() * size_of::<sdk::Port>())
            .saturating_add(
                self.ports
                    .iter()
                    .map(sdk::Port::allocated_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(self.plans.capacity() * size_of::<PortPlan>())
            .saturating_add(
                self.plans
                    .iter()
                    .flat_map(|plan| &plan.origins)
                    .map(|origin| {
                        size_of::<SourceOrigin>()
                            + match origin {
                                SourceOrigin::Durable(name) | SourceOrigin::Local(name) => {
                                    name.capacity()
                                }
                                _ => 0,
                            }
                    })
                    .sum::<usize>(),
            )
    }
}
