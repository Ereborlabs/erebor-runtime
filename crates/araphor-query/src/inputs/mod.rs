use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::AnalysisTableRequests;
use datafusion::catalog::TableProvider;
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::TableReference;
use datafusion::datasource::{provider_as_source, source_as_provider};
use datafusion::logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder, Volatility};
use snafu::ResultExt as _;

use crate::execution::{Engine, Session};
use crate::follow::Window;
use crate::sources::{SourceOrigin, SourceProvider, SourceSnapshot};
use crate::{InvalidSnafu, Result, SqlSnafu};

mod live;
mod physical;
mod receipt;
#[cfg(test)]
mod tests;

pub use live::InputOperation;
pub use physical::InputSet;

#[derive(Debug)]
pub struct Inputs {
    ports: Vec<sdk::Port>,
    plans: Vec<PortPlan>,
    sources: AnalysisTableRequests,
    packages: Vec<(usize, sdk::OutputRef)>,
    clock: bool,
    limits: sdk::Limits,
    mode: sdk::InputMode,
}

#[derive(Debug)]
struct PortPlan {
    slot: usize,
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
            sources: AnalysisTableRequests::new(),
            packages: Vec::new(),
            clock: false,
            limits: model.limits,
            mode: model.input_mode,
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

    pub fn admit(engine: &Engine, model: &sdk::Model) -> Result<Self> {
        let mut tables = SourceSnapshot::providers();
        for (slot, input) in model.inputs.iter().enumerate() {
            if let sdk::InputSource::Table(table) = &input.source {
                if matches!(table, sdk::TableRef::Named(name) if name == &input.port.name) {
                    continue;
                }
                let schema = Session::indexed_schema(&input.port.schema)?;
                tables.insert(input.port.name.clone(), SourceProvider::port(slot, schema));
            }
        }
        let state = engine.catalog(tables.clone())?;
        let mut plans = Vec::new();
        let mut packages = Vec::new();
        if model.input_mode == sdk::InputMode::Resolved {
            for (slot, input) in model.inputs.iter().enumerate() {
                let mut origins = BTreeSet::new();
                let plan = match &input.source {
                    sdk::InputSource::Query(sql) => {
                        let statement = engine.limits().parser.parse(sql)?;
                        let state = state.clone();
                        let (plan, sources) = engine.wait(async move {
                            crate::planner::Planner::new(&state)
                                .build_with_sources(statement, Vec::new())
                                .await
                        })?;
                        origins = sources;
                        plan
                    }
                    sdk::InputSource::Table(sdk::TableRef::Named(name)) => {
                        let provider = tables.get(name).cloned().ok_or_else(|| {
                            InvalidSnafu {
                                field: "input table",
                            }
                            .build()
                        })?;
                        Self::scan(name, provider, &input.port.schema)?
                    }
                    sdk::InputSource::Table(sdk::TableRef::Output(reference)) => {
                        packages.push((slot, reference.clone()));
                        let schema = Arc::new(input.port.schema.clone());
                        let provider = SourceProvider::package(slot, schema);
                        Self::scan(&input.port.name, provider, &input.port.schema)?
                    }
                };
                origins.extend(crate::planner::Planner::sources(&plan)?);
                let window = Window::infer(&plan)?;
                let identity = Self::identity(&plan).filter(|origin| {
                    matches!(origin, SourceOrigin::Port(_))
                        && origins.len() == 1
                        && origins.contains(origin)
                });
                plans.push(PortPlan {
                    slot,
                    window,
                    plan: Arc::new(plan),
                    origins,
                    identity,
                });
            }
        }
        let mut ordered = Vec::with_capacity(plans.len());
        let mut bound = BTreeSet::new();
        while !plans.is_empty() {
            let index = plans
                .iter()
                .position(|plan| {
                    plan.origins.iter().all(|origin| match origin {
                        SourceOrigin::Port(slot) => bound.contains(slot),
                        _ => true,
                    })
                })
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "input dependency cycle",
                    }
                    .build()
                })?;
            let plan = plans.remove(index);
            bound.insert(plan.slot);
            ordered.push(plan);
        }
        let mut clock = false;
        let mut sources = AnalysisTableRequests::new();
        for port in &ordered {
            clock |= Self::clocked(&port.plan)?;
            sources.extend(
                port.origins
                    .iter()
                    .filter_map(|origin| origin.durable().map(|name| (name.to_owned(), None))),
            );
        }
        clock |= sources.contains_key("notifications");
        Ok(Self {
            ports: model
                .inputs
                .iter()
                .map(|input| input.port.clone())
                .collect(),
            plans: ordered,
            sources,
            packages,
            clock,
            limits: model.limits,
            mode: model.input_mode,
        })
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

    pub fn clocked(plan: &LogicalPlan) -> Result<bool> {
        let mut clock = false;
        plan.apply_with_subqueries(|plan| {
            plan.apply_expressions(|expression| {
                expression.apply(|expression| {
                    if let Expr::ScalarFunction(function) = expression {
                        clock |= function.func.signature().volatility != Volatility::Immutable;
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
            })?;
            Ok(TreeNodeRecursion::Continue)
        })
        .context(SqlSnafu)?;
        Ok(clock)
    }

    pub fn input_clock(&self) -> bool {
        self.clock
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
            .saturating_add(
                self.sources
                    .iter()
                    .map(|(name, columns)| {
                        size_of::<(String, Option<BTreeSet<usize>>)>()
                            + name.capacity()
                            + columns
                                .as_ref()
                                .map_or(0, |columns| columns.len() * size_of::<usize>())
                    })
                    .sum::<usize>(),
            )
            .saturating_add(self.packages.capacity() * size_of::<(usize, sdk::OutputRef)>())
            .saturating_add(
                self.packages
                    .iter()
                    .map(|(_, reference)| {
                        reference.package.capacity()
                            + reference.revision.capacity()
                            + reference.export.capacity()
                            + reference.output.capacity()
                    })
                    .sum::<usize>(),
            )
    }
}
