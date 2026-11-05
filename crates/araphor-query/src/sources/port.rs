use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{DFSchema, DataFusionError, Result, TableReference};
use datafusion::datasource::{provider_as_source, source_as_provider};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::execution::{SessionState, TaskContext};
use datafusion::logical_expr::{
    Expr, LogicalPlan, LogicalPlanBuilder, TableScan, TableScanBuilder, TableType,
};
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::execution_plan::{reset_plan_states, Boundedness, EmissionType};
use datafusion::physical_plan::filter::FilterExec;
use datafusion::physical_plan::limit::GlobalLimitExec;
use datafusion::physical_plan::projection::ProjectionExec;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    ChildrenPropertiesMode, DisplayAs, DisplayFormatType, Distribution, ExecutionPlan,
    InputDistributionRequirements, PlanProperties, ReplaceChildrenOptions,
    SendableRecordBatchStream,
};
use futures_util::future::BoxFuture;
use futures_util::{stream, TryStreamExt};
use snafu::ResultExt as _;
use tokio::sync::OnceCell;

use super::{SourceData, SourceImage, SourceOrigin, SourceProvider, SourceSnapshot};

mod metrics;

#[cfg(test)]
mod tests;

impl SourceImage {
    pub fn plan(self, plan: &LogicalPlan) -> Result<LogicalPlan> {
        self.image_plan(plan, false, &mut BTreeMap::new())
    }

    pub fn plan_rows(self, plan: &LogicalPlan) -> Result<LogicalPlan> {
        self.image_plan(plan, true, &mut BTreeMap::new())
    }

    fn image_plan(
        self,
        plan: &LogicalPlan,
        rows: bool,
        sources: &mut BTreeMap<usize, (Arc<dyn TableProvider>, Arc<SourcePort>)>,
    ) -> Result<LogicalPlan> {
        Ok(plan
            .clone()
            .transform_down_with_subqueries(|node| {
                let LogicalPlan::TableScan(mut scan) = node else {
                    return Ok(Transformed::no(node));
                };
                let table = source_as_provider(&scan.source)?;
                if let Some(source) = table.downcast_ref::<SourcePort>() {
                    return if rows {
                        Ok(Transformed::no(LogicalPlan::TableScan(scan)))
                    } else {
                        let identity = std::ptr::from_ref(source) as usize;
                        let imaged = if let Some((_, imaged)) = sources.get(&identity) {
                            Arc::clone(imaged)
                        } else {
                            let imaged = Arc::new(source.imaged(self, sources)?);
                            sources.insert(identity, (Arc::clone(&table), Arc::clone(&imaged)));
                            imaged
                        };
                        imaged
                            .scan_plan(scan)
                            .map(|plan| Transformed::new(plan, true, TreeNodeRecursion::Jump))
                    };
                }
                let table = if let Some(source) = table.downcast_ref::<SourceProvider>() {
                    if (rows
                        && !source
                            .origin
                            .durable()
                            .is_some_and(araphor_data::AnalysisTableRead::source_rows))
                        || source
                            .origin
                            .durable()
                            .is_some_and(araphor_data::AnalysisTableRead::source_header)
                    {
                        return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
                    }
                    source.image(self)?
                } else if let Some(plan) = table.get_logical_plan() {
                    Arc::new(datafusion::catalog::view::ViewTable::new(
                        self.image_plan(&plan, rows, sources)?,
                        None,
                    )) as Arc<dyn TableProvider>
                } else if table.is::<datafusion::datasource::MemTable>()
                    || table.is::<datafusion::datasource::empty::EmptyTable>()
                {
                    match (self, rows) {
                        (_, true) | (Self::After | Self::Inserted, false) => table,
                        (Self::Before | Self::Removed, false) => Arc::new(
                            datafusion::datasource::empty::EmptyTable::new(table.schema()),
                        ),
                    }
                } else {
                    return datafusion::common::not_impl_err!(
                        "the source table has no change view"
                    );
                };
                scan.source = provider_as_source(table);
                Ok(Transformed::yes(LogicalPlan::TableScan(scan)))
            })?
            .data)
    }
}

pub struct PortRead {
    pub input: sdk::Input,
    pub memory: MemoryReservation,
    pub derived: Option<Arc<araphor_data::ManagedDerivedSource>>,
}

impl From<(sdk::Input, MemoryReservation)> for PortRead {
    fn from((input, memory): (sdk::Input, MemoryReservation)) -> Self {
        Self {
            input,
            memory,
            derived: None,
        }
    }
}

pub trait PortSource: fmt::Debug + Send + Sync {
    fn reusable(&self) -> bool {
        false
    }

    /// Return true only if the complete driver result and its effects apply to all consumers of the same snapshot and source image.
    fn snapshot_bound(&self) -> bool {
        false
    }

    /// Use the current port for its After image.
    fn after_is_current(&self) -> bool {
        false
    }

    fn key_columns(&self) -> &[(usize, usize)];

    fn image_keys(&self, _image: SourceImage) -> &[(usize, usize)] {
        self.key_columns()
    }

    fn driver(&self, _image: SourceImage, _driver: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        Ok(None)
    }

    fn header(&self, _image: SourceImage, _header: &LogicalPlan) -> Result<Option<LogicalPlan>> {
        Ok(None)
    }

    fn header_required(&self, _driver: &[sdk::RecordBatch]) -> Result<bool> {
        Ok(true)
    }

    fn read<'a>(
        &'a self,
        image: Option<SourceImage>,
        driver: Vec<sdk::RecordBatch>,
        header: Vec<sdk::RecordBatch>,
        source: Arc<SourceSnapshot>,
        context: Arc<TaskContext>,
    ) -> BoxFuture<'a, Result<PortRead>>;
}

pub(super) type PortKey = (usize, Option<SourceImage>, Option<i64>);

#[derive(Clone, Debug)]
pub(crate) struct PortDemand {
    pub(super) slot: usize,
    pub(super) expressions: Arc<[Arc<dyn PhysicalExpr>]>,
}

#[derive(Debug)]
pub(super) struct PortScope {
    format: super::keys::KeyFormat,
    expressions: Arc<[Arc<dyn PhysicalExpr>]>,
    values: Arc<BTreeSet<Vec<u8>>>,
}

impl PortDemand {
    pub(super) async fn resolve(
        &self,
        source: &SourceSnapshot,
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<PortScope> {
        let slot = source.key_slot(self.slot)?;
        let values = control
            .query_async(slot.values())
            .await
            .map_err(SourceSnapshot::data_error)?;
        Ok(PortScope {
            format: slot.format()?,
            expressions: Arc::clone(&self.expressions),
            values,
        })
    }
}

impl PortScope {
    pub(super) fn same(
        &self,
        other: &Self,
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<bool> {
        control.check().map_err(SourceSnapshot::data_error)?;
        if !self.format.same(&other.format)
            || self.expressions.len() != other.expressions.len()
            || self.values.len() != other.values.len()
        {
            return Ok(false);
        }
        for (left, right) in self.expressions.iter().zip(other.expressions.iter()) {
            control.check().map_err(SourceSnapshot::data_error)?;
            if left.as_ref() != right.as_ref() {
                return Ok(false);
            }
        }
        for (left, right) in self.values.iter().zip(other.values.iter()) {
            control.check().map_err(SourceSnapshot::data_error)?;
            if left != right {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone)]
pub struct SourcePort {
    pub(crate) slot: usize,
    role: String,
    schema: SchemaRef,
    inputs: [LogicalPlan; 2],
    state: SessionState,
    prepared: Arc<OnceCell<[Arc<dyn ExecutionPlan>; 2]>>,
    runtime: [bool; 2],
    source: Option<Arc<dyn PortSource>>,
    keys: Vec<(usize, usize)>,
    image: Option<SourceImage>,
    clock: Option<i64>,
    origins: BTreeSet<SourceOrigin>,
    windows: Arc<crate::follow::Windows>,
    clocks: usize,
    calls: bool,
    reusable: bool,
    shareable: bool,
}

impl SourcePort {
    pub(crate) fn reusable(&self) -> bool {
        self.reusable
    }

    pub(crate) fn inputs(&self) -> &[LogicalPlan; 2] {
        &self.inputs
    }

    pub(crate) fn is_native(&self) -> bool {
        self.source.is_none()
    }

    pub(crate) fn origins(&self) -> &BTreeSet<SourceOrigin> {
        &self.origins
    }

    pub(crate) fn windows(&self) -> &crate::follow::Windows {
        &self.windows
    }

    pub(crate) fn clocks(&self) -> usize {
        self.clocks
    }

    pub(crate) fn has_calls(&self) -> bool {
        self.calls
    }

    fn check_keys(&self, driver: &LogicalPlan) -> Result<()> {
        let mut outputs = BTreeSet::new();
        for &(output, input) in &self.keys {
            let valid = self
                .schema
                .fields()
                .get(output)
                .zip(driver.schema().fields().get(input))
                .is_some_and(|(output, input)| {
                    input.data_type().contains(output.data_type())
                        && (input.is_nullable() || !output.is_nullable())
                });
            if !valid || !outputs.insert(output) {
                return datafusion::common::plan_err!(
                    "source key mapping differs from its schema: role={}, output={} {:?}, input={} {:?}",
                    self.role,
                    output,
                    self.schema.fields().get(output),
                    input,
                    driver.schema().fields().get(input)
                );
            }
        }
        Ok(())
    }

    fn properties(&mut self) -> crate::Result<()> {
        self.origins.clear();
        self.clocks = 0;
        self.calls = false;
        self.reusable = self.source.as_ref().is_none_or(|source| source.reusable());
        for (index, input) in self.inputs.iter().enumerate() {
            self.runtime[index] |=
                crate::follow::Windows::programs(std::slice::from_ref(input))?.runtime();
            self.origins.extend(
                crate::planner::SourceDemand::collect(input, false).context(crate::SqlSnafu)?,
            );
            self.clocks += crate::follow::Window::clocks(input)?;
            self.calls |=
                crate::definition::PackageCall::contains(input).context(crate::SqlSnafu)?;
            self.reusable &=
                crate::stream::physical::SubscribeExec::reusable(input, &mut BTreeSet::new())
                    .context(crate::SqlSnafu)?;
        }
        self.windows = Arc::new(crate::follow::Windows::programs(&self.inputs)?);
        self.check_keys(&self.inputs[0]).context(crate::SqlSnafu)
    }

    fn prepare(input: LogicalPlan) -> Result<LogicalPlan> {
        let input = crate::definition::PackageCall::expose_programs(input)?;
        if !input.get_parameter_types()?.is_empty() {
            return datafusion::common::plan_err!("source parameters are not bound");
        }
        datafusion::execution::context::SQLOptions::new()
            .with_allow_ddl(false)
            .with_allow_dml(false)
            .with_allow_statements(false)
            .verify_plan(&input)?;
        Ok(input)
    }

    pub async fn new(
        session: &crate::execution::Session,
        role: String,
        schema: SchemaRef,
        driver: LogicalPlan,
        header: LogicalPlan,
        source: Arc<dyn PortSource>,
    ) -> crate::Result<Self> {
        let keys = source.key_columns().to_vec();
        Self::build(session, role, schema, [driver, header], keys, Some(source)).await
    }

    pub async fn native(
        session: &crate::execution::Session,
        role: String,
        driver: LogicalPlan,
        keys: Vec<(usize, usize)>,
    ) -> crate::Result<Self> {
        let schema = Arc::new(driver.schema().as_arrow().clone());
        let header = LogicalPlanBuilder::empty(true)
            .build()
            .context(crate::SqlSnafu)?;
        Self::build(session, role, schema, [driver, header], keys, None).await
    }

    async fn build(
        session: &crate::execution::Session,
        role: String,
        schema: SchemaRef,
        [driver, header]: [LogicalPlan; 2],
        keys: Vec<(usize, usize)>,
        source: Option<Arc<dyn PortSource>>,
    ) -> crate::Result<Self> {
        let inputs = [
            Self::prepare(driver).context(crate::SqlSnafu)?,
            Self::prepare(header).context(crate::SqlSnafu)?,
        ];
        let windows = Arc::new(crate::follow::Windows::default());
        let mut state = session.state()?;
        *state.config_mut() = state
            .config()
            .clone()
            .set_bool("datafusion.optimizer.enable_dynamic_filter_pushdown", false);
        let mut node = Self {
            slot: SourceProvider::identity()?,
            role,
            schema,
            inputs,
            state: state.clone(),
            prepared: Arc::new(OnceCell::new()),
            runtime: [true; 2],
            source,
            keys,
            image: None,
            clock: None,
            origins: BTreeSet::new(),
            windows,
            clocks: 0,
            calls: false,
            reusable: false,
            shareable: true,
        };
        node.properties()?;
        crate::execution::Engine::blocking(
            Arc::clone(session.control()),
            session.token()?,
            move || {
                for index in 0..node.inputs.len() {
                    let original = &node.inputs[index];
                    let scope = crate::follow::Windows::programs(std::slice::from_ref(original))?;
                    if scope.runtime() {
                        continue;
                    }
                    let origins = crate::planner::SourceDemand::collect(original, false)
                        .context(crate::SqlSnafu)?;
                    let reusable = crate::stream::physical::SubscribeExec::reusable(original, &mut BTreeSet::new())
                        .context(crate::SqlSnafu)?;
                    let child = if index == 0 { "driver" } else { "header" };
                    erebor_telemetry::debug!(stage="source_plan",role=%node.role,source_slot=node.slot,image=?node.image,clock=?node.clock,child,action="logical_start","Source logical planning started");
                    let logical_time = std::time::Instant::now();
                    let optimized = crate::parser::Parser::stack(|| state.optimize(original))
                        .context(crate::SqlSnafu)?;
                    erebor_telemetry::debug!(stage="source_plan",role=%node.role,source_slot=node.slot,image=?node.image,clock=?node.clock,child,action="logical_done",elapsed_us=logical_time.elapsed().as_micros(),"Source logical planning completed");
                    let optimized_scope = crate::follow::Windows::programs(std::slice::from_ref(&optimized))?;
                    if !scope.same_scope(&optimized_scope)
                        || origins != crate::planner::SourceDemand::collect(&optimized, false).context(crate::SqlSnafu)?
                        || reusable != crate::stream::physical::SubscribeExec::reusable(&optimized, &mut BTreeSet::new()).context(crate::SqlSnafu)?
                    {
                        continue;
                    }
                    node.inputs[index] = optimized;
                    node.runtime[index] = false;
                }
                node.check_keys(&node.inputs[0]).context(crate::SqlSnafu)?;
                Ok(node)
            },
        ).await
    }

    async fn prepare_inputs(&self, state: &SessionState) -> Result<[Arc<dyn ExecutionPlan>; 2]> {
        let rules = state
            .physical_optimizers()
            .iter()
            .filter(|rule| rule.name() != super::SourceLookup.name())
            .cloned()
            .collect();
        let mut state = SessionStateBuilder::new_from_existing(state.clone())
            .with_physical_optimizer_rules(rules)
            .build();
        if let Some(clock) = self.clock {
            state.execution_props_mut().query_execution_start_time =
                Some(chrono::DateTime::from_timestamp_nanos(clock));
        }
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for (index, input) in self.inputs.iter().enumerate() {
            let input = if let Some(calls) = state
                .config()
                .get_extension::<crate::definition::CallContext>()
                .filter(|calls| calls.has_windows())
            {
                calls.bind_window_clocks(input.clone(), &state)?
            } else {
                input.clone()
            };
            let logical = if self.runtime[index] {
                state.optimize(&input)?
            } else {
                input
            };
            if index == 0 {
                self.check_keys(&logical)?;
            }
            let physical = state
                .query_planner()
                .create_physical_plan(&logical, &state)
                .await?;
            if physical.schema().as_ref() != logical.schema().as_arrow() {
                return datafusion::common::plan_err!("source physical input schema differs");
            }
            inputs.push(physical);
        }
        inputs
            .try_into()
            .map_err(|_| DataFusionError::Internal("source physical inputs differ".into()))
    }

    fn table_name(&self) -> TableReference {
        let image = match self.image {
            None => 0,
            Some(SourceImage::Before) => 1,
            Some(SourceImage::After) => 2,
            Some(SourceImage::Inserted) => 3,
            Some(SourceImage::Removed) => 4,
        };
        let clock = self
            .clock
            .map_or_else(|| "capture".into(), |clock| clock.to_string());
        TableReference::bare(format!("__araphor_port_{}_{}_{}", self.slot, image, clock))
    }

    pub fn plan(self) -> crate::Result<LogicalPlan> {
        let role = self.role.clone();
        LogicalPlanBuilder::scan(self.table_name(), provider_as_source(Arc::new(self)), None)
            .and_then(|plan| plan.alias(role))
            .and_then(LogicalPlanBuilder::build)
            .context(crate::SqlSnafu)
    }

    pub(crate) fn scan_plan(self: Arc<Self>, scan: TableScan) -> Result<LogicalPlan> {
        let table_name = self.table_name();
        let old_name = scan.table_name;
        let plan = TableScanBuilder::new(table_name.clone(), provider_as_source(self))
            .with_projection(scan.projection)
            .with_filters(scan.filters)
            .with_fetch(scan.fetch)
            .with_statistics_requests(scan.statistics_requests)
            .build()
            .map(LogicalPlan::TableScan)?;
        if table_name == old_name {
            Ok(plan)
        } else {
            LogicalPlanBuilder::from(plan).alias(old_name)?.build()
        }
    }

    pub(crate) fn clocked(&self, state: &SessionState) -> Arc<Self> {
        let mut source = self.clone();
        source.prepared = Arc::new(OnceCell::new());
        source.clock = state
            .execution_props()
            .query_execution_start_time
            .and_then(|time| time.timestamp_nanos_opt());
        Arc::new(source)
    }

    pub(crate) fn sealed(
        &self,
        sources: &mut BTreeMap<usize, (Arc<dyn TableProvider>, Arc<dyn TableProvider>)>,
    ) -> Result<Self> {
        if !self.calls {
            return Ok(self.clone());
        }
        let mut source = self.clone();
        source.prepared = Arc::new(OnceCell::new());
        source.inputs = [
            crate::definition::PackageCall::seal_sources(self.inputs[0].clone(), sources)?,
            crate::definition::PackageCall::seal_sources(self.inputs[1].clone(), sources)?,
        ];
        source
            .properties()
            .map_err(|error| DataFusionError::External(Box::new(error)))?;
        Ok(source)
    }

    fn imaged(
        &self,
        image: SourceImage,
        sources: &mut BTreeMap<usize, (Arc<dyn TableProvider>, Arc<SourcePort>)>,
    ) -> Result<Self> {
        if image == SourceImage::After
            && self.image.is_none()
            && self
                .source
                .as_ref()
                .is_some_and(|source| source.after_is_current())
        {
            return Ok(self.clone());
        }
        let mut source = self.clone();
        source.shareable &= self.image.is_none();
        source.prepared = Arc::new(OnceCell::new());
        let header = match self
            .source
            .as_ref()
            .map(|source| source.header(image, &self.inputs[1]))
            .transpose()?
            .flatten()
        {
            Some(header) => {
                source.runtime[1] = true;
                Self::prepare(header)?
            }
            None => image.image_plan(&self.inputs[1], false, sources)?,
        };
        source.inputs = [
            match self
                .source
                .as_ref()
                .map(|source| source.driver(image, &self.inputs[0]))
                .transpose()?
                .flatten()
            {
                Some(driver) => {
                    source.runtime[0] = true;
                    Self::prepare(driver)?
                }
                None => image.image_plan(&self.inputs[0], false, sources)?,
            },
            header,
        ];
        source.image = Some(image);
        if let Some(reader) = &source.source {
            source.keys = reader.image_keys(image).to_vec();
        }
        source
            .properties()
            .map_err(|error| DataFusionError::External(Box::new(error)))?;
        Ok(source)
    }
}

impl fmt::Debug for SourcePort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SourcePort: {}", self.role)
    }
}

#[async_trait]
impl TableProvider for SourcePort {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        session: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let state = session
            .as_any()
            .downcast_ref::<SessionState>()
            .ok_or_else(|| DataFusionError::Plan("source planning session differs".into()))?;
        let retained = self.reusable
            && !self.calls
            && self.clocks == 0
            && !self.windows.runtime()
            && !self
                .origins
                .iter()
                .any(|origin| matches!(origin, SourceOrigin::Local(_)));
        let inputs = if retained {
            let prepared = self
                .prepared
                .get_or_try_init(|| self.prepare_inputs(&self.state))
                .await?;
            [
                PortExec::instantiate(Arc::clone(&prepared[0]))?,
                PortExec::instantiate(Arc::clone(&prepared[1]))?,
            ]
        } else {
            self.prepare_inputs(state).await?
        };
        let read = SourceProvider::identity()
            .map_err(|error| DataFusionError::External(Box::new(error)))?;
        let reader = SourceProvider::port(read, Arc::clone(&self.schema))
            .scan(state, None, &[], None)
            .await?;
        let boundedness = if inputs
            .iter()
            .any(|input| input.properties().boundedness.is_unbounded())
        {
            Boundedness::Unbounded {
                requires_infinite_memory: true,
            }
        } else {
            reader.properties().boundedness
        };
        let properties = Arc::new(
            reader
                .properties()
                .as_ref()
                .clone()
                .with_emission_type(EmissionType::Final)
                .with_boundedness(boundedness),
        );
        let mut plan: Arc<dyn ExecutionPlan> = Arc::new(PortExec {
            family: self.slot,
            read,
            role: self.role.clone(),
            schema: Arc::clone(&self.schema),
            inputs,
            reader,
            source: self.source.clone(),
            keys: self.keys.clone(),
            binding: (retained
                && self.shareable
                && self
                    .source
                    .as_ref()
                    .is_none_or(|source| source.snapshot_bound()))
            .then_some((self.slot, self.image, self.clock)),
            demand: None,
            image: self.image,
            properties,
        });
        let schema = DFSchema::try_from_qualified_schema(self.table_name(), &self.schema)?;
        for filter in filters {
            let filter = state.create_physical_expr(filter.clone(), &schema)?;
            plan = Arc::new(FilterExec::try_new(filter, plan)?);
        }
        if let Some(projection) = projection {
            let columns = projection
                .iter()
                .map(|&index| {
                    let field =
                        self.schema.fields().get(index).ok_or_else(|| {
                            DataFusionError::Plan("source projection differs".into())
                        })?;
                    Ok((
                        Arc::new(datafusion::physical_expr::expressions::Column::new(
                            field.name(),
                            index,
                        )) as Arc<dyn PhysicalExpr>,
                        field.name().clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            plan = Arc::new(ProjectionExec::try_new(columns, plan)?);
        }
        if let Some(limit) = limit {
            plan = Arc::new(GlobalLimitExec::new(plan, 0, Some(limit)));
        }
        Ok(plan)
    }
}

#[derive(Clone)]
pub(crate) struct PortExec {
    pub(crate) family: usize,
    pub(crate) read: usize,
    role: String,
    schema: SchemaRef,
    inputs: [Arc<dyn ExecutionPlan>; 2],
    reader: Arc<dyn ExecutionPlan>,
    source: Option<Arc<dyn PortSource>>,
    keys: Vec<(usize, usize)>,
    binding: Option<PortKey>,
    demand: Option<PortDemand>,
    image: Option<SourceImage>,
    properties: Arc<PlanProperties>,
}

impl PortExec {
    fn instantiate(plan: Arc<dyn ExecutionPlan>) -> Result<Arc<dyn ExecutionPlan>> {
        crate::parser::Parser::stack(|| {
            let children = plan
                .children()
                .into_iter()
                .map(|child| Self::instantiate(Arc::clone(child)))
                .collect::<Result<Vec<_>>>()?;
            let node = if children.is_empty() {
                plan
            } else {
                // Read identities change. Native plan properties remain the same.
                plan.replace_children(
                    children,
                    ReplaceChildrenOptions::new(ChildrenPropertiesMode::Keep),
                )?
            };
            if let Some(port) = node.downcast_ref::<Self>() {
                let inputs = [
                    Self::instantiate(Arc::clone(&port.inputs[0]))?,
                    Self::instantiate(Arc::clone(&port.inputs[1]))?,
                ];
                let read = SourceProvider::identity()
                    .map_err(|error| DataFusionError::External(Box::new(error)))?;
                let mut reader = SourceData::from_plan(port.reader.as_ref())
                    .filter(|reader| reader.origin == SourceOrigin::Port(port.read))
                    .ok_or_else(|| {
                        DataFusionError::Internal("prepared source reader differs".into())
                    })?
                    .clone();
                reader.origin = SourceOrigin::Port(read);
                return Ok(Arc::new(Self {
                    read,
                    inputs,
                    reader: datafusion::datasource::source::DataSourceExec::from_data_source(
                        reader,
                    ),
                    ..port.clone()
                }) as Arc<dyn ExecutionPlan>);
            }
            if node
                .downcast_ref::<crate::definition::physical::graph::GraphExec>()
                .is_some()
            {
                return node.reset_state();
            }
            if let Some(source) = SourceData::from_plan(node.as_ref()) {
                if source.key.is_some() {
                    return datafusion::common::internal_err!(
                        "prepared source keys are already bound"
                    );
                }
                let mut source = source.clone();
                source.read = SourceProvider::identity()
                    .map_err(|error| DataFusionError::External(Box::new(error)))?;
                return Ok(
                    datafusion::datasource::source::DataSourceExec::from_data_source(source)
                        as Arc<dyn ExecutionPlan>,
                );
            }
            if node.is::<super::keys::KeyBuildExec>() {
                return datafusion::common::internal_err!(
                    "prepared source key producer is already bound"
                );
            }
            node.reset_state()
        })
    }

    async fn bind(
        &self,
        source: &Arc<SourceSnapshot>,
        context: &Arc<TaskContext>,
        owner: &crate::definition::CallContext,
    ) -> Result<()> {
        let native = self
            .source
            .is_none()
            .then(|| source.read_context(context))
            .transpose()?;
        let memory = source.memory.reserve_input(0)?;
        let started = std::time::Instant::now();
        let driver = crate::definition::physical::PackageExec::collect_plan(
            &self.inputs[0],
            self.inputs[0].schema().as_ref(),
            owner,
            context,
            &memory,
            true,
        )
        .await?;
        let driven = std::time::Instant::now();
        if erebor_telemetry::tracing::enabled!(erebor_telemetry::tracing::Level::DEBUG) {
            let mut event_reads = 0usize;
            let mut keyed_events = 0usize;
            let mut projected_joins = 0usize;
            Self::apply(&self.inputs[0], &mut |plan| {
                if plan
                    .downcast_ref::<datafusion::physical_plan::joins::HashJoinExec>()
                    .is_some_and(|join| join.contains_projection())
                {
                    projected_joins += 1;
                }
                if let Some(raw) = SourceData::from_plan(plan.as_ref()) {
                    if raw.origin.durable() == Some("events") {
                        event_reads += 1;
                        keyed_events +=
                            usize::from(raw.image == Some(SourceImage::After) && raw.key.is_some());
                    }
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
            if let Ok(snapshot) = source.snapshot() {
                let cut = snapshot.page.extraction.meta.commit_revision;
                erebor_telemetry::debug!(stage="source_lookup_shape",role=%self.role,
                    family_id=self.family,read_id=self.read,image=?self.image,cut_revision=cut,
                    event_reads,keyed_after_events=keyed_events,projected_hash_joins=projected_joins,
                    driver_rows=driver.iter().map(sdk::RecordBatch::num_rows).sum::<usize>(),
                    "Native qualifier lookup shape completed");
            }
        }
        let header_required = self
            .source
            .as_ref()
            .map(|source| source.header_required(&driver))
            .transpose()?
            .unwrap_or(true);
        let metrics = (header_required
            && self.role == "graph_status"
            && erebor_telemetry::tracing::enabled!(erebor_telemetry::tracing::Level::DEBUG))
        .then(|| metrics::PortMetrics::capture(&self.inputs[1], source))
        .transpose()?;
        let requested = std::time::Instant::now();
        let header = if header_required {
            crate::definition::physical::PackageExec::collect_plan(
                &self.inputs[1],
                self.inputs[1].schema().as_ref(),
                owner,
                context,
                &memory,
                true,
            )
            .await?
        } else {
            Vec::new()
        };
        let headed = std::time::Instant::now();
        if let Some(metrics) = metrics {
            metrics.report(self, source)?;
        }
        let callback = std::time::Instant::now();
        let (data, input, _metadata, derived) = if let Some(reader) = &self.source {
            let PortRead {
                input,
                memory,
                derived,
            } = reader
                .read(
                    self.image,
                    driver,
                    header,
                    Arc::clone(source),
                    Arc::clone(context),
                )
                .await?;
            (input.data.clone(), Some(input), Some(memory), derived)
        } else {
            (
                sdk::Dataset {
                    name: self.role.clone(),
                    batches: driver,
                },
                None,
                None,
                None,
            )
        };
        let converted = std::time::Instant::now();
        if input
            .as_ref()
            .map_or_else(|| data.allocated_bytes(), sdk::Input::allocated_bytes)
            > source.limits.input_bytes
        {
            return Err(datafusion::common::DataFusionError::External(Box::new(
                sdk::Error::contract(sdk::ErrorCode::Limit, "source input bytes"),
            )));
        }
        if data.name != self.role
            || data
                .batches
                .iter()
                .any(|batch| batch.schema() != self.schema)
        {
            return datafusion::common::exec_err!("source output differs");
        }
        source.bind_port(
            self.read,
            Arc::clone(&self.schema),
            data.batches,
            input.as_ref(),
        )?;
        source.bind_lineage(
            self.read,
            &self.inputs[..if header_required { 2 } else { 1 }],
            owner,
            derived,
        )?;
        if let Some((_, control, _lease)) = &native {
            control
                .check()
                .map_err(|source| DataFusionError::External(Box::new(source)))?;
        }
        let bound = std::time::Instant::now();
        if let Ok(snapshot) = source.snapshot() {
            erebor_telemetry::debug!(
                stage = "port_timing", role = %self.role, family_id = self.family,
                read_id = self.read, image = ?self.image,
                cut_revision = snapshot.page.extraction.meta.commit_revision,
                driver_s = driven.duration_since(started).as_secs_f64(),
                header_s = headed.duration_since(requested).as_secs_f64(),
                callback_s = converted.duration_since(callback).as_secs_f64(),
                metrics_s = (requested.duration_since(driven) + callback.duration_since(headed)).as_secs_f64(),
                binding_s = bound.duration_since(converted).as_secs_f64(),
                elapsed_s = bound.duration_since(started).as_secs_f64(),
                "Source port execution timing completed"
            );
        }
        Ok(())
    }

    pub(crate) fn apply(
        plan: &Arc<dyn ExecutionPlan>,
        callback: &mut impl FnMut(&Arc<dyn ExecutionPlan>) -> Result<TreeNodeRecursion>,
    ) -> Result<TreeNodeRecursion> {
        plan.apply(|node| {
            let recursion = callback(node)?;
            if recursion == TreeNodeRecursion::Continue {
                if let Some(port) = node.downcast_ref::<Self>() {
                    for input in &port.inputs {
                        if Self::apply(input, callback)? == TreeNodeRecursion::Stop {
                            return Ok(TreeNodeRecursion::Stop);
                        }
                    }
                }
            }
            Ok(recursion)
        })
    }

    pub(crate) fn transform_down(
        plan: Arc<dyn ExecutionPlan>,
        callback: &mut impl FnMut(Arc<dyn ExecutionPlan>) -> Result<Transformed<Arc<dyn ExecutionPlan>>>,
    ) -> Result<Transformed<Arc<dyn ExecutionPlan>>> {
        plan.transform_down(|node| {
            let mut transformed = callback(node)?;
            if transformed.tnr != TreeNodeRecursion::Continue {
                return Ok(transformed);
            }
            let Some(port) = transformed.data.downcast_ref::<Self>() else {
                return Ok(transformed);
            };
            let mut inputs = port.inputs.clone();
            let mut changed = false;
            let mut recursion = TreeNodeRecursion::Continue;
            for input in &mut inputs {
                let result = Self::transform_down(Arc::clone(input), callback)?;
                *input = result.data;
                changed |= result.transformed;
                recursion = result.tnr;
                if recursion == TreeNodeRecursion::Stop {
                    break;
                }
            }
            if changed {
                transformed.data = port.replace_inputs(inputs)?;
                transformed.transformed = true;
            }
            transformed.tnr = recursion;
            Ok(transformed)
        })
    }

    pub(crate) fn inputs(&self) -> &[Arc<dyn ExecutionPlan>; 2] {
        &self.inputs
    }

    pub(crate) fn replace_inputs(
        &self,
        inputs: [Arc<dyn ExecutionPlan>; 2],
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if inputs
            .iter()
            .zip(&self.inputs)
            .any(|(new, old)| new.schema() != old.schema())
        {
            return datafusion::common::plan_err!("source physical input schema differs");
        }
        Ok(Arc::new(Self {
            inputs,
            ..self.clone()
        }))
    }

    pub(super) fn bind_driver(
        &self,
        driver: Arc<dyn ExecutionPlan>,
        demand: PortDemand,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        Self {
            demand: Some(demand),
            ..self.clone()
        }
        .replace_inputs([driver, Arc::clone(&self.inputs[1])])
    }

    pub(crate) fn is_bound(&self) -> bool {
        self.demand.is_some()
    }

    pub(crate) fn shared_slot(&self) -> Option<usize> {
        self.binding
            .and(self.demand.as_ref().map(|demand| demand.slot))
    }

    pub(crate) fn disable_sharing(&self) -> Arc<dyn ExecutionPlan> {
        Arc::new(Self {
            binding: None,
            ..self.clone()
        })
    }

    pub(crate) fn trace_lookup(&self, slot: usize, bound: bool) {
        if !self.keys.is_empty() {
            erebor_telemetry::debug!(stage="source_lookup_bind",role=%self.role,
                family_id=self.family,read_id=self.read,key_slot=slot,bound,
                driver=self.inputs[0].name(),"Native port key binding completed");
        }
    }

    pub(crate) fn key_columns(&self) -> &[(usize, usize)] {
        &self.keys
    }

    pub(crate) fn driver(&self) -> &Arc<dyn ExecutionPlan> {
        &self.inputs[0]
    }
}

impl fmt::Debug for PortExec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_as(DisplayFormatType::Default, formatter)
    }
}

impl DisplayAs for PortExec {
    fn fmt_as(&self, _: DisplayFormatType, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SourcePortExec: {}", self.role)
    }
}

impl ExecutionPlan for PortExec {
    fn name(&self) -> &str {
        "SourcePortExec"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.reader]
    }

    fn input_distribution_requirements(&self) -> InputDistributionRequirements {
        InputDistributionRequirements::new(vec![Distribution::SinglePartition])
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
        self.replace_children(
            children,
            ReplaceChildrenOptions::new(ChildrenPropertiesMode::Recompute),
        )
    }
    fn replace_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
        _options: ReplaceChildrenOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        let [reader] = children.as_slice() else {
            return datafusion::common::plan_err!("source physical children differ");
        };
        if reader.schema() != self.reader.schema() {
            return datafusion::common::plan_err!("source physical child schema differs");
        }
        Ok(Arc::new(Self {
            reader: Arc::clone(reader),
            ..self.as_ref().clone()
        }))
    }

    fn reset_state(self: Arc<Self>) -> Result<Arc<dyn ExecutionPlan>> {
        self.replace_inputs([
            reset_plan_states(Arc::clone(&self.inputs[0]))?,
            reset_plan_states(Arc::clone(&self.inputs[1]))?,
        ])
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return datafusion::common::exec_err!("source partition differs");
        }
        let node = self.clone();
        let stream = stream::once(async move {
            let source = context
                .session_config()
                .get_extension::<SourceSnapshot>()
                .ok_or_else(|| {
                    datafusion::common::DataFusionError::Execution(
                        "source capture is absent".into(),
                    )
                })?;
            let owner = context
                .session_config()
                .get_extension::<crate::definition::CallContext>()
                .ok_or_else(|| {
                    datafusion::common::DataFusionError::Execution(
                        "source call scope is absent".into(),
                    )
                })?;
            let input = node.clone();
            let captured = Arc::clone(&source);
            let task = Arc::clone(&context);
            let bind = async move { input.bind(&captured, &task, &owner).await };
            if let Some(key) = node.binding {
                source
                    .bind_shared(
                        key,
                        node.demand.as_ref(),
                        node.read,
                        Arc::clone(&node.schema),
                        &context,
                        bind,
                    )
                    .await?;
            } else {
                bind.await?;
            }
            node.reader.execute(partition, context)
        })
        .try_flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            self.schema(),
            stream,
        )))
    }
}
