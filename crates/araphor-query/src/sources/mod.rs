use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    AnalysisTableRequests, StorePositionV1,
};
use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion, TreeNodeVisitor};
use datafusion::common::{DFSchema, DataFusionError, Result, ScalarValue, Statistics};
use datafusion::datasource::source::{DataSource, DataSourceExec};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::logical_expr::{utils::conjunction, Expr, TableProviderFilterPushDown, TableType};
use datafusion::physical_expr::projection::ProjectionExprs;
use datafusion::physical_expr::{analyze, AnalysisContext, EquivalenceProperties, ExprBoundaries};
use datafusion::physical_plan::coop::cooperative;
use datafusion::physical_plan::execution_plan::SchedulingType;
use datafusion::physical_plan::memory::MemoryStream;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayFormatType, ExecutionPlan, Partitioning, SendableRecordBatchStream,
};
use futures_util::StreamExt as _;

use crate::memory::Memory;

#[cfg(test)]
mod bounds;
mod journal;
mod rows;
mod schema;
#[cfg(test)]
mod tests;

pub(crate) use journal::{Changes, JournalExec};
pub use rows::ArrowSnapshot;
pub(crate) use rows::Captured;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SourceOrigin {
    Durable(String),
    Port(usize),
    Package(usize),
    Local(String),
}

impl SourceOrigin {
    pub(crate) fn durable(&self) -> Option<&str> {
        match self {
            Self::Durable(name) => Some(name),
            Self::Port(_) | Self::Package(_) | Self::Local(_) => None,
        }
    }
}

pub(crate) struct InputCapture {
    pub(crate) scope: String,
    pub(crate) bindings: Vec<(usize, sdk::OutputRef, SchemaRef)>,
    pub(crate) limits: sdk::Limits,
    pub(crate) ranges: Vec<(u64, u64)>,
    pub(crate) include_results: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum ReadMode {
    Snapshot,
    Page(Option<StorePositionV1>),
    Metadata,
    Changes(StorePositionV1),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ScanBounds {
    pub(crate) fields: BTreeMap<&'static str, Interval>,
    pub(crate) events: Option<Vec<(u64, u64)>>,
}

#[derive(Default)]
struct ScanFrame {
    inputs: Vec<bool>,
    next: usize,
    required: bool,
    events: bool,
    range: Option<(u64, u64)>,
}

struct SourceScan<'a> {
    requests: &'a mut AnalysisTableRequests,
    bounds: ScanBounds,
    frames: Vec<ScanFrame>,
    scanned: bool,
    complete: bool,
}

impl<'n> TreeNodeVisitor<'n> for SourceScan<'_> {
    type Node = Arc<dyn ExecutionPlan>;

    fn f_down(&mut self, node: &'n Self::Node) -> Result<TreeNodeRecursion> {
        let required = self.frames.last_mut().is_some_and(|parent| {
            let required = parent.inputs.get(parent.next).copied().unwrap_or(false);
            parent.next += 1;
            required
        });
        let inputs = node
            .as_any()
            .downcast_ref::<crate::definition::physical::PackageExec>()
            .map(|package| package.event_inputs())
            .unwrap_or_default();
        let mut frame = ScanFrame {
            inputs,
            required,
            ..Default::default()
        };
        if let Some(source) = SourceData::from_plan(node.as_ref()) {
            if let Some(name) = source.origin.durable() {
                self.requests
                    .get_mut(name)
                    .ok_or_else(|| {
                        DataFusionError::Execution("the physical source was not admitted".into())
                    })?
                    .get_or_insert_with(BTreeSet::new)
                    .extend(source.indices.iter().copied());
                SourceSnapshot::extend_bounds(&mut self.bounds.fields, &source.bounds)?;
                if name == "events" {
                    frame.events = true;
                    self.scanned = true;
                    let interval = &source.bounds["received_utc_ns"];
                    let first = match interval.lower() {
                        ScalarValue::UInt64(Some(value)) => *value,
                        _ => 0,
                    };
                    let last = match interval.upper() {
                        ScalarValue::UInt64(Some(value)) => *value,
                        _ => u64::MAX,
                    };
                    frame.range = Some((first, last));
                }
            }
        }
        self.frames.push(frame);
        Ok(TreeNodeRecursion::Continue)
    }

    fn f_up(&mut self, _node: &'n Self::Node) -> Result<TreeNodeRecursion> {
        let frame = self.frames.pop().ok_or_else(|| {
            DataFusionError::Internal("the physical source scope is absent".into())
        })?;
        self.complete |= frame.required && !frame.events;
        if frame.required || self.frames.is_empty() {
            if let (Some(range), Some(ranges)) = (frame.range, &mut self.bounds.events) {
                ranges.push(range);
            }
        } else if let Some(parent) = self.frames.last_mut() {
            parent.range = match (parent.range, frame.range) {
                (Some((first, last)), Some((next, end))) => Some((first.min(next), last.max(end))),
                (previous, None) => previous,
                (None, next) => next,
            };
        }
        if let Some(parent) = self.frames.last_mut() {
            parent.events |= frame.events;
        }
        Ok(TreeNodeRecursion::Continue)
    }
}

pub(crate) struct SourceSnapshot {
    store: Arc<AnalysisStore>,
    selection: AnalysisSelectionV1,
    inputs: Option<InputCapture>,
    managed: Option<araphor_data::ManagedRead>,
    limits: AnalysisExtractLimits,
    control: AnalysisReadControl,
    extract_timeout: Option<Duration>,
    now: u64,
    memory: Arc<Memory>,
    captured: Mutex<Option<rows::Captured>>,
}

impl std::fmt::Debug for SourceSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceSnapshot")
            .field("tenant", &self.selection.tenant_id)
            .finish_non_exhaustive()
    }
}

impl SourceSnapshot {
    pub(crate) fn requests(
        requests: &mut AnalysisTableRequests,
        plans: &[Arc<dyn ExecutionPlan>],
    ) -> Result<ScanBounds> {
        let events = requests.contains_key("events").then(Vec::new);
        let mut scan = SourceScan {
            requests,
            bounds: ScanBounds {
                events,
                ..Default::default()
            },
            frames: Vec::new(),
            scanned: false,
            complete: false,
        };
        for plan in plans {
            plan.visit(&mut scan)?;
        }
        if scan.complete {
            scan.bounds.fields.remove("source_cursor");
        }
        if let Some(events) = &mut scan.bounds.events {
            if scan.complete || !scan.scanned {
                *events = vec![(0, u64::MAX)];
            } else {
                events.sort_unstable();
                events.dedup();
            }
        }
        Ok(scan.bounds)
    }

    pub(crate) fn extend_bounds(
        bounds: &mut BTreeMap<&'static str, Interval>,
        added: &BTreeMap<&'static str, Interval>,
    ) -> Result<()> {
        for (&field, interval) in added {
            let interval = match bounds.remove(field) {
                Some(previous) => previous.union(interval.clone())?,
                None => interval.clone(),
            };
            bounds.insert(field, interval);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: Arc<AnalysisStore>,
        selection: AnalysisSelectionV1,
        inputs: Option<InputCapture>,
        limits: AnalysisExtractLimits,
        control: AnalysisReadControl,
        extract_timeout: Option<Duration>,
        now: u64,
        memory: Arc<Memory>,
        managed: Option<araphor_data::ManagedRead>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            selection,
            inputs,
            managed,
            limits,
            control,
            extract_timeout,
            now,
            memory,
            captured: Mutex::new(None),
        })
    }

    pub(crate) fn providers() -> BTreeMap<String, Arc<dyn TableProvider>> {
        Self::schemas()
            .iter()
            .map(|(name, schema)| {
                let provider: Arc<dyn TableProvider> = Arc::new(SourceProvider {
                    origin: SourceOrigin::Durable(name.clone()),
                    schema: Arc::clone(schema),
                });
                (name.clone(), provider)
            })
            .collect()
    }

    pub(crate) fn capture(
        &self,
        requests: &AnalysisTableRequests,
        mut bounds: ScanBounds,
        mode: ReadMode,
    ) -> Result<Arc<ArrowSnapshot>> {
        if let Some(ranges) = bounds
            .events
            .as_deref()
            .or_else(|| self.inputs.as_ref().map(|inputs| inputs.ranges.as_slice()))
        {
            let window = ranges
                .iter()
                .copied()
                .reduce(|(first, last), (next, end)| (first.min(next), last.max(end)));
            let received = match window.filter(|_| {
                !requests.contains_key("trace_output")
                    && !requests.contains_key("trace_measurements")
            }) {
                Some((first, last)) => Some(Interval::try_new(
                    ScalarValue::UInt64(Some(first)),
                    ScalarValue::UInt64(Some(last)),
                )?),
                None => None,
            };
            bounds.fields.remove("received_utc_ns");
            if let Some(received) = received {
                bounds.fields.insert("received_utc_ns", received);
            }
        }
        let control = self
            .control
            .within(self.extract_timeout)
            .map_err(Self::data_error)?;
        control.check().map_err(Self::data_error)?;
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        if let Some(snapshot) = captured.as_ref() {
            return Ok(Arc::clone(&snapshot.receipt));
        }
        let snapshot = self.read(requests, &bounds, mode, &control)?;
        let receipt = Arc::clone(&snapshot.receipt);
        *captured = Some(snapshot);
        Ok(receipt)
    }

    pub(crate) fn capture_metadata(
        &self,
        sources: &AnalysisTableRequests,
    ) -> Result<Arc<ArrowSnapshot>> {
        let requests = sources.keys().map(|name| (name.clone(), None)).collect();
        self.capture(&requests, ScanBounds::default(), ReadMode::Metadata)
    }

    fn data_error(error: araphor_data::Error) -> DataFusionError {
        DataFusionError::External(Box::new(error))
    }

    pub(crate) fn prune_selection(
        mut selection: AnalysisSelectionV1,
        bounds: &ScanBounds,
    ) -> AnalysisSelectionV1 {
        let time = selection.time_range();
        let cursor = selection.cursor_range();
        for (field, range, from, until) in [
            (
                "received_utc_ns",
                time,
                &mut selection.received_from,
                &mut selection.received_until,
            ),
            (
                "source_cursor",
                cursor,
                &mut selection.cursor_from,
                &mut selection.cursor_until,
            ),
        ] {
            if let (Some(interval), Some((first, last))) = (bounds.fields.get(field), range) {
                let lower = match interval.lower() {
                    ScalarValue::UInt64(Some(value)) => *value,
                    _ => 0,
                };
                let upper = match interval.upper() {
                    ScalarValue::UInt64(Some(value)) => *value,
                    _ => u64::MAX,
                };
                if lower > first {
                    *from = Bound::Included(lower);
                }
                if upper < last {
                    *until = Bound::Included(upper);
                }
            }
        }
        selection
    }
}

#[derive(Debug)]
pub struct SourceProvider {
    pub(crate) origin: SourceOrigin,
    schema: SchemaRef,
}

impl SourceProvider {
    pub fn local(name: &str, schema: SchemaRef) -> Arc<dyn TableProvider> {
        Arc::new(Self {
            origin: SourceOrigin::Local(name.to_owned()),
            schema,
        })
    }

    pub(crate) fn port(port: usize, schema: SchemaRef) -> Arc<dyn TableProvider> {
        Arc::new(Self {
            origin: SourceOrigin::Port(port),
            schema,
        })
    }

    pub(crate) fn package(slot: usize, schema: SchemaRef) -> Arc<dyn TableProvider> {
        Arc::new(Self {
            origin: SourceOrigin::Package(slot),
            schema,
        })
    }

    fn bounds(
        &self,
        session: &dyn Session,
        filters: &[Expr],
    ) -> Result<BTreeMap<&'static str, Interval>> {
        let unbounded = Interval::make_unbounded(&datafusion::arrow::datatypes::DataType::UInt64)?;
        let mut bounds = BTreeMap::from([
            ("received_utc_ns", unbounded.clone()),
            ("source_cursor", unbounded),
        ]);
        let Some(predicate) = conjunction(filters.iter().cloned()) else {
            return Ok(bounds);
        };
        let schema = DFSchema::try_from(self.schema.as_ref().clone())?;
        let predicate = session.create_physical_expr(predicate, &schema)?;
        let initial = AnalysisContext::new(ExprBoundaries::try_new_unbounded(&self.schema)?);
        let Ok(context) = analyze(&predicate, initial, &self.schema) else {
            // DataFusion keeps the residual filter when interval analysis cannot apply.
            return Ok(bounds);
        };
        for boundary in context.boundaries {
            let Some(interval) = boundary.interval else {
                continue;
            };
            let narrowed = match boundary.column.name() {
                "received_utc_ns" => Some(("received_utc_ns", interval)),
                "source_cursor" => Some(("source_cursor", interval)),
                "received_at" => {
                    let convert = |value: &ScalarValue, upper: bool| match value {
                        ScalarValue::TimestampMicrosecond(Some(value), _) => {
                            let nanos = i128::from(*value) * 1000 + if upper { 999 } else { 0 };
                            ScalarValue::UInt64(Some(nanos.clamp(0, i128::from(u64::MAX)) as u64))
                        }
                        _ => ScalarValue::UInt64(None),
                    };
                    Some((
                        "received_utc_ns",
                        Interval::try_new(
                            convert(interval.lower(), false),
                            convert(interval.upper(), true),
                        )?,
                    ))
                }
                _ => None,
            };
            if let Some((field, interval)) = narrowed {
                let previous = &bounds[field];
                let interval = previous.intersect(interval)?.unwrap_or(Interval::try_new(
                    ScalarValue::UInt64(Some(0)),
                    ScalarValue::UInt64(Some(0)),
                )?);
                bounds.insert(field, interval);
            }
        }
        Ok(bounds)
    }
}

#[async_trait]
impl TableProvider for SourceProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
    fn table_type(&self) -> TableType {
        TableType::Base
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> Result<Vec<TableProviderFilterPushDown>> {
        Ok(vec![
            if self.origin.durable() == Some("events") {
                TableProviderFilterPushDown::Inexact
            } else {
                TableProviderFilterPushDown::Unsupported
            };
            filters.len()
        ])
    }

    async fn scan(
        &self,
        session: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        if let SourceOrigin::Local(name) = &self.origin {
            let tables = session
                .config()
                .get_extension::<crate::execution::LocalTables>()
                .ok_or_else(|| {
                    DataFusionError::Execution("local input tables are absent".into())
                })?;
            let (table, _) = tables
                .get(name)
                .ok_or_else(|| DataFusionError::Execution("local input table is absent".into()))?;
            if table.schema() != self.schema {
                return Err(DataFusionError::Execution(
                    "local input schema changed".into(),
                ));
            }
            return table.scan(session, projection, filters, limit).await;
        }
        let indices = projection
            .cloned()
            .unwrap_or_else(|| (0..self.schema.fields().len()).collect());
        Ok(DataSourceExec::from_data_source(SourceData {
            origin: self.origin.clone(),
            schema: Arc::new(self.schema.project(&indices)?),
            indices,
            bounds: if self.origin.durable() == Some("events") {
                self.bounds(session, filters)?
            } else {
                BTreeMap::new()
            },
            fetch: limit,
        }))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SourceData {
    pub(crate) origin: SourceOrigin,
    schema: SchemaRef,
    indices: Vec<usize>,
    bounds: BTreeMap<&'static str, Interval>,
    fetch: Option<usize>,
}

impl SourceData {
    pub(crate) fn from_plan(plan: &dyn ExecutionPlan) -> Option<&Self> {
        plan.as_any()
            .downcast_ref::<DataSourceExec>()?
            .data_source()
            .as_any()
            .downcast_ref::<Self>()
    }
}

impl DataSource for SourceData {
    fn open(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        if partition != 0 {
            return Err(DataFusionError::Execution(
                "source has one partition".into(),
            ));
        }
        let snapshot = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| {
                DataFusionError::Execution("the native task has no source snapshot".into())
            })?;
        let captured = snapshot
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let batches = captured
            .as_ref()
            .ok_or_else(|| {
                DataFusionError::Execution(
                    "the source snapshot was not captured before execution".into(),
                )
            })?
            .project(&self.origin, &self.indices, &self.schema)?;
        drop(captured);
        let stream = cooperative(
            MemoryStream::try_new(batches, Arc::clone(&self.schema), None)?.with_fetch(self.fetch),
        )
        .map(move |batch| {
            let _snapshot = &snapshot;
            batch
        });
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        )))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn fmt_as(
        &self,
        _format: DisplayFormatType,
        formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
        write!(
            formatter,
            "source={:?}, projection={:?}",
            self.origin, self.indices
        )
    }

    fn output_partitioning(&self) -> Partitioning {
        Partitioning::UnknownPartitioning(1)
    }

    fn eq_properties(&self) -> EquivalenceProperties {
        EquivalenceProperties::new(Arc::clone(&self.schema))
    }

    fn scheduling_type(&self) -> SchedulingType {
        SchedulingType::Cooperative
    }

    fn partition_statistics(&self, _partition: Option<usize>) -> Result<Statistics> {
        Ok(Statistics::new_unknown(&self.schema))
    }

    fn with_fetch(&self, fetch: Option<usize>) -> Option<Arc<dyn DataSource>> {
        let mut source = self.clone();
        source.fetch = fetch;
        Some(Arc::new(source))
    }

    fn fetch(&self) -> Option<usize> {
        self.fetch
    }

    fn try_swapping_with_projection(
        &self,
        _projection: &ProjectionExprs,
    ) -> Result<Option<Arc<dyn DataSource>>> {
        Ok(None)
    }
}

impl ArrowSnapshot {
    pub(crate) fn check_store(
        previous: &araphor_data::AnalysisStoreMetaV1,
        current: &araphor_data::AnalysisStoreMetaV1,
    ) -> crate::Result<()> {
        if previous.store_uuid != current.store_uuid
            || previous.schema_version != current.schema_version
            || previous.recovery_epoch != current.recovery_epoch
            || previous.commit_revision > current.commit_revision
        {
            return crate::InvalidSnafu {
                field: "cursor store",
            }
            .fail();
        }
        Ok(())
    }
}
