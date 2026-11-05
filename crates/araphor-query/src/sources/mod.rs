use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    AnalysisTableRead, AnalysisTableRequests, StorePositionV1,
};
use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion, TreeNodeVisitor};
use datafusion::common::{DFSchema, DataFusionError, Result, ScalarValue, Statistics};
use datafusion::datasource::source::{DataSource, DataSourceExec};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::logical_expr::{
    utils::conjunction, Expr, Operator, TableProviderFilterPushDown, TableType,
};
use datafusion::physical_expr::projection::ProjectionExprs;
use datafusion::physical_expr::{
    analyze, AnalysisContext, EquivalenceProperties, ExprBoundaries, PhysicalExpr,
};
use datafusion::physical_plan::coop::cooperative;
use datafusion::physical_plan::execution_plan::SchedulingType;
use datafusion::physical_plan::memory::MemoryStream;
use datafusion::physical_plan::metrics::ExecutionPlanMetricsSet;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayFormatType, ExecutionPlan, Partitioning, SendableRecordBatchStream,
};
use futures_util::StreamExt as _;

use crate::memory::Memory;

mod append;
pub(crate) use append::AppendRead;

#[cfg(test)]
mod bounds;
mod index;
mod keys;
pub(crate) use keys::{KeyRead, SourceJoin, SourceLookup};
mod journal;
pub use index::SourceImage;
pub(crate) use index::{SourceIndex, SourceKey, SourceView};
mod port;
mod rows;
pub(crate) use port::PortExec;
pub use port::{PortRead, PortSource, SourcePort};
mod lineage;
mod schema;
#[cfg(test)]
mod tests;
mod work;

pub(crate) use journal::Changes;
pub use rows::ArrowSnapshot;
pub(crate) use rows::{Captured, CapturedRequests, MetadataRead};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum SourceOrigin {
    Durable(String),
    Port(usize),
    Local(String),
}

impl SourceOrigin {
    fn name(&self) -> &str {
        match self {
            Self::Durable(name) | Self::Local(name) => name,
            Self::Port(_) => "port",
        }
    }

    pub(crate) fn durable(&self) -> Option<&str> {
        match self {
            Self::Durable(name) => Some(name),
            Self::Port(_) | Self::Local(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReadMode {
    Snapshot,
    Page(Option<StorePositionV1>),
    Metadata,
    Changes(StorePositionV1),
}

pub(crate) type WindowBound = (
    crate::follow::WindowSource,
    crate::follow::Window,
    (u64, u64),
    Option<i64>,
);

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ScanBounds {
    pub(crate) canonical_events: bool,
    pub(crate) fields: BTreeMap<&'static str, Interval>,
    pub(crate) events: Option<Vec<(u64, u64)>>,
    pub(crate) windows: Vec<WindowBound>,
    pub(crate) ports: BTreeSet<usize>,
    pub(crate) qualified: BTreeMap<usize, BTreeSet<usize>>,
    pub(crate) context_owners: Option<BTreeSet<String>>,
    pub(crate) context_images: BTreeSet<Option<SourceImage>>,
}

#[derive(Default)]
struct ScanFrame {
    inputs: Vec<(bool, Option<crate::follow::Window>)>,
    next: usize,
    call: Option<u64>,
    source: Option<crate::follow::WindowSource>,
    scoped: bool,
    required: bool,
    window: Option<crate::follow::Window>,
    events: bool,
    range: Option<(u64, u64)>,
    fulfilled: bool,
}

struct SourceScan<'a> {
    requests: &'a mut AnalysisTableRequests,
    bounds: ScanBounds,
    frames: Vec<ScanFrame>,
    scanned: bool,
    complete: bool,
    window: Option<crate::follow::Window>,
    moving: bool,
    context_seen: bool,
    calls: Option<&'a crate::definition::CallContext>,
    skipped: bool,
}

impl<'n> TreeNodeVisitor<'n> for SourceScan<'_> {
    type Node = Arc<dyn ExecutionPlan>;

    fn f_down(&mut self, node: &'n Self::Node) -> Result<TreeNodeRecursion> {
        let input = self.frames.last_mut().and_then(|parent| {
            let slot = parent.next;
            let input = parent.inputs.get(slot).cloned().map(|input| {
                (
                    input,
                    parent
                        .call
                        .map(|call| crate::follow::WindowSource::Input { call, slot }),
                )
            });
            parent.next += 1;
            input
        });
        let scoped = input.is_some();
        let ((required, window), source) = input.unwrap_or((
            (
                false,
                self.frames
                    .is_empty()
                    .then(|| self.window.clone())
                    .flatten(),
            ),
            self.frames
                .is_empty()
                .then_some(crate::follow::WindowSource::Query),
        ));
        let package = node.downcast_ref::<crate::definition::physical::PackageExec>();
        if package
            .map(|package| {
                self.calls
                    .map_or(Ok(false), |calls| calls.cached(package.logical_call()))
            })
            .transpose()?
            .unwrap_or(false)
        {
            self.skipped = true;
            self.frames.push(ScanFrame {
                fulfilled: true,
                ..Default::default()
            });
            return Ok(TreeNodeRecursion::Jump);
        }
        self.bounds.canonical_events |= package.is_some_and(|package| {
            package
                .logical_call()
                .model()
                .is_some_and(|model| model.graph.is_some())
        });
        if let Some(port) = node.downcast_ref::<PortExec>() {
            self.bounds
                .qualified
                .entry(port.family)
                .or_default()
                .insert(port.read);
        }
        if let Some(port) = node.downcast_ref::<crate::definition::physical::graph::GraphExec>() {
            self.bounds
                .qualified
                .entry(port.family)
                .or_default()
                .insert(port.read);
        }
        let inputs = package
            .map(|package| package.event_inputs(self.moving))
            .transpose()?
            .unwrap_or_default();
        let mut frame = ScanFrame {
            inputs,
            call: package.map(|package| package.call_id()),
            source,
            scoped: required || (self.moving && scoped),
            required,
            window,
            ..Default::default()
        };
        if let Some(source) = SourceData::from_plan(node.as_ref()) {
            if let SourceOrigin::Port(slot) = source.origin {
                self.bounds.ports.insert(slot);
            }
            if let Some(name) = source.origin.durable() {
                if name == "context_versions" {
                    self.bounds.context_images.insert(source.image);
                }
                self.requests
                    .get_mut(name)
                    .ok_or_else(|| {
                        DataFusionError::Execution("the physical source was not admitted".into())
                    })?
                    .get_or_insert_with(BTreeSet::new)
                    .extend(source.indices.iter().copied());
                SourceSnapshot::extend_bounds(&mut self.bounds.fields, &source.bounds)?;
                if matches!(
                    name,
                    "context_versions"
                        | "context"
                        | "targets"
                        | "compiled_policies"
                        | "notification_routes"
                ) {
                    let owners = (name == "context_versions")
                        .then(|| source.context_owners.clone())
                        .flatten();
                    if self.context_seen {
                        self.bounds.context_owners = match (&self.bounds.context_owners, owners) {
                            (Some(previous), Some(next)) => {
                                Some(previous.union(&next).cloned().collect())
                            }
                            _ => None,
                        };
                    } else {
                        self.bounds.context_owners = owners;
                        self.context_seen = true;
                    }
                }
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
        if let Some(port) = node.downcast_ref::<PortExec>() {
            for input in port.inputs() {
                if input.visit(self)? == TreeNodeRecursion::Stop {
                    return Ok(TreeNodeRecursion::Stop);
                }
            }
        }
        Ok(TreeNodeRecursion::Continue)
    }

    fn f_up(&mut self, _node: &'n Self::Node) -> Result<TreeNodeRecursion> {
        let frame = self.frames.pop().ok_or_else(|| {
            DataFusionError::Internal("the physical source scope is absent".into())
        })?;
        self.complete |= frame.required && !frame.events && !frame.fulfilled;
        if frame.scoped || self.frames.is_empty() {
            if let (Some(range), Some(ranges)) = (frame.range, &mut self.bounds.events) {
                ranges.push(range);
                if let Some(window) = frame.window {
                    self.bounds.windows.push((
                        frame.source.unwrap_or(crate::follow::WindowSource::Query),
                        window,
                        range,
                        None,
                    ));
                }
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
            parent.fulfilled |= frame.fulfilled;
        }
        Ok(TreeNodeRecursion::Continue)
    }
}

pub struct SourceSnapshot {
    store: Arc<AnalysisStore>,
    selection: AnalysisSelectionV1,
    managed: Option<araphor_data::ManagedRead>,
    reference: OnceLock<Arc<araphor_data::ManagedAttempt>>,
    attempt: OnceLock<Arc<araphor_data::ManagedAttempt>>,
    limits: AnalysisExtractLimits,
    control: AnalysisReadControl,
    extract_timeout: Option<Duration>,
    now: u64,
    memory: Arc<Memory>,
    captured: Mutex<Option<rows::Captured>>,
    index: Mutex<Option<Arc<SourceIndex>>>,
    append: Mutex<Option<Arc<AppendRead>>>,
    view: Mutex<Option<Arc<SourceView>>>,
    reads: Mutex<BTreeMap<usize, lineage::NativeRead>>,
    keys: Mutex<BTreeMap<usize, Arc<keys::KeySlot>>>,
    work: ExecutionPlanMetricsSet,
    reported: AtomicBool,
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
        run: Option<&crate::stream::Run>,
        calls: Option<&crate::definition::CallContext>,
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
            window: run.and_then(|run| run.window.clone()),
            moving: run.is_some_and(|run| run.follow || run.managed.is_some()),
            context_seen: false,
            calls,
            skipped: false,
        };
        for plan in plans {
            plan.visit(&mut scan)?;
        }
        if scan.skipped {
            scan.requests.retain(|_, columns| columns.is_some());
            if !scan.requests.contains_key("events") {
                scan.bounds.events = None;
            }
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
        if !scan.bounds.windows.is_empty() {
            let column = Self::schemas()["events"].index_of("received_utc_ns")?;
            scan.requests
                .get_mut("events")
                .ok_or_else(|| DataFusionError::Internal("window source is absent".into()))?
                .get_or_insert_with(BTreeSet::new)
                .insert(column);
        }
        Ok(scan.bounds)
    }

    pub(crate) fn project_requests(
        requests: &mut AnalysisTableRequests,
        bounds: &mut ScanBounds,
        indexed: bool,
    ) -> Result<()> {
        if !requests
            .get("context_versions")
            .is_some_and(Option::is_some)
        {
            bounds.context_owners = None;
        }
        if indexed && bounds.events.is_some() {
            bounds.events = Some(vec![(0, u64::MAX)]);
        }
        if !indexed && !bounds.canonical_events {
            return Ok(());
        }
        if indexed {
            bounds.fields.clear();
        }
        for (name, columns) in requests {
            if let Some(columns) = columns {
                let schema = &Self::schemas()[name];
                if let Some(names) = schema
                    .fields()
                    .first()
                    .and_then(|field| field.metadata().get("araphor.join_keys"))
                {
                    for name in names.split(',') {
                        columns.insert(schema.index_of(name)?);
                    }
                }
                for name in ["commit_revision", "ordinal", "received_utc_ns"] {
                    if let Ok(index) = schema.index_of(name) {
                        columns.insert(index);
                    }
                }
                if name == "events" && bounds.canonical_events {
                    columns.insert(schema.index_of("framed_record")?);
                }
            }
        }
        Ok(())
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
            managed,
            reference: OnceLock::new(),
            attempt: OnceLock::new(),
            limits,
            control,
            extract_timeout,
            now,
            memory,
            captured: Mutex::new(None),
            index: Mutex::new(None),
            append: Mutex::new(None),
            view: Mutex::new(None),
            reads: Mutex::new(BTreeMap::new()),
            keys: Mutex::new(BTreeMap::new()),
            work: ExecutionPlanMetricsSet::new(),
            reported: AtomicBool::new(false),
        })
    }

    pub(crate) fn bind_tables(
        tables: &crate::execution::LocalTables,
    ) -> crate::Result<BTreeMap<String, Arc<dyn TableProvider>>> {
        let mut sources = Self::providers();
        for (name, table) in tables {
            let provider = match table {
                crate::execution::TableBinding::Rows { table, .. } => {
                    SourceProvider::local(name, table.schema())
                }
                crate::execution::TableBinding::Provider(provider) => Arc::clone(provider),
            };
            if sources.insert(name.clone(), provider).is_some() {
                return crate::InvalidSnafu {
                    field: "definition source binding",
                }
                .fail();
            }
        }
        Ok(sources)
    }

    pub(crate) fn providers() -> BTreeMap<String, Arc<dyn TableProvider>> {
        Self::schemas()
            .iter()
            .map(|(name, schema)| {
                let provider: Arc<dyn TableProvider> = Arc::new(SourceProvider {
                    origin: SourceOrigin::Durable(name.clone()),
                    schema: Arc::clone(schema),
                    image: None,
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
        if let Some(ranges) = bounds.events.as_deref() {
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
        let mut snapshot = self.read(requests, &bounds, mode, &control)?;
        if let Some(index) = self
            .index
            .lock()
            .map_err(|_| DataFusionError::Internal("source index lock is poisoned".into()))?
            .as_ref()
        {
            let frame = snapshot
                .receipt
                .managed()
                .and_then(|managed| managed.source())
                .cloned()
                .ok_or_else(|| {
                    DataFusionError::Execution("the managed source frame is absent".into())
                })?;
            let view = index.stage(frame, &self.control)?;
            control.check().map_err(Self::data_error)?;
            *self
                .view
                .lock()
                .map_err(|_| DataFusionError::Internal("source view lock is poisoned".into()))? =
                Some(view);
        }
        let mut deadline = snapshot.receipt.next_change;
        let mut windows = Vec::new();
        for (scope, window, range, clock) in bounds.windows {
            let now = clock
                .map(u64::try_from)
                .transpose()
                .map_err(|_| DataFusionError::Execution("window statement time".into()))?
                .unwrap_or(self.now);
            let Some(selected) = window
                .selection(&snapshot.receipt.selection, now)
                .time_range()
            else {
                continue;
            };
            let range = (range.0.max(selected.0), range.1.min(selected.1));
            if range.0 <= range.1 {
                let received = snapshot.received_min(range, &control)?;
                let expiry = if let Some((start, end)) = window.fixed_range(now)? {
                    windows.push(crate::follow::WindowRange {
                        source: scope,
                        start_utc_ns: start,
                        end_utc_ns: end,
                        active: received.is_some(),
                    });
                    received.and_then(|_| u64::try_from(end).ok())
                } else {
                    window.expiry(received)
                };
                deadline = deadline.into_iter().chain(expiry).min();
            }
        }
        windows.sort_by_key(|window| (window.source, window.start_utc_ns, window.end_utc_ns));
        windows.dedup_by(|next, previous| {
            if (next.source, next.start_utc_ns, next.end_utc_ns)
                == (previous.source, previous.start_utc_ns, previous.end_utc_ns)
            {
                previous.active |= next.active;
                true
            } else {
                false
            }
        });
        let receipt = Arc::get_mut(&mut snapshot.receipt).ok_or_else(|| {
            DataFusionError::Internal("the source receipt is already shared".into())
        })?;
        receipt.set_windows(windows)?;
        receipt.next_change = deadline;
        let receipt = Arc::clone(&snapshot.receipt);
        *captured = Some(snapshot);
        Ok(receipt)
    }

    fn data_error(error: araphor_data::Error) -> DataFusionError {
        DataFusionError::External(Box::new(error))
    }

    pub(crate) fn bind_append(&self, append: Arc<AppendRead>) -> Result<()> {
        *self.append.lock().map_err(|_| {
            DataFusionError::Internal("the append reader binding is poisoned".into())
        })? = Some(append);
        Ok(())
    }

    pub(crate) fn bind_index(&self, index: Arc<SourceIndex>) -> Result<()> {
        let captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        if captured.is_some() {
            return Err(DataFusionError::Execution(
                "the source capture has already started".into(),
            ));
        }
        let mut current = self
            .index
            .lock()
            .map_err(|_| DataFusionError::Internal("source index lock is poisoned".into()))?;
        if current
            .as_ref()
            .is_some_and(|current| !Arc::ptr_eq(current, &index))
        {
            return Err(DataFusionError::Execution(
                "the source index binding differs".into(),
            ));
        }
        *current = Some(index);
        Ok(())
    }

    pub(crate) fn bind_reference(
        &self,
        reference: Arc<araphor_data::ManagedAttempt>,
    ) -> Result<()> {
        if self.attempt.get().is_some() {
            return Err(DataFusionError::Execution(
                "the current attempt is already bound".into(),
            ));
        }
        self.reference.set(reference).map_err(|_| {
            DataFusionError::Execution("the journal reference is already bound".into())
        })
    }

    pub(crate) fn bind_attempt(&self, attempt: Arc<araphor_data::ManagedAttempt>) -> Result<()> {
        if self.reference.get().is_some() {
            return Err(DataFusionError::Execution(
                "the historical reference is already bound".into(),
            ));
        }
        self.snapshot()?
            .managed()
            .ok_or_else(|| DataFusionError::Execution("the managed capture is absent".into()))?
            .check_current(&attempt)
            .map_err(Self::data_error)?;
        self.attempt
            .set(attempt)
            .map_err(|_| DataFusionError::Execution("the current attempt is already bound".into()))
    }

    pub(crate) fn attempt(&self) -> Option<&Arc<araphor_data::ManagedAttempt>> {
        self.attempt.get()
    }

    pub(crate) fn graph_store(&self) -> &Arc<AnalysisStore> {
        &self.store
    }

    pub(crate) fn source_view(&self) -> Result<Option<Arc<SourceView>>> {
        Ok(self
            .view
            .lock()
            .map_err(|_| DataFusionError::Internal("source view lock is poisoned".into()))?
            .clone())
    }

    fn point_image(&self, view: &SourceView) -> Result<SourceImage> {
        view.image_at(
            self.snapshot()?.page.extraction.meta.commit_revision,
            self.reference
                .get()
                .and_then(|reference| reference.receipt().map(|receipt| &receipt.selected)),
        )
    }

    pub fn check_point(
        &self,
        plans: &[Arc<dyn ExecutionPlan>],
        context: &TaskContext,
    ) -> Result<()> {
        let point = match self.source_view()? {
            Some(view) => self.point_image(&view)?,
            None => SourceImage::After,
        };
        let calls = context
            .session_config()
            .get_extension::<crate::definition::CallContext>();
        for plan in plans {
            PortExec::apply(plan, &mut |node| {
                if let (Some(package), Some(calls)) = (
                    node.downcast_ref::<crate::definition::physical::PackageExec>(),
                    calls.as_ref(),
                ) {
                    if calls.cached(package.logical_call())? {
                        return Ok(TreeNodeRecursion::Jump);
                    }
                }
                if SourceData::from_plan(node.as_ref()).is_some_and(|source| {
                    source.origin.durable().is_some()
                        && source.image.is_some_and(|image| image != point)
                }) {
                    return Err(DataFusionError::Execution(
                        "the composite source image differs from its captured point".into(),
                    ));
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(())
    }

    fn record_read(
        &self,
        id: usize,
        image: SourceImage,
        rows: Vec<araphor_data::ManagedSourceRows>,
    ) -> Result<()> {
        if matches!(image, SourceImage::After | SourceImage::Inserted) {
            let view = self
                .source_view()?
                .ok_or_else(|| DataFusionError::Internal("the source view is absent".into()))?;
            for selected in &rows {
                view.frame()
                    .record_rows(selected)
                    .map_err(Self::data_error)?;
            }
        }
        let mut reads = self
            .reads
            .lock()
            .map_err(|_| DataFusionError::Internal("source read lock is poisoned".into()))?;
        let bytes =
            std::mem::size_of::<lineage::NativeRead>().saturating_add(rows.len().saturating_mul(
                std::mem::size_of::<Arc<araphor_data::ManagedSourceRows>>()
                    + 2 * std::mem::size_of::<usize>(),
            ));
        let memory = self.memory.reserve_input(bytes)?;
        let read = reads.entry(id).or_insert_with(|| lineage::NativeRead {
            image,
            rows: Vec::new(),
            _memory: Vec::new(),
        });
        if read.image != image {
            return Err(DataFusionError::Internal(
                "the source read image differs".into(),
            ));
        }
        read.rows.extend(rows.into_iter().map(Arc::new));
        read._memory.push(memory);
        Ok(())
    }

    pub(crate) fn context_revision(&self, bounds: &ScanBounds) -> Result<Option<Option<u64>>> {
        let Some(view) = self.source_view()? else {
            return Ok(None);
        };
        let point = self.point_image(&view)?;
        if bounds
            .context_images
            .iter()
            .flatten()
            .any(|image| *image != point)
        {
            return Ok(Some(None));
        }
        Ok(Some(view.context_revision(point)))
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
    image: Option<SourceImage>,
}

impl SourceProvider {
    pub(crate) fn image(&self, image: SourceImage) -> Result<Arc<dyn TableProvider>> {
        if self.origin.durable().is_none() {
            return Err(DataFusionError::NotImplemented(
                "source image for a materialized port".into(),
            ));
        }
        Ok(Arc::new(Self {
            origin: self.origin.clone(),
            schema: Arc::clone(&self.schema),
            image: Some(image),
        }))
    }
    fn context_owner_filter(expression: &Expr) -> Option<BTreeSet<String>> {
        let owner = |expression: &Expr| matches!(expression, Expr::Column(column) if column.name == "owner_id");
        let literal = |expression: &Expr| match expression {
            Expr::Literal(ScalarValue::Utf8(Some(value)), _) => Some(value.clone()),
            _ => None,
        };
        match expression {
            Expr::InList(list) if !list.negated && owner(&list.expr) => {
                list.list.iter().map(literal).collect()
            }
            Expr::BinaryExpr(binary) if binary.op == Operator::Eq => owner(&binary.left)
                .then(|| literal(&binary.right))
                .flatten()
                .or_else(|| {
                    owner(&binary.right)
                        .then(|| literal(&binary.left))
                        .flatten()
                })
                .map(|value| BTreeSet::from([value])),
            Expr::BinaryExpr(binary) if binary.op == Operator::Or => {
                let left = Self::context_owner_filter(&binary.left)?;
                let right = Self::context_owner_filter(&binary.right)?;
                Some(left.union(&right).cloned().collect())
            }
            _ => None,
        }
    }

    fn context_owners(filters: &[Expr]) -> Option<BTreeSet<String>> {
        filters
            .iter()
            .filter_map(Self::context_owner_filter)
            .reduce(|left, right| left.intersection(&right).cloned().collect())
    }

    pub fn local(name: &str, schema: SchemaRef) -> Arc<dyn TableProvider> {
        Arc::new(Self {
            origin: SourceOrigin::Local(name.to_owned()),
            schema,
            image: None,
        })
    }

    pub(crate) fn port(port: usize, schema: SchemaRef) -> Arc<dyn TableProvider> {
        Arc::new(Self {
            origin: SourceOrigin::Port(port),
            schema,
            image: None,
        })
    }

    pub(crate) fn identity() -> crate::Result<usize> {
        static PORTS: AtomicUsize = AtomicUsize::new(0);
        PORTS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| {
                crate::InvalidSnafu {
                    field: "package relation identity",
                }
                .build()
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
        Ok(filters
            .iter()
            .map(|filter| {
                if self.origin.durable() == Some("events")
                    || (self.origin.durable() == Some("context_versions")
                        && Self::context_owner_filter(filter).is_some())
                {
                    TableProviderFilterPushDown::Inexact
                } else {
                    TableProviderFilterPushDown::Unsupported
                }
            })
            .collect())
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
            let crate::execution::TableBinding::Rows { table, .. } = tables
                .get(name)
                .ok_or_else(|| DataFusionError::Execution("local input table is absent".into()))?
            else {
                return Err(DataFusionError::Execution(
                    "local input is not a row table".into(),
                ));
            };
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
            context_owners: (self.origin.durable() == Some("context_versions"))
                .then(|| Self::context_owners(filters))
                .flatten(),
            fetch: limit,
            image: self.image,
            read: Self::identity().map_err(|error| DataFusionError::External(Box::new(error)))?,
            key: None,
        }))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SourceData {
    pub(crate) origin: SourceOrigin,
    schema: SchemaRef,
    indices: Vec<usize>,
    bounds: BTreeMap<&'static str, Interval>,
    context_owners: Option<BTreeSet<String>>,
    fetch: Option<usize>,
    image: Option<SourceImage>,
    read: usize,
    key: Option<KeyRead>,
}

impl SourceData {
    pub(crate) fn from_plan(plan: &dyn ExecutionPlan) -> Option<&Self> {
        plan.downcast_ref::<DataSourceExec>()?
            .data_source()
            .downcast_ref::<Self>()
    }

    pub(crate) fn supports_changes(&self) -> Result<bool> {
        if self.origin.durable() != Some("events") || self.fetch.is_some() {
            return Ok(false);
        }
        if SourceSnapshot::schemas()["events"].project(&self.indices)? != *self.schema {
            return Err(DataFusionError::Execution(
                "maintained source schema changed".into(),
            ));
        }
        Ok(true)
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
        if snapshot
            .managed
            .as_ref()
            .is_some_and(|managed| managed.source.is_some())
            && snapshot.source_view()?.is_none()
        {
            return Err(DataFusionError::Execution(
                "the managed source index is not bound".into(),
            ));
        }
        if let (Some(view), Some(name)) = (snapshot.source_view()?, self.origin.durable()) {
            if !AnalysisTableRead::source_rows(name) {
                if !AnalysisTableRead::source_header(name) {
                    return Err(DataFusionError::NotImplemented(format!(
                        "retained source changes for {name}"
                    )));
                }
                let point = snapshot.point_image(&view)?;
                if self.image.is_some_and(|image| image != point) {
                    return Err(DataFusionError::Execution(
                        "the canonical header image differs from its captured point".into(),
                    ));
                }
            } else {
                use futures_util::TryStreamExt as _;
                let schema = Arc::clone(&self.schema);
                let columns = self.indices.clone();
                let name = name.to_owned();
                let key = self.key.clone();
                let image = self.image.map_or_else(|| snapshot.point_image(&view), Ok)?;
                let read = self.read;
                let fetch = self.fetch;
                let stream = futures_util::stream::once(async move {
                    let values = if let Some(key) = &key {
                        let slot = snapshot.key_slot(key.slot)?;
                        Some(
                            snapshot
                                .control
                                .query_async(slot.values())
                                .await
                                .map_err(SourceSnapshot::data_error)?,
                        )
                    } else {
                        None
                    };
                    snapshot
                        .control
                        .check()
                        .map_err(SourceSnapshot::data_error)?;
                    let keys = key
                        .as_ref()
                        .zip(values.as_deref())
                        .map(|(key, values)| (key.key.id, values));
                    let receipt = snapshot.snapshot()?;
                    let rows =
                        view.read(&name, image, keys, &columns, &schema, receipt.metadata())?;
                    snapshot.record_work(
                        read,
                        &name,
                        Some(image),
                        rows.batches.iter().map(|batch| batch.num_rows()).sum(),
                        rows.origins.iter().flat_map(|origin| origin.witnesses()),
                    );
                    snapshot.record_read(read, image, rows.origins)?;
                    Ok::<_, DataFusionError>(
                        MemoryStream::try_new(rows.batches, schema, None)?.with_fetch(fetch),
                    )
                })
                .try_flatten();
                return Ok(Box::pin(RecordBatchStreamAdapter::new(
                    Arc::clone(&self.schema),
                    stream,
                )));
            }
        }
        if matches!(self.image, Some(SourceImage::Before | SourceImage::Removed))
            && snapshot.source_view()?.is_none()
        {
            snapshot.record_work(
                self.read,
                self.origin.name(),
                self.image,
                0,
                std::iter::empty(),
            );
            return Ok(Box::pin(MemoryStream::try_new(
                Vec::new(),
                Arc::clone(&self.schema),
                None,
            )?));
        }
        let captured = snapshot
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let current = captured.as_ref().ok_or_else(|| {
            DataFusionError::Execution(
                "the source snapshot was not captured before execution".into(),
            )
        })?;
        let batches = current.project(&self.origin, &self.indices, &self.schema)?;
        snapshot.record_header(self.read, self.origin.name(), &batches, &current.receipt);
        snapshot.record_work(
            self.read,
            self.origin.name(),
            self.image,
            batches.iter().map(|batch| batch.num_rows()).sum(),
            std::iter::empty(),
        );
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

    fn partition_statistics(&self, _partition: Option<usize>) -> Result<Arc<Statistics>> {
        Ok(Arc::new(Statistics::new_unknown(&self.schema)))
    }

    fn apply_expressions(
        &self,
        f: &mut dyn FnMut(&Arc<dyn PhysicalExpr>) -> Result<TreeNodeRecursion>,
    ) -> Result<TreeNodeRecursion> {
        datafusion::physical_plan::apply_expression_roots(
            self.key.iter().flat_map(|read| read.key.expressions.iter()),
            f,
        )
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
