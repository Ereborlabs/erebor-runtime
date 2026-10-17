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
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
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
pub(crate) use rows::{Captured, Removal};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SourceOrigin {
    Durable(String),
    Port(usize),
    Package(usize),
}

impl SourceOrigin {
    pub(crate) fn durable(&self) -> Option<&str> {
        match self {
            Self::Durable(name) => Some(name),
            Self::Port(_) | Self::Package(_) => None,
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

pub(crate) struct SourceSnapshot {
    store: Arc<AnalysisStore>,
    selection: AnalysisSelectionV1,
    inputs: Option<InputCapture>,
    limits: AnalysisExtractLimits,
    control: AnalysisReadControl,
    extract_timeout: Duration,
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
    ) -> Result<Option<Interval>> {
        let mut received: Option<Interval> = None;
        for plan in plans {
            plan.apply(|node| {
                let Some(source) = SourceData::from_plan(node.as_ref()) else {
                    return Ok(TreeNodeRecursion::Continue);
                };
                let Some(name) = source.origin.durable() else {
                    return Ok(TreeNodeRecursion::Continue);
                };
                requests
                    .get_mut(name)
                    .ok_or_else(|| {
                        DataFusionError::Execution("the physical source was not admitted".into())
                    })?
                    .get_or_insert_with(BTreeSet::new)
                    .extend(source.indices.iter().copied());
                if let Some(bounds) = &source.received {
                    received = Some(match received.take() {
                        Some(previous) => previous.union(bounds.clone())?,
                        None => bounds.clone(),
                    });
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(received)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: Arc<AnalysisStore>,
        selection: AnalysisSelectionV1,
        inputs: Option<InputCapture>,
        limits: AnalysisExtractLimits,
        control: AnalysisReadControl,
        extract_timeout: Duration,
        now: u64,
        memory: Arc<Memory>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            selection,
            inputs,
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
        mut received: Option<Interval>,
        mode: ReadMode,
    ) -> Result<Arc<ArrowSnapshot>> {
        if let Some(inputs) = &self.inputs {
            let bounds = inputs
                .ranges
                .iter()
                .copied()
                .reduce(|(first, last), (next, end)| (first.min(next), last.max(end)));
            received = match bounds.filter(|_| {
                !requests.contains_key("trace_output")
                    && !requests.contains_key("trace_measurements")
            }) {
                Some((first, last)) => Some(Interval::try_new(
                    ScalarValue::UInt64(Some(first)),
                    ScalarValue::UInt64(Some(last)),
                )?),
                None => None,
            };
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
        let snapshot = self.read(requests, received.as_ref(), mode, &control)?;
        let receipt = Arc::clone(&snapshot.receipt);
        *captured = Some(snapshot);
        Ok(receipt)
    }

    pub(crate) fn capture_metadata(
        &self,
        sources: &AnalysisTableRequests,
    ) -> Result<Arc<ArrowSnapshot>> {
        let requests = sources.keys().map(|name| (name.clone(), None)).collect();
        self.capture(&requests, None, ReadMode::Metadata)
    }

    fn data_error(error: araphor_data::Error) -> DataFusionError {
        DataFusionError::External(Box::new(error))
    }

    pub(crate) fn prune_selection(
        mut selection: AnalysisSelectionV1,
        received: Option<&Interval>,
    ) -> AnalysisSelectionV1 {
        if let Some(interval) = received {
            if let Some((first, last)) = selection.time_range() {
                let lower = match interval.lower() {
                    ScalarValue::UInt64(Some(value)) => *value,
                    _ => 0,
                };
                let upper = match interval.upper() {
                    ScalarValue::UInt64(Some(value)) => *value,
                    _ => u64::MAX,
                };
                if lower > first {
                    selection.received_from = Bound::Included(lower);
                }
                if upper < last {
                    selection.received_until = Bound::Included(upper);
                }
            }
        }
        selection
    }
}

#[derive(Debug)]
pub(crate) struct SourceProvider {
    pub(crate) origin: SourceOrigin,
    schema: SchemaRef,
}

impl SourceProvider {
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

    fn received_bounds(&self, session: &dyn Session, filters: &[Expr]) -> Result<Interval> {
        let unbounded = Interval::make_unbounded(&datafusion::arrow::datatypes::DataType::UInt64)?;
        let Some(predicate) = conjunction(filters.iter().cloned()) else {
            return Ok(unbounded);
        };
        let schema = DFSchema::try_from(self.schema.as_ref().clone())?;
        let predicate = session.create_physical_expr(predicate, &schema)?;
        let initial = AnalysisContext::new(ExprBoundaries::try_new_unbounded(&self.schema)?);
        let Ok(context) = analyze(&predicate, initial, &self.schema) else {
            // DataFusion keeps the residual filter when interval analysis cannot apply.
            return Ok(unbounded);
        };
        let mut received = unbounded;
        for boundary in context.boundaries {
            let Some(interval) = boundary.interval else {
                continue;
            };
            let bounds = match boundary.column.name() {
                "received_utc_ns" => Some(interval),
                "received_at" => {
                    let convert = |value: &ScalarValue, upper: bool| match value {
                        ScalarValue::TimestampMicrosecond(Some(value), _) => {
                            let nanos = i128::from(*value) * 1000 + if upper { 999 } else { 0 };
                            ScalarValue::UInt64(Some(nanos.clamp(0, i128::from(u64::MAX)) as u64))
                        }
                        _ => ScalarValue::UInt64(None),
                    };
                    Some(Interval::try_new(
                        convert(interval.lower(), false),
                        convert(interval.upper(), true),
                    )?)
                }
                _ => None,
            };
            if let Some(bounds) = bounds {
                received = received.intersect(bounds)?.unwrap_or(Interval::try_new(
                    ScalarValue::UInt64(Some(0)),
                    ScalarValue::UInt64(Some(0)),
                )?);
            }
        }
        Ok(received)
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
        let indices = projection
            .cloned()
            .unwrap_or_else(|| (0..self.schema.fields().len()).collect());
        Ok(DataSourceExec::from_data_source(SourceData {
            origin: self.origin.clone(),
            schema: Arc::new(self.schema.project(&indices)?),
            indices,
            received: if self.origin.durable() == Some("events") {
                Some(self.received_bounds(session, filters)?)
            } else {
                None
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
    received: Option<Interval>,
    fetch: Option<usize>,
}

impl SourceData {
    pub(crate) fn positioned(&self) -> Result<Arc<dyn ExecutionPlan>> {
        let Some(name @ ("events" | "trace_output")) = self.origin.durable() else {
            return Err(DataFusionError::NotImplemented("positioned source".into()));
        };
        let canonical = &SourceSnapshot::schemas()[name];
        if canonical.project(&self.indices)? != *self.schema {
            return Err(DataFusionError::Execution("source schema changed".into()));
        }
        let mut indices = self.indices.clone();
        indices.push(canonical.index_of("commit_revision")?);
        indices.push(canonical.index_of("ordinal")?);
        Ok(DataSourceExec::from_data_source(Self {
            schema: Arc::new(canonical.project(&indices)?),
            indices,
            ..self.clone()
        }))
    }

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
