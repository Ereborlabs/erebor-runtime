use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, StorePositionV1,
};
use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{DFSchema, DataFusionError, Result, ScalarValue};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::logical_expr::{utils::conjunction, Expr, TableProviderFilterPushDown, TableType};
use datafusion::physical_expr::{analyze, AnalysisContext, ExprBoundaries};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::streaming::{PartitionStream, StreamingTableExec};
use datafusion::physical_plan::{ExecutionPlan, SendableRecordBatchStream};

use crate::memory::Memory;

mod batch;
#[cfg(test)]
mod bounds;
mod journal;
mod rows;
mod schema;
#[cfg(test)]
mod tests;

pub(crate) use journal::JournalExec;
pub use rows::ArrowSnapshot;
pub(crate) use rows::{Captured, Removal};

type Requests = (BTreeMap<String, BTreeSet<usize>>, Option<Interval>);

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
    limits: AnalysisExtractLimits,
    control: AnalysisReadControl,
    extract_timeout: Duration,
    now: u64,
    memory: Arc<Memory>,
    requested: Mutex<BTreeMap<String, BTreeSet<usize>>>,
    received: Mutex<Option<Interval>>,
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
    pub(crate) fn requests(&self) -> Result<Requests> {
        let requests = self
            .requested
            .lock()
            .map_err(|_| DataFusionError::Internal("source projection lock is poisoned".into()))?
            .clone();
        let received = self
            .received
            .lock()
            .map_err(|_| DataFusionError::Internal("source interval lock is poisoned".into()))?
            .clone();
        Ok((requests, received))
    }

    pub(crate) fn new(
        store: Arc<AnalysisStore>,
        selection: AnalysisSelectionV1,
        limits: AnalysisExtractLimits,
        control: AnalysisReadControl,
        extract_timeout: Duration,
        now: u64,
        memory: Arc<Memory>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            selection,
            limits,
            control,
            extract_timeout,
            now,
            memory,
            requested: Mutex::new(BTreeMap::new()),
            received: Mutex::new(None),
            captured: Mutex::new(None),
        })
    }

    pub(crate) fn providers() -> BTreeMap<String, Arc<dyn TableProvider>> {
        Self::schemas()
            .iter()
            .map(|(name, schema)| {
                let provider: Arc<dyn TableProvider> = Arc::new(SourceProvider {
                    name: name.clone(),
                    schema: Arc::clone(schema),
                });
                (name.clone(), provider)
            })
            .collect()
    }

    pub(crate) fn capture(&self, sources: &BTreeSet<String>) -> Result<Arc<ArrowSnapshot>> {
        self.capture_mode(sources, ReadMode::Snapshot)
    }

    pub(crate) fn capture_positions(
        &self,
        sources: &BTreeSet<String>,
        after: Option<StorePositionV1>,
    ) -> Result<Arc<ArrowSnapshot>> {
        self.capture_mode(sources, ReadMode::Page(after))
    }

    pub(crate) fn capture_metadata(
        &self,
        sources: &BTreeSet<String>,
    ) -> Result<Arc<ArrowSnapshot>> {
        self.capture_mode(sources, ReadMode::Metadata)
    }

    fn capture_mode(
        &self,
        sources: &BTreeSet<String>,
        mode: ReadMode,
    ) -> Result<Arc<ArrowSnapshot>> {
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
        let requests = self
            .requested
            .lock()
            .map_err(|_| DataFusionError::Internal("source projection lock is poisoned".into()))?;
        let snapshot = self.read(sources, &requests, mode, &control)?;
        let receipt = Arc::clone(&snapshot.receipt);
        *captured = Some(snapshot);
        Ok(receipt)
    }

    fn data_error(error: araphor_data::Error) -> DataFusionError {
        DataFusionError::External(Box::new(error))
    }

    pub(crate) fn set_received(&self, bounds: Interval) -> Result<()> {
        let mut received = self
            .received
            .lock()
            .map_err(|_| DataFusionError::Internal("source interval lock is poisoned".into()))?;
        *received = Some(match received.as_ref() {
            Some(previous) => previous.union(bounds)?,
            None => bounds,
        });
        Ok(())
    }

    fn prune_selection(&self, mut selection: AnalysisSelectionV1) -> Result<AnalysisSelectionV1> {
        let received = self
            .received
            .lock()
            .map_err(|_| DataFusionError::Internal("source interval lock is poisoned".into()))?;
        if let Some(interval) = received.as_ref() {
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
        Ok(selection)
    }
}

#[derive(Debug)]
pub(crate) struct SourceProvider {
    name: String,
    schema: SchemaRef,
}

impl SourceProvider {
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
            if self.name == "events" {
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
        let snapshot = session
            .config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| {
                DataFusionError::Execution("the native session has no source snapshot".into())
            })?;
        let indices = projection
            .cloned()
            .unwrap_or_else(|| (0..self.schema.fields().len()).collect());
        let schema = Arc::new(self.schema.project(&indices)?);
        if snapshot
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?
            .is_some()
        {
            return Err(DataFusionError::Plan(
                "a source snapshot cannot accept another physical plan".into(),
            ));
        }
        snapshot
            .requested
            .lock()
            .map_err(|_| DataFusionError::Internal("source projection lock is poisoned".into()))?
            .entry(self.name.clone())
            .or_default()
            .extend(indices.iter().copied());
        if self.name == "events" {
            snapshot.set_received(self.received_bounds(session, filters)?)?;
        }
        SnapshotPartition {
            name: self.name.clone(),
            schema,
            indices,
        }
        .plan(limit)
    }
}

#[derive(Debug)]
struct SnapshotPartition {
    name: String,
    schema: SchemaRef,
    indices: Vec<usize>,
}

impl SnapshotPartition {
    fn plan(self, limit: Option<usize>) -> Result<Arc<dyn ExecutionPlan>> {
        let schema = Arc::clone(&self.schema);
        Ok(Arc::new(StreamingTableExec::try_new(
            schema,
            vec![Arc::new(self)],
            None,
            [],
            false,
            limit,
        )?))
    }
}

impl PartitionStream for SnapshotPartition {
    fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    fn execute(&self, context: Arc<TaskContext>) -> SendableRecordBatchStream {
        let snapshot = (|| {
            let snapshot = context
                .session_config()
                .get_extension::<SourceSnapshot>()
                .ok_or_else(|| {
                    DataFusionError::Execution("the native task has no source snapshot".into())
                })?;
            let captured = snapshot.captured.lock().map_err(|_| {
                DataFusionError::Internal("source snapshot lock is poisoned".into())
            })?;
            captured
                .as_ref()
                .ok_or_else(|| {
                    DataFusionError::Execution(
                        "the source snapshot was not captured before execution".into(),
                    )
                })
                .and_then(|snapshot| snapshot.project(&self.name, &self.indices))
        })();
        let stream = futures_util::stream::iter(match snapshot {
            Ok(batches) => batches.into_iter().map(Ok).collect(),
            Err(error) => vec![Err(error)],
        });
        Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(&self.schema),
            stream,
        ))
    }
}
