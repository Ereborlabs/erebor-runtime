use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::mem::size_of;
use std::sync::Arc;

use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisStreamIdentityV1, AnalysisWitnessV1,
    StorePositionV1,
};
use datafusion::arrow::array::{BooleanArray, RecordBatch, UInt32Array, UInt64Array};
use datafusion::arrow::compute::filter_record_batch;
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::logical_expr::interval_arithmetic::Interval;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType, SchedulingType};
use datafusion::physical_plan::streaming::StreamingTableExec;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures_util::stream;
use snafu::ResultExt as _;
use tokio::sync::watch;

use super::{Captured, ReadMode, Removal, SourceSnapshot};
use crate::execution::{Engine, PendingRead};
use crate::stream::{Input, Message, Run};
use crate::{InvalidSnafu, Result, SqlSnafu};

#[derive(Debug)]
pub(crate) struct JournalExec {
    columns: Vec<usize>,
    positions: [usize; 2],
    requests: Arc<BTreeMap<String, BTreeSet<usize>>>,
    received: Option<Interval>,
    properties: Arc<PlanProperties>,
}

impl JournalExec {
    pub(crate) fn new(
        source: &StreamingTableExec,
        received: Option<Interval>,
    ) -> NativeResult<Self> {
        if source.is_infinite() || source.limit().is_some() || source.partitions().len() != 1 {
            return Err(DataFusionError::NotImplemented(
                "committed native evidence scan".into(),
            ));
        }
        let schema = source.schema();
        let canonical = &SourceSnapshot::schemas()["events"];
        let columns = schema
            .fields()
            .iter()
            .map(|field| {
                canonical
                    .index_of(field.name())
                    .map_err(DataFusionError::from)
            })
            .collect::<NativeResult<Vec<_>>>()?;
        if canonical.project(&columns)? != *schema {
            return Err(DataFusionError::Execution(
                "maintained source schema changed".into(),
            ));
        }
        let positions = [
            canonical.index_of("commit_revision")?,
            canonical.index_of("ordinal")?,
        ];
        let mut requested = columns.iter().copied().collect::<BTreeSet<_>>();
        requested.extend(positions);
        let requests = Arc::new(BTreeMap::from([("events".to_owned(), requested)]));
        let properties = Arc::new(
            PlanProperties::new(
                EquivalenceProperties::new(schema),
                Partitioning::UnknownPartitioning(1),
                EmissionType::Incremental,
                // The store bounds live raw records. Retirements remove cached rows.
                Boundedness::Unbounded {
                    requires_infinite_memory: false,
                },
            )
            .with_scheduling_type(SchedulingType::Cooperative),
        );
        Ok(Self {
            columns,
            positions,
            requests,
            received,
            properties,
        })
    }

    pub(crate) fn execute_committed(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<Input> {
        if partition != 0 {
            return Err(DataFusionError::Execution(
                "Journal has one partition".into(),
            ))
            .context(SqlSnafu);
        }
        let run = context
            .session_config()
            .get_extension::<Run>()
            .ok_or_else(|| DataFusionError::Execution("source run is absent".into()))
            .context(SqlSnafu)?;
        run.control.check()?;
        if run.sources.len() != 1 || !run.sources.contains("events") {
            return Err(DataFusionError::NotImplemented(
                "maintained original evidence inventory".into(),
            ))
            .context(SqlSnafu);
        }
        let changes = run.engine.store().subscribe_revision();
        let state = Changes {
            memory: run.engine.memory().reserve_input(0).context(SqlSnafu)?,
            pending_memory: run.engine.memory().reserve_input(0).context(SqlSnafu)?,
            run,
            columns: self.columns.clone(),
            positions: self.positions,
            requests: Arc::clone(&self.requests),
            received: self.received.clone(),
            retained: Vec::new(),
            frontier: None,
            changes,
            pending: VecDeque::new(),
        };
        Ok(Box::pin(stream::try_unfold(state, |mut state| {
            tokio::task::coop::cooperative(async move {
                if state.pending.is_empty() && !state.capture().await? {
                    return Ok(None);
                }
                let message = state.pending.pop_front().ok_or_else(|| {
                    InvalidSnafu {
                        field: "committed source",
                    }
                    .build()
                })?;
                Ok(Some((message, state)))
            })
        })))
    }
}

impl DisplayAs for JournalExec {
    fn fmt_as(&self, _format: DisplayFormatType, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("JournalExec: source=events")
    }
}

impl ExecutionPlan for JournalExec {
    fn name(&self) -> &str {
        "JournalExec"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        Vec::new()
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> NativeResult<Arc<dyn ExecutionPlan>> {
        if !children.is_empty() {
            return Err(DataFusionError::Internal("Journal has no child".into()));
        }
        Ok(self)
    }

    fn execute(
        &self,
        _partition: usize,
        _context: Arc<TaskContext>,
    ) -> NativeResult<SendableRecordBatchStream> {
        Err(DataFusionError::NotImplemented(
            "signed source changes require committed execution".into(),
        ))
    }
}

struct Changes {
    run: Arc<Run>,
    columns: Vec<usize>,
    positions: [usize; 2],
    requests: Arc<BTreeMap<String, BTreeSet<usize>>>,
    received: Option<Interval>,
    retained: Vec<Chunk>,
    frontier: Option<StorePositionV1>,
    changes: watch::Receiver<u64>,
    memory: MemoryReservation,
    pending: VecDeque<Message>,
    pending_memory: MemoryReservation,
}

struct Chunk {
    batch: RecordBatch,
    keys: Vec<Key>,
}

struct Key {
    identity: Arc<AnalysisStreamIdentityV1>,
    cursor: u64,
    position: StorePositionV1,
}

impl Changes {
    async fn capture(&mut self) -> Result<bool> {
        let engine = Arc::clone(&self.run.engine);
        let control = Arc::clone(&self.run.control);
        if let Some(frontier) = self.frontier {
            let changed = control
                .query_async(async {
                    Ok::<_, crate::Error>(
                        self.changes
                            .wait_for(|revision| *revision > frontier.commit_revision)
                            .await
                            .is_ok(),
                    )
                })
                .await?;
            if !changed {
                return Ok(false);
            }
        }
        let permit = Arc::new(
            control
                .query_async(engine.acquire_evaluation(self.run.selection.tenant_id))
                .await?,
        );
        let stage = Arc::new(control.within(engine.limits().extract_timeout)?);
        let mut pending = PendingRead {
            control: Arc::clone(&stage),
            active: true,
        };
        let capture = SourceSnapshot::new(
            Arc::clone(engine.store()),
            self.run.selection.clone(),
            AnalysisExtractLimits {
                scan_bytes: engine.limits().scan_bytes,
                input_bytes: engine.limits().input_bytes,
                ..Default::default()
            },
            stage.within(stage.remaining()?)?,
            engine.limits().extract_timeout,
            self.run.now,
            Arc::clone(engine.memory()),
        );
        if let Some(received) = &self.received {
            capture.set_received(received.clone()).context(SqlSnafu)?;
        }
        let requests = Arc::clone(&self.requests);
        let mode = self.frontier.map_or(ReadMode::Snapshot, ReadMode::Changes);
        let run = Arc::clone(&self.run);
        let worker = Arc::clone(&stage);
        let capture_permit = Arc::clone(&permit);
        let mut captured = stage
            .query_async(async move {
                tokio::task::spawn_blocking(move || {
                    let _permit = capture_permit;
                    capture.read(&run.sources, &requests, mode, &worker)
                })
                .await
                .map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?
                .context(SqlSnafu)
            })
            .await?;
        pending.active = false;
        control.check()?;
        engine.check_read(&captured.receipt).await?;
        let evaluation = Arc::new(control.within(engine.limits().evaluate_timeout)?);
        let result = self.apply(&engine, &captured, &evaluation)?;
        evaluation.check()?;
        let count = self
            .retained
            .iter()
            .map(|chunk| chunk.keys.len())
            .sum::<usize>();
        let witness_bytes = count
            .saturating_mul(size_of::<AnalysisWitnessV1>())
            .saturating_add(
                self.retained
                    .iter()
                    .flat_map(|chunk| &chunk.keys)
                    .map(|key| match key.identity.as_ref() {
                        AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.len(),
                        AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.len(),
                    })
                    .sum::<usize>(),
            );
        let bytes = self
            .retained
            .iter()
            .map(|chunk| chunk.batch.get_array_memory_size())
            .sum::<usize>();
        if bytes
            .saturating_add(self.memory.size())
            .saturating_add(witness_bytes)
            > engine.limits().input_bytes
        {
            return Err(DataFusionError::ResourcesExhausted(
                "maintained query input".into(),
            ))
            .context(SqlSnafu);
        }
        let witness_memory = engine
            .memory()
            .reserve_input(witness_bytes)
            .context(SqlSnafu)?;
        let mut witnesses = Vec::with_capacity(count);
        for key in self.retained.iter().flat_map(|chunk| &chunk.keys) {
            witnesses.push(AnalysisWitnessV1 {
                identity: key.identity.as_ref().clone(),
                cursor: key.cursor,
                expires_utc_ns: 0,
            });
        }
        captured.set_witnesses(witnesses).context(SqlSnafu)?;
        drop(witness_memory);
        let position = StorePositionV1 {
            commit_revision: captured.receipt.page.extraction.meta.commit_revision,
            ordinal: u32::MAX,
        };
        let (before, after) = result;
        evaluation.check()?;
        let count = before.len().saturating_add(after.len()).saturating_add(2);
        self.pending_memory
            .try_resize(count.saturating_mul(size_of::<Message>()))
            .map_err(|source| crate::Error::Capacity {
                resource: "shared input",
                source,
            })?;
        self.pending = VecDeque::with_capacity(count);
        self.pending.push_back(Message::Begin(evaluation));
        self.pending.extend(before.into_iter().map(Message::Delete));
        self.pending.extend(after.into_iter().map(Message::Insert));
        self.pending.push_back(Message::Commit {
            position,
            snapshot: captured.receipt,
            _permit: Some(permit),
        });
        self.frontier = Some(position);
        Ok(true)
    }

    fn apply(
        &mut self,
        engine: &Engine,
        captured: &Captured,
        control: &AnalysisReadControl,
    ) -> Result<(Vec<RecordBatch>, Vec<RecordBatch>)> {
        let rows = self
            .retained
            .iter()
            .map(|chunk| chunk.keys.len())
            .sum::<usize>();
        let incoming = captured
            .receipt
            .witnesses
            .iter()
            .map(|witness| {
                size_of::<Key>()
                    + size_of::<AnalysisStreamIdentityV1>()
                    + 4 * size_of::<usize>()
                    + match &witness.identity {
                        AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                        AnalysisStreamIdentityV1::Diagnostic(identity) => {
                            identity.node_id.capacity()
                        }
                    }
            })
            .sum::<usize>();
        let copied = if captured.removals.is_empty() {
            0
        } else {
            self.retained
                .iter()
                .map(|chunk| chunk.batch.get_array_memory_size())
                .sum::<usize>()
                .saturating_mul(2)
                .saturating_add(rows.saturating_mul(3))
        };
        let mut scratch = engine
            .memory()
            .reserve_input(
                incoming
                    .saturating_add(copied)
                    .saturating_add((rows + captured.receipt.witnesses.len()) * size_of::<usize>()),
            )
            .context(SqlSnafu)?;
        let mut before = Vec::new();
        for chunk in self
            .retained
            .iter_mut()
            .filter(|_| !captured.removals.is_empty())
        {
            control.check()?;
            let removed = chunk
                .keys
                .iter()
                .map(|key| Self::removed(key, &captured.removals))
                .collect::<Vec<_>>();
            if removed.iter().any(|removed| *removed) {
                let deleted =
                    filter_record_batch(&chunk.batch, &BooleanArray::from(removed.clone()))
                        .map_err(DataFusionError::from)
                        .context(SqlSnafu)?;
                before.push(deleted);
                let keep =
                    BooleanArray::from(removed.iter().map(|removed| !removed).collect::<Vec<_>>());
                chunk.batch = filter_record_batch(&chunk.batch, &keep)
                    .map_err(DataFusionError::from)
                    .context(SqlSnafu)?;
                let mut index = 0;
                chunk.keys.retain(|_| {
                    let keep = !removed[index];
                    index += 1;
                    keep
                });
            }
        }
        self.retained.retain(|chunk| chunk.batch.num_rows() != 0);
        let mut witnesses = captured.receipt.witnesses.iter();
        let batches = captured
            .project("events", &self.positions)
            .context(SqlSnafu)?;
        let inputs = captured
            .project("events", &self.columns)
            .context(SqlSnafu)?;
        let mut after = Vec::new();
        let mut identities = Vec::<Arc<AnalysisStreamIdentityV1>>::new();
        for (batch, input) in batches.into_iter().zip(inputs) {
            control.check()?;
            let revisions = batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "stream revision",
                    }
                    .build()
                })?;
            let ordinals = batch
                .column(1)
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "stream ordinal",
                    }
                    .build()
                })?;
            let mut keys = Vec::with_capacity(batch.num_rows());
            for row in 0..batch.num_rows() {
                let witness = witnesses.next().ok_or_else(|| {
                    InvalidSnafu {
                        field: "stream witness",
                    }
                    .build()
                })?;
                let position = StorePositionV1 {
                    commit_revision: revisions.value(row),
                    ordinal: ordinals.value(row),
                };
                let identity = match identities
                    .iter()
                    .find(|identity| identity.as_ref() == &witness.identity)
                {
                    Some(identity) => Arc::clone(identity),
                    None => {
                        let identity = Arc::new(witness.identity.clone());
                        identities.push(Arc::clone(&identity));
                        identity
                    }
                };
                keys.push(Key {
                    identity,
                    cursor: witness.cursor,
                    position,
                });
            }
            let keep = keys
                .iter()
                .map(|key| !Self::removed(key, &captured.removals))
                .collect::<Vec<_>>();
            let batch = filter_record_batch(&input, &BooleanArray::from(keep.clone()))
                .map_err(DataFusionError::from)
                .context(SqlSnafu)?;
            let mut row = 0;
            keys.retain(|_| {
                let keep = keep[row];
                row += 1;
                keep
            });
            if batch.num_rows() != 0 {
                after.push(batch.clone());
                self.retained.push(Chunk { batch, keys });
            }
        }
        let bytes = self
            .retained
            .iter()
            .map(|chunk| chunk.batch.get_array_memory_size())
            .sum::<usize>();
        let mut owners = Vec::new();
        let identity_bytes = self
            .retained
            .iter()
            .flat_map(|chunk| &chunk.keys)
            .filter_map(|key| {
                let pointer = Arc::as_ptr(&key.identity) as usize;
                if owners.contains(&pointer) {
                    return None;
                }
                owners.push(pointer);
                Some(
                    size_of::<AnalysisStreamIdentityV1>()
                        + 2 * size_of::<usize>()
                        + match key.identity.as_ref() {
                            AnalysisStreamIdentityV1::Evidence(identity) => {
                                identity.node_id.capacity()
                            }
                            AnalysisStreamIdentityV1::Diagnostic(identity) => {
                                identity.node_id.capacity()
                            }
                        },
                )
            })
            .sum::<usize>();
        let metadata = self.retained.capacity() * size_of::<Chunk>()
            + self
                .retained
                .iter()
                .map(|chunk| chunk.keys.capacity() * size_of::<Key>())
                .sum::<usize>()
            + identity_bytes;
        if bytes.saturating_add(metadata) > engine.limits().input_bytes {
            return Err(DataFusionError::ResourcesExhausted(
                "maintained query input".into(),
            ))
            .context(SqlSnafu);
        }
        for chunk in &self.retained {
            engine
                .memory()
                .retain_input(&chunk.batch, &mut scratch)
                .context(SqlSnafu)?;
        }
        for batch in before.iter().chain(&after) {
            engine
                .memory()
                .retain_input(batch, &mut scratch)
                .context(SqlSnafu)?;
        }
        self.memory
            .try_resize(metadata)
            .map_err(|source| crate::Error::Capacity {
                resource: "shared input",
                source,
            })?;
        scratch.free();
        Ok((before, after))
    }

    fn removed(key: &Key, removals: &[Removal]) -> bool {
        removals.iter().any(|removal| {
            key.identity.as_ref() == &removal.identity
                && (removal.first..=removal.last).contains(&key.cursor)
                && key.position <= removal.position
        })
    }
}
