use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::mem::size_of;
use std::sync::Arc;

use araphor_data::{
    AnalysisExtractLimits, AnalysisGapV1, AnalysisReadControl, AnalysisStoreMetaV1,
    AnalysisStreamIdentityV1, AnalysisTableRequests, AnalysisWitnessV1, StorePositionV1,
};
use datafusion::arrow::array::{ArrayRef, BooleanArray, RecordBatch, UInt32Array, UInt64Array};
use datafusion::arrow::compute::filter_record_batch;
use datafusion::common::{DataFusionError, Result as NativeResult};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType, SchedulingType};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use snafu::ResultExt as _;

use super::{Captured, ReadMode, ScanBounds, SourceData, SourceOrigin, SourceSnapshot};
use crate::execution::{Engine, Permit, Session};
use crate::stream::{Change, Run};
use crate::{InvalidSnafu, Result, SqlSnafu};

#[derive(Debug)]
pub(crate) struct JournalExec {
    columns: Vec<usize>,
    positions: [usize; 2],
    requests: Arc<AnalysisTableRequests>,
    bounds: ScanBounds,
    properties: Arc<PlanProperties>,
}

impl JournalExec {
    pub(crate) fn new(source: &SourceData) -> NativeResult<Self> {
        if source.origin.durable() != Some("events") || source.fetch.is_some() {
            return Err(DataFusionError::NotImplemented(
                "committed native evidence scan".into(),
            ));
        }
        let schema = Arc::clone(&source.schema);
        let canonical = &SourceSnapshot::schemas()["events"];
        let columns = source.indices.clone();
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
        let requests = Arc::new(BTreeMap::from([("events".to_owned(), Some(requested))]));
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
            bounds: ScanBounds {
                fields: source.bounds.clone(),
                ..Default::default()
            },
            properties,
        })
    }

    pub(crate) fn open(&self, context: Arc<TaskContext>) -> Result<Changes> {
        let run = context
            .session_config()
            .get_extension::<Run>()
            .ok_or_else(|| DataFusionError::Execution("source run is absent".into()))
            .context(SqlSnafu)?;
        run.session.control().check()?;
        if run.sources.len() != 1 || !run.sources.contains_key("events") {
            return Err(DataFusionError::NotImplemented(
                "maintained original evidence inventory".into(),
            ))
            .context(SqlSnafu);
        }
        Ok(Changes {
            memory: run.session.memory().reserve_input(0).context(SqlSnafu)?,
            run,
            columns: self.columns.clone(),
            positions: self.positions,
            requests: Arc::clone(&self.requests),
            bounds: self.bounds.clone(),
            retained: Vec::new(),
            frontier: None,
            meta: None,
        })
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

pub(crate) struct Changes {
    run: Arc<Run>,
    columns: Vec<usize>,
    positions: [usize; 2],
    requests: Arc<AnalysisTableRequests>,
    bounds: ScanBounds,
    retained: Vec<Chunk>,
    frontier: Option<StorePositionV1>,
    meta: Option<AnalysisStoreMetaV1>,
    memory: MemoryReservation,
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
    pub(crate) async fn capture(&mut self, permit: Arc<Permit>, now: u64) -> Result<Change> {
        tokio::task::coop::cooperative(self.read(permit, now)).await
    }

    async fn read(&mut self, permit: Arc<Permit>, now: u64) -> Result<Change> {
        let run = Arc::clone(&self.run);
        let session = &run.session;
        let engine = session.engine();
        let control = Arc::clone(session.control());
        let stage = Arc::new(control.within(engine.limits().extract_timeout)?);
        let capture = SourceSnapshot::new(
            Arc::clone(engine.store()),
            self.run.session.selection().clone(),
            None,
            AnalysisExtractLimits {
                scan_bytes: engine.limits().scan_bytes,
                input_bytes: engine.limits().input_bytes,
                keys: engine.limits().extract_keys,
                ..Default::default()
            },
            stage.within(stage.remaining()?)?,
            engine.limits().extract_timeout,
            now,
            Arc::clone(session.memory()),
            None,
        );
        let requests = Arc::clone(&self.requests);
        let bounds = self.bounds.clone();
        let mode = self.frontier.map_or(ReadMode::Snapshot, ReadMode::Changes);
        let worker = Arc::clone(&stage);
        let capture_permit = Arc::clone(&permit);
        let scope = session.token()?;
        let mut captured = Engine::blocking(stage, scope, move || {
            let _permit = capture_permit;
            capture
                .read(&requests, &bounds, mode, &worker)
                .context(SqlSnafu)
        })
        .await?;
        control.check()?;
        session.check_read(&captured.receipt).await?;
        if let Some(previous) = &self.meta {
            super::ArrowSnapshot::check_store(previous, &captured.receipt.page.extraction.meta)?;
        }
        let evaluation = Arc::new(control.within(engine.limits().evaluate_timeout)?);
        let (before, after) = self.apply(session, &captured, &evaluation)?;
        evaluation.check()?;
        let headers = |batches: &Vec<RecordBatch>| {
            batches
                .capacity()
                .saturating_mul(size_of::<RecordBatch>())
                .saturating_add(
                    batches
                        .iter()
                        .map(|batch| batch.num_columns().saturating_mul(size_of::<ArrayRef>()))
                        .sum::<usize>(),
                )
        };
        let before_bytes = headers(&before);
        let after_bytes = headers(&after);
        // Native binding and opening each clone the active batch headers.
        let metadata = before_bytes
            .saturating_add(after_bytes)
            .saturating_add(before_bytes.max(after_bytes).saturating_mul(2));
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
            .saturating_add(metadata)
            > engine.limits().input_bytes
        {
            return Err(DataFusionError::ResourcesExhausted(
                "maintained query input".into(),
            ))
            .context(SqlSnafu);
        }
        let witness_memory = session
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
        evaluation.check()?;
        let memory = session.memory().reserve_input(metadata).context(SqlSnafu)?;
        self.frontier = Some(position);
        self.meta = Some(captured.receipt.page.extraction.meta.clone());
        Ok(Change {
            before,
            after,
            position,
            snapshot: captured.receipt,
            control: evaluation,
            _permit: Some(permit),
            _memory: memory,
        })
    }

    fn apply(
        &mut self,
        session: &Session,
        captured: &Captured,
        control: &AnalysisReadControl,
    ) -> Result<(Vec<RecordBatch>, Vec<RecordBatch>)> {
        let engine = session.engine();
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
        let scratch = session
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
        let origin = SourceOrigin::Durable("events".into());
        let canonical = &SourceSnapshot::schemas()["events"];
        let positions = Arc::new(
            canonical
                .project(&self.positions)
                .map_err(DataFusionError::from)
                .context(SqlSnafu)?,
        );
        let schema = Arc::new(
            canonical
                .project(&self.columns)
                .map_err(DataFusionError::from)
                .context(SqlSnafu)?,
        );
        let batches = captured
            .project(&origin, &self.positions, &positions)
            .context(SqlSnafu)?;
        let inputs = captured
            .project(&origin, &self.columns, &schema)
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
            session
                .memory()
                .retain_input(&chunk.batch, &scratch)
                .context(SqlSnafu)?;
        }
        for batch in before.iter().chain(&after) {
            session
                .memory()
                .retain_input(batch, &scratch)
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

    fn removed(
        key: &Key,
        removals: &BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>>,
    ) -> bool {
        removals.get(key.identity.as_ref()).is_some_and(|gaps| {
            gaps.iter().any(|gap| {
                (gap.first_cursor..=gap.last_cursor).contains(&key.cursor)
                    && key.position.commit_revision <= gap.commit_revision
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_keeps_new_rows() {
        let identity = Arc::new(AnalysisStreamIdentityV1::Evidence(
            araphor_data::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "retirement".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
        ));
        let removals = BTreeMap::from([(
            identity.as_ref().clone(),
            vec![
                AnalysisGapV1 {
                    first_cursor: 3,
                    last_cursor: 5,
                    commit_revision: 12,
                },
                AnalysisGapV1 {
                    first_cursor: 1,
                    last_cursor: 3,
                    commit_revision: 10,
                },
                AnalysisGapV1 {
                    first_cursor: 4,
                    last_cursor: 6,
                    commit_revision: 11,
                },
                AnalysisGapV1 {
                    first_cursor: u64::MAX,
                    last_cursor: u64::MAX,
                    commit_revision: u64::MAX,
                },
            ],
        )]);
        for (cursor, revision, ordinal, expected) in [
            (0, 0, 0, false),
            (1, 9, 0, true),
            (3, 10, u32::MAX, true),
            (4, 12, 0, true),
            (4, 13, 0, false),
            (6, 11, u32::MAX, true),
            (6, 12, 0, false),
            (7, 10, 0, false),
            (u64::MAX, u64::MAX, 0, true),
            (u64::MAX, u64::MAX, u32::MAX, true),
        ] {
            let key = Key {
                identity: Arc::clone(&identity),
                cursor,
                position: StorePositionV1 {
                    commit_revision: revision,
                    ordinal,
                },
            };
            assert_eq!(Changes::removed(&key, &removals), expected);
            assert!(!Changes::removed(&key, &BTreeMap::new()));
        }
        let foreign = Key {
            identity: Arc::new(AnalysisStreamIdentityV1::Diagnostic(
                araphor_data::TraceIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "retirement".into(),
                    node_boot_id: [2; 16],
                    request_id: [4; 16],
                    execution_id: [3; 16],
                    source_sha256: [5; 32],
                },
            )),
            cursor: 3,
            position: StorePositionV1 {
                commit_revision: 10,
                ordinal: 0,
            },
        };
        assert!(!Changes::removed(&foreign, &removals));
    }
}
