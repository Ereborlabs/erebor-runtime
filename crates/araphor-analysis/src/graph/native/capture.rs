use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::{Arc, Weak};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, DiscoveryRecordIdV1, DiscoveryRecordV1,
    EvidenceIntakeIdentityV1, GraphCoverageKeyV1, GraphReplayInputV1, GraphRevisionV1,
    StorePositionV1,
};
use araphor_query::sources::SourceSnapshot;
use datafusion::arrow::array::{
    Array, BinaryArray, BooleanArray, StringArray, UInt32Array, UInt64Array,
};
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::execution::TaskContext;
use datafusion::physical_plan::execution_plan::reset_plan_states;
use datafusion::physical_plan::{execute_stream, ExecutionPlan};
use futures_util::TryStreamExt as _;

use super::{Capture, GraphRun, Head, Projection};
use crate::Graph;

type CapturedRecords = (
    Vec<DiscoveryRecordV1>,
    Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
);

impl Projection {
    pub(super) async fn capture(
        self: &Arc<Self>,
        plans: &[Arc<dyn ExecutionPlan>],
        context: &Arc<TaskContext>,
    ) -> Result<Arc<Capture>> {
        let source = context
            .session_config()
            .get_extension::<SourceSnapshot>()
            .ok_or_else(|| Self::invalid("graph captured source"))?;
        let run = GraphRun::from_context(context, self)?;
        let captured = run
            .captured
            .get_or_init(|| async {
                let captured = self
                    .read(plans, context, Arc::clone(&source))
                    .await
                    .map(Arc::new)
                    .map_err(Arc::new);
                #[cfg(test)]
                if let (Ok(value), Some(observer)) = (
                    &captured,
                    self.observed
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .as_ref(),
                ) {
                    let _sent = observer.send(Arc::clone(value));
                }
                captured
            })
            .await
            .clone()
            .map_err(DataFusionError::Shared)?;
        if !Weak::ptr_eq(&captured.source, &Arc::downgrade(&source)) {
            return Err(Self::invalid("graph input belongs to another capture"));
        }
        Ok(captured)
    }

    async fn read(
        self: &Arc<Self>,
        plans: &[Arc<dyn ExecutionPlan>],
        context: &Arc<TaskContext>,
        source: Arc<SourceSnapshot>,
    ) -> Result<Capture> {
        let reset;
        let plans = if let Some(prepared) = &self.prepared {
            reset = prepared
                .iter()
                .map(|plan| reset_plan_states(Arc::clone(plan)))
                .collect::<Result<Vec<_>>>()?;
            reset.as_slice()
        } else {
            plans
        };
        if plans.len() != 6 {
            return Err(Self::invalid("graph source plans"));
        }
        let control = context
            .session_config()
            .get_extension::<araphor_data::AnalysisReadControl>()
            .ok_or_else(|| Self::invalid("graph execution control"))?;
        let staging = self.memory.reserve_input(0)?;
        let memory = self.memory.reserve_input(0)?;
        let frames = self.memory.reserve_input(0)?;
        let mut inputs = Vec::with_capacity(6);
        for plan in plans {
            let mut stream = execute_stream(Arc::clone(plan), Arc::clone(context))?;
            let mut batches = Vec::new();
            while let Some(batch) = stream.try_next().await? {
                control.check().map_err(Self::external)?;
                self.memory.retain_input(&batch, &staging)?;
                staging.try_grow(size_of::<sdk::RecordBatch>())?;
                batches.push(batch);
            }
            inputs.push(batches);
        }
        let owner = Arc::clone(self);
        source
            .blocking(context, staging, move |source, control| {
                owner
                    .project(inputs, source, control, memory, frames)
                    .map_err(|source| araphor_query::Error::Sql { source })
            })
            .await
    }

    fn project(
        &self,
        inputs: Vec<Vec<sdk::RecordBatch>>,
        source: &Arc<SourceSnapshot>,
        control: &araphor_data::AnalysisReadControl,
        memory: MemoryReservation,
        frames: MemoryReservation,
    ) -> Result<Capture> {
        let (records, positions) = source.with_table("events", |_, canonical| {
            Self::records(&inputs[0], canonical, &frames)
        })?;
        let identity = records
            .first()
            .ok_or_else(|| Self::invalid("empty graph window"))?
            .id
            .stream
            .clone();
        if identity.tenant_id != self.tenant || records.iter().any(|row| row.id.stream != identity)
        {
            return Err(Self::invalid("one exact graph source"));
        }
        let (consumed, floor, accepted) = Self::progress(&inputs[3], &identity)?;
        let latest = Self::coverage_revision(&inputs[3], &identity)?;
        let mut heads = Vec::new();
        let mut manifests = Vec::new();
        for batch in &inputs[4] {
            for row in 0..batch.num_rows() {
                if Self::column::<BinaryArray>(batch, "source_key")?.value(row) != identity.key() {
                    continue;
                }
                let revision: GraphRevisionV1 = Self::value(batch, "graph_revision", row)?;
                if !revision
                    .evidence
                    .iter()
                    .any(|id| records.binary_search_by(|record| record.id.cmp(id)).is_ok())
                {
                    continue;
                }
                let refs: Vec<araphor_data::AnalysisContextRefV1> =
                    Self::value(batch, "context_refs", row)?;
                heads.push(Head {
                    id: Self::column::<StringArray>(batch, "graph_result_id")?
                        .value(row)
                        .into(),
                    first: Self::column::<UInt64Array>(batch, "first_cursor")?.value(row),
                    deadline: Self::column::<UInt64Array>(batch, "witness_deadline_utc_ns")?
                        .value(row),
                    coverage: Self::column::<UInt64Array>(batch, "notice_coverage_revision")?
                        .value(row),
                    packages: refs
                        .into_iter()
                        .filter(|reference| reference.key.owner_id == "native-package-v1")
                        .map(|reference| reference.key)
                        .collect(),
                    reusable: false,
                });
                manifests.push(revision);
            }
        }
        let deadline = heads
            .iter()
            .map(|head| head.deadline)
            .min()
            .or_else(|| {
                source
                    .time_utc_ns()
                    .checked_add(araphor_data::GRAPH_WITNESS_TTL_NS)
            })
            .ok_or_else(|| Self::invalid("graph witness deadline"))?;
        Self::check_deadline(deadline).map_err(Self::external)?;
        let keys = manifests
            .iter()
            .flat_map(|manifest| &manifest.context)
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut facts = Self::frozen_facts(&inputs[1], &keys, &records)?;
        let (incoming, proofs) = self
            .facts
            .facts(&inputs[1], &records)
            .map_err(Self::external)?;
        facts.extend(incoming);
        let mut coverage = Vec::new();
        for batch in &inputs[2] {
            let values: Vec<araphor_data::DiscoveryCoverageV1> =
                serde_arrow::from_record_batch(batch).map_err(Self::external)?;
            coverage.extend(values.into_iter().filter(|range| range.stream == identity));
        }
        let intervals = records
            .iter()
            .filter_map(|record| {
                record
                    .decode()
                    .ok()
                    .and_then(|wire| <[u8; 16]>::try_from(wire.coverage_interval_id.as_ref()).ok())
            })
            .collect::<BTreeSet<_>>();
        let requested = manifests
            .iter()
            .flat_map(|manifest| &manifest.coverage)
            .filter(|key| key.source == identity && intervals.contains(&key.interval_id))
            .map(|key| key.report_revision)
            .chain([latest])
            .collect::<BTreeSet<_>>();
        let mut versions = BTreeMap::new();
        let mut matching = BTreeSet::new();
        for batch in &inputs[5] {
            let ids = Self::column::<BinaryArray>(batch, "interval_id")?;
            for row in 0..batch.num_rows() {
                if ids.is_null(row) || Self::identity(batch, row)? != identity {
                    continue;
                }
                let id: [u8; 16] = ids
                    .value(row)
                    .try_into()
                    .map_err(|_| Self::invalid("captured coverage identity"))?;
                let report = Self::column::<UInt64Array>(batch, "coverage_revision")?.value(row);
                let cpu = Self::column::<UInt32Array>(batch, "cpu_id")?.value(row);
                let version = Self::column::<UInt64Array>(batch, "interval_revision")?.value(row);
                if versions
                    .insert((report, id, cpu), version)
                    .is_some_and(|old| old != version)
                {
                    return Err(Self::invalid("conflicting captured coverage interval"));
                }
                if requested.contains(&report) && intervals.contains(&id) {
                    matching.insert(report);
                }
            }
        }
        let fallback = !coverage
            .iter()
            .any(|range| matching.contains(&range.coverage_revision));
        coverage.retain(|range| {
            if fallback {
                range.coverage_revision == latest
            } else {
                matching.contains(&range.coverage_revision)
            }
        });
        let coverage_keys = if fallback {
            Vec::new()
        } else {
            coverage
                .iter()
                .map(|range| {
                    let mut gaps = range.gap_reasons.clone();
                    gaps.sort();
                    gaps.dedup();
                    GraphCoverageKeyV1 {
                        source: identity.clone(),
                        cpu_id: range.cpu_id,
                        report_revision: range.coverage_revision,
                        interval_id: range.coverage_interval_id,
                        interval_revision: versions
                            .get(&(
                                range.coverage_revision,
                                range.coverage_interval_id,
                                range.cpu_id,
                            ))
                            .copied()
                            .unwrap_or(0),
                        state: range.state,
                        gap_reasons: gaps,
                    }
                })
                .collect()
        };
        let mut missing = manifests
            .iter()
            .flat_map(|manifest| manifest.missing_ranges.iter().copied())
            .collect::<Vec<_>>();
        if floor > 0 && heads.is_empty() {
            missing.push((1, floor));
        }
        let input = GraphReplayInputV1 {
            source: identity,
            records,
            input_positions: positions.clone(),
            coverage,
            coverage_keys,
            facts,
            missing_ranges: missing,
        }
        .normalized()
        .map_err(Self::external)?;
        let mut graph = Graph::try_from(input).map_err(Self::external)?;
        let (contexts, fact_refs) = Self::bind_facts(&graph.input.facts, &inputs[1])?;
        let recheck = heads.iter().zip(&manifests).any(|(head, previous)| {
            let prior_ids = previous.evidence.iter().collect::<BTreeSet<_>>();
            let context = graph
                .input
                .facts
                .iter()
                .zip(&graph.facts)
                .filter(|(_, fact)| prior_ids.contains(&fact.record_id))
                .map(|(version, _)| version.key.clone())
                .collect::<Vec<_>>();
            let prior_host = graph.input.facts.iter().any(|fact| {
                previous.context.contains(&fact.key)
                    && fact.sensitivity == araphor_data::ContextSensitivityV1::HostRestricted
            });
            let current_host =
                graph.input.facts.iter().any(|fact| {
                    fact.sensitivity == araphor_data::ContextSensitivityV1::HostRestricted
                });
            previous
                .evidence
                .iter()
                .any(|id| graph.revision.evidence.binary_search(id).is_err())
                || context != previous.context
                || previous.missing_ranges != graph.revision.missing_ranges
                || head.coverage != latest
                || (!prior_host && current_host)
        });
        for (head, manifest) in heads.iter_mut().zip(&manifests) {
            head.reusable = graph
                .input
                .records
                .first()
                .is_some_and(|row| row.id.durable_cursor == head.first)
                && graph
                    .input
                    .records
                    .last()
                    .is_some_and(|row| row.id.durable_cursor <= consumed)
                && head.deadline > source.time_utc_ns()
                && head.coverage == latest
                && manifest == &graph.revision;
        }
        memory.try_grow(
            positions.len() * size_of::<(DiscoveryRecordIdV1, StorePositionV1)>()
                + heads.len() * size_of::<Head>()
                + proofs.len() * size_of::<araphor_data::AnalysisContextRefV1>(),
        )?;
        let times = graph
            .observations
            .iter()
            .map(|row| row.ingested_utc_ns)
            .collect::<Vec<_>>();
        let revision = sdk::Revision {
            owner: araphor_data::GRAPH_PROCESSOR.into(),
            id: araphor_data::InputRevision::of_native(&(
                &graph.input.source,
                &graph.input.records,
                &graph.input.input_positions,
                &graph.input.coverage,
                &graph.input.coverage_keys,
                &graph.input.facts,
                &graph.input.missing_ranges,
            ))
            .map_err(Self::external)?,
            window: Some(sdk::SourceWindow {
                source: graph.input.source.exact_key(),
                start_utc_ns: times.iter().copied().min().unwrap_or(0),
                end_utc_ns: times.iter().copied().max().unwrap_or(0),
            }),
        };
        let state = if !graph.input.missing_ranges.is_empty()
            || graph
                .input
                .coverage
                .iter()
                .any(|range| range.state == araphor_data::DiscoveryCoverageStateV1::Gapped)
        {
            sdk::CoverageState::Gapped
        } else if graph.observations.iter().any(|row| {
            row.proof_quality.temporal_coverage != araphor_data::TemporalCoverageV1::Complete
        }) {
            sdk::CoverageState::Unknown
        } else {
            sdk::CoverageState::Complete
        };
        let coverage = sdk::Coverage {
            state,
            limits: if state == sdk::CoverageState::Complete {
                Vec::new()
            } else {
                vec!["SOURCE_COVERAGE_INSUFFICIENT".into()]
            },
        };
        control.check().map_err(Self::external)?;
        let inputs = self.inputs(&graph, &revision, &coverage, &memory, &frames)?;
        graph._memory = Some(frames);
        #[cfg(test)]
        self.projections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Capture {
            source: Arc::downgrade(source),
            graph: std::sync::Mutex::new(Some(graph)),
            positions,
            heads,
            proofs,
            fact_refs,
            contexts,
            consumed,
            accepted,
            coverage_revision: latest,
            recheck,
            now: source.time_utc_ns(),
            inputs,
            _memory: memory,
        })
    }

    pub(super) fn inputs(
        &self,
        graph: &Graph<'_>,
        revision: &sdk::Revision,
        coverage: &sdk::Coverage,
        memory: &MemoryReservation,
        frames: &MemoryReservation,
    ) -> Result<Vec<sdk::Input>> {
        let before = memory.size();
        let values = graph.projection().map_err(Self::external)?;
        let mut inputs = Vec::with_capacity(3);
        let mut metadata = 0usize;
        for data in values {
            if data.allocated_bytes() > self.limits.input_bytes {
                return Err(Self::external(
                    araphor_data::PackageErrorCodeV1::Limit.error("graph input bytes"),
                ));
            }
            frames.try_grow(data.metadata_bytes())?;
            let input = sdk::Input {
                data: data.clone(),
                revision: revision.clone(),
                coverage: coverage.clone(),
            };
            for batch in &input.data.batches {
                self.memory.retain_input(batch, memory)?;
            }
            metadata = metadata
                .checked_add(input.metadata_bytes())
                .and_then(|bytes| bytes.checked_add(size_of::<sdk::Input>()))
                .ok_or_else(|| Self::invalid("graph port metadata overflow"))?;
            inputs.push(input);
        }
        memory.try_resize(
            before
                .checked_add(metadata)
                .ok_or_else(|| Self::invalid("graph input metadata overflow"))?,
        )?;
        Ok(inputs)
    }

    pub(super) fn records(
        selected: &[sdk::RecordBatch],
        canonical: &[sdk::RecordBatch],
        memory: &MemoryReservation,
    ) -> Result<CapturedRecords> {
        let mut retained = BTreeMap::new();
        for batch in canonical {
            for row in 0..batch.num_rows() {
                retained.insert(
                    (
                        Self::column::<UInt64Array>(batch, "commit_revision")?.value(row),
                        Self::column::<UInt32Array>(batch, "ordinal")?.value(row),
                    ),
                    (batch, row),
                );
            }
        }
        let mut records = BTreeMap::new();
        let mut positions = BTreeMap::new();
        for batch in selected {
            for row in 0..batch.num_rows() {
                let revision = Self::column::<UInt64Array>(batch, "commit_revision")?.value(row);
                let ordinal = Self::column::<UInt32Array>(batch, "ordinal")?.value(row);
                let (actual, index) = retained
                    .get(&(revision, ordinal))
                    .ok_or_else(|| Self::invalid("uncaptured graph event position"))?;
                for name in [
                    "tenant_id",
                    "node_id",
                    "node_boot_id",
                    "label_epoch",
                    "source_id",
                    "source_epoch",
                    "cpu_id",
                    "source_cursor",
                    "framed_record",
                    "temporal_coverage",
                    "kernel_sequence",
                    "coverage_interval_id",
                ] {
                    let left = batch
                        .column_by_name(name)
                        .ok_or_else(|| Self::invalid("graph event field"))?
                        .slice(row, 1);
                    let right = actual
                        .column_by_name(name)
                        .ok_or_else(|| Self::invalid("graph event field"))?
                        .slice(*index, 1);
                    if left.as_ref() != right.as_ref() {
                        return Err(Self::invalid("graph event differs from capture"));
                    }
                }
                let id = DiscoveryRecordIdV1 {
                    stream: Self::identity(batch, row)?,
                    cpu_id: Self::column::<UInt32Array>(batch, "cpu_id")?.value(row),
                    durable_cursor: Self::column::<UInt64Array>(batch, "source_cursor")?.value(row),
                };
                let bytes = Self::column::<BinaryArray>(batch, "framed_record")?.value(row);
                memory.try_grow(bytes.len())?;
                let record =
                    DiscoveryRecordV1::try_from((id.clone(), bytes)).map_err(Self::external)?;
                if records.insert(id.clone(), record).is_some() {
                    return Err(Self::invalid("duplicate graph event"));
                }
                positions.insert(
                    id,
                    StorePositionV1 {
                        commit_revision: revision,
                        ordinal,
                    },
                );
            }
        }
        Ok((
            records.into_values().collect(),
            positions.into_iter().collect(),
        ))
    }

    pub(super) fn progress(
        batches: &[sdk::RecordBatch],
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<(u64, u64, u64)> {
        let mut found = None;
        for batch in batches {
            for row in 0..batch.num_rows() {
                if Self::identity(batch, row)? != *source {
                    continue;
                }
                let retired = Self::column::<BooleanArray>(batch, "retired")?;
                let class = Self::column::<StringArray>(batch, "processor_class")?;
                let consumed = Self::column::<UInt64Array>(batch, "consumed_cursor")?;
                if retired.is_null(row)
                    || retired.value(row)
                    || class.is_null(row)
                    || class.value(row) != "required"
                    || consumed.is_null(row)
                    || found.is_some()
                {
                    return Err(Self::invalid("required graph progress"));
                }
                let resumed = Self::column::<UInt64Array>(batch, "resume_floor")?;
                if resumed.is_null(row) || resumed.value(row) > consumed.value(row) {
                    return Err(Self::invalid("graph resume gap"));
                }
                found = Some((
                    consumed.value(row),
                    Self::column::<UInt64Array>(batch, "retained_floor")?.value(row),
                    Self::column::<UInt64Array>(batch, "contiguous_cursor")?.value(row),
                ));
            }
        }
        found.ok_or_else(|| Self::invalid("graph source registration"))
    }

    fn coverage_revision(
        batches: &[sdk::RecordBatch],
        source: &EvidenceIntakeIdentityV1,
    ) -> Result<u64> {
        for batch in batches {
            for row in 0..batch.num_rows() {
                if Self::identity(batch, row)? == *source {
                    return Ok(Self::column::<UInt64Array>(batch, "coverage_revision")?.value(row));
                }
            }
        }
        Err(Self::invalid("graph source receipt"))
    }

    fn frozen_facts(
        batches: &[sdk::RecordBatch],
        keys: &BTreeSet<AnalysisContextKeyV1>,
        records: &[DiscoveryRecordV1],
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        let mut values = BTreeMap::new();
        for batch in batches {
            for row in 0..batch.num_rows() {
                let key = Self::context_key(batch, row)?;
                if !keys.contains(&key) {
                    continue;
                }
                let from = Self::column::<UInt64Array>(batch, "valid_from_utc_ns")?;
                let until = Self::column::<UInt64Array>(batch, "valid_until_utc_ns")?;
                let value = AnalysisContextVersionV1 {
                    key: key.clone(),
                    valid_from_utc_ns: (!from.is_null(row)).then(|| from.value(row)),
                    valid_until_utc_ns: (!until.is_null(row)).then(|| until.value(row)),
                    sensitivity: Self::column::<StringArray>(batch, "sensitivity")?
                        .value(row)
                        .try_into()
                        .map_err(|_| Self::invalid("graph context sensitivity"))?,
                    body: Self::column::<BinaryArray>(batch, "body")?
                        .value(row)
                        .into(),
                };
                if values
                    .insert(key, value.clone())
                    .is_some_and(|old| old != value)
                {
                    return Err(Self::invalid("graph context identity"));
                }
            }
        }
        if values.len() != keys.len() {
            return Err(Self::invalid("frozen graph fact is absent"));
        }
        values
            .into_values()
            .filter_map(|value| match araphor_data::GraphFactV1::try_from(&value) {
                Ok(fact) => records
                    .binary_search_by(|row| row.id.cmp(&fact.record_id))
                    .is_ok()
                    .then_some(Ok(value)),
                Err(error) => Some(Err(Self::external(error))),
            })
            .collect()
    }

    fn bind_facts(
        values: &[AnalysisContextVersionV1],
        batches: &[sdk::RecordBatch],
    ) -> Result<(
        Vec<AnalysisContextVersionV1>,
        Vec<araphor_data::AnalysisContextRefV1>,
    )> {
        let mut stored = BTreeMap::new();
        for batch in batches {
            for row in 0..batch.num_rows() {
                if stored
                    .insert(Self::context_key(batch, row)?, (batch, row))
                    .is_some()
                {
                    return Err(Self::invalid("graph context identity"));
                }
            }
        }
        let mut contexts = Vec::new();
        let mut references = Vec::new();
        for value in values {
            let Some(&(batch, row)) = stored.get(&value.key) else {
                contexts.push(value.clone());
                continue;
            };
            let from = Self::column::<UInt64Array>(batch, "valid_from_utc_ns")?;
            let until = Self::column::<UInt64Array>(batch, "valid_until_utc_ns")?;
            let sensitivity: araphor_data::ContextSensitivityV1 =
                Self::column::<StringArray>(batch, "sensitivity")?
                    .value(row)
                    .try_into()
                    .map_err(|_| Self::invalid("graph context sensitivity"))?;
            if value.valid_from_utc_ns != (!from.is_null(row)).then(|| from.value(row))
                || value.valid_until_utc_ns != (!until.is_null(row)).then(|| until.value(row))
                || value.sensitivity != sensitivity
                || value.body.as_slice() != Self::column::<BinaryArray>(batch, "body")?.value(row)
            {
                return Err(Self::external(
                    araphor_data::PackageErrorCodeV1::Conflict.error("graph context identity"),
                ));
            }
            references.push(araphor_data::AnalysisContextRefV1 {
                key: value.key.clone(),
                commit_revision: Self::column::<UInt64Array>(batch, "commit_revision")?.value(row),
            });
        }
        Ok((contexts, references))
    }

    pub(super) fn context_key(
        batch: &sdk::RecordBatch,
        row: usize,
    ) -> Result<AnalysisContextKeyV1> {
        Ok(AnalysisContextKeyV1 {
            tenant_id: Self::column::<BinaryArray>(batch, "tenant_id")?
                .value(row)
                .try_into()
                .map_err(|_| Self::invalid("context tenant"))?,
            owner_id: Self::column::<StringArray>(batch, "owner_id")?
                .value(row)
                .into(),
            entity_key: Self::column::<BinaryArray>(batch, "entity_key")?
                .value(row)
                .into(),
            lifetime_key: Self::column::<BinaryArray>(batch, "lifetime_key")?
                .value(row)
                .into(),
            owner_revision: Self::column::<UInt64Array>(batch, "owner_revision")?.value(row),
        })
    }

    fn identity(batch: &sdk::RecordBatch, row: usize) -> Result<EvidenceIntakeIdentityV1> {
        Ok(EvidenceIntakeIdentityV1 {
            tenant_id: Self::column::<BinaryArray>(batch, "tenant_id")?
                .value(row)
                .try_into()
                .map_err(|_| Self::invalid("graph tenant"))?,
            node_id: Self::column::<StringArray>(batch, "node_id")?
                .value(row)
                .into(),
            node_boot_id: Self::column::<BinaryArray>(batch, "node_boot_id")?
                .value(row)
                .try_into()
                .map_err(|_| Self::invalid("graph boot"))?,
            label_epoch: Self::column::<UInt64Array>(batch, "label_epoch")?.value(row),
            source_id: Self::column::<BinaryArray>(batch, "source_id")?
                .value(row)
                .try_into()
                .map_err(|_| Self::invalid("graph source"))?,
            source_epoch: Self::column::<UInt64Array>(batch, "source_epoch")?.value(row),
        })
    }

    pub(super) fn value<T: serde::de::DeserializeOwned>(
        batch: &sdk::RecordBatch,
        name: &str,
        row: usize,
    ) -> Result<T> {
        #[derive(serde::Deserialize)]
        struct Cell<T> {
            value: T,
        }
        let column = batch
            .column_by_name(name)
            .ok_or_else(|| Self::invalid("graph native column"))?
            .slice(row, 1);
        let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            column.data_type().clone(),
            true,
        )]));
        let batch = sdk::RecordBatch::try_new(schema, vec![column]).map_err(Self::external)?;
        let mut values: Vec<Cell<T>> =
            serde_arrow::from_record_batch(&batch).map_err(Self::external)?;
        values
            .pop()
            .map(|value| value.value)
            .ok_or_else(|| Self::invalid("graph native value"))
    }

    pub(super) fn column<'a, T: Array + 'static>(
        batch: &'a sdk::RecordBatch,
        name: &str,
    ) -> Result<&'a T> {
        batch
            .column_by_name(name)
            .and_then(|column| column.as_any().downcast_ref())
            .ok_or_else(|| Self::invalid("graph native column"))
    }
}
