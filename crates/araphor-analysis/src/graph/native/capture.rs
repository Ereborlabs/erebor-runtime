use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::{Arc, Weak};

use araphor_analysis_builtins::Rows;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, DiscoveryRecordIdV1, DiscoveryRecordV1,
    EvidenceIntakeIdentityV1, GraphCoverageKeyV1, GraphReplayInputV1, GraphRevisionV1,
    StorePositionV1,
};
use araphor_query::sources::SourceSnapshot;
use datafusion::arrow::array::{Array, BinaryArray, StringArray, UInt32Array, UInt64Array};
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::TaskContext;
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
        let value = run
            .captured
            .get_or_init(|| async {
                let value = self
                    .read(plans, context, Arc::clone(&source))
                    .await
                    .map(Arc::new)
                    .map_err(Arc::new);
                #[cfg(test)]
                {
                    let observed = self
                        .observed
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .clone();
                    if let (Ok(value), Some(observed)) = (&value, observed) {
                        let _observed = observed.send(Arc::clone(value));
                    }
                }
                value
            })
            .await
            .clone()
            .map_err(DataFusionError::Shared)?;
        if !Weak::ptr_eq(&value.source, &Arc::downgrade(&source)) {
            return Err(Self::invalid("graph input belongs to another capture"));
        }
        Ok(value)
    }

    async fn read(
        self: &Arc<Self>,
        plans: &[Arc<dyn ExecutionPlan>],
        context: &Arc<TaskContext>,
        source: Arc<SourceSnapshot>,
    ) -> Result<Capture> {
        if plans.len() != 6 {
            return Err(Self::invalid("graph source plans"));
        }
        let control = context
            .session_config()
            .get_extension::<araphor_data::AnalysisReadControl>()
            .ok_or_else(|| Self::invalid("graph execution control"))?;
        let memory = self.memory.reserve_input(0)?;
        let temporary = self.memory.reserve_input(0)?;
        let frames = self.memory.reserve_input(0)?;
        let mut inputs = Vec::with_capacity(plans.len());
        for plan in plans {
            let mut stream = execute_stream(Arc::clone(plan), Arc::clone(context))?;
            let mut batches = Vec::new();
            while let Some(batch) = stream.try_next().await? {
                control.check().map_err(Self::external)?;
                self.memory.retain_input(&batch, &temporary)?;
                let before = batches.capacity();
                batches.push(batch);
                temporary.try_grow(
                    (batches.capacity() - before)
                        .checked_mul(size_of::<sdk::RecordBatch>())
                        .ok_or_else(|| Self::invalid("graph batch metadata overflow"))?,
                )?;
            }
            inputs.push(batches);
        }
        let owner = Arc::clone(self);
        source
            .blocking(context, temporary, move |source, control| {
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
        memory: datafusion::execution::memory_pool::MemoryReservation,
        frames: datafusion::execution::memory_pool::MemoryReservation,
    ) -> Result<Capture> {
        let (records, positions) = source.with_table("events", |_, canonical| {
            Self::records(&inputs[0], canonical, &frames)
        })?;
        let first = records
            .first()
            .ok_or_else(|| Self::invalid("empty graph window"))?;
        let identity = &first.id.stream;
        if identity.tenant_id != self.tenant
            || records.iter().any(|record| record.id.stream != *identity)
        {
            return Err(Self::invalid("one exact graph source"));
        }
        let (consumed, floor, accepted) = Self::progress(&inputs[3], identity)?;
        let mut heads = Vec::new();
        let mut manifests = Vec::new();
        for batch in &inputs[4] {
            for row in 0..batch.num_rows() {
                if Self::column::<BinaryArray>(batch, "source_key")?.value(row) != identity.key() {
                    continue;
                }
                let revision: GraphRevisionV1 = Self::json(batch, "graph_revision", row)?;
                if revision
                    .evidence
                    .iter()
                    .any(|id| records.binary_search_by(|record| record.id.cmp(id)).is_ok())
                {
                    heads.push(Head {
                        id: Self::column::<StringArray>(batch, "graph_result_id")?
                            .value(row)
                            .into(),
                        revision: Self::column::<UInt64Array>(batch, "commit_revision")?.value(row),
                        first: Self::column::<UInt64Array>(batch, "first_cursor")?.value(row),
                        deadline: Self::column::<UInt64Array>(batch, "witness_deadline_utc_ns")?
                            .value(row),
                        coverage: Self::column::<UInt64Array>(batch, "notice_coverage_revision")?
                            .value(row),
                        packages: Self::json::<Vec<araphor_data::AnalysisContextRefV1>>(
                            batch,
                            "context_refs",
                            row,
                        )?
                        .into_iter()
                        .filter(|reference| reference.key.owner_id == "native-package-v1")
                        .map(|reference| reference.key)
                        .collect(),
                        reusable: false,
                    });
                    manifests.push(revision);
                }
            }
        }
        let deadline = heads
            .iter()
            .map(|head| head.deadline)
            .min()
            .map(Ok)
            .unwrap_or_else(|| {
                source
                    .time_utc_ns()
                    .checked_add(araphor_data::GRAPH_WITNESS_TTL_NS)
                    .ok_or_else(|| Self::invalid("graph witness deadline"))
            })?;
        Self::check_deadline(deadline).map_err(Self::external)?;
        let keys = manifests
            .iter()
            .flat_map(|manifest| manifest.context.iter())
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
            coverage.extend(values.into_iter().filter(|range| range.stream == *identity));
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
        let latest = Self::coverage_revision(&inputs[3], identity)?;
        let mut requested = manifests
            .iter()
            .flat_map(|manifest| &manifest.coverage)
            .filter(|key| key.source == *identity && intervals.contains(&key.interval_id))
            .map(|key| key.report_revision)
            .collect::<BTreeSet<_>>();
        requested.insert(latest);
        let mut versions = BTreeMap::new();
        let mut matching = BTreeSet::new();
        for batch in &inputs[5] {
            let ids = Self::column::<BinaryArray>(batch, "interval_id")?;
            for row in 0..batch.num_rows() {
                if ids.is_null(row) || Self::identity(batch, row)? != *identity {
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
                    .is_some_and(|previous| previous != version)
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
            source: identity.clone(),
            records,
            coverage,
            coverage_keys,
            facts,
            missing_ranges: missing,
        };
        let copied_frames = input.records.iter().try_fold(0usize, |bytes, record| {
            bytes
                .checked_add(record.wire_record.len())
                .ok_or_else(|| Self::invalid("graph frame bytes overflow"))
        })?;
        frames.try_grow(copied_frames)?;
        let normalized = input.normalized().map_err(Self::external)?;
        drop(input);
        frames.shrink(copied_frames);
        #[cfg(test)]
        self.projections
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut graph = Graph::try_from(normalized).map_err(Self::external)?;
        let first = graph
            .input
            .records
            .iter()
            .map(|record| record.id.durable_cursor)
            .min();
        let last = graph
            .input
            .records
            .iter()
            .map(|record| record.id.durable_cursor)
            .max();
        for (head, manifest) in heads.iter_mut().zip(&manifests) {
            head.reusable = first == Some(head.first)
                && last.is_some_and(|last| last <= consumed)
                && head.deadline > source.time_utc_ns()
                && head.coverage == latest
                && manifest == &graph.revision;
        }
        frames.try_grow(Self::graph_metadata(&graph)?)?;
        graph._memory = Some(frames);
        let mut retained = positions
            .capacity()
            .checked_mul(size_of::<(DiscoveryRecordIdV1, StorePositionV1)>())
            .and_then(|bytes| bytes.checked_add(heads.capacity().checked_mul(size_of::<Head>())?))
            .and_then(|bytes| {
                bytes.checked_add(
                    proofs
                        .capacity()
                        .checked_mul(size_of::<araphor_data::AnalysisContextRefV1>())?,
                )
            })
            .ok_or_else(|| Self::invalid("graph retained metadata overflow"))?;
        for bytes in positions
            .iter()
            .map(|(id, _)| id.stream.node_id.capacity())
            .chain(heads.iter().map(|head| head.id.capacity()))
            .chain(proofs.iter().flat_map(|proof| {
                [
                    proof.key.owner_id.capacity(),
                    proof.key.entity_key.capacity(),
                    proof.key.lifetime_key.capacity(),
                ]
            }))
        {
            retained = retained
                .checked_add(bytes)
                .ok_or_else(|| Self::invalid("graph retained metadata overflow"))?;
        }
        for key in heads.iter().flat_map(|head| &head.packages) {
            retained = retained
                .checked_add(
                    size_of::<araphor_data::AnalysisContextKeyV1>()
                        + key.owner_id.capacity()
                        + key.entity_key.capacity()
                        + key.lifetime_key.capacity(),
                )
                .ok_or_else(|| Self::invalid("graph retained metadata overflow"))?;
        }
        memory.try_grow(retained)?;
        let times = graph
            .input
            .records
            .iter()
            .map(|record| record.decode().map(|wire| wire.ingested_utc_ns))
            .collect::<araphor_data::Result<Vec<_>>>()
            .map_err(Self::external)?;
        let revision = sdk::Revision {
            owner: araphor_data::GRAPH_PROCESSOR.into(),
            id: araphor_data::InputRevision::of(&(
                &graph.input.source,
                &graph.input.records,
                &graph.input.coverage,
                &graph.input.coverage_keys,
                &graph.input.facts,
                &graph.input.missing_ranges,
            ))
            .map_err(Self::external)?,
            window: Some(sdk::SourceWindow {
                source: serde_json::to_vec(&graph.input.source).map_err(Self::external)?,
                start_utc_ns: times.iter().copied().min().unwrap_or(0),
                end_utc_ns: times.iter().copied().max().unwrap_or(0),
            }),
        };
        let incomplete = graph.input.records.iter().any(|record| {
            graph
                .observation(record)
                .is_ok_and(|record| !record.complete)
        });
        let state = if !graph.input.missing_ranges.is_empty()
            || graph
                .input
                .coverage
                .iter()
                .any(|range| range.state == araphor_data::DiscoveryCoverageStateV1::Gapped)
        {
            sdk::CoverageState::Gapped
        } else if incomplete {
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
        let values = graph.projection();
        let mut inputs = Vec::with_capacity(3);
        for (port, values) in self.ports.iter().zip(values) {
            let (bytes, allocation) = Rows::capacity(values).map_err(Self::external)?;
            if bytes > self.limits.input_bytes {
                return Err(Self::external(
                    araphor_data::PackageErrorCodeV1::Limit.error("graph input bytes"),
                ));
            }
            let before = memory.size();
            memory.try_grow(allocation)?;
            let data = Rows::encode_capacity(port, values, bytes).map_err(Self::external)?;
            for batch in &data.batches {
                self.memory.retain_input(batch, &memory)?;
            }
            memory.try_resize(
                before
                    .checked_add(data.metadata_bytes())
                    .ok_or_else(|| Self::invalid("graph input metadata overflow"))?,
            )?;
            let input = sdk::Input {
                data,
                revision: revision.clone(),
                coverage: coverage.clone(),
            };
            memory.try_grow(
                input
                    .metadata_bytes()
                    .saturating_sub(input.data.metadata_bytes())
                    .checked_add(size_of::<sdk::Input>())
                    .ok_or_else(|| Self::invalid("graph port metadata overflow"))?,
            )?;
            inputs.push(input);
        }
        control.check().map_err(Self::external)?;
        Ok(Capture {
            source: Arc::downgrade(source),
            graph: std::sync::Mutex::new(Some(graph)),
            positions,
            heads,
            proofs,
            consumed,
            accepted,
            coverage_revision: latest,
            now: source.time_utc_ns(),
            inputs,
            _memory: memory,
        })
    }

    fn graph_metadata(graph: &Graph<'_>) -> Result<usize> {
        let input = &graph.input;
        let mut bytes = 0usize;
        let mut add = |size| {
            bytes = bytes
                .checked_add(size)
                .ok_or_else(|| Self::invalid("graph metadata overflow"))?;
            Ok::<_, DataFusionError>(())
        };
        for (capacity, width) in [
            (input.records.capacity(), size_of::<DiscoveryRecordV1>()),
            (
                input.coverage.capacity(),
                size_of::<araphor_data::DiscoveryCoverageV1>(),
            ),
            (
                input.coverage_keys.capacity(),
                size_of::<GraphCoverageKeyV1>(),
            ),
            (
                input.facts.capacity(),
                size_of::<AnalysisContextVersionV1>(),
            ),
            (input.missing_ranges.capacity(), size_of::<(u64, u64)>()),
            (
                graph.facts.capacity(),
                size_of::<araphor_data::GraphFactV1>(),
            ),
            (
                graph.revision.evidence.capacity(),
                size_of::<DiscoveryRecordIdV1>(),
            ),
            (
                graph.revision.coverage.capacity(),
                size_of::<GraphCoverageKeyV1>(),
            ),
            (
                graph.revision.context.capacity(),
                size_of::<AnalysisContextKeyV1>(),
            ),
            (
                graph.revision.missing_ranges.capacity(),
                size_of::<(u64, u64)>(),
            ),
        ] {
            add(capacity
                .checked_mul(width)
                .ok_or_else(|| Self::invalid("graph metadata overflow"))?)?;
        }
        add(input.source.node_id.capacity())?;
        for id in input
            .records
            .iter()
            .map(|record| &record.id)
            .chain(&graph.revision.evidence)
        {
            add(id.stream.node_id.capacity())?;
        }
        for range in &input.coverage {
            add(range.stream.node_id.capacity())?;
            add(range
                .gap_reasons
                .capacity()
                .checked_mul(size_of::<String>())
                .ok_or_else(|| Self::invalid("graph metadata overflow"))?)?;
            for reason in &range.gap_reasons {
                add(reason.capacity())?;
            }
        }
        for range in input.coverage_keys.iter().chain(&graph.revision.coverage) {
            add(range.source.node_id.capacity())?;
            add(range
                .gap_reasons
                .capacity()
                .checked_mul(size_of::<String>())
                .ok_or_else(|| Self::invalid("graph metadata overflow"))?)?;
            for reason in &range.gap_reasons {
                add(reason.capacity())?;
            }
        }
        for key in input
            .facts
            .iter()
            .map(|fact| &fact.key)
            .chain(&graph.revision.context)
        {
            add(key.owner_id.capacity())?;
            add(key.entity_key.capacity())?;
            add(key.lifetime_key.capacity())?;
        }
        for fact in &input.facts {
            add(fact.body.capacity())?;
        }
        let mut values = Vec::new();
        for rows in graph.projection() {
            add(rows
                .capacity()
                .checked_mul(size_of::<serde_json::Value>())
                .ok_or_else(|| Self::invalid("graph metadata overflow"))?)?;
            values.extend(rows);
        }
        while let Some(value) = values.pop() {
            match value {
                serde_json::Value::String(value) => add(value.capacity())?,
                serde_json::Value::Array(array) => {
                    add(array
                        .capacity()
                        .checked_mul(size_of::<serde_json::Value>())
                        .ok_or_else(|| Self::invalid("graph metadata overflow"))?)?;
                    values.extend(array);
                }
                serde_json::Value::Object(object) => {
                    add(object
                        .len()
                        .checked_mul(size_of::<(String, serde_json::Value)>())
                        .ok_or_else(|| Self::invalid("graph metadata overflow"))?)?;
                    for (key, value) in object {
                        add(key.capacity())?;
                        values.push(value);
                    }
                }
                _ => {}
            }
        }
        Ok(bytes)
    }

    pub(super) fn records(
        selected: &[sdk::RecordBatch],
        canonical: &[sdk::RecordBatch],
        memory: &datafusion::execution::memory_pool::MemoryReservation,
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
                let identity = Self::identity(batch, row)?;
                let id = DiscoveryRecordIdV1 {
                    stream: identity,
                    cpu_id: Self::column::<UInt32Array>(batch, "cpu_id")?.value(row),
                    durable_cursor: Self::column::<UInt64Array>(batch, "source_cursor")?.value(row),
                };
                memory.try_grow(
                    Self::column::<BinaryArray>(batch, "framed_record")?
                        .value(row)
                        .len(),
                )?;
                let record = DiscoveryRecordV1::try_from((
                    id.clone(),
                    Self::column::<BinaryArray>(batch, "framed_record")?.value(row),
                ))
                .map_err(Self::external)?;
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
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<(u64, u64, u64)> {
        let mut progress = None;
        for batch in batches {
            for row in 0..batch.num_rows() {
                if Self::identity(batch, row)? != *identity {
                    continue;
                }
                let retired = Self::column::<sdk::arrow_array::BooleanArray>(batch, "retired")?;
                let class = Self::column::<StringArray>(batch, "processor_class")?;
                let consumed = Self::column::<UInt64Array>(batch, "consumed_cursor")?;
                if retired.is_null(row)
                    || retired.value(row)
                    || class.is_null(row)
                    || class.value(row) != "required"
                    || consumed.is_null(row)
                    || progress.is_some()
                {
                    return Err(Self::invalid("required graph progress"));
                }
                let resumed = Self::column::<UInt64Array>(batch, "resume_floor")?;
                if resumed.is_null(row) || resumed.value(row) > consumed.value(row) {
                    return Err(Self::invalid("graph resume gap"));
                }
                progress = Some((
                    consumed.value(row),
                    Self::column::<UInt64Array>(batch, "retained_floor")?.value(row),
                    Self::column::<UInt64Array>(batch, "contiguous_cursor")?.value(row),
                ));
            }
        }
        progress.ok_or_else(|| Self::invalid("graph source registration"))
    }

    fn coverage_revision(
        batches: &[sdk::RecordBatch],
        identity: &EvidenceIntakeIdentityV1,
    ) -> Result<u64> {
        for batch in batches {
            for row in 0..batch.num_rows() {
                if Self::identity(batch, row)? == *identity {
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
        let mut facts = BTreeMap::new();
        for batch in batches {
            for row in 0..batch.num_rows() {
                let key = Self::context_key(batch, row)?;
                if !keys.contains(&key) {
                    continue;
                }
                let valid_from = Self::column::<UInt64Array>(batch, "valid_from_utc_ns")?;
                let valid_until = Self::column::<UInt64Array>(batch, "valid_until_utc_ns")?;
                facts.insert(
                    key.clone(),
                    AnalysisContextVersionV1 {
                        key,
                        valid_from_utc_ns: (!valid_from.is_null(row))
                            .then(|| valid_from.value(row)),
                        valid_until_utc_ns: (!valid_until.is_null(row))
                            .then(|| valid_until.value(row)),
                        sensitivity: Self::column::<StringArray>(batch, "sensitivity")?
                            .value(row)
                            .try_into()
                            .map_err(|_| Self::invalid("graph context sensitivity"))?,
                        body: Self::column::<BinaryArray>(batch, "body")?
                            .value(row)
                            .into(),
                    },
                );
            }
        }
        if facts.len() != keys.len() {
            return Err(Self::invalid("frozen graph fact is absent"));
        }
        let mut selected = Vec::new();
        for context in facts.into_values() {
            let fact = araphor_data::GraphFactV1::try_from(&context).map_err(Self::external)?;
            if records
                .binary_search_by(|record| record.id.cmp(&fact.record_id))
                .is_ok()
            {
                selected.push(context);
            }
        }
        Ok(selected)
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

    pub(super) fn json<T: serde::de::DeserializeOwned>(
        batch: &sdk::RecordBatch,
        name: &str,
        row: usize,
    ) -> Result<T> {
        serde_json::from_slice(Self::column::<BinaryArray>(batch, name)?.value(row))
            .map_err(Self::external)
    }

    pub(super) fn column<'a, T: Array + 'static>(
        batch: &'a sdk::RecordBatch,
        name: &str,
    ) -> Result<&'a T> {
        batch
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref::<T>())
            .ok_or_else(|| Self::invalid("graph native column"))
    }
}
