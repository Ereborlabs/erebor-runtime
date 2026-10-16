use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;

use araphor_data::analysis::PackageResultRefV1;
use araphor_data::{
    AnalysisContextRefV1, AnalysisInputV1, AnalysisPositionPageV1, AnalysisProjection,
    AnalysisSelectionV1, AnalysisStreamIdentityV1, AnalysisWitnessV1, ProjectionSink, Selection,
    StorePositionV1, TraceRecipeV1,
};
use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::{DataType, SchemaRef};
use datafusion::common::{DataFusionError, Result, ScalarValue};
use datafusion::execution::memory_pool::MemoryReservation;

use super::{batch::ArrowBatch, ReadMode, SourceSnapshot};

mod context;
mod discovery;
mod events;
mod graph;
mod metadata;
mod notification;
mod trace;

#[cfg(test)]
mod tests;

pub struct ArrowSnapshot {
    pub page: AnalysisPositionPageV1,
    pub selection: AnalysisSelectionV1,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
    pub results: Vec<PackageResultRefV1>,
    pub mutable_discovery: bool,
    pub received_min: Option<u64>,
    pub next_change: Option<u64>,
    _metadata: MemoryReservation,
}

impl std::fmt::Debug for ArrowSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArrowSnapshot")
            .field("revision", &self.page.extraction.meta.commit_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct Captured {
    pub(crate) receipt: Arc<ArrowSnapshot>,
    pub(crate) removals: Vec<Removal>,
    _removals: MemoryReservation,
    tables: BTreeMap<String, (Vec<usize>, Vec<RecordBatch>)>,
}

impl Captured {
    pub(crate) fn set_witnesses(&mut self, witnesses: Vec<AnalysisWitnessV1>) -> Result<()> {
        let receipt = Arc::get_mut(&mut self.receipt).ok_or_else(|| {
            DataFusionError::Internal("the source receipt is already shared".into())
        })?;
        let overflow = || DataFusionError::Internal("source witness allocation overflowed".into());
        let bytes = |values: &Vec<AnalysisWitnessV1>| {
            values.iter().try_fold(
                values
                    .capacity()
                    .checked_mul(std::mem::size_of::<AnalysisWitnessV1>())
                    .ok_or_else(overflow)?,
                |bytes, witness| {
                    let capacity = match &witness.identity {
                        AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                        AnalysisStreamIdentityV1::Diagnostic(identity) => {
                            identity.node_id.capacity()
                        }
                    };
                    bytes.checked_add(capacity).ok_or_else(overflow)
                },
            )
        };
        let previous = receipt._metadata.size();
        let old = bytes(&receipt.witnesses)?;
        let added = bytes(&witnesses)?;
        let retained = previous
            .checked_sub(old)
            .and_then(|retained| retained.checked_add(added))
            .ok_or_else(overflow)?;
        if retained > previous {
            receipt
                ._metadata
                .try_grow(retained - previous)
                .map_err(|source| {
                    DataFusionError::External(Box::new(crate::Error::Capacity {
                        resource: "shared input",
                        source,
                    }))
                })?;
        }
        receipt.witnesses = witnesses;
        if retained < previous {
            receipt._metadata.shrink(previous - retained);
        }
        Ok(())
    }

    pub(crate) fn project(&self, name: &str, indices: &[usize]) -> Result<Vec<RecordBatch>> {
        let Some((captured, batches)) = self.tables.get(name) else {
            return Ok(Vec::new());
        };
        let projection = indices
            .iter()
            .map(|index| {
                captured.binary_search(index).map_err(|_| {
                    DataFusionError::Internal(
                        "a native scan requested an uncaptured source column".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        batches
            .iter()
            .map(|batch| batch.project(&projection).map_err(Into::into))
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct Removal {
    pub(crate) identity: AnalysisStreamIdentityV1,
    pub(crate) first: u64,
    pub(crate) last: u64,
    pub(crate) position: StorePositionV1,
}

struct Capture<'a> {
    sources: &'a BTreeSet<String>,
    scope: &'a AnalysisSelectionV1,
    requested: &'a BTreeMap<String, BTreeSet<usize>>,
    schemas: BTreeMap<String, SchemaRef>,
    tables: BTreeMap<String, ArrowBatch>,
    witnesses: Vec<AnalysisWitnessV1>,
    removals: Vec<Removal>,
    latest: BTreeMap<([u8; 16], String), (u64, usize)>,
    trace_recipes: BTreeMap<[u8; 16], TraceRecipeV1>,
    mutable_discovery: bool,
    received_min: Option<u64>,
    next_change: Option<u64>,
    now: u64,
}

impl SourceSnapshot {
    pub(crate) fn read(
        &self,
        sources: &BTreeSet<String>,
        requests: &BTreeMap<String, BTreeSet<usize>>,
        mode: ReadMode,
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<Captured> {
        let mut reservation = if matches!(mode, ReadMode::Changes(_)) {
            self.memory.prepare_input(self.limits.input_bytes)?
        } else {
            self.memory.reserve_input(self.limits.input_bytes)?
        };
        let mut limits = self.limits;
        limits.input_bytes = reservation.size();
        let constrained = limits.input_bytes < self.limits.input_bytes;
        let data_error = |error| {
            if constrained
                && matches!(error, araphor_data::Error::AnalysisInputTooLarge { resource, .. }
                if resource != "scanned segment bytes" && resource != "projected row bytes")
            {
                DataFusionError::External(Box::new(crate::Error::Capacity {
                    resource: "shared input",
                    source: Self::data_error(error),
                }))
            } else {
                Self::data_error(error)
            }
        };
        let selection = self.prune_selection(
            Capture::selection(&self.selection, sources).map_err(Self::data_error)?,
        )?;
        let capture = Capture {
            sources,
            scope: &selection,
            requested: requests,
            schemas: Self::schemas(),
            tables: BTreeMap::new(),
            witnesses: Vec::new(),
            removals: Vec::new(),
            latest: BTreeMap::new(),
            trace_recipes: BTreeMap::new(),
            mutable_discovery: false,
            received_min: None,
            next_change: None,
            now: self.now,
        };
        let (mut page, mut capture) = match mode {
            ReadMode::Page(after) => self
                .store
                .position_rows(&selection, after, limits, control, capture),
            ReadMode::Changes(after) => self
                .store
                .change_rows(&selection, after, limits, control, capture),
            ReadMode::Snapshot
                if sources.contains("events")
                    || sources.contains("trace_output")
                    || sources.contains("trace_measurements") =>
            {
                self.store
                    .extract_rows(&selection, limits, control, capture)
            }
            ReadMode::Snapshot | ReadMode::Metadata => self
                .store
                .metadata_rows(&selection, limits, control, capture),
        }
        .map_err(data_error)?;
        capture
            .metadata(&mut page.extraction, control)
            .map_err(data_error)?;
        {
            let mut sink = page.extraction.sink(control);
            for table in capture.tables.values_mut() {
                table.finish(&mut sink).map_err(data_error)?;
            }
            if let Some(findings) = capture.tables.get_mut("findings") {
                let selected = capture.latest.values().map(|(_, row)| *row).collect();
                findings
                    .select_rows(&selected, &mut sink)
                    .map_err(data_error)?;
            }
        }
        for table in capture.tables.values() {
            for batch in &table.batches {
                self.memory.retain_input(batch, &mut reservation)?;
            }
        }
        let metadata = std::mem::size_of::<ArrowSnapshot>()
            .saturating_add(
                page.extraction
                    .allocation_bytes()
                    .saturating_sub(std::mem::size_of::<araphor_data::AnalysisExtractionV1>()),
            )
            .saturating_add(
                selection
                    .allocation_bytes()
                    .saturating_sub(std::mem::size_of::<AnalysisSelectionV1>()),
            )
            .saturating_add(
                capture
                    .witnesses
                    .capacity()
                    .saturating_mul(std::mem::size_of::<AnalysisWitnessV1>()),
            )
            .saturating_add(
                capture
                    .witnesses
                    .iter()
                    .map(|witness| match &witness.identity {
                        araphor_data::AnalysisStreamIdentityV1::Evidence(identity) => {
                            identity.node_id.capacity()
                        }
                        araphor_data::AnalysisStreamIdentityV1::Diagnostic(identity) => {
                            identity.node_id.capacity()
                        }
                    })
                    .sum::<usize>(),
            );
        let removed = capture
            .removals
            .capacity()
            .saturating_mul(std::mem::size_of::<Removal>())
            .saturating_add(
                capture
                    .removals
                    .iter()
                    .map(|removal| match &removal.identity {
                        AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                        AnalysisStreamIdentityV1::Diagnostic(identity) => {
                            identity.node_id.capacity()
                        }
                    })
                    .sum::<usize>(),
            );
        if metadata.saturating_add(removed) > reservation.size() {
            let source = DataFusionError::ResourcesExhausted(
                "source metadata exceeds the admitted input".into(),
            );
            return Err(if constrained {
                DataFusionError::External(Box::new(crate::Error::Capacity {
                    resource: "shared input",
                    source,
                }))
            } else {
                source
            });
        }
        reservation.try_resize(metadata.saturating_add(removed))?;
        let removal_memory = reservation.split(removed);
        control.check().map_err(Self::data_error)?;
        let Capture {
            tables,
            witnesses,
            removals,
            mutable_discovery,
            received_min,
            next_change,
            ..
        } = capture;
        let contexts = std::mem::take(&mut page.extraction.context_refs);
        let results = std::mem::take(&mut page.extraction.result_refs);
        let receipt = Arc::new(ArrowSnapshot {
            page,
            selection,
            witnesses,
            contexts,
            results,
            mutable_discovery,
            received_min,
            next_change,
            _metadata: reservation,
        });
        Ok(Captured {
            receipt,
            removals,
            _removals: removal_memory,
            tables: tables
                .into_iter()
                .map(|(name, table)| (name, (table.indices, table.batches)))
                .collect(),
        })
    }
}

impl Capture<'_> {
    fn selection(
        scope: &AnalysisSelectionV1,
        sources: &BTreeSet<String>,
    ) -> araphor_data::Result<AnalysisSelectionV1> {
        let mut selection = scope.clone();
        let graph = sources.iter().any(|name| {
            matches!(
                name.as_str(),
                "findings"
                    | "relationships"
                    | "graph_subjects"
                    | "graph_branches"
                    | "correlation_packages"
                    | "policy_observations"
                    | "graph_manifest"
            )
        });
        let discovery = sources.contains("behaviors");
        let targets = sources.contains("targets");
        let context =
            sources.contains("context") || sources.contains("context_versions") || targets;
        if !sources.contains("events")
            && !sources.contains("coverage")
            && !sources.contains("notifications")
            && !graph
            && !discovery
        {
            selection.sources = Selection::Exact(Vec::new());
        }
        if !sources.iter().any(|name| {
            matches!(
                name.as_str(),
                "traces" | "trace_output" | "trace_measurements"
            )
        }) {
            selection.traces = Selection::Exact(Vec::new());
        }
        if !context {
            selection.contexts = Selection::Exact(Vec::new());
        }
        selection.select_targets(
            targets,
            targets
                && !sources.contains("events")
                && !sources.contains("context")
                && !sources.contains("context_versions"),
        )?;
        let profiles = if selection.profiles().is_empty() {
            Selection::All
        } else {
            Selection::Exact(selection.profiles().to_vec())
        };
        selection.select_profiles(if discovery {
            profiles
        } else {
            Selection::Exact(Vec::new())
        })?;
        let traversal = selection.graph_traversal().cloned();
        selection.select_graphs(
            if graph {
                if selection.graphs().is_empty() {
                    Selection::All
                } else {
                    Selection::Exact(selection.graphs().to_vec())
                }
            } else {
                Selection::Exact(Vec::new())
            },
            if graph { traversal } else { None },
        )?;
        let notifications = if selection.notification_keys().is_empty() {
            Selection::All
        } else {
            Selection::Exact(selection.notification_keys().to_vec())
        };
        selection.select_notifications(if sources.contains("notifications") {
            notifications
        } else {
            Selection::Exact(Vec::new())
        })?;
        Ok(selection)
    }

    fn append(
        &mut self,
        name: &str,
        sink: &mut ProjectionSink<'_>,
        value: impl FnMut(&str, &DataType, &mut ProjectionSink<'_>) -> araphor_data::Result<ScalarValue>,
    ) -> araphor_data::Result<bool> {
        let Some(indices) = self.requested.get(name) else {
            return Ok(true);
        };
        if !self.tables.contains_key(name) {
            sink.charge(name.len() + 512)?;
            let schema = self
                .schemas
                .get(name)
                .ok_or_else(|| ArrowBatch::invalid("the source has no native Arrow schema"))?;
            let indices = indices.iter().copied().collect::<Vec<_>>();
            let schema = Arc::new(schema.project(&indices).map_err(ArrowBatch::arrow_error)?);
            self.tables
                .insert(name.into(), ArrowBatch::new(schema, indices, sink)?);
        }
        self.tables
            .get_mut(name)
            .ok_or_else(|| ArrowBatch::invalid("the native source builder is absent"))?
            .append(sink, value)
    }

    fn null(kind: &DataType) -> araphor_data::Result<ScalarValue> {
        ScalarValue::try_from(kind)
            .map_err(|_| ArrowBatch::invalid("the source has no native null value"))
    }

    fn binary(
        value: Option<&[u8]>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<ScalarValue> {
        sink.charge(value.map_or(0, <[u8]>::len))?;
        Ok(ScalarValue::Binary(value.map(<[u8]>::to_vec)))
    }

    fn text(
        value: Option<&str>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<ScalarValue> {
        sink.charge(value.map_or(0, str::len))?;
        Ok(ScalarValue::Utf8(value.map(str::to_owned)))
    }

    fn json(
        value: &impl serde::Serialize,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<ScalarValue> {
        let mut counter = JsonSize {
            bytes: 0,
            limit: sink.remaining_bytes(),
        };
        serde_json::to_writer(&mut counter, value).map_err(|_| ArrowBatch::overflow())?;
        sink.charge(
            counter
                .bytes
                .checked_mul(2)
                .ok_or_else(ArrowBatch::overflow)?,
        )?;
        let mut buffer = araphor_analysis_sdk::wire::BoundedBuffer::new(counter.bytes as u64);
        serde_json::to_writer(&mut buffer, value).map_err(|source| {
            araphor_data::Error::PackageEncoding {
                source,
                location: snafu::location!(),
            }
        })?;
        Ok(ScalarValue::Binary(Some(buffer.finish())))
    }
}

impl AnalysisProjection for Capture<'_> {
    fn decodes_events(&self) -> bool {
        self.sources.contains("events")
    }
    fn graph_subjects(&self) -> bool {
        self.requested.contains_key("graph_subjects")
    }
    fn graph_relationships(&self) -> bool {
        self.requested.contains_key("relationships")
    }
    fn graph_headers(&self) -> bool {
        self.sources.contains("graph_manifest")
    }

    fn project(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> araphor_data::Result<bool> {
        match input {
            AnalysisInputV1::RawRemoval {
                identity,
                first_cursor,
                last_cursor,
                position,
            } => {
                sink.grow(&mut self.removals)?;
                sink.charge(match identity {
                    AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.len(),
                    AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.len(),
                })?;
                self.removals.push(Removal {
                    identity: identity.clone(),
                    first: first_cursor,
                    last: last_cursor,
                    position,
                });
                Ok(true)
            }
            input @ AnalysisInputV1::Event { .. } => self.event(input, sink),
            AnalysisInputV1::Context(context) | AnalysisInputV1::DiscoveryContext(context) => {
                self.context(context, sink)
            }
            input @ (AnalysisInputV1::Behavior { .. } | AnalysisInputV1::Profile { .. }) => {
                self.discovery(input, sink)
            }
            AnalysisInputV1::Target { context, fact } => self.target(context, fact, sink),
            input @ AnalysisInputV1::Graph { .. } => self.graph(input, sink),
            input @ AnalysisInputV1::Notification { .. } => self.notification(input, sink),
            input @ (AnalysisInputV1::Trace { .. }
            | AnalysisInputV1::TraceOutput { .. }
            | AnalysisInputV1::TraceMeasurement { .. }) => self.trace(input, sink),
            AnalysisInputV1::Result { .. } => Ok(true),
        }
    }
}

struct JsonSize {
    bytes: usize,
    limit: usize,
}

impl Write for JsonSize {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| std::io::Error::other("source JSON exceeds its input bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
