use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::analysis::PackageResultRefV1;
use araphor_data::{
    AnalysisContextRefV1, AnalysisGapV1, AnalysisInputTables, AnalysisPositionPageV1,
    AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1, AnalysisStreamIdentityV1,
    AnalysisTableRead, AnalysisTableRequests, AnalysisWitnessV1, Selection,
};
use datafusion::arrow::array::{RecordBatch, UInt64Array};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;

use super::{ReadMode, ScanBounds, SourceOrigin, SourceSnapshot};

mod package;

#[cfg(test)]
mod tests;

pub struct ArrowSnapshot {
    pub page: AnalysisPositionPageV1,
    pub selection: AnalysisSelectionV1,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub mutable_discovery: bool,
    pub received_min: Option<u64>,
    pub next_change: Option<u64>,
    pub windows: Vec<crate::follow::WindowRange>,
    pub(crate) now: u64,
    managed: Option<araphor_data::ManagedCapture>,
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

impl ArrowSnapshot {
    pub fn time_utc_ns(&self) -> u64 {
        self.now
    }

    pub(super) fn set_windows(&mut self, windows: Vec<crate::follow::WindowRange>) -> Result<()> {
        self._metadata.try_grow(
            windows
                .capacity()
                .saturating_mul(2 * size_of::<crate::follow::WindowRange>()),
        )?;
        self.windows = windows;
        Ok(())
    }

    pub fn managed(&self) -> Option<&araphor_data::ManagedCapture> {
        self.managed.as_ref()
    }

    pub fn contexts(&self) -> impl Iterator<Item = &AnalysisContextRefV1> {
        self.page
            .extraction
            .references
            .iter()
            .filter_map(araphor_data::AnalysisReferenceV1::context)
    }

    pub fn results(&self) -> impl Iterator<Item = &PackageResultRefV1> {
        self.page
            .extraction
            .references
            .iter()
            .filter_map(araphor_data::AnalysisReferenceV1::result)
    }
}

type Table = (
    SchemaRef,
    Vec<usize>,
    Vec<RecordBatch>,
    Option<Arc<sdk::Input>>,
);

#[derive(Debug)]
pub(crate) struct Captured {
    pub(crate) receipt: Arc<ArrowSnapshot>,
    pub(crate) removals: BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>>,
    _memory: MemoryReservation,
    tables: BTreeMap<SourceOrigin, Table>,
    package_coverage: BTreeMap<usize, araphor_analysis_sdk::Coverage>,
    source_bytes: usize,
}

impl Captured {
    pub(super) fn received_min(
        &self,
        range: (u64, u64),
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<Option<u64>> {
        let Some((_, indices, batches, _)) = self
            .tables
            .iter()
            .find_map(|(origin, table)| (origin.durable() == Some("events")).then_some(table))
        else {
            return Ok(None);
        };
        let canonical = SourceSnapshot::schemas()["events"].index_of("received_utc_ns")?;
        let column = indices
            .binary_search(&canonical)
            .map_err(|_| DataFusionError::Internal("window intake time is not captured".into()))?;
        let mut received = None;
        for batch in batches {
            control.check().map_err(SourceSnapshot::data_error)?;
            let values = batch
                .column(column)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or_else(|| {
                    DataFusionError::Internal("window intake time has an invalid type".into())
                })?;
            for value in values.iter().flatten() {
                if (range.0..=range.1).contains(&value) {
                    received = Some(received.map_or(value, |old: u64| old.min(value)));
                }
            }
        }
        Ok(received)
    }

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

    pub(crate) fn project(
        &self,
        origin: &SourceOrigin,
        indices: &[usize],
        schema: &SchemaRef,
    ) -> Result<Vec<RecordBatch>> {
        let Some((stored, captured, batches, _)) = self.tables.get(origin) else {
            return match origin {
                SourceOrigin::Durable(_) => Ok(Vec::new()),
                SourceOrigin::Port(_) | SourceOrigin::Package(_) | SourceOrigin::Local(_) => Err(
                    DataFusionError::Execution("the materialized port is not bound".into()),
                ),
            };
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
        if stored.project(&projection)? != **schema {
            return Err(DataFusionError::Execution(
                "the captured source schema differs from the native scan".into(),
            ));
        }
        batches
            .iter()
            .map(|batch| batch.project(&projection).map_err(Into::into))
            .collect()
    }
}

impl SourceSnapshot {
    pub async fn blocking<T: Send + 'static>(
        self: &Arc<Self>,
        context: &datafusion::execution::TaskContext,
        lease: impl Send + 'static,
        operation: impl FnOnce(&Arc<Self>, &AnalysisReadControl) -> crate::Result<T> + Send + 'static,
    ) -> Result<T> {
        let config = context.session_config();
        let source = config
            .get_extension::<Self>()
            .ok_or_else(|| DataFusionError::Execution("source snapshot is absent".into()))?;
        if !Arc::ptr_eq(self, &source) {
            return Err(DataFusionError::Execution(
                "source execution context differs".into(),
            ));
        }
        let calls = config
            .get_extension::<crate::definition::CallContext>()
            .ok_or_else(|| DataFusionError::Execution("execution context is absent".into()))?;
        let control = config
            .get_extension::<AnalysisReadControl>()
            .ok_or_else(|| DataFusionError::Execution("execution control is absent".into()))?;
        let permit = config
            .get_extension::<crate::execution::Permit>()
            .ok_or_else(|| DataFusionError::Execution("evaluation permit is absent".into()))?;
        control.check().map_err(Self::data_error)?;
        let worker = calls.token()?;
        let stage = Arc::clone(&control);
        crate::execution::Engine::blocking(control, (permit, lease, worker), move || {
            operation(&source, &stage)
        })
        .await
        .map_err(|source| DataFusionError::External(Box::new(source)))
    }

    pub fn time_utc_ns(&self) -> u64 {
        self.now
    }

    pub fn with_table<T>(
        &self,
        name: &str,
        read: impl FnOnce(&SchemaRef, &[RecordBatch]) -> Result<T>,
    ) -> Result<T> {
        let captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let captured = captured
            .as_ref()
            .ok_or_else(|| DataFusionError::Execution("source snapshot was not captured".into()))?;
        let (schema, _, batches, _) = captured
            .tables
            .get(&SourceOrigin::Durable(name.to_owned()))
            .ok_or_else(|| DataFusionError::Execution("captured source table is absent".into()))?;
        read(schema, batches)
    }

    pub(crate) fn input_bounds(
        &self,
        plan: &Arc<dyn datafusion::physical_plan::ExecutionPlan>,
    ) -> Result<ScanBounds> {
        let mut requests = {
            let captured = self.captured.lock().map_err(|_| {
                DataFusionError::Internal("source snapshot lock is poisoned".into())
            })?;
            captured
                .as_ref()
                .ok_or_else(|| {
                    DataFusionError::Execution("source snapshot was not captured".into())
                })?
                .tables
                .keys()
                .filter_map(|origin| origin.durable().map(|name| (name.to_owned(), None)))
                .collect()
        };
        Self::requests(&mut requests, std::slice::from_ref(plan), None)
    }

    pub(crate) fn snapshot(&self) -> Result<Arc<ArrowSnapshot>> {
        self.captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?
            .as_ref()
            .map(|captured| Arc::clone(&captured.receipt))
            .ok_or_else(|| DataFusionError::Execution("the source snapshot is absent".into()))
    }

    pub(crate) fn received_min(&self, range: (u64, u64)) -> Result<Option<u64>> {
        self.captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?
            .as_ref()
            .ok_or_else(|| DataFusionError::Internal("the source snapshot is not captured".into()))?
            .received_min(range, &self.control)
    }

    pub(crate) fn selection(
        scope: &AnalysisSelectionV1,
        sources: &AnalysisTableRequests,
    ) -> araphor_data::Result<AnalysisSelectionV1> {
        let mut selection = scope.clone();
        let graph = sources.keys().any(|name| {
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
        let discovery = sources.contains_key("behaviors");
        let targets = sources.contains_key("targets");
        let context = sources.contains_key("context")
            || sources.contains_key("context_versions")
            || sources.contains_key("notification_routes")
            || sources.contains_key("compiled_policies")
            || targets;
        if !sources.contains_key("events")
            && !sources.contains_key("coverage")
            && !sources.contains_key("graph_coverage")
            && !sources.contains_key("discovery_state")
            && !sources.contains_key("graph_state")
            && !sources.contains_key("notifications")
            && !graph
            && !discovery
        {
            selection.sources = Selection::Exact(Vec::new());
        }
        if !sources.keys().any(|name| {
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
                && !sources.contains_key("events")
                && !sources.contains_key("context")
                && !sources.contains_key("context_versions")
                && !sources.contains_key("compiled_policies"),
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
        selection.select_notifications(if sources.contains_key("notifications") {
            notifications
        } else {
            Selection::Exact(Vec::new())
        })?;
        Ok(selection)
    }

    pub fn bind_port(
        &self,
        port: usize,
        schema: SchemaRef,
        batches: Vec<RecordBatch>,
        input: Option<&sdk::Input>,
    ) -> Result<()> {
        self.control.check().map_err(Self::data_error)?;
        if batches.iter().any(|batch| batch.schema() != schema) {
            return Err(DataFusionError::Execution(
                "the materialized port differs from its declared schema".into(),
            ));
        }
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let captured = captured.as_mut().ok_or_else(|| {
            DataFusionError::Execution("the source snapshot was not captured before binding".into())
        })?;
        let origin = SourceOrigin::Port(port);
        if let Some((previous, _, rows, binding)) = captured.tables.get(&origin) {
            if previous == &schema
                && rows == &batches
                && input
                    .zip(binding.as_deref())
                    .is_some_and(|(input, binding)| {
                        input.data.name == binding.data.name
                            && input.revision == binding.revision
                            && input.coverage == binding.coverage
                    })
            {
                return Ok(());
            }
            return Err(DataFusionError::Execution(
                "the materialized port is already bound".into(),
            ));
        }
        let bytes =
            Captured::table_bytes(&schema, &batches).saturating_add(input.map_or(0, |input| {
                input
                    .metadata_bytes()
                    .saturating_add(std::mem::size_of::<sdk::Input>())
            }));
        let reservation = self.memory.reserve_input(0)?;
        for batch in &batches {
            self.memory.retain_input(batch, &reservation)?;
        }
        self.control.check().map_err(Self::data_error)?;
        captured._memory.try_grow(bytes).map_err(|source| {
            DataFusionError::External(Box::new(crate::Error::Capacity {
                resource: "shared input",
                source,
            }))
        })?;
        captured.tables.insert(
            origin,
            (
                schema.clone(),
                (0..schema.fields().len()).collect(),
                batches,
                input.map(|input| Arc::new(input.clone())),
            ),
        );
        Ok(())
    }

    pub(crate) fn read(
        &self,
        requests: &AnalysisTableRequests,
        bounds: &ScanBounds,
        mode: ReadMode,
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<Captured> {
        let metadata_read = matches!(mode, ReadMode::Metadata);
        let reservation = if metadata_read {
            self.memory.reserve_input(0)?
        } else {
            self.memory.prepare_input(self.limits.input_bytes)?
        };
        let prepaid = !metadata_read
            && (self.memory.input_capacity().is_some() || self.limits.input_bytes != usize::MAX);
        let mut limits = self.limits;
        if metadata_read {
            limits.input_bytes = limits
                .input_bytes
                .min(self.memory.input_capacity().unwrap_or(usize::MAX));
        } else if prepaid {
            limits.input_bytes = reservation.size();
        }
        let constrained = prepaid && limits.input_bytes < self.limits.input_bytes;
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
        let mut selection = Self::prune_selection(
            Self::selection(&self.selection, requests).map_err(Self::data_error)?,
            bounds,
        );
        if self
            .inputs
            .as_ref()
            .is_some_and(|inputs| !inputs.include_results)
        {
            selection.results.clear();
        }
        let outputs = self.inputs.as_ref().map(|inputs| {
            inputs
                .bindings
                .iter()
                .map(|(_, reference, schema)| (reference.clone(), Arc::clone(schema)))
                .collect::<Vec<_>>()
        });
        let inputs = self
            .inputs
            .as_ref()
            .zip(outputs.as_ref())
            .map(|(inputs, outputs)| AnalysisInputTables {
                authorized: &self.selection,
                scope: &inputs.scope,
                outputs,
            });
        let read = AnalysisTableRead {
            requests,
            event_ranges: bounds
                .events
                .as_deref()
                .or_else(|| self.inputs.as_ref().map(|inputs| inputs.ranges.as_slice())),
            inputs,
            mode: match mode {
                ReadMode::Snapshot => AnalysisReadModeV1::Complete,
                ReadMode::Page(after) => AnalysisReadModeV1::Page(after),
                ReadMode::Changes(after) => AnalysisReadModeV1::Changes(after),
                ReadMode::Metadata => AnalysisReadModeV1::Metadata,
            },
            now: self.now,
        };
        let (mut page, managed) = match &self.managed {
            Some(managed) => {
                let captured = self
                    .store
                    .read_managed_tables(&selection, managed, read, limits, control)
                    .map_err(data_error)?;
                (captured.page, Some(captured.state))
            }
            None => (
                self.store
                    .read_tables(&selection, read, limits, control)
                    .map_err(data_error)?,
                None,
            ),
        };
        let overflow = || {
            data_error(araphor_data::Error::AnalysisInputTooLarge {
                resource: "selected input bytes",
                location: snafu::location!(),
            })
        };
        let entry_bytes = std::mem::size_of::<(SourceOrigin, Table)>();
        let mut added = 0usize;
        for (name, batches) in &page.tables {
            let canonical = Self::schemas().get(name).ok_or_else(|| {
                DataFusionError::Internal("the captured table has no native source schema".into())
            })?;
            let indices = requests.get(name).and_then(Option::as_ref).ok_or_else(|| {
                DataFusionError::Internal("the captured table was not requested".into())
            })?;
            let Some(first) = batches.first() else {
                continue;
            };
            let schema = first.schema_ref();
            if schema.metadata() != canonical.metadata()
                || schema.fields().len() != indices.len()
                || schema
                    .fields()
                    .iter()
                    .zip(indices)
                    .any(|(field, index)| canonical.fields().get(*index) != Some(field))
                || batches.iter().any(|batch| batch.schema_ref() != schema)
            {
                return Err(DataFusionError::Execution(
                    "the captured table differs from its projected native schema".into(),
                ));
            }
            added = indices
                .len()
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|bytes| bytes.checked_add(entry_bytes))
                .and_then(|bytes| bytes.checked_add(added))
                .ok_or_else(overflow)?;
        }
        for (index, (schema, batches, _)) in &page.packages {
            let (_, _, expected) = self
                .inputs
                .as_ref()
                .and_then(|inputs| inputs.bindings.get(*index))
                .ok_or_else(|| {
                    DataFusionError::Internal(
                        "the captured package has no native input binding".into(),
                    )
                })?;
            if schema != expected || batches.iter().any(|batch| batch.schema_ref() != schema) {
                return Err(DataFusionError::Execution(
                    "the captured package differs from its declared native schema".into(),
                ));
            }
            added = schema
                .fields()
                .len()
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|bytes| bytes.checked_add(entry_bytes))
                .and_then(|bytes| {
                    bytes
                        .checked_add(std::mem::size_of::<(usize, araphor_analysis_sdk::Coverage)>())
                })
                .and_then(|bytes| bytes.checked_add(added))
                .ok_or_else(overflow)?;
        }
        page.extraction.input_bytes = page
            .extraction
            .input_bytes
            .checked_add(added)
            .filter(|bytes| *bytes <= limits.input_bytes)
            .ok_or_else(overflow)?;
        let mut native = std::mem::take(&mut page.tables);
        let packages = std::mem::take(&mut page.packages);
        let removals = std::mem::take(&mut page.removals);
        let mut tables = BTreeMap::new();
        let mut source_bytes = 0usize;
        for (name, columns) in requests {
            let Some(columns) = columns else {
                continue;
            };
            let indices = columns.iter().copied().collect::<Vec<_>>();
            let batches = native.remove(name).unwrap_or_default();
            let schema = match batches.first() {
                Some(first) => Arc::clone(first.schema_ref()),
                None => Arc::new(
                    Self::schemas()
                        .get(name)
                        .ok_or_else(|| {
                            DataFusionError::Internal(
                                "the captured table has no native source schema".into(),
                            )
                        })?
                        .project(&indices)?,
                ),
            };
            for batch in &batches {
                self.memory.retain_input(batch, &reservation)?;
            }
            let name = name.clone();
            source_bytes = source_bytes
                .saturating_add(Captured::table_bytes(&schema, &batches))
                .saturating_add(name.capacity());
            tables.insert(
                SourceOrigin::Durable(name),
                (schema, indices, batches, None),
            );
        }
        let mut package_coverage = BTreeMap::new();
        for (index, (schema, batches, coverage)) in packages {
            let (slot, source, _) = self
                .inputs
                .as_ref()
                .and_then(|inputs| inputs.bindings.get(index))
                .ok_or_else(|| {
                    DataFusionError::Internal(
                        "the captured package has no native input binding".into(),
                    )
                })?;
            for batch in &batches {
                self.memory.retain_input(batch, &reservation)?;
            }
            source_bytes = source_bytes
                .saturating_add(Captured::table_bytes(&schema, &batches))
                .saturating_add(Captured::coverage_bytes(&coverage));
            let input = if let araphor_data::AnalysisInputSource::Managed(reference) = source {
                let input = sdk::Input {
                    data: sdk::Dataset {
                        name: reference.output().output.clone(),
                        batches: batches.clone(),
                    },
                    revision: sdk::Revision {
                        owner: format!(
                            "{}.{}",
                            reference.output().package,
                            reference.output().export
                        ),
                        id: format!(
                            "{}:{}",
                            reference.result().result_id,
                            reference.result().commit_revision
                        ),
                        window: None,
                    },
                    coverage: coverage.clone(),
                };
                source_bytes = source_bytes
                    .saturating_add(std::mem::size_of::<sdk::Input>())
                    .saturating_add(input.metadata_bytes());
                Some(Arc::new(input))
            } else {
                None
            };
            let indices = (0..schema.fields().len()).collect();
            if tables
                .insert(
                    SourceOrigin::Package(*slot),
                    (schema, indices, batches, input),
                )
                .is_some()
                || package_coverage.insert(*slot, coverage).is_some()
            {
                return Err(DataFusionError::Internal(
                    "the package source is bound twice".into(),
                ));
            }
        }
        if let Some(managed) = &managed {
            for batch in managed.batches() {
                self.memory.retain_input(batch, &reservation)?;
            }
        }
        let mut witnesses = std::mem::take(&mut page.extraction.witnesses);
        let retained = self
            .inputs
            .as_ref()
            .is_some_and(|inputs| inputs.retained.is_some());
        if self
            .inputs
            .as_ref()
            .is_some_and(|inputs| inputs.retained.is_none())
        {
            for witness in &mut witnesses {
                if witness.expires_utc_ns == 0 {
                    witness.expires_utc_ns =
                        self.now.saturating_add(7 * 24 * 60 * 60 * 1_000_000_000);
                }
            }
        }
        witnesses.sort_by(|left, right| {
            left.identity
                .cmp(&right.identity)
                .then(left.cursor.cmp(&right.cursor))
                .then_with(|| {
                    let expiry = |value: u64| {
                        if retained && value == 0 {
                            u64::MAX
                        } else {
                            value
                        }
                    };
                    expiry(left.expires_utc_ns).cmp(&expiry(right.expires_utc_ns))
                })
        });
        witnesses
            .dedup_by(|left, right| left.identity == right.identity && left.cursor == right.cursor);
        let metadata = std::mem::size_of::<ArrowSnapshot>()
            .saturating_add(
                managed
                    .as_ref()
                    .map_or(0, araphor_data::ManagedCapture::metadata_bytes),
            )
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
                witnesses
                    .capacity()
                    .saturating_mul(std::mem::size_of::<AnalysisWitnessV1>()),
            )
            .saturating_add(
                witnesses
                    .iter()
                    .map(|witness| match &witness.identity {
                        AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                        AnalysisStreamIdentityV1::Diagnostic(identity) => {
                            identity.node_id.capacity()
                        }
                    })
                    .sum::<usize>(),
            );
        let removed = removals.iter().fold(0usize, |bytes, (identity, gaps)| {
            bytes
                .saturating_add(std::mem::size_of::<(
                    AnalysisStreamIdentityV1,
                    Vec<AnalysisGapV1>,
                )>())
                .saturating_add(
                    gaps.capacity()
                        .saturating_mul(std::mem::size_of::<AnalysisGapV1>()),
                )
                .saturating_add(match identity {
                    AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                    AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.capacity(),
                })
        });
        let retained = removed.saturating_add(source_bytes);
        let limit = if metadata_read {
            limits.input_bytes
        } else {
            reservation.size()
        };
        if (prepaid || metadata_read) && metadata.saturating_add(retained) > limit {
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
        reservation.try_resize(metadata.saturating_add(retained))?;
        let table_memory = reservation.split(retained);
        control.check().map_err(Self::data_error)?;
        let receipt = Arc::new(ArrowSnapshot {
            mutable_discovery: std::mem::take(&mut page.mutable_discovery),
            received_min: page.received_min.take(),
            next_change: page.next_change.take(),
            windows: Vec::new(),
            now: self.now,
            page,
            selection,
            witnesses,
            managed,
            _metadata: reservation,
        });
        Ok(Captured {
            receipt,
            removals,
            _memory: table_memory,
            tables,
            package_coverage,
            source_bytes,
        })
    }
}
