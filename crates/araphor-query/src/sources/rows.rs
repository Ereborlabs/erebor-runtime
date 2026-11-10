use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::analysis::PackageResultRefV1;
use araphor_data::{
    AnalysisContextRefV1, AnalysisGapV1, AnalysisPositionPageV1, AnalysisReadControl,
    AnalysisReadModeV1, AnalysisSelectionV1, AnalysisStreamIdentityV1, AnalysisTableRead,
    AnalysisTableRequests, AnalysisWitnessV1,
};
use datafusion::arrow::array::{RecordBatch, UInt64Array};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;

use super::{ReadMode, ScanBounds, SourceOrigin, SourceSnapshot};

mod before;
mod metadata;
mod package;

pub(crate) use metadata::MetadataRead;

#[cfg(test)]
mod tests;

pub(crate) struct CapturedRequests {
    context_owners: Option<BTreeSet<String>>,
    _memory: MemoryReservation,
}

impl CapturedRequests {
    fn metadata_bytes(tables: &AnalysisTableRequests) -> Option<usize> {
        tables.keys().try_fold(size_of::<Self>(), |bytes, name| {
            bytes
                .checked_add(size_of::<(String, Option<BTreeSet<usize>>)>())?
                .checked_add(name.capacity())
        })
    }

    pub(crate) fn context_owners(&self) -> Option<&BTreeSet<String>> {
        self.context_owners.as_ref()
    }

    fn allocation_bytes(context_owners: Option<&BTreeSet<String>>) -> Option<usize> {
        context_owners.map_or(Some(size_of::<Self>()), |owners| {
            owners.iter().try_fold(size_of::<Self>(), |bytes, owner| {
                bytes
                    .checked_add(size_of::<String>())?
                    .checked_add(owner.capacity())
            })
        })
    }
}

pub struct ArrowSnapshot {
    pub page: AnalysisPositionPageV1,
    pub selection: AnalysisSelectionV1,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub mutable_discovery: bool,
    pub received_min: Option<u64>,
    pub next_change: Option<u64>,
    pub windows: Vec<crate::follow::WindowRange>,
    pub(crate) now: u64,
    requests: Arc<CapturedRequests>,
    managed: Option<araphor_data::ManagedCapture>,
    
    notification: Option<araphor_data::analysis::native::NotificationCapture>,
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
    pub(super) fn metadata(&self) -> &MemoryReservation {
        &self._metadata
    }

    pub(crate) fn requests(&self) -> &Arc<CapturedRequests> {
        &self.requests
    }

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

    
    pub fn notification_capture(
        &self,
    ) -> Option<&araphor_data::analysis::native::NotificationCapture> {
        self.notification.as_ref()
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
    pub(super) _memory: MemoryReservation,
    tables: BTreeMap<SourceOrigin, Table>,
    ports: BTreeMap<super::port::PortKey, Vec<package::PortBinding>>,
    pub(super) lineage: BTreeMap<usize, Arc<super::lineage::PortLineage>>,
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
                SourceOrigin::Port(_) | SourceOrigin::Local(_) => Err(DataFusionError::Execution(
                    "the materialized port is not bound".into(),
                )),
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
    fn input_error(error: araphor_data::Error, constrained: bool) -> DataFusionError {
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
    }

    pub(crate) fn discard_prior(&self, call: u64) -> Result<()> {
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let captured = captured
            .as_mut()
            .ok_or_else(|| DataFusionError::Internal("source capture is absent".into()))?;
        let receipt = Arc::get_mut(&mut captured.receipt).ok_or_else(|| {
            DataFusionError::Internal("the source receipt is already shared".into())
        })?;
        let managed = receipt
            .managed
            .as_mut()
            .ok_or_else(|| DataFusionError::Internal("managed source capture is absent".into()))?;
        receipt._metadata.shrink(managed.discard_prior(call));
        self.control.check().map_err(Self::data_error)
    }

    pub(crate) fn hydrate_prior(
        &self,
        call: u64,
        model: &sdk::Model,
        parameters: Option<sdk::Dataset>,
        retained: Option<Arc<araphor_data::RetainedCall>>,
    ) -> Result<()> {
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?;
        let captured = captured
            .as_mut()
            .ok_or_else(|| DataFusionError::Internal("source capture is absent".into()))?;
        let receipt = Arc::get_mut(&mut captured.receipt).ok_or_else(|| {
            DataFusionError::Internal("the source receipt is already shared".into())
        })?;
        let managed = receipt
            .managed
            .as_mut()
            .ok_or_else(|| DataFusionError::Internal("managed source capture is absent".into()))?;
        let added = managed
            .hydrate_prior(call, model, parameters, retained)
            .map_err(Self::data_error)?;
        for batch in managed.batches() {
            self.memory.retain_input(batch, &captured._memory)?;
        }
        receipt._metadata.try_grow(added)?;
        self.control.check().map_err(Self::data_error)
    }

    pub async fn blocking<T: Send + 'static>(
        self: &Arc<Self>,
        context: &datafusion::execution::TaskContext,
        lease: impl Send + 'static,
        operation: impl FnOnce(&Arc<Self>, &AnalysisReadControl) -> crate::Result<T> + Send + 'static,
    ) -> Result<T> {
        let entered = std::time::Instant::now();
        let name = std::any::type_name_of_val(&operation);
        let (source, control, worker) = self.read_context(context)?;
        let cut = self
            .snapshot()
            .ok()
            .map(|snapshot| snapshot.page.extraction.meta.commit_revision);
        let stage = Arc::clone(&control);
        let queued = std::time::Instant::now();
        let (output, started, finished) =
            crate::execution::Engine::blocking(control, (lease, worker), move || {
                let started = std::time::Instant::now();
                let output = operation(&source, &stage);
                let finished = std::time::Instant::now();
                Ok((output, started, finished))
            })
            .await
            .map_err(|source| DataFusionError::External(Box::new(source)))?;
        let returned = std::time::Instant::now();
        if let Some(cut) = cut {
            erebor_telemetry::debug!(
                stage = "source_blocking_timing",
                operation = name,
                cut_revision = cut,
                preflight_s = queued.duration_since(entered).as_secs_f64(),
                queue_s = started.duration_since(queued).as_secs_f64(),
                work_s = finished.duration_since(started).as_secs_f64(),
                return_s = returned.duration_since(finished).as_secs_f64(),
                elapsed_s = returned.duration_since(entered).as_secs_f64(),
                success = output.is_ok(),
                "Native source worker timing completed"
            );
        }
        output.map_err(|source| DataFusionError::External(Box::new(source)))
    }

    pub fn inline<T>(
        self: &Arc<Self>,
        context: &datafusion::execution::TaskContext,
        operation: impl FnOnce(&Arc<Self>, &AnalysisReadControl) -> crate::Result<T>,
    ) -> Result<T> {
        let (source, control, _lease) = self.read_context(context)?;
        let result = operation(&source, &control);
        control.check().map_err(Self::data_error)?;
        result.map_err(|source| DataFusionError::External(Box::new(source)))
    }

    pub(in crate::sources) fn read_context(
        self: &Arc<Self>,
        context: &datafusion::execution::TaskContext,
    ) -> Result<(Arc<Self>, Arc<AnalysisReadControl>, impl Send + 'static)> {
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
        let control = Arc::new(control.operation().map_err(Self::data_error)?);
        let worker = calls.token()?;
        Ok((source, control, (permit, worker)))
    }

    pub fn time_utc_ns(&self) -> u64 {
        self.now
    }

    pub fn memory(&self) -> &Arc<crate::memory::Memory> {
        &self.memory
    }

    pub fn extraction_limits(&self) -> araphor_data::AnalysisExtractLimits {
        self.limits
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
        let (schema, columns, batches, _) = captured
            .tables
            .get(&SourceOrigin::Durable(name.to_owned()))
            .ok_or_else(|| DataFusionError::Execution("captured source table is absent".into()))?;
        if AnalysisTableRead::source_rows(name) {
            if let Some(view) = self.source_view()? {
                let image = view.image_at(
                    captured.receipt.page.extraction.meta.commit_revision,
                    self.reference
                        .get()
                        .and_then(|reference| reference.receipt().map(|receipt| &receipt.selected)),
                )?;
                let memory = self.memory.reserve_input(0)?;
                let rows = view.read(name, image, None, columns, schema, &memory)?;
                return read(schema, &rows.batches);
            }
        }
        read(schema, batches)
    }

    pub(crate) fn input_bounds(
        &self,
        plan: &Arc<dyn datafusion::physical_plan::ExecutionPlan>,
        calls: Option<&crate::definition::CallContext>,
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
        Self::requests(&mut requests, std::slice::from_ref(plan), None, calls)
    }

    pub(crate) fn snapshot(&self) -> Result<Arc<ArrowSnapshot>> {
        self.captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source snapshot lock is poisoned".into()))?
            .as_ref()
            .map(|captured| Arc::clone(&captured.receipt))
            .ok_or_else(|| DataFusionError::Execution("the source snapshot is absent".into()))
    }

    pub fn with_capture<T>(
        &self,
        read: impl FnOnce(
            &crate::storage::AnalysisStore,
            &araphor_data::ManagedCapture,
            Option<&araphor_data::ManagedAttempt>,
        ) -> araphor_data::Result<T>,
    ) -> Result<T> {
        let snapshot = self.snapshot()?;
        let capture = snapshot.managed().ok_or_else(|| {
            DataFusionError::Execution("the managed source capture is absent".into())
        })?;
        read(&self.store, capture, self.reference.get().map(Arc::as_ref)).map_err(Self::data_error)
    }

    pub fn bind_port(
        &self,
        port: usize,
        schema: SchemaRef,
        batches: Vec<RecordBatch>,
        input: Option<&sdk::Input>,
    ) -> Result<()> {
        self.bind_input(SourceOrigin::Port(port), schema, batches, input)
    }

    pub(crate) fn copy_port(&self, port: usize, to: &Self) -> Result<()> {
        let (schema, batches) = {
            let captured = self.captured.lock().map_err(|_| {
                DataFusionError::Internal("source snapshot lock is poisoned".into())
            })?;
            let (schema, _, batches, _) = captured
                .as_ref()
                .and_then(|captured| captured.tables.get(&SourceOrigin::Port(port)))
                .ok_or_else(|| DataFusionError::Execution("the source port is not bound".into()))?;
            (Arc::clone(schema), batches.clone())
        };
        to.bind_port(port, schema, batches, None)
    }

    fn bind_input(
        &self,
        origin: SourceOrigin,
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
        if let Some((previous, _, rows, binding)) = captured.tables.get(&origin) {
            if previous == &schema
                && rows == &batches
                && match (input, binding.as_deref()) {
                    (Some(input), Some(binding)) => {
                        input.data.name == binding.data.name
                            && input.revision == binding.revision
                            && input.coverage == binding.coverage
                    }
                    (None, None) => true,
                    _ => false,
                }
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
        let selection = self.selection.project(requests).map_err(Self::data_error)?;
        let selection = Self::prune_selection(selection, bounds);
        self.read_selected(requests, bounds, mode, control, selection)
    }

    fn read_selected(
        &self,
        requests: &AnalysisTableRequests,
        bounds: &ScanBounds,
        mode: ReadMode,
        control: &araphor_data::AnalysisReadControl,
        selection: AnalysisSelectionV1,
    ) -> Result<Captured> {
        let metadata_read = matches!(mode, ReadMode::Metadata);
        let mut header_requests = None;
        let mut header_selection = None;
        if metadata_read && self.source_view()?.is_some() {
            let headers = requests
                .iter()
                .filter(|(name, _)| {
                    AnalysisTableRead::source_header(name) || name.as_str() == "events"
                })
                .map(|(name, columns)| {
                    (
                        name.clone(),
                        AnalysisTableRead::source_header(name)
                            .then(|| columns.clone())
                            .flatten(),
                    )
                })
                .collect::<AnalysisTableRequests>();
            let mut selected = selection.project(&headers).map_err(Self::data_error)?;
            selected.results.clear();
            header_selection = Some(selected);
            header_requests = Some(headers);
        }
        let requested = header_requests.as_ref().unwrap_or(requests);
        let selected = header_selection.as_ref().unwrap_or(&selection);
        let context_owners = if header_requests.is_some() {
            None
        } else {
            bounds.context_owners.as_ref()
        };
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
        let data_error = |error| Self::input_error(error, constrained);
        let read = AnalysisTableRead {
            requests: requested,
            event_ranges: if header_requests.is_some() {
                None
            } else {
                bounds.events.as_deref()
            },
            mode: match mode {
                ReadMode::Snapshot => AnalysisReadModeV1::Complete,
                ReadMode::Page(after) => AnalysisReadModeV1::Page(after),
                ReadMode::Changes(after) => AnalysisReadModeV1::Changes(after),
                ReadMode::Metadata => AnalysisReadModeV1::Metadata,
            },
            now: self.now,
        };
        let append = match mode {
            ReadMode::Page(after) => self
                .append
                .lock()
                .map_err(|_| {
                    DataFusionError::Internal("the append reader binding is poisoned".into())
                })?
                .clone()
                .map(|append| (append, after)),
            _ => None,
        };
        
        let mut notification = None;
        let (mut page, managed) = if let Some(reference) = self.reference.get() {
            let captured = self
                .store
                .read_managed_reference(selected, reference, read, limits, control, context_owners)
                .map_err(data_error)?;
            (captured.page, Some(captured.state))
        } else {
            match (&self.managed, append) {
                (Some(managed), _) => {
                    
                    let captured = if let Some(inputs) = self.inputs.get() {
                        self.store.read_managed_subscribed(
                            inputs,
                            selected,
                            managed,
                            read,
                            limits,
                            control,
                            context_owners,
                        )
                    } else {
                        self.store.read_managed_tables_filtered(
                            selected,
                            managed,
                            read,
                            limits,
                            control,
                            context_owners,
                        )
                    }
                    .map_err(data_error)?;
                    
                    (captured.page, Some(captured.state))
                }
                (None, Some((append, after))) => {
                    let (page, meta) = append.read(
                        &self.store,
                        selected,
                        &self.selection,
                        read,
                        after,
                        limits,
                        control,
                        &reservation,
                        data_error,
                    )?;
                    ArrowSnapshot::check_store(&page.extraction.meta, &meta)
                        .map_err(|source| DataFusionError::External(Box::new(source)))?;
                    (page, None)
                }
                
                (None, None) if self.consumer.get().is_some() => {
                    let consumer = self.consumer.get().ok_or_else(|| {
                        DataFusionError::Internal("notification consumer is absent".into())
                    })?;
                    let inputs = self.inputs.get().ok_or_else(|| {
                        DataFusionError::Internal("notification subscription is absent".into())
                    })?;
                    let (page, capture) = self
                        .store
                        .read_notification_subscribed(
                            inputs,
                            selected,
                            consumer,
                            read,
                            limits,
                            control,
                            context_owners,
                        )
                        .map_err(data_error)?;
                    notification = Some(capture);
                    (page, None)
                }
                (None, None) => (
                    self.store
                        .read_tables_filtered(
                            selected,
                            &self.selection,
                            read,
                            limits,
                            control,
                            context_owners,
                        )
                        .map_err(data_error)?,
                    None,
                ),
            }
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
        page.extraction.input_bytes = page
            .extraction
            .input_bytes
            .checked_add(added)
            .filter(|bytes| *bytes <= limits.input_bytes)
            .ok_or_else(overflow)?;
        let mut native = std::mem::take(&mut page.tables);
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
        if let Some(managed) = &managed {
            for batch in managed.batches() {
                self.memory.retain_input(batch, &reservation)?;
            }
        }
        let mut witnesses = std::mem::take(&mut page.extraction.witnesses);
        witnesses.sort_by(|left, right| {
            left.identity
                .cmp(&right.identity)
                .then(left.cursor.cmp(&right.cursor))
                .then(left.expires_utc_ns.cmp(&right.expires_utc_ns))
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
        
        let metadata = metadata.saturating_add(
            notification
                .as_ref()
                .map_or(0, |capture| capture.metadata_bytes()),
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
        let request_bytes = CapturedRequests::allocation_bytes(bounds.context_owners.as_ref())
            .ok_or_else(overflow)?;
        let total = metadata
            .checked_add(retained)
            .and_then(|bytes| bytes.checked_add(request_bytes))
            .ok_or_else(overflow)?;
        let limit = if metadata_read {
            limits.input_bytes
        } else {
            reservation.size()
        };
        if (prepaid || metadata_read) && total > limit {
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
        reservation.try_resize(total)?;
        let table_memory = reservation.split(retained);
        control.check().map_err(Self::data_error)?;
        let requests = Arc::new(CapturedRequests {
            context_owners: bounds.context_owners.clone(),
            _memory: reservation.split(request_bytes),
        });
        let receipt = Arc::new(ArrowSnapshot {
            mutable_discovery: std::mem::take(&mut page.mutable_discovery),
            received_min: page.received_min.take(),
            next_change: page.next_change.take(),
            windows: Vec::new(),
            now: self.now,
            page,
            selection,
            witnesses,
            requests,
            managed,
            
            notification,
            _metadata: reservation,
        });
        Ok(Captured {
            receipt,
            removals,
            _memory: table_memory,
            tables,
            ports: BTreeMap::new(),
            lineage: BTreeMap::new(),
        })
    }
}
