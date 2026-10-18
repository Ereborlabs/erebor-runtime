use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_data::{AnalysisExtractLimits, AnalysisReadControl, AnalysisSelectionV1};
use datafusion::arrow::array::ArrayRef;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::physical_plan::{execute_stream, ExecutionPlan};
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use super::Inputs;
use crate::execution::{Engine, Session};
use crate::memory::Memory;
use crate::sources::{ArrowSnapshot, InputCapture, ReadMode, SourceSnapshot};
use crate::{InvalidSnafu, Result, SqlSnafu};

pub struct InputSet {
    pub inputs: Vec<sdk::Input>,
    pub snapshot: Option<Arc<ArrowSnapshot>>,
    pub now: u64,
    pub(super) expiry: Option<u64>,
    source: Option<Arc<SourceSnapshot>>,
    memory_owner: Arc<Memory>,
    _memory: MemoryReservation,
}

impl Inputs {
    pub fn read(
        self: &Arc<Self>,
        engine: Arc<Engine>,
        selection: AnalysisSelectionV1,
        scope: String,
        control: &AnalysisReadControl,
        now: u64,
    ) -> Result<Arc<InputSet>> {
        let definition = Arc::clone(self);
        let session = engine.session(selection, control, now)?;
        let runtime = Arc::clone(&engine);
        engine.wait(async move { definition.execute(runtime, session, scope, now).await })
    }

    pub(super) async fn execute(
        self: &Arc<Self>,
        engine: Arc<Engine>,
        session: Session,
        scope: String,
        now: u64,
    ) -> Result<Arc<InputSet>> {
        if self.mode != sdk::InputMode::Resolved || self.plans.len() != self.ports.len() {
            return Err(araphor_data::PackageErrorCodeV1::Missing
                .error("host-prepared inputs")
                .into());
        }
        let memory_owner = Arc::clone(session.memory());
        if self.ports.is_empty() {
            return Ok(Arc::new(InputSet {
                inputs: Vec::new(),
                snapshot: None,
                now,
                expiry: None,
                source: None,
                _memory: memory_owner.reserve_input(0).context(SqlSnafu)?,
                memory_owner,
            }));
        }
        let permit = Arc::new(engine.reserve_evaluation(session.selection().tenant_id)?);
        let mut state = session.state()?;
        let mut physical = Vec::<Arc<dyn ExecutionPlan>>::with_capacity(self.plans.len());
        for input in &self.plans {
            physical.push(session.physical(&input.plan, &state).await?);
        }
        let mut requests = self.sources.clone();
        let mut bounds = BTreeMap::new();
        let scopes = self.scopes(session.selection(), &physical, &mut requests, &mut bounds)?;
        if self.plans.iter().any(|port| port.window.is_some()) {
            if let Some(Some(columns)) = requests.get_mut("events") {
                columns.insert(
                    SourceSnapshot::schemas()["events"]
                        .index_of("received_utc_ns")
                        .map_err(datafusion::common::DataFusionError::from)
                        .context(SqlSnafu)?,
                );
            }
        }
        let mut ranges = Vec::new();
        for (input, scope) in self.plans.iter().zip(&scopes) {
            if input
                .origins
                .iter()
                .any(|origin| origin.durable() == Some("events"))
            {
                if let Some(range) = scope.selection.time_range() {
                    ranges.push(range);
                }
            }
        }
        let input_limit = self
            .limits
            .max_bytes
            .min(engine.limits().input_bytes as u64) as usize;
        let mut limits = self.limits;
        limits.max_bytes = input_limit as u64;
        let capture = InputCapture {
            scope,
            bindings: self
                .packages
                .iter()
                .map(|(slot, reference)| {
                    (
                        *slot,
                        reference.clone(),
                        Arc::new(self.ports[*slot].schema.clone()),
                    )
                })
                .collect(),
            limits,
            ranges,
            include_results: self.packages.len() < self.plans.len(),
        };
        let control = session.control();
        let source = SourceSnapshot::new(
            Arc::clone(engine.store()),
            session.selection().clone(),
            Some(capture),
            AnalysisExtractLimits {
                scan_bytes: engine.limits().scan_bytes,
                input_bytes: engine.limits().input_bytes,
                ..Default::default()
            },
            control.within(None)?,
            engine.limits().extract_timeout,
            now,
            Arc::clone(&memory_owner),
        );
        state.config_mut().set_extension(Arc::clone(&source));
        let snapshot = session
            .capture(
                Arc::clone(&source),
                requests,
                bounds,
                ReadMode::Snapshot,
                Arc::clone(&permit),
            )
            .await?;
        if snapshot.mutable_discovery {
            return Err(araphor_data::PackageErrorCodeV1::Unsupported
                .error("mutable discovery input")
                .into());
        }
        let mut expiry = snapshot.next_change;
        for (port, scope) in self.plans.iter().zip(&scopes) {
            if let Some(window) = port.window {
                let selected = window.selection(&scope.selection, now);
                let received = selected
                    .time_range()
                    .map(|range| source.received_min(range))
                    .transpose()
                    .context(SqlSnafu)?
                    .flatten();
                expiry = expiry.into_iter().chain(window.expiry(received)).min();
            }
        }
        let execution = control.within(engine.limits().evaluate_timeout)?;
        let context = state.task_ctx();
        let memory = memory_owner.prepare_input(input_limit).context(SqlSnafu)?;
        let mut inputs = Vec::<sdk::Input>::with_capacity(self.ports.len());
        let (mut rows, mut bytes, mut count) = (0u64, 0u64, 0u64);
        let mut indexed_bytes = 0usize;
        for ((input, physical), scope) in self.plans.iter().zip(physical).zip(&scopes) {
            let port = &self.ports[input.slot];
            let schema = Arc::new(port.schema.clone());
            let mut stream = execute_stream(physical, Arc::clone(&context)).context(SqlSnafu)?;
            let mut batches = Vec::new();
            while let Some(batch) = execution
                .query_async(async { stream.try_next().await.context(SqlSnafu) })
                .await?
            {
                execution.check()?;
                let conversion = sdk::Dataset::conversion_bytes(&batch, &schema)?;
                if conversion > input_limit {
                    return Err(
                        sdk::Error::contract(sdk::ErrorCode::Limit, "input conversion").into(),
                    );
                }
                memory
                    .try_resize(InputSet::metadata_bytes(&inputs).saturating_add(conversion))
                    .context(SqlSnafu)?;
                let batch = sdk::Dataset::normalize_batch(batch, Arc::clone(&schema))?;
                rows = rows.saturating_add(batch.num_rows() as u64);
                bytes = bytes.saturating_add(batch.get_array_memory_size() as u64);
                indexed_bytes = indexed_bytes
                    .saturating_add(batch.get_array_memory_size())
                    .saturating_add(size_of::<sdk::RecordBatch>())
                    .saturating_add(batch.num_columns().saturating_mul(size_of::<ArrayRef>()))
                    .saturating_add(batch.num_rows().saturating_mul(size_of::<u64>()));
                count = count.saturating_add(1);
                if rows > limits.max_rows
                    || bytes > limits.max_bytes
                    || count > u64::from(limits.max_batches)
                    || indexed_bytes > engine.limits().input_bytes
                {
                    return Err(sdk::Error::contract(
                        sdk::ErrorCode::Limit,
                        "selected model inputs",
                    )
                    .into());
                }
                memory_owner
                    .retain_input(&batch, &memory)
                    .context(SqlSnafu)?;
                batches.push(batch);
            }
            if batches.is_empty() {
                count = count.saturating_add(1);
                indexed_bytes = indexed_bytes
                    .saturating_add(size_of::<sdk::RecordBatch>())
                    .saturating_add(schema.fields().len().saturating_mul(size_of::<ArrayRef>()));
                if count > u64::from(limits.max_batches)
                    || indexed_bytes > engine.limits().input_bytes
                {
                    return Err(sdk::Error::contract(
                        sdk::ErrorCode::Limit,
                        "selected model inputs",
                    )
                    .into());
                }
                batches.push(sdk::RecordBatch::new_empty(Arc::clone(&schema)));
            }
            let data = sdk::Dataset {
                name: port.name.clone(),
                batches,
            };
            data.validate(port, limits)?;
            let inherited = input
                .origins
                .iter()
                .filter_map(|origin| {
                    let crate::sources::SourceOrigin::Port(slot) = origin else {
                        return None;
                    };
                    inputs
                        .iter()
                        .find(|value| value.data.name == self.ports[*slot].name)
                        .cloned()
                })
                .collect::<Vec<_>>();
            let coverage = self
                .packages
                .iter()
                .any(|(slot, _)| *slot == input.slot)
                .then(|| source.package_coverage(input.slot))
                .transpose()
                .context(SqlSnafu)?;
            let value = self.input(data, &snapshot, scope, &inherited, coverage.as_ref())?;
            let indexed_schema = Session::indexed_schema(&port.schema)?;
            let indexed = session.index_batches(
                Arc::clone(&indexed_schema),
                &value.data.batches,
                &memory,
                InputSet::metadata_bytes(&inputs),
            )?;
            memory
                .try_resize(InputSet::metadata_bytes(&inputs))
                .context(SqlSnafu)?;
            source
                .bind_port(input.slot, indexed_schema, indexed)
                .context(SqlSnafu)?;
            inputs.push(value);
            memory
                .try_resize(InputSet::metadata_bytes(&inputs))
                .context(SqlSnafu)?;
        }
        inputs.sort_by_key(|input| {
            self.ports
                .iter()
                .position(|port| port.name == input.data.name)
        });
        if snapshot
            .witnesses
            .iter()
            .any(|witness| witness.expires_utc_ns <= now)
        {
            for input in &mut inputs {
                input.coverage.state = sdk::CoverageState::Unknown;
                input
                    .coverage
                    .limits
                    .push("source evidence retention expired".into());
            }
        }
        memory
            .try_resize(InputSet::metadata_bytes(&inputs))
            .context(SqlSnafu)?;
        if snapshot.witnesses.len() > 8192
            || snapshot.contexts().count() > 256
            || snapshot.results().count() > 64
        {
            return Err(
                sdk::Error::contract(sdk::ErrorCode::Limit, "selected model references").into(),
            );
        }
        engine.check_read(&snapshot).await?;
        source.retain_ports().context(SqlSnafu)?;
        execution.check()?;
        Ok(Arc::new(InputSet {
            inputs,
            snapshot: Some(snapshot),
            now,
            expiry,
            source: Some(source),
            memory_owner,
            _memory: memory,
        }))
    }
}

impl InputSet {
    pub fn memory(&self) -> &Arc<Memory> {
        &self.memory_owner
    }

    pub fn check(&self, engine: &Arc<Engine>, control: &AnalysisReadControl) -> Result<()> {
        control.check()?;
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !snapshot.page.extraction.trace_reads().is_empty())
        {
            engine.wait(self.check_async(engine, control))?;
        }
        control.check()?;
        Ok(())
    }

    pub fn check_async(
        &self,
        engine: &Arc<Engine>,
        control: &AnalysisReadControl,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let snapshot = self
            .snapshot
            .as_ref()
            .filter(|snapshot| !snapshot.page.extraction.trace_reads().is_empty())
            .cloned();
        let engine = Arc::clone(engine);
        let control = control.within(None);
        async move {
            let control = control?;
            control.check()?;
            if let Some(snapshot) = snapshot {
                control.query_async(engine.check_read(&snapshot)).await?;
            }
            control.check()?;
            Ok(())
        }
    }

    pub fn dependencies(
        &self,
    ) -> impl Iterator<Item = &araphor_data::analysis::PackageResultRefV1> {
        self.snapshot.iter().flat_map(|snapshot| snapshot.results())
    }

    pub fn contexts(&self) -> impl Iterator<Item = &araphor_data::AnalysisContextRefV1> {
        self.snapshot
            .iter()
            .flat_map(|snapshot| snapshot.contexts())
    }

    pub fn source_revisions(&self) -> Vec<(String, u64)> {
        let mut revisions = self
            .snapshot
            .iter()
            .flat_map(|snapshot| {
                let revision = snapshot.page.extraction.meta.commit_revision;
                let mut revisions = snapshot.selection.source_revisions(revision);
                if snapshot.page.tables.contains_key("discovery_state") {
                    revisions.extend([
                        ("processor_progress".into(), revision),
                        ("processor_gaps".into(), revision),
                        ("analysis_results".into(), revision),
                    ]);
                }
                revisions
            })
            .collect::<Vec<_>>();
        revisions.sort();
        revisions.dedup_by(|left, right| left.0 == right.0);
        revisions
    }

    pub fn witnesses(&self) -> impl Iterator<Item = &araphor_data::AnalysisWitnessV1> + Clone {
        self.snapshot
            .iter()
            .flat_map(|snapshot| &snapshot.witnesses)
            .filter(move |witness| witness.expires_utc_ns > self.now)
    }

    fn metadata_bytes(inputs: &Vec<sdk::Input>) -> usize {
        inputs
            .capacity()
            .saturating_mul(size_of::<sdk::Input>())
            .saturating_add(inputs.iter().map(sdk::Input::metadata_bytes).sum::<usize>())
    }

    pub fn register(&self, session: &mut Session) -> Result<()> {
        for (slot, input) in self.inputs.iter().enumerate() {
            let source = self.source.as_ref().ok_or_else(|| {
                InvalidSnafu {
                    field: "input source receipt",
                }
                .build()
            })?;
            let (schema, batches) = source.port_table(slot).context(SqlSnafu)?;
            session.register(&input.data.name, schema, &batches)?;
        }
        Ok(())
    }
}
