use std::sync::Arc;

use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_sdk as sdk;
use araphor_data::{AnalysisReadControl, AnalysisTableRequests, PackageErrorCodeV1};
use araphor_discovery_definition::{Definition, ResolvedDefinition};
use datafusion::arrow::array::RecordBatch;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;
use futures_util::future::{BoxFuture, FutureExt};
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use crate::execution::{CapturedPhysical, Engine, PendingRead, PhysicalStream, Read, Session};
use crate::planner::Planner;
use crate::{InvalidSnafu, Result, SqlSnafu};

mod call;
mod package;
pub(crate) mod physical;
mod replay;
#[cfg(test)]
mod tests;

pub use call::PackageCall;
pub(crate) use physical::CallContext;
pub use physical::{CallResult, ExecutionReceipt, Invocation};

#[derive(Clone)]
pub struct PreparedDefinition {
    pub(crate) plan: LogicalPlan,
    physical: Option<(
        std::sync::Weak<Engine>,
        Arc<dyn datafusion::physical_plan::ExecutionPlan>,
    )>,
    revision: Option<u64>,
    admission: Arc<DefinitionAdmission>,
}

enum ImageRead<'a> {
    Installed,
    Root(araphor_package::PackageRefV1),
    Retained(&'a ResolvedDefinition, u64),
}

struct DefinitionAdmission {
    resolved: ResolvedDefinition,
    store: std::sync::Weak<araphor_data::AnalysisStore>,
    sources: AnalysisTableRequests,
    tenant: [u8; 16],
    images: Arc<package::Bundles>,
    _memory: MemoryReservation,
}

impl DefinitionAdmission {
    fn allocation_bytes(
        resolved: &ResolvedDefinition,
        sources: &AnalysisTableRequests,
    ) -> Result<usize> {
        let bytes = resolved
            .allocation_bytes()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<ResolvedDefinition>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<u64>>()));
        bytes
            .and_then(|bytes| {
                sources.iter().try_fold(bytes, |bytes, (name, columns)| {
                    bytes
                        .checked_add(std::mem::size_of::<(String, Option<BTreeSet<usize>>)>())?
                        .checked_add(name.capacity())?
                        .checked_add(columns.as_ref().map_or(Some(0), |columns| {
                            columns.len().checked_mul(std::mem::size_of::<usize>())
                        })?)
                })
            })
            .ok_or_else(|| {
                PackageErrorCodeV1::Limit
                    .error("definition metadata memory")
                    .into()
            })
    }
}

impl PreparedDefinition {
    pub fn plan(&self) -> &LogicalPlan {
        &self.plan
    }

    pub fn into_plan(self) -> LogicalPlan {
        self.plan
    }

    pub(crate) fn executable(
        &self,
        engine: &Arc<Engine>,
    ) -> Option<Arc<dyn datafusion::physical_plan::ExecutionPlan>> {
        self.physical
            .as_ref()
            .filter(|(owner, _)| std::sync::Weak::ptr_eq(owner, &Arc::downgrade(engine)))
            .map(|(_, plan)| Arc::clone(plan))
    }

    pub fn resolved(&self) -> &ResolvedDefinition {
        &self.admission.resolved
    }

    pub fn revision(&self) -> Option<u64> {
        self.revision
    }

    pub fn check_store(&self, engine: &Engine) -> Result<()> {
        if !std::sync::Weak::ptr_eq(&self.admission.store, &Arc::downgrade(engine.store())) {
            return Err(PackageErrorCodeV1::Conflict
                .error("definition store owner")
                .into());
        }
        Ok(())
    }

    pub fn bind_revision(
        mut self,
        engine: &Engine,
        revision: u64,
        control: &AnalysisReadControl,
    ) -> Result<Self> {
        self.check_store(engine)?;
        let saved = engine
            .store()
            .definition(
                self.admission.tenant,
                &self.resolved().definition.name,
                Some(revision),
                control,
            )?
            .ok_or_else(|| PackageErrorCodeV1::Missing.error("retained definition revision"))?;
        if saved.0 != *self.resolved() || saved.1 != revision {
            return Err(PackageErrorCodeV1::Conflict
                .error("retained definition pin")
                .into());
        }
        self.revision = Some(revision);
        Ok(self)
    }

    pub fn sources(&self) -> &AnalysisTableRequests {
        &self.admission.sources
    }

    pub fn images(&self) -> impl Iterator<Item = &araphor_package::PackageBundle> {
        self.admission
            .images
            .iter()
            .map(|(bundle, _)| bundle.as_ref())
    }
}

pub struct DefinitionOutput {
    pub snapshot: Arc<crate::sources::ArrowSnapshot>,
    pub batches: Vec<RecordBatch>,
    pub calls: BTreeMap<u64, Arc<CallResult>>,
}

pub struct CapturedExecution {
    captured: CapturedPhysical,
    session: Session,
    calls: Arc<CallContext>,
    parent: Arc<AnalysisReadControl>,
    pending: PendingRead,
}

impl CapturedExecution {
    pub(crate) fn new(
        captured: CapturedPhysical,
        session: Session,
        calls: Arc<CallContext>,
        parent: Arc<AnalysisReadControl>,
        pending: PendingRead,
    ) -> Self {
        Self {
            captured,
            session,
            calls,
            parent,
            pending,
        }
    }

    pub(crate) fn into_parts(self) -> (CapturedPhysical, PendingRead) {
        let Self {
            captured, pending, ..
        } = self;
        (captured, pending)
    }

    pub fn snapshot(&self) -> &crate::sources::ArrowSnapshot {
        &self.captured.snapshot
    }

    pub async fn blocking<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&crate::sources::ArrowSnapshot, &AnalysisReadControl) -> Result<T>
            + Send
            + 'static,
    ) -> Result<T> {
        let snapshot = Arc::clone(&self.captured.snapshot);
        let control = Arc::clone(&self.parent);
        let lease = (
            self.calls.token().context(SqlSnafu)?,
            Arc::clone(&self.captured.permit),
        );
        Engine::blocking(Arc::clone(&control), lease, move || {
            operation(&snapshot, &control)
        })
        .await
    }

    pub async fn execute(self) -> Result<DefinitionOutput> {
        let Self {
            captured,
            session,
            calls,
            parent,
            mut pending,
        } = self;
        let source = captured
            .context
            .session_config()
            .get_extension::<crate::sources::SourceSnapshot>();
        let result = {
            let execution = async {
                parent.check()?;
                let PhysicalStream {
                    snapshot,
                    stream,
                    permit,
                    control,
                    reservation,
                } = captured.start()?;
                let stream = session.bounded(
                    stream,
                    permit,
                    control,
                    reservation,
                    Some(Arc::clone(&snapshot)),
                );
                let batches = stream.try_collect().await.context(SqlSnafu)?;
                session
                    .control()
                    .query_async(session.check_read(&snapshot))
                    .await?;
                session.control().check()?;
                Ok(DefinitionOutput {
                    snapshot,
                    batches,
                    calls: calls.results().context(SqlSnafu)?,
                })
            };
            tokio::pin!(execution);
            tokio::select! {
                result = &mut execution => result,
                stopped = parent.query_async(std::future::pending::<Result<DefinitionOutput>>()) => {
                    let _cancelled = session.control().cancel();
                    let _finished = execution.await;
                    stopped
                }
            }
        };
        if result.is_err() {
            let _cancelled = session.control().cancel();
        }
        calls.finish().await;
        if let Some(source) = source {
            source.report_work();
        }
        parent.check()?;
        pending.active = false;
        result
    }

    pub async fn cancel_and_join(self) -> Result<()> {
        let Self {
            captured,
            session,
            calls,
            pending,
            ..
        } = self;
        let result = session.control().cancel().map_err(crate::Error::from);
        let source = captured
            .context
            .session_config()
            .get_extension::<crate::sources::SourceSnapshot>();
        drop(captured);
        calls.finish().await;
        if let Some(source) = source {
            source.report_work();
        }
        drop(pending);
        result
    }
}

impl Engine {
    pub async fn admit_definition(
        &self,
        tenant: [u8; 16],
        definition: Definition,
        control: Arc<AnalysisReadControl>,
    ) -> Result<ResolvedDefinition> {
        Ok(self
            .prepare_definition(tenant, &definition, control)
            .await?
            .resolved()
            .clone())
    }

    pub async fn prepare_definition(
        &self,
        tenant: [u8; 16],
        definition: &Definition,
        control: Arc<AnalysisReadControl>,
    ) -> Result<PreparedDefinition> {
        self.prepare_definition_tables(
            tenant,
            definition,
            control,
            Arc::default(),
            Arc::clone(self.memory()),
            ImageRead::Installed,
            None,
        )
        .await
    }

    async fn prepare_definition_tables(
        &self,
        tenant: [u8; 16],
        definition: &Definition,
        control: Arc<AnalysisReadControl>,
        tables: Arc<crate::execution::LocalTables>,
        memory: Arc<crate::memory::Memory>,
        images: ImageRead<'_>,
        input_gate: Option<LogicalPlan>,
    ) -> Result<PreparedDefinition> {
        control.check()?;
        if tenant == [0; 16] {
            return InvalidSnafu {
                field: "definition tenant",
            }
            .fail();
        }
        definition
            .validate_captured()
            .map_err(araphor_data::Error::from)?;
        let revision = match &images {
            ImageRead::Retained(_, revision) => Some(*revision),
            _ => None,
        };
        let mut resolved = match &images {
            ImageRead::Retained(retained, _) => (*retained).clone(),
            _ => ResolvedDefinition::new(
                definition.clone(),
                definition
                    .program
                    .sql()
                    .map_err(araphor_data::Error::from)?,
                Vec::new(),
            )
            .map_err(araphor_data::Error::from)?,
        };
        let retained = memory
            .reserve_input(DefinitionAdmission::allocation_bytes(
                &resolved,
                &AnalysisTableRequests::new(),
            )?)
            .context(SqlSnafu)?;
        let statement = self.limits().parser.parse(&resolved.sql)?;
        let references = package::Packages::references(&statement)?;
        let bundles = if let ImageRead::Retained(retained, _) = images {
            let store = Arc::clone(self.store());
            let read = Arc::clone(&control);
            let pins = retained.images.clone();
            Self::blocking(Arc::clone(&control), (), move || {
                let bundles = pins
                    .iter()
                    .map(|pin| {
                        store
                            .retained_package_image(tenant, pin, &read)?
                            .ok_or_else(|| {
                                PackageErrorCodeV1::Missing
                                    .error("retained definition image")
                                    .into()
                            })
                    })
                    .collect::<Result<Vec<_>>>()?;
                for reference in references {
                    if !bundles.iter().any(|bundle| {
                        bundle
                            .bundle()
                            .artifacts
                            .iter()
                            .any(|artifact| artifact.reference() == reference)
                    }) {
                        return Err(PackageErrorCodeV1::Missing
                            .error("retained definition artifact")
                            .into());
                    }
                }
                Ok(bundles)
            })
            .await?
        } else if let ImageRead::Root(image) = images {
            let store = Arc::clone(self.store());
            let read = Arc::clone(&control);
            Self::blocking(Arc::clone(&control), (), move || {
                let bundle = store
                    .package_image(tenant, &image.package_id, Some(&image.revision), &read)?
                    .ok_or_else(|| {
                        PackageErrorCodeV1::Missing.error("definition image revision")
                    })?;
                for reference in references {
                    bundle
                        .bundle()
                        .artifact(&reference)
                        .map_err(araphor_data::Error::from)?;
                }
                Ok(vec![bundle])
            })
            .await?
        } else if references.is_empty() {
            Vec::new()
        } else {
            let store = Arc::clone(self.store());
            let read = Arc::clone(&control);
            Self::blocking(Arc::clone(&control), (), move || {
                references
                    .into_iter()
                    .map(|image| {
                        store
                            .package_image(tenant, &image.package_id, Some(&image.revision), &read)?
                            .ok_or_else(|| {
                                PackageErrorCodeV1::Missing.error("definition image revision")
                            })
                            .map_err(crate::Error::from)
                    })
                    .collect()
            })
            .await?
        };
        let packages = package::Packages::new(self, bundles, tenant, tables, Arc::clone(&memory))?;
        let packages = Arc::new(packages);
        let mut state = packages.state.clone();
        state
            .register_relation_planner(packages.clone())
            .context(SqlSnafu)?;
        let (plan, mut origins) = Planner::new(&state)
            .build_with_demand(statement, Vec::new(), Arc::clone(&packages.demand))
            .await?;
        let plan = if let Some(gate) = input_gate {
            use datafusion::logical_expr::{lit, Expr, LogicalPlanBuilder};
            datafusion::execution::context::SQLOptions::new()
                .with_allow_ddl(false)
                .with_allow_dml(false)
                .with_allow_statements(false)
                .verify_plan(&gate)
                .context(SqlSnafu)?;
            if PackageCall::contains(&gate).context(SqlSnafu)? {
                return InvalidSnafu {
                    field: "input gate package call",
                }
                .fail();
            }
            let columns = plan
                .schema()
                .columns()
                .into_iter()
                .map(Expr::Column)
                .collect::<Vec<_>>();
            LogicalPlanBuilder::from(gate)
                .project([lit(1i64).alias("__graph_has_input")])
                .and_then(|gate| gate.limit(0, Some(1)))
                .and_then(|gate| gate.cross_join(plan))
                .and_then(|joined| joined.project(columns))
                .and_then(LogicalPlanBuilder::build)
                .context(SqlSnafu)?
        } else {
            plan
        };
        // Seal the complete native plan after parameter binding.
        let plan = PackageCall::seal(plan).context(SqlSnafu)?;
        Planner::quotas(&plan, self.limits())?;
        origins.extend(crate::planner::SourceDemand::collect(&plan, false).context(SqlSnafu)?);
        let sources = origins
            .into_iter()
            .filter_map(|source| source.durable().map(|name| (name.to_owned(), None)))
            .collect();
        let image_count = packages.bundles.len();
        let image_bytes = image_count
            .checked_mul(std::mem::size_of::<(
                Arc<araphor_package::PackageBundle>,
                Arc<MemoryReservation>,
            )>())
            .ok_or_else(|| PackageErrorCodeV1::Limit.error("retained image closure"))?;
        retained.try_grow(image_bytes).context(SqlSnafu)?;
        let mut images = Vec::with_capacity(image_count);
        for entry in packages.bundles.iter() {
            if let Some((prior, _)) = images.iter().find(
                |(prior, _): &&(Arc<araphor_package::PackageBundle>, Arc<MemoryReservation>)| {
                    prior.bundle().root == entry.0.bundle().root
                },
            ) {
                if prior.digest() != entry.0.digest() {
                    return Err(PackageErrorCodeV1::Conflict
                        .error("retained image pin")
                        .into());
                }
            } else {
                images.push(entry.clone());
            }
        }
        let images: Arc<package::Bundles> = images.into();
        resolved.images = packages.pins()?;
        retained
            .try_resize(
                DefinitionAdmission::allocation_bytes(&resolved, &sources)?
                    .checked_add(image_bytes)
                    .ok_or_else(|| PackageErrorCodeV1::Limit.error("retained image closure"))?,
            )
            .context(SqlSnafu)?;
        control.check()?;
        Ok(PreparedDefinition {
            plan,
            physical: None,
            revision,
            admission: Arc::new(DefinitionAdmission {
                resolved,
                store: Arc::downgrade(self.store()),
                sources,
                tenant,
                images,
                _memory: retained,
            }),
        })
    }
}

impl Session {
    pub async fn prepare_definition(
        &self,
        definition: &Definition,
        input_gate: Option<LogicalPlan>,
    ) -> Result<PreparedDefinition> {
        self.engine()
            .prepare_definition_tables(
                self.selection().tenant_id,
                definition,
                Arc::clone(self.control()),
                Arc::clone(&self.tables),
                Arc::clone(self.memory()),
                ImageRead::Installed,
                input_gate,
            )
            .await
    }

    pub async fn prepare_image(
        &self,
        definition: &Definition,
        image: araphor_package::PackageRefV1,
    ) -> Result<PreparedDefinition> {
        self.engine()
            .prepare_definition_tables(
                self.selection().tenant_id,
                definition,
                Arc::clone(self.control()),
                Arc::clone(&self.tables),
                Arc::clone(self.memory()),
                ImageRead::Root(image),
                None,
            )
            .await
    }

    pub async fn prepare_resolved(
        &self,
        definition: &ResolvedDefinition,
        revision: Option<u64>,
        input_gate: Option<LogicalPlan>,
    ) -> Result<PreparedDefinition> {
        definition.validate().map_err(araphor_data::Error::from)?;
        let store = Arc::clone(self.engine().store());
        let tenant = self.selection().tenant_id;
        let control = Arc::clone(self.control());
        let stage = Arc::clone(&control);
        let bytes = definition
            .allocation_bytes()
            .ok_or_else(|| PackageErrorCodeV1::Limit.error("retained definition metadata"))?;
        let reserved = self.memory().reserve_input(bytes).context(SqlSnafu)?;
        let expected = definition.clone();
        let (revision, reserved) = Engine::blocking(control, (), move || {
            let revision = if let Some(revision) = revision {
                let saved = store
                    .definition(tenant, &expected.definition.name, Some(revision), &stage)?
                    .ok_or_else(|| {
                        PackageErrorCodeV1::Missing.error("retained definition revision")
                    })?;
                if saved.0 != expected || saved.1 != revision {
                    return Err(PackageErrorCodeV1::Conflict
                        .error("retained definition pin")
                        .into());
                }
                Some(revision)
            } else {
                store.definition_revision(tenant, &expected, &stage)?
            };
            Ok((revision, reserved))
        })
        .await?;
        let images = match revision {
            Some(revision) => ImageRead::Retained(definition, revision),
            None => ImageRead::Installed,
        };
        drop(reserved);
        let prepared = self
            .engine()
            .prepare_definition_tables(
                tenant,
                &definition.definition,
                Arc::clone(self.control()),
                Arc::clone(&self.tables),
                Arc::clone(self.memory()),
                images,
                input_gate,
            )
            .await?;
        if prepared.resolved() != definition {
            return Err(PackageErrorCodeV1::Conflict
                .error("resolved definition pin")
                .into());
        }
        Ok(prepared)
    }

    pub async fn prepare_execution(&self, definition: &mut PreparedDefinition) -> Result<()> {
        definition.check_store(self.engine())?;
        self.control().check()?;
        if definition.executable(self.engine()).is_some() {
            return Ok(());
        }
        PackageCall::check_admission(&definition.plan).context(SqlSnafu)?;
        let origins =
            crate::planner::SourceDemand::collect(&definition.plan, false).context(SqlSnafu)?;
        let reusable = !self.calls.as_ref().is_some_and(|calls| calls.has_windows())
            && crate::follow::Window::clocks(&definition.plan)? == 0
            && !origins
                .iter()
                .any(|origin| matches!(origin, crate::sources::SourceOrigin::Local(_)))
            && crate::stream::physical::SubscribeExec::reusable(
                &definition.plan,
                &mut BTreeSet::new(),
            )
            .context(SqlSnafu)?;
        let permit = Arc::new(
            self.control()
                .query_async(self.engine().acquire_evaluation(self.selection().tenant_id))
                .await?,
        );
        let mut state = self.state()?;
        state.config_mut().set_extension(Arc::clone(&permit));
        *state.config_mut() = state
            .config()
            .clone()
            .set_bool("datafusion.optimizer.enable_dynamic_filter_pushdown", false);
        let physical = self.physical(&definition.plan, &state).await?;
        self.control().check()?;
        if reusable {
            definition.physical = Some((Arc::downgrade(self.engine()), physical));
        }
        Ok(())
    }

    pub async fn execute_definition(
        &self,
        definition: &PreparedDefinition,
        invocation: Invocation,
    ) -> Result<DefinitionOutput> {
        self.capture_definition(definition, invocation)
            .await?
            .execute()
            .await
    }

    pub async fn capture_definition(
        &self,
        definition: &PreparedDefinition,
        invocation: Invocation,
    ) -> Result<CapturedExecution> {
        self.capture_invocation(definition, invocation, None).await
    }

    pub async fn capture_managed(
        &self,
        definition: &PreparedDefinition,
        invocation: Invocation,
        managed: araphor_data::ManagedRead,
    ) -> Result<CapturedExecution> {
        self.capture_invocation(definition, invocation, Some(managed))
            .await
    }

    fn capture_invocation<'a>(
        &'a self,
        definition: &'a PreparedDefinition,
        invocation: Invocation,
        managed: Option<araphor_data::ManagedRead>,
    ) -> BoxFuture<'a, Result<CapturedExecution>> {
        async move {
            if definition.revision().is_some() {
                definition.check_store(self.engine())?;
            }
            self.control().check()?;
            definition.check_invocation(self.selection(), &invocation, managed.as_ref())?;
            let mut session = self.clone();
            session.definition = Some(Arc::new(definition.clone()));
            session.managed = managed;
            session.control = Arc::new(self.control().operation()?);
            let pending = PendingRead {
                control: Arc::clone(session.control()),
                active: true,
            };
            let calls = session.call_context(invocation);
            session.calls = Some(Arc::clone(&calls));
            let result = {
                let capture = async {
                    let permit = session.evaluation_permit()?;
                    session
                        .capture_plan(
                            &definition.plan,
                            definition.sources(),
                            Read::Snapshot,
                            permit,
                        )
                        .await
                };
                tokio::pin!(capture);
                tokio::select! {
                    result = &mut capture => result,
                    stopped = self.control().query_async(std::future::pending::<Result<CapturedPhysical>>()) => {
                        let _cancelled = session.control().cancel();
                        let _finished = capture.await;
                        stopped
                    }
                }
            };
            let result = result.and_then(|captured| {
                self.control().check()?;
                Ok(captured)
            });
            match result {
                Ok(captured) => Ok(CapturedExecution::new(
                    captured,
                    session,
                    calls,
                    Arc::clone(self.control()),
                    pending,
                )),
                Err(error) => {
                    let _cancelled = session.control().cancel();
                    calls.finish().await;
                    self.control().check()?;
                    Err(error)
                }
            }
        }
        .boxed()
    }
}

impl PreparedDefinition {
    pub(crate) fn check_invocation(
        &self,
        selection: &araphor_data::AnalysisSelectionV1,
        invocation: &Invocation,
        managed: Option<&araphor_data::ManagedRead>,
    ) -> Result<()> {
        if self.admission.tenant != selection.tenant_id {
            return Err(PackageErrorCodeV1::Denied
                .error("definition execution tenant")
                .into());
        }
        if invocation.id.is_empty() {
            return InvalidSnafu {
                field: "invocation identity",
            }
            .fail();
        }
        if let Some(managed) = managed {
            if !invocation.inputs.is_empty()
                || !invocation.checkpoints.is_empty()
                || !invocation.previous_outputs.is_empty()
                || invocation.time_utc_ns.is_some()
            {
                return Err(PackageErrorCodeV1::Invalid
                    .error("managed invocation state")
                    .into());
            }
            let spec = &managed.instance.spec;
            if spec.tenant != selection.tenant_id
                || spec
                    .destination
                    .selection(&managed.instance.grant.selection)?
                    != *selection
                || spec.definition != *self.resolved()
                || self.revision != Some(spec.manifest.definition)
            {
                return Err(PackageErrorCodeV1::Denied
                    .error("managed invocation scope")
                    .into());
            }
        }
        let mut checkpoints = invocation
            .checkpoints
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut inputs = invocation.inputs.keys().copied().collect::<BTreeSet<_>>();
        let mut previous = invocation
            .previous_outputs
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        if !checkpoints.is_empty() || !inputs.is_empty() || !previous.is_empty() {
            PackageCall::any(&self.plan, &mut |_, call| {
                if inputs.remove(&call.id()) {
                    call.input_scope
                        .check_supplied(&invocation.inputs[&call.id()])
                        .map_err(|error| {
                            datafusion::common::DataFusionError::External(Box::new(error))
                        })?;
                }
                if checkpoints.remove(&call.id())
                    && call.model().is_none_or(|model| model.checkpoint.is_none())
                {
                    return Err(datafusion::common::DataFusionError::External(Box::new(
                        PackageErrorCodeV1::Invalid.error("invocation checkpoint export"),
                    )));
                }
                if previous.remove(&call.id()) {
                    let model = call
                        .model()
                        .filter(|model| {
                            model
                                .checkpoint
                                .as_ref()
                                .is_some_and(|spec| spec.resume_input_changes)
                        })
                        .filter(|_| invocation.checkpoints.contains_key(&call.id()))
                        .ok_or_else(|| {
                            datafusion::common::DataFusionError::External(Box::new(
                                PackageErrorCodeV1::Invalid
                                    .error("invocation previous output export"),
                            ))
                        })?;
                    sdk::Dataset::validate_all(
                        &invocation.previous_outputs[&call.id()],
                        &model.outputs,
                    )
                    .map_err(|error| {
                        datafusion::common::DataFusionError::External(Box::new(error))
                    })?;
                }
                Ok(false)
            })
            .context(SqlSnafu)?;
            if !checkpoints.is_empty() {
                return Err(PackageErrorCodeV1::Invalid
                    .error("invocation checkpoint call")
                    .into());
            }
            if !inputs.is_empty() {
                return Err(PackageErrorCodeV1::Invalid
                    .error("invocation input call")
                    .into());
            }
            if !previous.is_empty() {
                return Err(PackageErrorCodeV1::Invalid
                    .error("invocation previous output call")
                    .into());
            }
        }
        PackageCall::check_admission(&self.plan).context(SqlSnafu)?;
        Ok(())
    }
}
