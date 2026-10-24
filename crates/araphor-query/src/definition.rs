use std::sync::Arc;

use std::collections::{BTreeMap, BTreeSet};

use araphor_data::{AnalysisReadControl, AnalysisTableRequests, PackageErrorCodeV1};
use araphor_discovery_definition::{Definition, ResolvedDefinition};
use datafusion::arrow::array::RecordBatch;
use datafusion::catalog::TableProvider as _;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;
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
pub use physical::{CallResult, CallReuse, ExecutionReceipt, Invocation};

#[derive(Clone)]
pub struct PreparedDefinition {
    pub plan: LogicalPlan,
    admission: Arc<DefinitionAdmission>,
}

enum ImageRead<'a> {
    Installed,
    Root(araphor_package::PackageRefV1),
    Retained(&'a ResolvedDefinition),
}

struct DefinitionAdmission {
    resolved: ResolvedDefinition,
    sources: AnalysisTableRequests,
    tenant: [u8; 16],
    images: Arc<package::Bundles>,
    retained: Option<Arc<crate::sources::InputCapture>>,
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
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()));
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
    pub fn resolved(&self) -> &ResolvedDefinition {
        &self.admission.resolved
    }

    pub fn sources(&self) -> &AnalysisTableRequests {
        &self.admission.sources
    }

    pub fn images(&self) -> impl Iterator<Item = (&araphor_package::PackageBundleV1, &str)> {
        self.admission
            .images
            .iter()
            .map(|(bundle, digest, _)| (bundle.as_ref(), digest.as_str()))
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
        drop(captured);
        calls.finish().await;
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
        let mut resolved = match &images {
            ImageRead::Retained(retained) => (*retained).clone(),
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
        let bundles = if let ImageRead::Retained(retained) = images {
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
        let providers = tables
            .iter()
            .map(|(name, table)| {
                let provider = match table {
                    crate::execution::TableBinding::Rows { table, .. } => {
                        crate::sources::SourceProvider::local(name, table.schema())
                    }
                    crate::execution::TableBinding::Provider(provider) => Arc::clone(provider),
                };
                (name.clone(), provider)
            })
            .collect();
        let registered = Arc::clone(&tables);
        let mut packages =
            package::Packages::new(self, bundles, tenant, providers, Arc::clone(&memory))?;
        packages.state.config_mut().set_extension(tables);
        let packages = Arc::new(packages);
        let mut state = packages.state.clone();
        state
            .register_relation_planner(packages.clone())
            .context(SqlSnafu)?;
        let (plan, origins) = Planner::new(&state)
            .build_with_demand(statement, Vec::new(), Arc::clone(&packages.demand))
            .await?;
        // Seal after native parameter binding reconstructs child schemas.
        let plan = PackageCall::seal(plan).context(SqlSnafu)?;
        let admitted = |table: &Arc<dyn datafusion::catalog::TableProvider>| {
            table
                .as_any()
                .downcast_ref::<crate::sources::SourceProvider>()
                .and_then(crate::sources::SourceProvider::retained_source)
                .filter(|source| {
                    origins.contains(&crate::sources::SourceOrigin::Package(source.slot))
                })
                .cloned()
        };
        let count = registered
            .values()
            .filter(|table| admitted(&table.provider()).is_some())
            .count();
        let source_bytes = count
            .checked_mul(std::mem::size_of::<Arc<crate::sources::RetainedSource>>())
            .ok_or_else(|| PackageErrorCodeV1::Limit.error("definition retained sources"))?;
        let bytes = source_bytes
            .checked_add(if count == 0 {
                0
            } else {
                std::mem::size_of::<crate::sources::InputCapture>()
            })
            .ok_or_else(|| PackageErrorCodeV1::Limit.error("definition retained sources"))?;
        let transient = source_bytes
            .checked_add(source_bytes)
            .map(|transient| transient.max(bytes))
            .ok_or_else(|| PackageErrorCodeV1::Limit.error("definition retained sources"))?;
        let bindings_memory = memory.reserve_input(transient).context(SqlSnafu)?;
        let mut bindings = Vec::with_capacity(count);
        for table in registered
            .values()
            .map(crate::execution::TableBinding::provider)
        {
            if let Some(source) = admitted(&table) {
                bindings.push(source);
            }
        }
        let retained_sources: Arc<[Arc<crate::sources::RetainedSource>]> = bindings.into();
        bindings_memory.try_resize(bytes).context(SqlSnafu)?;
        let inputs = (!retained_sources.is_empty()).then(|| {
            Arc::new(crate::sources::InputCapture {
                retained: retained_sources,
                _memory: bindings_memory,
            })
        });
        let sources = origins
            .into_iter()
            .filter_map(|source| source.durable().map(|name| (name.to_owned(), None)))
            .collect();
        resolved.images = packages.pins()?;
        retained
            .try_resize(DefinitionAdmission::allocation_bytes(&resolved, &sources)?)
            .context(SqlSnafu)?;
        let validation =
            crate::parser::Parser::stack(|| state.optimize(&plan)).context(SqlSnafu)?;
        state
            .query_planner()
            .create_physical_plan(&validation, &state)
            .await
            .context(SqlSnafu)?;
        control.check()?;
        Ok(PreparedDefinition {
            plan,
            admission: Arc::new(DefinitionAdmission {
                resolved,
                sources,
                tenant,
                images: Arc::clone(&packages.bundles),
                retained: inputs,
                _memory: retained,
            }),
        })
    }
}

impl Session {
    pub async fn prepare_definition(&self, definition: &Definition) -> Result<PreparedDefinition> {
        self.engine()
            .prepare_definition_tables(
                self.selection().tenant_id,
                definition,
                Arc::clone(self.control()),
                Arc::clone(&self.tables),
                Arc::clone(self.memory()),
                ImageRead::Installed,
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
            )
            .await
    }

    pub async fn prepare_resolved(
        &self,
        definition: &ResolvedDefinition,
    ) -> Result<PreparedDefinition> {
        definition.validate().map_err(araphor_data::Error::from)?;
        let store = Arc::clone(self.engine().store());
        let tenant = self.selection().tenant_id;
        let name = definition.definition.name.clone();
        let digest = definition.digest().map_err(araphor_data::Error::from)?;
        let control = Arc::clone(self.control());
        let stage = Arc::clone(&control);
        let bytes = definition
            .allocation_bytes()
            .ok_or_else(|| PackageErrorCodeV1::Limit.error("retained definition metadata"))?;
        let reserved = self.memory().reserve_input(bytes).context(SqlSnafu)?;
        let (saved, reserved) = Engine::blocking(control, (), move || {
            Ok((
                store.definition(tenant, &name, Some(&digest), &stage)?,
                reserved,
            ))
        })
        .await?;
        if saved.as_ref().is_some_and(|saved| saved != definition) {
            return Err(PackageErrorCodeV1::Conflict
                .error("retained definition pin")
                .into());
        }
        let images = if saved.is_some() {
            ImageRead::Retained(definition)
        } else {
            ImageRead::Installed
        };
        drop(saved);
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
            )
            .await?;
        if prepared.resolved() != definition {
            return Err(PackageErrorCodeV1::Conflict
                .error("resolved definition pin")
                .into());
        }
        Ok(prepared)
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

    async fn capture_invocation(
        &self,
        definition: &PreparedDefinition,
        invocation: Invocation,
        managed: Option<araphor_data::ManagedRead>,
    ) -> Result<CapturedExecution> {
        self.control().check()?;
        definition.check_invocation(self.selection(), &invocation, managed.as_ref())?;
        let mut session = self.clone();
        session.managed = managed;
        session.inputs = definition.admission.retained.clone();
        session.control = Arc::new(self.control().operation()?);
        let pending = PendingRead {
            control: Arc::clone(session.control()),
            active: true,
        };
        let calls = session.call_context(invocation);
        session.calls = Some(Arc::clone(&calls));
        let result = {
            let capture = async {
                let permit = Arc::new(
                    session
                        .engine()
                        .reserve_evaluation(session.selection().tenant_id)?,
                );
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
            if self.admission.retained.is_some() {
                return Err(PackageErrorCodeV1::Unsupported
                    .error("retained source publication")
                    .into());
            }
            if !invocation.inputs.is_empty()
                || !invocation.checkpoints.is_empty()
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
        if !checkpoints.is_empty() || !inputs.is_empty() {
            self.plan
                .apply_with_subqueries(|plan| {
                    if let LogicalPlan::Extension(extension) = plan {
                        if let Some(call) = extension.node.as_any().downcast_ref::<PackageCall>() {
                            if inputs.remove(&call.id()) {
                                call.input_scope
                                    .check_supplied(&invocation.inputs[&call.id()])
                                    .map_err(|error| {
                                        datafusion::common::DataFusionError::External(Box::new(
                                            error,
                                        ))
                                    })?;
                            }
                            if checkpoints.remove(&call.id())
                                && call
                                    .descriptor()
                                    .exports
                                    .iter()
                                    .find(|model| model.name == call.export())
                                    .is_none_or(|model| model.checkpoint.is_none())
                            {
                                return Err(datafusion::common::DataFusionError::External(
                                    Box::new(
                                        PackageErrorCodeV1::Invalid
                                            .error("invocation checkpoint export"),
                                    ),
                                ));
                            }
                        }
                    }
                    Ok(TreeNodeRecursion::Continue)
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
        }
        PackageCall::check_admission(&self.plan).context(SqlSnafu)?;
        Ok(())
    }
}
