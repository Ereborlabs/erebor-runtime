use std::sync::Arc;

use std::collections::{BTreeMap, BTreeSet};

use araphor_data::{AnalysisReadControl, AnalysisTableRequests, PackageErrorCodeV1};
use araphor_discovery_definition::{Definition, ResolvedDefinition};
use datafusion::arrow::array::RecordBatch;
use datafusion::catalog::TableProvider as _;
use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::logical_expr::LogicalPlan;
use futures_util::TryStreamExt as _;
use snafu::ResultExt as _;

use crate::execution::{CapturedPhysical, Engine, PendingRead, PhysicalStream, Read, Session};
use crate::planner::Planner;
use crate::{InvalidSnafu, Result, SqlSnafu};

mod call;
mod package;
pub(crate) mod physical;
#[cfg(test)]
mod tests;

pub use call::PackageCall;
pub(crate) use physical::CallContext;
pub use physical::{CallResult, ExecutionReceipt, Invocation};

#[derive(Clone)]
pub struct PreparedDefinition {
    pub resolved: ResolvedDefinition,
    pub plan: LogicalPlan,
    pub sources: AnalysisTableRequests,
    tenant: [u8; 16],
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
            .resolved)
    }

    pub async fn prepare_definition(
        &self,
        tenant: [u8; 16],
        definition: &Definition,
        control: Arc<AnalysisReadControl>,
    ) -> Result<PreparedDefinition> {
        self.prepare_definition_tables(tenant, definition, control, Arc::default())
            .await
    }

    async fn prepare_definition_tables(
        &self,
        tenant: [u8; 16],
        definition: &Definition,
        control: Arc<AnalysisReadControl>,
        tables: Arc<crate::execution::LocalTables>,
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
        let sql = definition
            .program
            .sql()
            .map_err(araphor_data::Error::from)?;
        let statement = self.limits().parser.parse(&sql)?;
        let references = package::Packages::references(&statement)?;
        let bundles = if references.is_empty() {
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
            .map(|(name, (table, _))| {
                (
                    name.clone(),
                    crate::sources::SourceProvider::local(name, table.schema()),
                )
            })
            .collect();
        let mut packages = package::Packages::new(self, bundles, tenant, providers)?;
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
        let sources = origins
            .into_iter()
            .filter_map(|source| source.durable().map(|name| (name.to_owned(), None)))
            .collect();
        let images = packages.pins()?;
        let validation = state.optimize(&plan).context(SqlSnafu)?;
        state
            .query_planner()
            .create_physical_plan(&validation, &state)
            .await
            .context(SqlSnafu)?;
        control.check()?;
        Ok(PreparedDefinition {
            resolved: ResolvedDefinition::new(definition.clone(), sql, images)
                .map_err(araphor_data::Error::from)?,
            plan,
            sources,
            tenant,
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
            )
            .await
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
        if definition.tenant != self.selection().tenant_id {
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
        if let Some(managed) = &managed {
            if !invocation.inputs.is_empty() || !invocation.checkpoints.is_empty() {
                return Err(PackageErrorCodeV1::Invalid
                    .error("managed invocation state")
                    .into());
            }
            let spec = &managed.instance.spec;
            if spec.tenant != self.selection().tenant_id
                || spec.grant.selection != *self.selection()
                || spec.definition != definition.resolved
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
            definition
                .plan
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
        PackageCall::check_admission(&definition.plan).context(SqlSnafu)?;
        let mut session = self.clone();
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
                let permit = Arc::new(
                    session
                        .engine()
                        .reserve_evaluation(session.selection().tenant_id)?,
                );
                session
                    .capture_plan(
                        &definition.plan,
                        &definition.sources,
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
            Ok(captured) => Ok(CapturedExecution {
                captured,
                session,
                calls,
                parent: Arc::clone(self.control()),
                pending,
            }),
            Err(error) => {
                let _cancelled = session.control().cancel();
                calls.finish().await;
                self.control().check()?;
                Err(error)
            }
        }
    }
}
