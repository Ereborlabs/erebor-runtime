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

use crate::execution::{Engine, Read, Session};
use crate::planner::Planner;
use crate::{InvalidSnafu, Result, SqlSnafu};

mod call;
mod package;
pub(crate) mod physical;
#[cfg(test)]
mod tests;

pub use call::PackageCall;
pub(crate) use physical::CallContext;
pub use physical::{CallResult, Invocation};

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
        let mut session = self.clone();
        session.control = Arc::new(self.control().operation()?);
        let calls = session.call_context(invocation);
        session.calls = Some(Arc::clone(&calls));
        let execution = async {
            let (snapshot, stream) = session
                .stream(&definition.plan, &definition.sources, Read::Snapshot)
                .await?;
            let batches = stream.try_collect().await.context(SqlSnafu)?;
            session
                .control()
                .query_async(self.engine().check_read(&snapshot))
                .await?;
            session.control().check()?;
            Ok(DefinitionOutput {
                snapshot,
                batches,
                calls: calls.results().context(SqlSnafu)?,
            })
        };
        tokio::pin!(execution);
        let result = tokio::select! {
            result = &mut execution => result,
            stopped = self.control().query_async(std::future::pending::<Result<DefinitionOutput>>()) => {
                let _cancelled = session.control().cancel();
                let _finished = execution.await;
                stopped
            }
        };
        if result.is_err() {
            let _cancelled = session.control().cancel();
        }
        calls.finish().await;
        self.control().check()?;
        result
    }
}
