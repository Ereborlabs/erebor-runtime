use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextRefV1, AnalysisContextVersionV1, PackageActionV1, PackageAuthorization,
    PackageErrorCodeV1 as Code, PackageGrantV1, StorePositionV1,
};
use araphor_discovery_definition::{Definition, Program, ResolvedDefinition, Source};
use araphor_query::definition::{PackageCall, PreparedDefinition};
use araphor_query::execution::{Limits, Session};
use araphor_query::memory::Memory;
use araphor_query::sources::SourceSnapshot;
use datafusion::common::DataFusionError;
use datafusion::datasource::view::ViewTable;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::{Extension, LogicalPlan};
use datafusion::physical_plan::ExecutionPlan;
use tokio::sync::OnceCell;

use crate::{Graph, Result};

mod capture;
mod commit;
mod managed;
mod node;
mod program;
pub(crate) use commit::GraphConversion;

#[cfg(test)]
mod tests;

pub trait GraphFacts: Send + Sync {
    /// List every context owner used for proof input or saved Graph facts.
    /// Return None to read all context owners.
    fn context_owners(&self) -> Option<&'static [&'static str]> {
        None
    }

    fn facts(
        &self,
        contexts: &[sdk::RecordBatch],
        records: &[araphor_data::DiscoveryRecordV1],
    ) -> araphor_data::Result<(Vec<AnalysisContextVersionV1>, Vec<AnalysisContextRefV1>)>;
}

#[derive(Clone)]
pub struct GraphPublication {
    session: Session,
    #[cfg(test)]
    grant: PackageGrantV1,
    prepared: PreparedDefinition,
    feedback: bool,
    calls: BTreeMap<u64, PackageCall>,
    packages: BTreeMap<u64, AnalysisContextRefV1>,
    sparse: BTreeSet<u64>,
    projection: Arc<Projection>,
}

struct Projection {
    tenant: [u8; 16],
    facts: Arc<dyn GraphFacts>,
    ports: Vec<sdk::Port>,
    memory: Arc<Memory>,
    limits: Limits,
    prepared: Option<Vec<Arc<dyn ExecutionPlan>>>,
    #[cfg(test)]
    projections: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    observed: Mutex<Option<std::sync::mpsc::Sender<Arc<Capture>>>>,
}

struct GraphRun {
    projection: Weak<Projection>,
    captured: OnceCell<std::result::Result<Arc<Capture>, Arc<DataFusionError>>>,
}

struct Capture {
    source: Weak<SourceSnapshot>,
    graph: Mutex<Option<Graph<'static>>>,
    positions: Vec<(araphor_data::DiscoveryRecordIdV1, StorePositionV1)>,
    heads: Vec<Head>,
    proofs: Vec<AnalysisContextRefV1>,
    fact_refs: Vec<AnalysisContextRefV1>,
    contexts: Vec<AnalysisContextVersionV1>,
    consumed: u64,
    accepted: u64,
    coverage_revision: u64,
    recheck: bool,
    now: u64,
    inputs: Vec<sdk::Input>,
    _memory: MemoryReservation,
}

struct Head {
    id: String,
    first: u64,
    deadline: u64,
    coverage: u64,
    packages: BTreeSet<araphor_data::AnalysisContextKeyV1>,
    reusable: bool,
}

enum DefinitionRef<'a> {
    Fresh(&'a Definition),
    Retained(&'a ResolvedDefinition),
}

impl GraphPublication {
    pub async fn prepare(
        session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events: LogicalPlan,
        definition: Definition,
        facts: Arc<dyn GraphFacts>,
    ) -> Result<Self> {
        let feedback = araphor_query::planner::Planner::reads_table(&events, "graph_manifest")?;
        Self::prepare_on(
            session,
            authority,
            grant,
            events,
            feedback,
            DefinitionRef::Fresh(&definition),
            facts,
            true,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Graph preparation binds the admitted inputs, package definition, and authority."
    )]
    async fn prepare_on(
        mut session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events: LogicalPlan,
        feedback: bool,
        definition: DefinitionRef<'_>,
        facts: Arc<dyn GraphFacts>,
        compile: bool,
    ) -> Result<Self> {
        let mut selection = session.selection().clone();
        selection.sources = grant.selection.sources.clone();
        if selection != grant.selection
            || !grant.selection.binding_ids.is_empty()
            || grant.selection.graph_traversal().is_some()
            || !grant.selection.contexts.is_all()
            || (!grant.selection.sources.is_all()
                && (session.selection().sources.is_all()
                    || session
                        .selection()
                        .sources
                        .as_slice()
                        .iter()
                        .any(|source| !grant.selection.sources.as_slice().contains(source))))
        {
            return Err(Code::Denied.error("complete graph source scope").into());
        }
        if let Some(remaining) = grant.remaining()? {
            session.set_timeout(remaining)?;
        }
        let checked = Arc::clone(&authority);
        let checked_grant = grant.clone();
        araphor_query::execution::Engine::blocking(Arc::clone(session.control()), (), move || {
            checked
                .check(&checked_grant, PackageActionV1::Run)
                .map_err(Into::into)
        })
        .await?;
        let query = Arc::clone(session.engine());
        let coverage = query
            .prepare("SELECT * FROM graph_coverage", Vec::new())
            .await?
            .0;
        let mut ranges = session.clone();
        ranges.register_table(
            "__graph_events",
            Arc::new(ViewTable::new(events.clone(), None)),
        )?;
        ranges.register_table(
            "__graph_coverage",
            Arc::new(ViewTable::new(coverage.clone(), None)),
        )?;
        let datafusion::sql::sqlparser::ast::Statement::Query(ranges_sql) =
            crate::package::builtin::query(
                araphor_analysis_builtins::discovery::sql::COVERAGE_RANGES_SQL,
            )
            .map_err(|source| araphor_query::Error::Sql { source })?
        else {
            return Err(Code::Invalid.error("native coverage view").into());
        };
        let range_sql = format!("WITH events AS (SELECT * FROM __graph_events), coverage AS (SELECT * FROM __graph_coverage)
            SELECT named_struct('tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id,
                'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch) AS stream,
                cpu_id, first_cursor, last_cursor, expected_records, coverage_revision, coverage_interval_id,
                state, gap_reasons FROM ({ranges_sql}) AS qualified");
        let ranges = ranges
            .prepare_definition(&Definition {
                name: "graph-coverage".into(),
                description: String::new(),
                labels: Default::default(),
                program: Program::Sql {
                    source: Source::Inline { inline: range_sql },
                },
            })
            .await?;
        let mut children = vec![events];
        let contexts = query
            .prepare("SELECT * FROM context_versions", Vec::new())
            .await?
            .0;
        let contexts = match facts.context_owners() {
            Some(owners) if !owners.is_empty() => {
                use datafusion::logical_expr::{col, lit, LogicalPlanBuilder};
                LogicalPlanBuilder::from(contexts)
                    .filter(
                        col("owner_id")
                            .in_list(owners.iter().map(|owner| lit(*owner)).collect(), false),
                    )
                    .and_then(LogicalPlanBuilder::build)
                    .map_err(|source| araphor_query::Error::Sql { source })?
            }
            _ => contexts,
        };
        children.push(contexts);
        children.push(ranges.plan);
        children.push(
            query
                .prepare("SELECT * FROM graph_state", Vec::new())
                .await?
                .0,
        );
        children.push(query.prepare("SELECT tenant_id, source_key, graph_result_id, commit_revision, graph_revision,
            first_cursor, last_cursor, witness_deadline_utc_ns, context_refs, notice_coverage_revision
            FROM graph_manifest QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key,
            first_cursor ORDER BY commit_revision DESC) = 1", Vec::new()).await?.0);
        children.push(coverage);
        let prepared_inputs = if compile {
            session.prepare_reusable_inputs(&children).await?
        } else {
            None
        };
        let projection = Arc::new(Projection {
            tenant: grant.selection.tenant_id,
            facts,
            ports: Detector::inputs().to_vec(),
            memory: Arc::clone(session.memory()),
            limits: query.limits().clone(),
            prepared: prepared_inputs,
            #[cfg(test)]
            projections: Default::default(),
            #[cfg(test)]
            observed: Default::default(),
        });
        for (index, port) in projection.ports.iter().enumerate() {
            let source = Arc::new(node::Port {
                owner: Arc::clone(&projection),
                index,
            });
            let schema = Arc::new(port.schema.clone());
            let provider = if projection.prepared.is_some() {
                araphor_query::sources::SourcePort::prepared(
                    port.name.clone(),
                    schema,
                    &children,
                    source,
                )?
            } else {
                araphor_query::sources::SourcePort::new(
                    port.name.clone(),
                    schema,
                    children.clone(),
                    source,
                )?
            };
            session.register_table(
                &port.name,
                Arc::new(ViewTable::new(
                    LogicalPlan::Extension(Extension {
                        node: Arc::new(provider),
                    }),
                    None,
                )),
            )?;
        }
        let prepared = match definition {
            DefinitionRef::Fresh(definition) => session.prepare_definition(definition).await?,
            DefinitionRef::Retained(definition) => session.prepare_resolved(definition).await?,
        };
        let mut calls = BTreeMap::new();
        PackageCall::any(&prepared.plan, &mut |call| {
            if !prepared.images().any(|image| {
                image.bundle().root == call.image().image && image.digest() == call.image().digest
            }) {
                return Err(Projection::external(
                    Code::Denied.error("graph call image admission"),
                ));
            }
            if calls
                .insert(call.id(), call.clone())
                .is_some_and(|previous| !previous.same_call(call))
            {
                return Err(Projection::invalid("graph call identity"));
            }
            Ok(false)
        })
        .map_err(|source| araphor_query::Error::Sql { source })?;
        let mut supported = BTreeSet::new();
        for call in calls.values().filter(|call| {
            call.descriptor()
                .exports
                .iter()
                .any(|model| model.name == call.export() && Graph::supports(model))
        }) {
            if !supported.insert(call.package().package_id.as_str()) {
                return Err(Code::Invalid.error("multiple graph detector calls").into());
            }
        }
        if araphor_data::FindingV1::PACKAGES
            .iter()
            .any(|id| !supported.contains(id))
        {
            return Err(Code::Invalid.error("required graph detector call").into());
        }
        let mut sparse = BTreeMap::new();
        let values = calls
            .iter()
            .map(|(&id, call)| {
                let image = prepared
                    .images()
                    .find(|image| {
                        image.bundle().root == call.image().image
                            && image.digest() == call.image().digest
                    })
                    .ok_or_else(|| Code::Denied.error("graph image attribution"))?;
                let artifact = image
                    .bundle()
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.reference() == *call.package())
                    .ok_or_else(|| Code::Denied.error("graph package attribution"))?;
                if let araphor_data::PackageImplementationV1::Wasm {
                    artifact: component,
                    ..
                } = artifact
                    .implementation(call.export())
                    .map_err(araphor_data::Error::from)?
                {
                    if Detector::supports_resume(call.descriptor(), call.export(), component) {
                        sparse.insert(id, call.clone());
                    }
                }
                Ok((
                    id,
                    AnalysisContextVersionV1::from_package(
                        image,
                        grant.selection.tenant_id,
                        call.package(),
                        call.export(),
                        call.output(),
                    )?,
                ))
            })
            .collect::<araphor_data::Result<BTreeMap<_, _>>>()?;
        let checked = Arc::clone(&authority);
        let stage = Arc::clone(session.control());
        let granted = grant.clone();
        let store = Arc::clone(session.engine().store());
        let (prepared, packages) =
            araphor_query::execution::Engine::blocking(Arc::clone(&stage), (), move || {
                let images = prepared.images().collect::<Vec<_>>();
                let mut grants = vec![(&granted, PackageActionV1::Run, None)];
                grants.extend(
                    images
                        .iter()
                        .map(|image| (&granted, PackageActionV1::Run, Some(*image))),
                );
                let contexts = values.values().cloned().collect::<Vec<_>>();
                let mut references = None;
                checked.commit_many(&grants, &mut || {
                    references = Some(store.intern_contexts_guarded(&contexts, || {
                        granted.remaining()?;
                        stage.check()
                    })?);
                    Ok(())
                })?;
                let references =
                    references.ok_or_else(|| Code::Incomplete.error("graph package references"))?;
                if references.len() != values.len()
                    || references
                        .iter()
                        .zip(values.values())
                        .any(|(reference, value)| reference.key != value.key)
                {
                    return Err(Code::Conflict.error("graph package references").into());
                }
                let packages = values
                    .into_keys()
                    .zip(references)
                    .collect::<BTreeMap<_, _>>();
                Ok((prepared, packages))
            })
            .await?;
        let package_keys = packages
            .values()
            .map(|reference| reference.key.clone())
            .collect::<BTreeSet<_>>();
        let sparse_ids = sparse.keys().copied().collect();
        let weak = Arc::downgrade(&projection);
        session.set_context_init(move |config| {
            let run = Arc::new(GraphRun {
                projection: weak.clone(),
                captured: OnceCell::new(),
            });
            config.set_extension(Arc::clone(&run));
            let checked = Arc::clone(&run);
            let sparse = sparse.clone();
            config.set_extension(Arc::new(araphor_query::definition::CallSparse::new(
                move |call| {
                    sparse
                        .get(&call.id())
                        .is_some_and(|expected| expected.same_call(call))
                        && checked
                            .captured
                            .get()
                            .and_then(|value| value.as_ref().ok())
                            .is_some()
                },
            )));
            let packages = package_keys.clone();
            config.set_extension(Arc::new(araphor_query::definition::CallReuse::new(
                move |call| {
                    call.descriptor()
                        .exports
                        .iter()
                        .any(|model| model.name == call.export() && Graph::supports(model))
                        && run
                            .captured
                            .get()
                            .and_then(|value| value.as_ref().ok())
                            .is_some_and(|capture| {
                                capture
                                    .heads
                                    .iter()
                                    .any(|head| head.reusable && head.packages == packages)
                            })
                },
            )));
        });
        Ok(Self {
            session,
            #[cfg(test)]
            grant,
            prepared,
            feedback,
            calls,
            packages,
            sparse: sparse_ids,
            projection,
        })
    }
}

impl Projection {
    fn external(source: impl std::error::Error + Send + Sync + 'static) -> DataFusionError {
        DataFusionError::External(Box::new(source))
    }
    fn invalid(field: &'static str) -> DataFusionError {
        Self::external(araphor_data::GraphInvalidSnafu { field }.build())
    }
    fn check_deadline(deadline: u64) -> araphor_data::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|value| u64::try_from(value.as_nanos()).ok())
            .ok_or_else(|| Code::Incomplete.error("graph publication time"))?;
        if now >= deadline {
            return Err(Code::Incomplete.error("graph witness expired"));
        }
        Ok(())
    }
}

impl GraphRun {
    fn from_context(
        context: &datafusion::execution::TaskContext,
        projection: &Arc<Projection>,
    ) -> std::result::Result<Arc<Self>, DataFusionError> {
        let run = context
            .session_config()
            .get_extension::<Self>()
            .ok_or_else(|| Projection::invalid("graph execution context"))?;
        if !Weak::ptr_eq(&run.projection, &Arc::downgrade(projection)) {
            return Err(Projection::invalid("graph execution projection"));
        }
        Ok(run)
    }
}
