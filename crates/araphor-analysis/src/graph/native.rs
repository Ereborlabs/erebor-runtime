use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
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
use datafusion::sql::sqlparser::ast::Statement;
use tokio::sync::OnceCell;

use crate::{Graph, Result};

mod capture;
mod commit;
pub(crate) use commit::GraphConversion;
mod managed;
mod node;
mod program;

#[cfg(test)]
mod tests;

pub trait GraphFacts: Send + Sync {
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
    consumed: u64,
    accepted: u64,
    coverage_revision: u64,
    now: u64,
    inputs: Vec<sdk::Input>,
    _memory: MemoryReservation,
}

struct Head {
    id: String,
    first: u64,
    deadline: u64,
    coverage: u64,
    packages: std::collections::BTreeSet<araphor_data::AnalysisContextKeyV1>,
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

    async fn prepare_on(
        mut session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events: LogicalPlan,
        feedback: bool,
        definition: DefinitionRef<'_>,
        facts: Arc<dyn GraphFacts>,
        compile_inputs: bool,
    ) -> Result<Self> {
        let mut selection = session.selection().clone();
        selection.sources = grant.selection.sources.clone();
        if selection != grant.selection
            || (!grant.selection.sources.is_all()
                && (session.selection().sources.is_all()
                    || session
                        .selection()
                        .sources
                        .as_slice()
                        .iter()
                        .any(|source| !grant.selection.sources.as_slice().contains(source))))
            || !grant.selection.binding_ids.is_empty()
            || grant.selection.graph_traversal().is_some()
            || !grant.selection.contexts.is_all()
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
        let mut range_session = session.clone();
        range_session.register_table(
            "__graph_selected_events",
            Arc::new(ViewTable::new(events.clone(), None)),
        )?;
        let coverage = query
            .prepare("SELECT * FROM graph_coverage", Vec::new())
            .await?
            .0;
        range_session.register_table(
            "__graph_captured_coverage",
            Arc::new(ViewTable::new(coverage.clone(), None)),
        )?;
        let Statement::Query(ranges) = crate::package::builtin::query(
            araphor_analysis_builtins::discovery::sql::COVERAGE_RANGES_SQL,
        )
        .map_err(|source| araphor_query::Error::Sql { source })?
        else {
            return Err(Code::Invalid.error("native coverage view").into());
        };
        let sql = format!("WITH events AS (SELECT * FROM __graph_selected_events), coverage AS (SELECT * FROM __graph_captured_coverage)
            SELECT named_struct('tenant_id', tenant_id, 'node_id', node_id, 'node_boot_id', node_boot_id,
                'label_epoch', label_epoch, 'source_id', source_id, 'source_epoch', source_epoch) AS stream,
                cpu_id, first_cursor, last_cursor, expected_records, coverage_revision, coverage_interval_id,
                state, gap_reasons FROM ({}) AS qualified", ranges);
        let ranges = range_session
            .prepare_definition(&Definition {
                name: "graph-coverage".into(),
                description: String::new(),
                labels: Default::default(),
                program: Program::Sql {
                    source: Source::Inline { inline: sql },
                },
            })
            .await?;
        let mut children = vec![events];
        for sql in [
            "SELECT * FROM context_versions",
            "SELECT * FROM graph_state",
            "SELECT tenant_id, source_key, graph_result_id, commit_revision, graph_revision,
                graph_sensitivity, first_cursor, last_cursor, previous_result_id,
                context_notice_revision, witness_deadline_utc_ns, subject_count,
                relationship_count, max_hops, hop_boundary, context_refs,
                notice_coverage_revision FROM graph_manifest
                QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key, first_cursor
                ORDER BY commit_revision DESC) = 1",
        ] {
            children.push(query.prepare(sql, Vec::new()).await?.0);
        }
        children.insert(2, ranges.plan.clone());
        children.push(coverage);
        let prepared_inputs = if compile_inputs {
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
            projections: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            observed: Mutex::new(None),
        });
        for index in 0..projection.ports.len() {
            let source = Arc::new(node::Port {
                owner: Arc::clone(&projection),
                index,
            });
            let port = if projection.prepared.is_some() {
                araphor_query::sources::SourcePort::prepared(
                    projection.ports[index].name.clone(),
                    Arc::new(projection.ports[index].schema.clone()),
                    &children,
                    source,
                )?
            } else {
                araphor_query::sources::SourcePort::new(
                    projection.ports[index].name.clone(),
                    Arc::new(projection.ports[index].schema.clone()),
                    children.clone(),
                    source,
                )?
            };
            session.register_table(
                &projection.ports[index].name,
                Arc::new(ViewTable::new(
                    LogicalPlan::Extension(Extension {
                        node: Arc::new(port),
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
        let mut foreign = false;
        PackageCall::any(&prepared.plan, &mut |call| {
            if !prepared.images().any(|bundle| {
                bundle.bundle().root == call.image().image
                    && bundle.digest() == call.image().digest.as_str()
            }) {
                foreign = true;
                return Ok(false);
            }
            if let Some(previous) = calls.insert(call.id(), call.clone()) {
                if !previous.same_call(call) {
                    return Err(Projection::invalid("graph call identity"));
                }
            }
            Ok(false)
        })
        .map_err(|source| araphor_query::Error::Sql { source })?;
        if foreign {
            return Err(Code::Denied.error("graph call image admission").into());
        }
        let mut supported = std::collections::BTreeSet::new();
        for call in calls.values().filter(|call| {
            call.descriptor()
                .exports
                .iter()
                .find(|model| model.name == call.export())
                .is_some_and(Graph::supports)
        }) {
            if !supported.insert(call.package().package_id.as_str()) {
                return Err(Code::Invalid.error("multiple graph detector calls").into());
            }
        }
        if araphor_data::FindingV1::PACKAGES
            .iter()
            .any(|id| !supported.contains(*id))
        {
            return Err(Code::Invalid.error("required graph detector call").into());
        }
        let check = Arc::clone(&authority);
        let stage = Arc::clone(session.control());
        let granted = grant.clone();
        let prepared =
            araphor_query::execution::Engine::blocking(Arc::clone(&stage), (), move || {
                granted.remaining()?;
                check.check(&granted, PackageActionV1::Run)?;
                for bundle in prepared.images() {
                    check.admit(&granted, bundle)?;
                }
                stage.check()?;
                Ok(prepared)
            })
            .await?;
        let packages = calls
            .values()
            .map(|call| {
                let bundle = prepared
                    .images()
                    .find(|bundle| {
                        bundle.bundle().root == call.image().image
                            && bundle.digest() == call.image().digest.as_str()
                    })
                    .ok_or_else(|| Code::Denied.error("graph image attribution"))?;
                Ok(araphor_data::AnalysisContextVersionV1::from_package(
                    bundle,
                    grant.selection.tenant_id,
                    call.package(),
                    call.export(),
                    call.output(),
                )?
                .key)
            })
            .collect::<araphor_data::Result<std::collections::BTreeSet<_>>>()?;
        let selected = Arc::downgrade(&projection);
        session.set_context_init(move |config| {
            let run = Arc::new(GraphRun {
                projection: selected.clone(),
                captured: OnceCell::new(),
            });
            config.set_extension(Arc::clone(&run));
            let packages = packages.clone();
            config.set_extension(Arc::new(araphor_query::definition::CallReuse::new(
                move |call| {
                    call.descriptor()
                        .exports
                        .iter()
                        .find(|model| model.name == call.export())
                        .is_some_and(Graph::supports)
                        && run
                            .captured
                            .get()
                            .and_then(|captured| captured.as_ref().ok())
                            .is_some_and(|captured| {
                                captured
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
            projection,
        })
    }
}

impl Projection {
    fn check_deadline(deadline: u64) -> araphor_data::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok())
            .ok_or_else(|| Code::Incomplete.error("graph publication time"))?;
        if now >= deadline {
            return Err(Code::Incomplete.error("graph witness expired"));
        }
        Ok(())
    }

    fn external(source: impl std::error::Error + Send + Sync + 'static) -> DataFusionError {
        DataFusionError::External(Box::new(source))
    }
    fn invalid(field: &'static str) -> DataFusionError {
        Self::external(araphor_data::Error::GraphInvalid {
            field,
            location: snafu::location!(),
        })
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
