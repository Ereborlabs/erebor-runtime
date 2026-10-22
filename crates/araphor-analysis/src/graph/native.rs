use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisResultReceiptV1, PackageActionV1,
    PackageAuthorization, PackageBundleRef, PackageErrorCodeV1 as Code, PackageGrantV1,
    StorePositionV1,
};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_query::definition::{PackageCall, PreparedDefinition};
use araphor_query::execution::{Limits, Session};
use araphor_query::memory::Memory;
use araphor_query::sources::SourceSnapshot;
use datafusion::common::DataFusionError;
use datafusion::datasource::{provider_as_source, view::ViewTable};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::{dml::InsertOp, Extension, LogicalPlan, LogicalPlanBuilder};
use datafusion::sql::sqlparser::ast::Statement;
use tokio::sync::OnceCell;

use crate::{Graph, Result};

mod capture;
mod node;
mod sink;

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
    authority: Arc<dyn PackageAuthorization>,
    grant: PackageGrantV1,
    prepared: PreparedDefinition,
    calls: BTreeMap<u64, PackageCall>,
    projection: Arc<Projection>,
}

struct Projection {
    tenant: [u8; 16],
    facts: Arc<dyn GraphFacts>,
    ports: Vec<sdk::Port>,
    memory: Arc<Memory>,
    limits: Limits,
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
    coverage_revision: u64,
    now: u64,
    inputs: Vec<sdk::Input>,
    _memory: MemoryReservation,
}

struct Head {
    id: String,
    revision: u64,
    first: u64,
    deadline: u64,
}

impl GraphPublication {
    pub async fn prepare(
        mut session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events: LogicalPlan,
        definition: Definition,
        facts: Arc<dyn GraphFacts>,
    ) -> Result<Self> {
        if session.selection() != &grant.selection
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
            "SELECT * FROM graph_manifest QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key, first_cursor ORDER BY commit_revision DESC) = 1",
        ] {
            children.push(query.prepare(sql, Vec::new()).await?.0);
        }
        children.insert(2, ranges.plan.clone());
        children.push(coverage);
        let projection = Arc::new(Projection {
            tenant: grant.selection.tenant_id,
            facts,
            ports: Detector::inputs().to_vec(),
            memory: Arc::clone(session.memory()),
            limits: query.limits().clone(),
            #[cfg(test)]
            projections: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            observed: Mutex::new(None),
        });
        let selected = Arc::downgrade(&projection);
        session.set_context_init(move |config| {
            config.set_extension(Arc::new(GraphRun {
                projection: selected.clone(),
                captured: OnceCell::new(),
            }));
        });
        for index in 0..projection.ports.len() {
            let source = Arc::new(node::Port {
                owner: Arc::clone(&projection),
                index,
            });
            let port = araphor_query::sources::SourcePort::new(
                Arc::new(projection.ports[index].schema.clone()),
                children.clone(),
                source,
            )?;
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
        let prepared = session.prepare_definition(&definition).await?;
        let mut calls = BTreeMap::new();
        let mut foreign = false;
        PackageCall::any(&prepared.plan, &mut |call| {
            if !prepared.images().any(|(bundle, digest)| {
                bundle.root == call.image().image && digest == call.image().digest.as_str()
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
                for (bundle, digest) in prepared.images() {
                    check.admit(&granted, &PackageBundleRef::retained(bundle, digest))?;
                }
                stage.check()?;
                Ok(prepared)
            })
            .await?;
        Ok(Self {
            session,
            authority,
            grant,
            prepared,
            calls,
            projection,
        })
    }

    pub async fn refresh(self, result_id: String) -> Result<(String, AnalysisResultReceiptV1)> {
        self.grant.remaining()?;
        let mut changes = self.authority.changes_for(&self.grant);
        let read = Arc::clone(self.session.control());
        let receipt = Arc::new(Mutex::new(None));
        let state = Arc::clone(&receipt);
        let owner = Arc::new(self);
        let execution = async {
            let schema = Arc::clone(owner.prepared.plan.schema().inner());
            let sink = Arc::new(sink::Publication {
                owner: Arc::clone(&owner),
                schema,
                result_id,
                receipt: state,
            });
            let mut definition = owner.prepared.clone();
            definition.plan = LogicalPlanBuilder::insert_into(
                definition.plan,
                "__graph_publication",
                provider_as_source(sink),
                InsertOp::Append,
            )
            .and_then(LogicalPlanBuilder::build)
            .map_err(|source| araphor_query::Error::Sql { source })?;
            owner
                .session
                .execute_definition(&definition, Default::default())
                .await?;
            Ok::<_, crate::Error>(())
        };
        tokio::pin!(execution);
        owner.check_current().await?;
        loop {
            tokio::select! {
                result = &mut execution => { result?; break; },
                changed = changes.changed() => {
                    let checked = if changed.is_ok() { owner.check_current().await }
                        else { Err(Code::Incomplete.error("graph authority watch").into()) };
                    if let Err(error) = checked {
                        read.cancel()?;
                        let _joined = execution.await;
                        return Err(error);
                    }
                }
            }
        }
        owner.check_current().await?;
        let result = receipt
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| Code::Incomplete.error("graph publication receipt"))?;
        Ok(result)
    }
    async fn check_current(self: &Arc<Self>) -> Result<()> {
        let checked = Arc::clone(self);
        let stage = Arc::clone(self.session.control());
        araphor_query::execution::Engine::blocking(Arc::clone(&stage), (), move || {
            let images = checked
                .prepared
                .images()
                .map(|(bundle, digest)| PackageBundleRef::retained(bundle, digest))
                .collect::<Vec<_>>();
            let grants = std::iter::once((&checked.grant, None))
                .chain(images.iter().map(|image| (&checked.grant, Some(image))))
                .collect::<Vec<_>>();
            checked
                .authority
                .commit_many(&grants, PackageActionV1::Run, &mut || {
                    checked.grant.remaining()?;
                    stage.check()
                })?;
            Ok(())
        })
        .await?;
        Ok(())
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
