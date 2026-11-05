use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use araphor_analysis_builtins::graph::Detector;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::{GraphManifest, PackageResultRefV1},
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, DiscoveryCoverageV1,
    DiscoveryRecordIdV1, DiscoveryRecordV1, GraphCoverageKeyV1, PackageActionV1,
    PackageAuthorization, PackageErrorCodeV1 as Code, PackageGrantV1, StorePositionV1,
};
use araphor_discovery_definition::{Definition, Program, ResolvedDefinition, Source};
use araphor_query::definition::{PackageCall, PreparedDefinition};
use araphor_query::execution::Session;
use araphor_query::sources::SourceSnapshot;
use datafusion::common::DataFusionError;
use datafusion::datasource::view::ViewTable;
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;

use crate::{Graph, Result};

mod capture;
mod commit;
mod entered;
mod facts;
mod managed;
mod node;
mod records;
mod roots;
pub(crate) use commit::GraphConversion;

#[cfg(test)]
mod tests;

pub trait GraphFacts: Send + Sync {
    fn local_observations(&self) -> bool {
        false
    }

    fn plans<'a>(
        &'a self,
        session: &'a Session,
        events: &'a LogicalPlan,
        contexts: &'a LogicalPlan,
    ) -> futures_util::future::BoxFuture<'a, araphor_query::Result<(LogicalPlan, LogicalPlan)>>;

    /// List every context owner used for proof input or saved Graph facts.
    /// Return None to read all context owners.
    fn context_owners(&self) -> Option<&'static [&'static str]> {
        None
    }
}

#[derive(Clone)]
pub struct GraphPublication {
    session: Session,
    #[cfg(test)]
    grant: PackageGrantV1,
    prepared: PreparedDefinition,
    calls: BTreeMap<u64, PackageCall>,
    graph_calls: BTreeSet<u64>,
    projection: Arc<Projection>,
}

struct Projection {
    tenant: [u8; 16],
    facts: Arc<dyn GraphFacts>,
    append_stable: bool,
}

struct GraphRun {
    projection: Weak<Projection>,
    captured: Mutex<Option<Capture>>,
}

struct Capture {
    source: Weak<SourceSnapshot>,
    metadata: GraphManifest,
    parent: Option<PackageResultRefV1>,
    base: Option<PackageResultRefV1>,
    base_last: Option<u64>,
    expired: bool,
    base_count: Option<u64>,
    restricted: Option<u64>,
    append: Option<bool>,
    progress: Option<(u64, u64, u64, u64)>,
    records: BTreeMap<DiscoveryRecordIdV1, (DiscoveryRecordV1, StorePositionV1)>,
    facts: BTreeMap<AnalysisContextKeyV1, (AnalysisContextVersionV1, Option<AnalysisContextRefV1>)>,
    proofs: BTreeMap<(DiscoveryRecordIdV1, AnalysisContextKeyV1), AnalysisContextRefV1>,
    coverage: BTreeMap<(DiscoveryRecordIdV1, u64, Option<u64>), DiscoveryCoverageV1>,
    coverage_keys: BTreeSet<GraphCoverageKeyV1>,
    removed: BTreeSet<DiscoveryRecordIdV1>,
    _memory: Vec<MemoryReservation>,
}

enum DefinitionRef<'a> {
    Fresh(&'a Definition),
    Retained(&'a ResolvedDefinition, Option<u64>),
}

impl Projection {
    fn source_ports() -> [(&'static str, sdk::Port); 2] {
        [
            (
                "graph_records",
                araphor_analysis_builtins::graph::Observation::port(),
            ),
            (
                "graph_facts",
                araphor_analysis_builtins::graph::Fact::source_port(),
            ),
        ]
    }
}

impl GraphPublication {
    pub(crate) fn session(&self) -> &Session {
        &self.session
    }

    async fn native_plan(session: &Session, sql: &str) -> Result<LogicalPlan> {
        Ok(session.prepare(sql, Vec::new()).await?.0)
    }

    fn check_driver(
        events: &LogicalPlan,
        resolved: &LogicalPlan,
        changed: &LogicalPlan,
    ) -> Result<()> {
        let record = events.schema().field(0);
        let event = events.schema().field(1);
        let valid = resolved.schema().fields().len() == 3
            && changed.schema().fields().len() == 1
            && resolved.schema().field(0).name() == "record"
            && resolved.schema().field(0).data_type() == record.data_type()
            && resolved.schema().field(1).name() == "event"
            && resolved.schema().field(1).data_type() == event.data_type()
            && resolved.schema().field(2).name() == "resolved"
            && resolved.schema().field(2).data_type()
                == &sdk::DataType::Struct(Self::resolved_schema().fields().clone())
            && changed.schema().field(0).name() == "record"
            && changed.schema().field(0).data_type() == record.data_type();
        if !valid {
            return Err(Code::Invalid.error("Graph native fact plans").into());
        }
        Ok(())
    }

    pub(super) async fn prepare_control(session: &mut Session, sql: &str) -> Result<LogicalPlan> {
        if sql.is_empty() {
            return Err(Code::Invalid.error("Graph control SQL").into());
        }
        let scalar = datafusion::logical_expr::LogicalPlanBuilder::empty(true)
            .build()
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let capture = node::MetadataPort::Capture.plan(session, scalar).await?;
        session.register_table("graph_capture", Arc::new(ViewTable::new(capture, None)))?;
        let prepared = session
            .prepare_definition(
                &Definition {
                    name: "graph-control".into(),
                    description: String::new(),
                    labels: Default::default(),
                    program: Program::Sql {
                        source: Source::Inline { inline: sql.into() },
                    },
                },
                None,
            )
            .await?;
        use sdk::DataType;
        let fields = [
            ("source_key", DataType::Binary),
            ("first_cursor", DataType::UInt64),
            ("last_cursor", DataType::UInt64),
            ("base_result_id", DataType::Utf8),
            ("base_commit_revision", DataType::UInt64),
        ];
        if prepared.plan().schema().fields().len() != fields.len()
            || fields.iter().any(|(name, data_type)| {
                prepared
                    .plan()
                    .schema()
                    .field_with_unqualified_name(name)
                    .map_or(true, |field| field.data_type() != data_type)
            })
        {
            return Err(Code::Invalid.error("Graph control schema").into());
        }
        if PackageCall::any(prepared.plan(), &mut |_, _| Ok(true))
            .map_err(|source| araphor_query::Error::Sql { source })?
        {
            return Err(Code::Invalid.error("Graph control SQL package call").into());
        }
        session.register_table(
            "__graph_selected_control",
            Arc::new(ViewTable::new(prepared.into_plan(), None)),
        )?;
        let header = Self::native_plan(
            session,
            "
            SELECT selected.*, state.tenant_id, state.node_id, state.node_boot_id,
                state.label_epoch, state.source_id, state.source_epoch, state.cpu_id,
                state.processor_class, state.retired, state.consumed_cursor,
                state.resume_floor, state.retained_floor, state.contiguous_cursor,
                state.coverage_revision, notice.commit_revision AS notice_base_revision,
                CASE WHEN selected.base_result_id IS NULL THEN CAST(0 AS BIGINT UNSIGNED)
                    ELSE notice.notice_context_revision END AS notice_context_revision,
                CASE WHEN selected.base_result_id IS NULL THEN CAST(0 AS BIGINT UNSIGNED)
                    ELSE notice.notice_coverage_revision END AS notice_coverage_revision
            FROM __graph_selected_control selected JOIN graph_state state
                ON selected.source_key = state.source_key
            LEFT JOIN graph_manifest notice ON notice.source_key = selected.source_key
                AND notice.graph_result_id = selected.base_result_id
                AND notice.commit_revision = selected.base_commit_revision",
        )
        .await?;
        let rows = araphor_query::sources::SourceImage::After
            .plan_rows(&header)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let plan = node::MetadataPort::Control.plan(session, rows).await?;
        session.register_table(
            "graph_control",
            Arc::new(ViewTable::new(plan.clone(), None)),
        )?;
        Ok(plan)
    }

    pub async fn prepare(
        session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events: LogicalPlan,
        control: LogicalPlan,
        definition: Definition,
        facts: Arc<dyn GraphFacts>,
    ) -> Result<Self> {
        let append_stable = Self::append_selection(&events)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        Self::prepare_on(
            session,
            authority,
            grant,
            events,
            control,
            DefinitionRef::Fresh(&definition),
            facts,
            append_stable,
        )
        .await
    }

    async fn prepare_on(
        mut session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events: LogicalPlan,
        control: LogicalPlan,
        definition: DefinitionRef<'_>,
        facts: Arc<dyn GraphFacts>,
        append_stable: bool,
    ) -> Result<Self> {
        session.register_table(
            "graph_control",
            Arc::new(ViewTable::new(control.clone(), None)),
        )?;
        let window = node::MetadataPort::Window
            .plan(&session, control.clone())
            .await?;
        session.register_table("graph_window", Arc::new(ViewTable::new(window, None)))?;
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
        let identities = datafusion::logical_expr::LogicalPlanBuilder::from(events.clone())
            .project([Self::record_expr().alias("record")])
            .and_then(datafusion::logical_expr::LogicalPlanBuilder::build)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let identities = araphor_query::sources::SourceImage::After
            .plan_rows(&identities)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let events = Self::event_driver(&session, events).await?;
        let entered = entered::EnteredPort::plan(&session, control.clone(), append_stable).await?;
        session.register_table("__graph_entered", Arc::new(ViewTable::new(entered, None)))?;
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
        let (resolved, changed) = facts.plans(&session, &events, &contexts).await?;
        Self::check_driver(&events, &resolved, &changed)?;
        let resolved = Self::coverage_driver(&session, resolved).await?;
        let resolved = araphor_query::sources::SourceImage::After
            .plan_rows(&resolved)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        session.register_table(
            "__graph_current_ids",
            Arc::new(ViewTable::new(identities, None)),
        )?;
        let resolved = araphor_query::sources::SourcePort::native(
            &session,
            "__graph_resolved".into(),
            resolved,
            vec![(0, 0)],
        )
        .await?
        .plan()?;
        session.register_table(
            "__graph_resolved",
            Arc::new(ViewTable::new(resolved.clone(), None)),
        )?;
        session.register_table(
            "__graph_native_changes",
            Arc::new(ViewTable::new(changed, None)),
        )?;
        let changed = Self::native_plan(
            &session,
            "SELECT record FROM __graph_native_changes UNION SELECT record FROM __graph_entered",
        )
        .await?;
        session.register_table("__graph_changed", Arc::new(ViewTable::new(changed, None)))?;
        let prefix = node::MetadataPort::Prefix
            .plan(&session, control.clone())
            .await?;
        session.register_table("__graph_prefix", Arc::new(ViewTable::new(prefix, None)))?;
        let prefix = Self::native_plan(&session, &format!("
            WITH coverage AS (
                SELECT c.* FROM coverage c JOIN graph_control control
                    ON c.tenant_id = control.tenant_id AND c.node_id = control.node_id
                    AND c.node_boot_id = control.node_boot_id AND c.label_epoch = control.label_epoch
                    AND c.source_id = control.source_id AND c.source_epoch = control.source_epoch
            ), events AS (SELECT * FROM __graph_prefix), prefix AS (
                SELECT COALESCE(bool_and(available AND state IN ('HEALTHY','CLOSED')), false) AS complete
                FROM ({}) qualified
            ), status AS (
                SELECT COUNT(*) FILTER (WHERE kind IN ('pending','recovery','expired')) = 0 AS complete
                FROM coverage
            )
            SELECT prefix.complete AND status.complete AS complete
            FROM prefix CROSS JOIN status", araphor_analysis_builtins::discovery::sql::COVERAGE_ROWS_SQL)).await?;
        session.register_table(
            "__graph_prefix_check",
            Arc::new(ViewTable::new(prefix, None)),
        )?;
        let fallback = Self::native_plan(
            &session,
            "SELECT control.tenant_id, control.node_id, control.node_boot_id,
                control.label_epoch, control.source_id, control.source_epoch
             FROM graph_control control CROSS JOIN graph_capture capture
             CROSS JOIN __graph_prefix_check prefix
             WHERE NOT capture.resume_window OR NOT prefix.complete
                OR control.restricted_count IS NULL",
        )
        .await?;
        let fallback = araphor_query::sources::SourcePort::native(
            &session,
            "__graph_status_fallback".into(),
            fallback,
            Vec::new(),
        )
        .await?
        .plan()?;
        session.register_table(
            "__graph_status_fallback",
            Arc::new(ViewTable::new(fallback, None)),
        )?;
        let keys = Self::native_plan(
            &session,
            "
            SELECT record FROM __graph_changed
            UNION
            SELECT current.record FROM __graph_status_fallback control
            JOIN __graph_current_ids current
                ON current.record['stream']['tenant_id'] = control.tenant_id
                AND current.record['stream']['node_id'] = control.node_id
                AND current.record['stream']['node_boot_id'] = control.node_boot_id
                AND current.record['stream']['label_epoch'] = control.label_epoch
                AND current.record['stream']['source_id'] = control.source_id
                AND current.record['stream']['source_epoch'] = control.source_epoch",
        )
        .await?;
        session.register_table("__graph_status_keys", Arc::new(ViewTable::new(keys, None)))?;
        let status = Self::native_plan(&session, "
            SELECT control.*, capture.resume_window, prefix.complete AS prefix_complete,
                keys.record, current.event, current.resolved,
                current.coverage_revision AS record_coverage_revision,
                current.interval_revision, current.coverage_interval_id,
                current.coverage_state, current.coverage_reasons
            FROM graph_control control CROSS JOIN graph_capture capture CROSS JOIN __graph_prefix_check prefix
            LEFT JOIN __graph_status_keys keys ON TRUE
            LEFT JOIN __graph_resolved current ON current.record = keys.record").await?;
        let status = node::MetadataPort::Status.plan(&session, status).await?;
        session.register_table(
            "graph_status",
            Arc::new(ViewTable::new(status.clone(), None)),
        )?;
        let header = status;
        let fallback = Self::native_plan(
            &session,
            "SELECT control.tenant_id, control.node_id, control.node_boot_id,
                control.label_epoch, control.source_id, control.source_epoch
             FROM graph_control control CROSS JOIN graph_capture capture
             CROSS JOIN graph_status status WHERE NOT status.append_only",
        )
        .await?;
        let fallback = araphor_query::sources::SourcePort::native(
            &session,
            "__graph_dirty_fallback".into(),
            fallback,
            Vec::new(),
        )
        .await?
        .plan()?;
        session.register_table(
            "__graph_dirty_fallback",
            Arc::new(ViewTable::new(fallback, None)),
        )?;
        let dirty = Self::native_plan(
            &session,
            "
            WITH keys AS (
                SELECT record FROM __graph_changed
                UNION
                SELECT current.record FROM __graph_dirty_fallback control
                JOIN __graph_current_ids current
                    ON current.record['stream']['tenant_id'] = control.tenant_id
                    AND current.record['stream']['node_id'] = control.node_id
                    AND current.record['stream']['node_boot_id'] = control.node_boot_id
                    AND current.record['stream']['label_epoch'] = control.label_epoch
                    AND current.record['stream']['source_id'] = control.source_id
                    AND current.record['stream']['source_epoch'] = control.source_epoch
            ) SELECT keys.record, current.event, current.resolved,
                current.coverage_revision AS record_coverage_revision,
                current.interval_revision, current.coverage_interval_id,
                current.coverage_state, current.coverage_reasons
            FROM keys LEFT JOIN __graph_resolved current ON current.record = keys.record",
        )
        .await?;
        let projection = Arc::new(Projection {
            tenant: grant.selection.tenant_id,
            facts,
            append_stable,
        });
        for (index, (alias, port, driver)) in Projection::source_ports()
            .into_iter()
            .map(|(alias, port)| (alias, port, resolved.clone()))
            .chain(std::iter::once((
                "graph_dirty",
                araphor_analysis_builtins::graph::Unit::affected_port(),
                dirty.clone(),
            )))
            .enumerate()
        {
            let source = Arc::new(node::Port {
                owner: Arc::clone(&projection),
                index,
            });
            let node = araphor_query::sources::SourcePort::new(
                &session,
                port.name.clone(),
                Arc::new(port.schema),
                driver,
                if index < 2 {
                    control.clone()
                } else {
                    header.clone()
                },
                source,
            )
            .await?;
            let plan = node.plan()?;
            let table: Arc<dyn datafusion::catalog::TableProvider> =
                Arc::new(ViewTable::new(plan, None));
            if index < 2 {
                session.register_table(&port.name, Arc::clone(&table))?;
            }
            session.register_table(alias, table)?;
        }
        let driver = Self::native_plan(
            &session,
            "SELECT selected.id AS record FROM graph_window lifecycle
             CROSS JOIN graph_records selected WHERE NOT lifecycle.expired",
        )
        .await?;
        let roots = araphor_query::sources::SourcePort::new(
            &session,
            "__graph_roots".into(),
            Arc::new(araphor_analysis_builtins::graph::Unit::port().schema),
            driver,
            header.clone(),
            Arc::new(roots::RootPort {
                owner: Arc::clone(&projection),
            }),
        )
        .await?
        .plan()?;
        session.register_table("__graph_roots", Arc::new(ViewTable::new(roots, None)))?;
        let settings = Self::native_plan(&session, &format!(
            "SELECT CAST({} AS BIGINT UNSIGNED) AS window_ns, status.restricted FROM graph_status status",
            araphor_data::GRAPH_WINDOW_NS,
        )).await?;
        let settings: Arc<dyn datafusion::catalog::TableProvider> =
            Arc::new(ViewTable::new(settings, None));
        session.register_table("manifest", Arc::clone(&settings))?;
        session.register_table("graph_settings", settings)?;
        session.register_table(
            "__graph_selection_rows",
            Arc::new(ViewTable::new(dirty, None)),
        )?;
        let selection = Self::native_plan(
            &session,
            "SELECT dirty.*, status.append_only FROM graph_status status
             LEFT JOIN __graph_selection_rows dirty ON TRUE",
        )
        .await?;
        let input_gate = Some(
            araphor_query::sources::SourcePort::new(
                &session,
                "__source_selection".into(),
                Arc::new(sdk::Schema::empty()),
                control,
                selection,
                Arc::new(node::Port {
                    owner: Arc::clone(&projection),
                    index: 3,
                }),
            )
            .await?
            .plan()?,
        );
        let prepared = match definition {
            DefinitionRef::Fresh(definition) => {
                session.prepare_definition(definition, input_gate).await?
            }
            DefinitionRef::Retained(definition, revision) => {
                session
                    .prepare_resolved(definition, revision, input_gate)
                    .await?
            }
        };
        let mut calls = BTreeMap::new();
        PackageCall::any(prepared.plan(), &mut |_, call| {
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
        let graph_calls = calls
            .values()
            .filter(|call| {
                call.descriptor()
                    .exports
                    .iter()
                    .any(|model| model.name == call.export() && model.graph.is_some())
            })
            .map(PackageCall::id)
            .collect();
        let checked = Arc::clone(&authority);
        let stage = Arc::clone(session.control());
        let granted = grant.clone();
        let mut prepared =
            araphor_query::execution::Engine::blocking(Arc::clone(&stage), (), move || {
                let images = prepared.images().collect::<Vec<_>>();
                let mut grants = vec![(&granted, PackageActionV1::Run, None)];
                grants.extend(
                    images
                        .iter()
                        .map(|image| (&granted, PackageActionV1::Run, Some(*image))),
                );
                checked.commit_many(&grants, &mut || {
                    granted.remaining()?;
                    stage.check()
                })?;
                Ok(prepared)
            })
            .await?;
        let weak = Arc::downgrade(&projection);
        session.set_context_init(move |config| {
            let run = Arc::new(GraphRun {
                projection: weak.clone(),
                captured: Mutex::new(None),
            });
            config.set_extension(Arc::clone(&run));
        });
        session.prepare_execution(&mut prepared).await?;
        Ok(Self {
            session,
            #[cfg(test)]
            grant,
            prepared,
            calls,
            graph_calls,
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
