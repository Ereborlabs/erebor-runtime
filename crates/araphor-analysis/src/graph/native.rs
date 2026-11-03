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
mod facts;
mod managed;
mod node;
mod program;
mod records;
pub(crate) use commit::GraphConversion;

#[cfg(test)]
mod tests;

pub trait GraphFacts: Send + Sync {
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
    packages: BTreeMap<u64, AnalysisContextRefV1>,
    projection: Arc<Projection>,
}

struct Projection {
    tenant: [u8; 16],
    facts: Arc<dyn GraphFacts>,
}

struct GraphRun {
    projection: Weak<Projection>,
    captured: Mutex<Option<Capture>>,
}

struct Capture {
    source: Weak<SourceSnapshot>,
    metadata: GraphManifest,
    base: Option<PackageResultRefV1>,
    base_count: Option<u64>,
    restricted: Option<u64>,
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
        Self::prepare_on(
            session,
            authority,
            grant,
            events,
            control,
            DefinitionRef::Fresh(&definition),
            facts,
            None,
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
        input_gate: Option<LogicalPlan>,
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
        let events = Self::event_driver(&session, events).await?;
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
        session.register_table(
            "__graph_resolved",
            Arc::new(ViewTable::new(resolved.clone(), None)),
        )?;
        session.register_table("__graph_changed", Arc::new(ViewTable::new(changed, None)))?;
        let keys = Self::native_plan(
            &session,
            "
            SELECT record FROM __graph_changed
            UNION
            SELECT current.record FROM graph_control control
            CROSS JOIN graph_capture capture JOIN __graph_resolved current
                ON current.record['stream']['tenant_id'] = control.tenant_id
                AND current.record['stream']['node_id'] = control.node_id
                AND current.record['stream']['node_boot_id'] = control.node_boot_id
                AND current.record['stream']['label_epoch'] = control.label_epoch
                AND current.record['stream']['source_id'] = control.source_id
                AND current.record['stream']['source_epoch'] = control.source_epoch
            WHERE NOT capture.resume_window OR control.restricted_count IS NULL",
        )
        .await?;
        session.register_table("__graph_status_keys", Arc::new(ViewTable::new(keys, None)))?;
        let status = Self::native_plan(&session, "
            SELECT control.*, capture.resume_window, keys.record, current.event, current.resolved,
                current.coverage_revision AS record_coverage_revision,
                current.interval_revision, current.coverage_interval_id,
                current.coverage_state, current.coverage_reasons
            FROM graph_control control CROSS JOIN graph_capture capture LEFT JOIN __graph_status_keys keys ON TRUE
            LEFT JOIN __graph_resolved current ON current.record = keys.record").await?;
        let status = node::MetadataPort::Status.plan(&session, status).await?;
        session.register_table(
            "graph_status",
            Arc::new(ViewTable::new(status.clone(), None)),
        )?;
        let header = status;
        let dirty = Self::native_plan(
            &session,
            "
            WITH keys AS (
                SELECT record FROM __graph_changed
                UNION
                SELECT current.record FROM graph_control control CROSS JOIN graph_capture capture
                CROSS JOIN graph_status status JOIN __graph_resolved current
                    ON current.record['stream']['tenant_id'] = control.tenant_id
                    AND current.record['stream']['node_id'] = control.node_id
                    AND current.record['stream']['node_boot_id'] = control.node_boot_id
                    AND current.record['stream']['label_epoch'] = control.label_epoch
                    AND current.record['stream']['source_id'] = control.source_id
                    AND current.record['stream']['source_epoch'] = control.source_epoch
                WHERE status.zero_crossing OR NOT capture.resume_window
                    OR control.restricted_count IS NULL
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
        });
        for (index, (alias, port, driver)) in Projection::source_ports()
            .into_iter()
            .map(|(alias, port)| (alias, port, resolved.clone()))
            .chain(std::iter::once((
                "graph_dirty",
                araphor_analysis_builtins::graph::Unit::affected_port(),
                dirty,
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
        let settings = Self::native_plan(&session, &format!(
            "SELECT CAST({} AS BIGINT UNSIGNED) AS window_ns, status.restricted FROM graph_status status",
            araphor_data::GRAPH_WINDOW_NS,
        )).await?;
        let settings: Arc<dyn datafusion::catalog::TableProvider> =
            Arc::new(ViewTable::new(settings, None));
        session.register_table("manifest", Arc::clone(&settings))?;
        session.register_table("graph_settings", settings)?;
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
        let mut supported = BTreeSet::new();
        if calls.values().any(|call| {
            call.has_input_overrides()
                && call
                    .descriptor()
                    .exports
                    .iter()
                    .any(|model| model.name == call.export() && Detector::supports_units(model))
        }) {
            return Err(Code::Invalid.error("Graph unit input override").into());
        }
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
        let (mut prepared, packages) =
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
            packages,
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
