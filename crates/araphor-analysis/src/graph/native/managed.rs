use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, EvidenceIntakeIdentityV1, ManagedDestination, ManagedGraphOperation,
    PackageAuthorization, PackageErrorCodeV1 as Code, PackageGrantV1,
};
use araphor_discovery_definition::{Definition, Program, ResolvedDefinition, Source};
use araphor_query::definition::{PackageCall, PreparedDefinition};
use araphor_query::execution::{Engine, Session};
use datafusion::logical_expr::{lit, Expr, LogicalPlan, LogicalPlanBuilder};

use super::{DefinitionRef, GraphFacts, GraphPublication};
use crate::{Instance, Result};

impl GraphPublication {
    pub(crate) fn uses_facts(&self, facts: &Arc<dyn GraphFacts>) -> bool {
        Arc::ptr_eq(&self.projection.facts, facts)
    }

    pub(crate) fn replay_tables(session: &mut Session) -> Result<()> {
        for port in super::Detector::inputs() {
            session.register_table(
                &port.name,
                Arc::new(datafusion::datasource::empty::EmptyTable::new(Arc::new(
                    port.schema.clone(),
                ))),
            )?;
        }
        Ok(())
    }

    pub async fn admit_expiry(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        id: String,
        source: EvidenceIntakeIdentityV1,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        let destination = ManagedDestination::Graph {
            source,
            events_sql: String::new(),
            calls: BTreeSet::new(),
            operation: ManagedGraphOperation::Expire,
        };
        let session = query.session_on(
            destination.selection(&grant.selection)?,
            control,
            0,
            query.memory().scope(),
        )?;
        let prepared = session.prepare_definition(&Self::expiry_program()).await?;
        Instance::admit_prepared(session, authority, grant, id, prepared, destination).await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The native Graph job retains its exact source, SQL, image pins, and current authority."
    )]
    pub async fn admit(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Arc<dyn GraphFacts>,
        grant: PackageGrantV1,
        id: String,
        source: EvidenceIntakeIdentityV1,
        events_sql: String,
        definition: ResolvedDefinition,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        let destination = ManagedDestination::Graph {
            source,
            events_sql,
            calls: BTreeSet::new(),
            operation: ManagedGraphOperation::Evaluate,
        };
        let (session, prepared, destination, owner) = Self::prepare_managed(
            query,
            Arc::clone(&authority),
            Some(facts),
            &grant,
            definition,
            destination,
            control,
        )
        .await?;
        Instance::admit_graph(
            session,
            authority,
            grant,
            id,
            prepared,
            destination,
            owner.ok_or_else(|| Code::Incomplete.error("Graph projection owner"))?,
        )
        .await
    }

    pub(crate) async fn prepare_managed(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Option<Arc<dyn GraphFacts>>,
        grant: &PackageGrantV1,
        definition: ResolvedDefinition,
        mut destination: ManagedDestination,
        control: &AnalysisReadControl,
    ) -> Result<(
        Session,
        PreparedDefinition,
        ManagedDestination,
        Option<Arc<Self>>,
    )> {
        let ManagedDestination::Graph {
            events_sql,
            operation,
            ..
        } = &destination
        else {
            return Err(Code::Invalid.error("Graph preparation destination").into());
        };
        definition.validate().map_err(araphor_data::Error::from)?;
        let mut session = query.session_on(
            destination.selection(&grant.selection)?,
            control,
            0,
            query.memory().scope(),
        )?;
        if *operation == ManagedGraphOperation::Expire {
            if definition.definition != Self::expiry_program()
                || !events_sql.is_empty()
                || !matches!(&destination, ManagedDestination::Graph { calls, .. } if calls.is_empty())
            {
                return Err(Code::Invalid.error("graph expiry definition").into());
            }
            let prepared = session.prepare_resolved(&definition).await?;
            if prepared.resolved() != &definition {
                return Err(Code::Conflict.error("graph expiry definition pin").into());
            }
            return Ok((session, prepared, destination, None));
        }
        let facts = facts.ok_or_else(|| Code::Incomplete.error("Graph facts owner"))?;
        let events = session
            .prepare_definition(&Definition {
                name: "graph-events".into(),
                description: String::new(),
                labels: Default::default(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: events_sql.clone(),
                    },
                },
            })
            .await?;
        let feedback = events.sources().contains_key("graph_manifest");
        let mut calls_package = false;
        PackageCall::any(&events.plan, &mut |_| {
            calls_package = true;
            Ok(false)
        })
        .map_err(|source| araphor_query::Error::Sql { source })?;
        if calls_package {
            return Err(Code::Invalid.error("graph event SQL package call").into());
        }
        session.register_table(
            "__graph_current_events",
            Arc::new(datafusion::datasource::view::ViewTable::new(
                events.plan,
                None,
            )),
        )?;
        let events = session
            .prepare_definition(&Definition {
                name: "graph-continuation".into(),
                description: String::new(),
                labels: Default::default(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: "WITH heads AS (
                            SELECT tenant_id, source_key, first_cursor, last_cursor,
                                retained_input_expired, witness_deadline_utc_ns
                            FROM graph_manifest
                            QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key,
                                first_cursor ORDER BY commit_revision DESC) = 1
                        ), expired AS (
                            SELECT DISTINCT s.tenant_id, s.node_id, s.node_boot_id,
                                s.label_epoch, s.source_id, s.source_epoch, s.consumed_cursor
                            FROM graph_state s JOIN heads h
                                ON s.tenant_id = h.tenant_id AND s.source_key = h.source_key
                            JOIN __graph_current_events e
                                ON s.tenant_id = e.tenant_id AND s.node_id = e.node_id
                                    AND s.node_boot_id = e.node_boot_id
                                    AND s.label_epoch = e.label_epoch
                                    AND s.source_id = e.source_id AND s.source_epoch = e.source_epoch
                            WHERE e.source_cursor BETWEEN h.first_cursor AND h.last_cursor
                                AND (h.retained_input_expired OR h.first_cursor <= s.retained_floor
                                    OR h.witness_deadline_utc_ns <= CAST(CAST(CURRENT_TIMESTAMP
                                        AS BIGINT) AS BIGINT UNSIGNED))
                        ) SELECT e.* FROM __graph_current_events e LEFT JOIN expired s
                            ON e.tenant_id = s.tenant_id AND e.node_id = s.node_id
                                AND e.node_boot_id = s.node_boot_id AND e.label_epoch = s.label_epoch
                                AND e.source_id = s.source_id AND e.source_epoch = s.source_epoch
                        WHERE s.consumed_cursor IS NULL OR e.source_cursor > s.consumed_cursor"
                            .into(),
                    },
                },
            })
            .await?;
        let selected = events.plan.clone();
        let mut owner = Self::prepare_on(
            session,
            authority,
            grant.clone(),
            events.plan,
            feedback,
            DefinitionRef::Retained(&definition),
            facts,
        )
        .await?;
        if owner.prepared.resolved() != &definition {
            return Err(Code::Conflict.error("graph definition pin").into());
        }
        owner.prepared.plan = Self::input_gate(selected, owner.prepared.plan)?;
        if let ManagedDestination::Graph { calls, .. } = &mut destination {
            *calls = owner.calls.keys().copied().collect();
        }
        let owner = Arc::new(owner);
        Ok((
            owner.session.clone(),
            owner.prepared.clone(),
            destination,
            Some(owner),
        ))
    }

    pub(super) fn input_gate(events: LogicalPlan, program: LogicalPlan) -> Result<LogicalPlan> {
        let columns = program
            .schema()
            .columns()
            .into_iter()
            .map(Expr::Column)
            .collect::<Vec<_>>();
        LogicalPlanBuilder::from(events)
            .project([lit(1i64).alias("__graph_has_input")])
            .and_then(|gate| gate.limit(0, Some(1)))
            .and_then(|gate| gate.cross_join(program))
            .and_then(|joined| joined.project(columns))
            .and_then(LogicalPlanBuilder::build)
            .map_err(|source| araphor_query::Error::Sql { source }.into())
    }
}
