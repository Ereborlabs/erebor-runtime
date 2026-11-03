use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, EvidenceIntakeIdentityV1, ManagedDestination, ManagedGraphOperation,
    PackageAuthorization, PackageErrorCodeV1 as Code, PackageGrantV1,
};
use araphor_discovery_definition::{Definition, Program, ResolvedDefinition, Source};
use araphor_query::definition::{PackageCall, PreparedDefinition};
use araphor_query::execution::{Engine, Session};

use super::{DefinitionRef, GraphFacts, GraphPublication};
use crate::{Instance, Result};

impl GraphPublication {
    pub fn expiry_program() -> Definition {
        Definition { name: "graph-expiry".into(), description: String::new(), labels: Default::default(),
            program: Program::Sql { source: Source::Inline { inline: "WITH heads AS (
                SELECT tenant_id, source_key, graph_result_id, commit_revision, metadata, context_refs,
                    first_cursor, witness_deadline_utc_ns, retained_input_expired FROM graph_manifest
                QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key, first_cursor ORDER BY commit_revision DESC) = 1
            ) SELECT h.graph_result_id, h.commit_revision, h.metadata, h.context_refs, s.*
            FROM heads h JOIN graph_state s USING (tenant_id, source_key)
            WHERE NOT h.retained_input_expired AND (h.first_cursor <= s.retained_floor
                OR h.witness_deadline_utc_ns <= s.capture_time_utc_ns)
            ORDER BY h.tenant_id, h.source_key, h.first_cursor".into() } } }
    }

    pub(crate) fn uses_facts(&self, facts: &Arc<dyn GraphFacts>) -> bool {
        Arc::ptr_eq(&self.projection.facts, facts)
    }

    pub(crate) fn facts(&self) -> Arc<dyn GraphFacts> {
        Arc::clone(&self.projection.facts)
    }

    pub async fn admit_expiry(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        id: String,
        source: EvidenceIntakeIdentityV1,
        revision: u64,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        let destination = ManagedDestination::Graph {
            source,
            events_sql: String::new(),
            control_sql: String::new(),
            calls: BTreeSet::new(),
            operation: ManagedGraphOperation::Expire,
        };
        let session = query.session_on(
            destination.selection(&grant.selection)?,
            control,
            0,
            query.memory().scope(),
        )?;
        let definition = Self::expiry_program();
        let sql = definition
            .program
            .sql()
            .map_err(araphor_data::Error::from)?;
        let resolved = ResolvedDefinition::new(definition, sql, Vec::new())
            .map_err(araphor_data::Error::from)?;
        let prepared = session
            .prepare_resolved(&resolved, Some(revision), None)
            .await?;
        Instance::admit_prepared(session, authority, grant, id, prepared, destination).await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "A Graph instance binds one source, SQL selection, package pins, and authority."
    )]
    pub async fn admit(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        facts: Arc<dyn GraphFacts>,
        grant: PackageGrantV1,
        id: String,
        source: EvidenceIntakeIdentityV1,
        events_sql: String,
        control_sql: String,
        (definition, revision): (ResolvedDefinition, Option<u64>),
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        let destination = ManagedDestination::Graph {
            source,
            events_sql,
            control_sql,
            calls: BTreeSet::new(),
            operation: ManagedGraphOperation::Evaluate,
        };
        let (session, prepared, destination, owner) = Self::prepare_managed(
            query,
            Arc::clone(&authority),
            Some(facts),
            &grant,
            (definition, revision),
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
        (definition, revision): (ResolvedDefinition, Option<u64>),
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
            control_sql,
            operation,
            ..
        } = &destination
        else {
            return Err(Code::Invalid.error("Graph preparation destination").into());
        };
        definition.validate().map_err(araphor_data::Error::from)?;
        let session = query.session_on(
            destination.selection(&grant.selection)?,
            control,
            0,
            query.memory().scope(),
        )?;
        if *operation == ManagedGraphOperation::Expire {
            if definition.definition != Self::expiry_program()
                || !events_sql.is_empty()
                || !control_sql.is_empty()
                || !matches!(&destination, ManagedDestination::Graph { calls, .. } if calls.is_empty())
            {
                return Err(Code::Invalid.error("graph expiry definition").into());
            }
            let prepared = session
                .prepare_resolved(&definition, revision, None)
                .await?;
            if prepared.resolved() != &definition {
                return Err(Code::Conflict.error("graph expiry definition pin").into());
            }
            return Ok((session, prepared, destination, None));
        }
        let facts = facts.ok_or_else(|| Code::Incomplete.error("Graph facts owner"))?;
        let owner = Self::prepare_program(
            session,
            authority,
            grant.clone(),
            events_sql,
            control_sql,
            DefinitionRef::Retained(&definition, revision),
            facts,
        )
        .await?;
        if owner.prepared.resolved() != &definition {
            return Err(Code::Conflict.error("graph definition pin").into());
        }
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

    pub(super) async fn prepare_program(
        mut session: Session,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        events_sql: &str,
        control_sql: &str,
        definition: DefinitionRef<'_>,
        facts: Arc<dyn GraphFacts>,
    ) -> Result<Self> {
        let source_control = Self::prepare_control(&mut session, control_sql).await?;
        let selected = session
            .prepare_definition(
                &Definition {
                    name: "graph-events".into(),
                    description: String::new(),
                    labels: Default::default(),
                    program: Program::Sql {
                        source: Source::Inline {
                            inline: events_sql.to_owned(),
                        },
                    },
                },
                None,
            )
            .await?;
        let mut nested = false;
        PackageCall::any(selected.plan(), &mut |_, _| {
            nested = true;
            Ok(false)
        })
        .map_err(|source| araphor_query::Error::Sql { source })?;
        if nested {
            return Err(Code::Invalid.error("graph event SQL package call").into());
        }
        session.register_table(
            "__graph_current_events",
            Arc::new(datafusion::datasource::view::ViewTable::new(
                selected.into_plan(),
                None,
            )),
        )?;
        let selected = session.prepare_definition(&Definition { name: "graph-continuation".into(), description: String::new(), labels: Default::default(), program: Program::Sql { source: Source::Inline { inline: "WITH heads AS (
            SELECT tenant_id, source_key, first_cursor, last_cursor, retained_input_expired, witness_deadline_utc_ns
            FROM graph_manifest QUALIFY ROW_NUMBER() OVER (PARTITION BY tenant_id, source_key, first_cursor ORDER BY commit_revision DESC) = 1
        ), expired AS (
            SELECT DISTINCT s.tenant_id, s.node_id, s.node_boot_id, s.label_epoch, s.source_id, s.source_epoch, s.consumed_cursor
            FROM graph_state s JOIN heads h ON s.tenant_id = h.tenant_id AND s.source_key = h.source_key
            JOIN __graph_current_events e ON s.tenant_id = e.tenant_id AND s.node_id = e.node_id
                AND s.node_boot_id = e.node_boot_id AND s.label_epoch = e.label_epoch
                AND s.source_id = e.source_id AND s.source_epoch = e.source_epoch
            WHERE e.source_cursor BETWEEN h.first_cursor AND h.last_cursor
                AND (h.retained_input_expired OR h.first_cursor <= s.retained_floor OR h.witness_deadline_utc_ns <= s.capture_time_utc_ns)
        ) SELECT e.* FROM __graph_current_events e LEFT JOIN expired s ON e.tenant_id = s.tenant_id
            AND e.node_id = s.node_id AND e.node_boot_id = s.node_boot_id AND e.label_epoch = s.label_epoch
            AND e.source_id = s.source_id AND e.source_epoch = s.source_epoch
        WHERE s.consumed_cursor IS NULL OR e.source_cursor > s.consumed_cursor".into() } } }, None).await?;
        let gate = source_control.clone();
        Self::prepare_on(
            session,
            authority,
            grant,
            selected.into_plan(),
            source_control,
            definition,
            facts,
            Some(gate),
        )
        .await
    }
}
