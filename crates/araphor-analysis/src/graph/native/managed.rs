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
    pub(crate) fn uses_facts(&self, facts: &Arc<dyn GraphFacts>) -> bool {
        Arc::ptr_eq(&self.projection.facts, facts)
    }

    pub(crate) fn facts(&self) -> Arc<dyn GraphFacts> {
        Arc::clone(&self.projection.facts)
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
        if *operation != ManagedGraphOperation::Evaluate {
            return Err(Code::Unsupported.error("Graph execution operation").into());
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
            *calls = owner.graph_calls.clone();
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
        let append_stable = events_sql == araphor_data::ResolvedInput::EVENTS_SQL
            || Self::append_selection(selected.plan())
                .map_err(|source| araphor_query::Error::Sql { source })?;
        session.register_table(
            "__graph_current_events",
            Arc::new(datafusion::datasource::view::ViewTable::new(
                selected.into_plan(),
                None,
            )),
        )?;
        let selected = Self::native_plan(&session,
            "SELECT events.* FROM __graph_current_events events CROSS JOIN graph_control control WHERE NOT control.expired",
        ).await?;
        Self::prepare_on(
            session,
            authority,
            grant,
            selected,
            source_control,
            definition,
            facts,
            append_stable,
        )
        .await
    }
}
