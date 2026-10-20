use std::sync::Arc;

use araphor_data::{AnalysisReadControl, ManagedFrontier, ManagedRead};
use datafusion::catalog::TableProvider;
use datafusion::datasource::provider_as_source;
use datafusion::logical_expr::{dml::InsertOp, LogicalPlanBuilder};
use snafu::ResultExt as _;

use super::{Clock, Subscription};
use crate::definition::{Invocation, PreparedDefinition};
use crate::execution::Session;
use crate::sources::ArrowSnapshot;
use crate::{Result, SqlSnafu};

/// Read metadata at begin. Register the captured attempt before native execution.
pub trait ManagedPublication: TableProvider {
    fn begin(&self, control: &AnalysisReadControl) -> Result<(Invocation, ManagedRead)>;

    fn admit(
        &self,
        snapshot: &ArrowSnapshot,
        invocation: &Invocation,
        frontier: &ManagedFrontier,
        control: &AnalysisReadControl,
    ) -> Result<()>;
}

impl Subscription {
    pub fn managed(
        session: Session,
        definition: PreparedDefinition,
        publication: Arc<dyn ManagedPublication>,
        binding: &[u8],
        resume: Option<ManagedFrontier>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let target: Arc<dyn TableProvider> = publication.clone();
        let plan = LogicalPlanBuilder::insert_into(
            definition.plan.clone(),
            "__araphor_managed_output",
            provider_as_source(target),
            InsertOp::Append,
        )
        .and_then(LogicalPlanBuilder::build)
        .context(SqlSnafu)?;
        let next_change = resume.as_ref().and_then(|frontier| frontier.next_change);
        let cursor = resume
            .map(|frontier| super::Cursor::decode(&frontier.cursor))
            .transpose()?;
        Self::open(
            session,
            Arc::new(plan),
            definition.sources.clone(),
            binding,
            cursor,
            clock,
            true,
            Some((definition, publication)),
            next_change,
        )
    }
}
