use std::sync::Arc;

use araphor_data::{AnalysisReadControl, ManagedFrontier, ManagedRead};
use datafusion::catalog::TableProvider;
use datafusion::datasource::provider_as_source;
use datafusion::logical_expr::{dml::InsertOp, LogicalPlanBuilder};
use futures_util::StreamExt as _;
use snafu::ResultExt as _;

use super::{Clock, Subscription};
use crate::definition::{Invocation, PreparedDefinition};
use crate::execution::Session;
use crate::sources::ArrowSnapshot;
use crate::{Result, SqlSnafu};

/// Read metadata at begin. Register the captured attempt before native execution.
/// Completed publications acknowledge their commit through `ExecutionReceipt`.
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

struct FixedClock {
    now: u64,
    changes: tokio::sync::watch::Sender<u64>,
}

impl Clock for FixedClock {
    fn now_ns(&self) -> Result<u64> {
        Ok(self.now)
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

impl Subscription {
    pub(crate) async fn managed_once(
        session: Session,
        definition: PreparedDefinition,
        publication: Arc<dyn ManagedPublication>,
        binding: &[u8],
        now: u64,
    ) -> Result<super::Update> {
        let clock = Arc::new(FixedClock {
            now,
            changes: tokio::sync::watch::channel(0).0,
        });
        let mut subscription = Self::managed_with_mode(
            session,
            definition,
            publication,
            binding,
            None,
            clock,
            false,
        )?;
        let result = subscription.next().await.ok_or_else(|| {
            araphor_data::PackageErrorCodeV1::Incomplete.error("managed native result")
        });
        let joined = subscription.cancel_and_join().await;
        let update = result??;
        joined?;
        Ok(update)
    }

    pub fn managed(
        session: Session,
        definition: PreparedDefinition,
        publication: Arc<dyn ManagedPublication>,
        binding: &[u8],
        resume: Option<ManagedFrontier>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        Self::managed_with_mode(
            session,
            definition,
            publication,
            binding,
            resume,
            clock,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn managed_with_mode(
        session: Session,
        definition: PreparedDefinition,
        publication: Arc<dyn ManagedPublication>,
        binding: &[u8],
        resume: Option<ManagedFrontier>,
        clock: Arc<dyn Clock>,
        follow: bool,
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
            Default::default(),
            binding,
            cursor,
            clock,
            follow,
            Some((definition, publication)),
            next_change,
        )
    }
}
