use std::sync::Arc;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests};
use datafusion::common::ScalarValue;
use datafusion::logical_expr::LogicalPlan;

use super::Engine;
use crate::definition::PreparedDefinition;
use crate::follow::{Clock, Cursor, ManagedPublication, Subscription};
use crate::sources::SourceSnapshot;
use crate::{planner::Planner, Result};

impl Engine {
    pub async fn prepare(
        &self,
        sql: &str,
        parameters: Vec<ScalarValue>,
    ) -> Result<(LogicalPlan, AnalysisTableRequests)> {
        let state = self.catalog(SourceSnapshot::providers())?;
        let statement = self.limits.parser.parse(sql)?;
        let planner = Planner::new(&state);
        let (plan, origins) = planner.build_with_sources(statement, parameters).await?;
        let sources = origins
            .into_iter()
            .filter_map(|source| source.durable().map(|name| (name.to_owned(), None)))
            .collect();
        Ok((plan, sources))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe(
        self: &Arc<Self>,
        sql: &str,
        parameters: Vec<ScalarValue>,
        selection: AnalysisSelectionV1,
        control: Arc<AnalysisReadControl>,
        binding: &[u8],
        resume: Option<Cursor>,
        clock: Arc<dyn Clock>,
        follow: bool,
    ) -> Result<Subscription> {
        control.check()?;
        let (plan, sources) = self.prepare(sql, parameters).await?;
        Subscription::new(
            self.session(selection, &control, 0)?,
            Arc::new(plan),
            sources,
            binding,
            resume,
            clock,
            follow,
        )
    }
}

impl super::Session {
    pub async fn run_managed(
        mut self,
        definition: PreparedDefinition,
        publication: Arc<dyn ManagedPublication>,
        binding: &[u8],
    ) -> Result<crate::follow::Update> {
        let parent = Arc::clone(self.control());
        let operation = Arc::new(parent.operation()?);
        self.control = Arc::clone(&operation);
        let now = self.now;
        let result = {
            let execution = Subscription::managed_once(self, definition, publication, binding, now);
            tokio::pin!(execution);
            tokio::select! {
                result = &mut execution => result,
                stopped = parent.query_async(std::future::pending::<Result<crate::follow::Update>>()) => {
                    let _cancelled = operation.cancel();
                    let _joined = execution.await;
                    stopped
                }
            }
        };
        parent.check()?;
        result
    }

    pub fn subscribe_managed(
        self,
        definition: PreparedDefinition,
        publication: Arc<dyn ManagedPublication>,
        binding: &[u8],
        resume: Option<araphor_data::ManagedFrontier>,
    ) -> Result<Subscription> {
        Subscription::managed(
            self,
            definition,
            publication,
            binding,
            resume,
            Arc::new(crate::follow::SystemClock::default()),
        )
    }

    pub fn subscribe(
        self,
        plan: LogicalPlan,
        sources: AnalysisTableRequests,
        binding: &[u8],
        follow: bool,
    ) -> Result<Subscription> {
        Subscription::new(
            self,
            Arc::new(plan),
            sources,
            binding,
            None,
            Arc::new(crate::follow::SystemClock::default()),
            follow,
        )
    }
}
