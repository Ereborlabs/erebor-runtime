use std::sync::Arc;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests};
use datafusion::common::ScalarValue;
use datafusion::logical_expr::LogicalPlan;

use super::Engine;
use crate::follow::{Clock, Cursor, Subscription};
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
        let sources = planner
            .sources(&statement)
            .await?
            .into_iter()
            .filter_map(|source| source.durable().map(|name| (name.to_owned(), None)))
            .collect();
        let plan = planner.build(statement, parameters).await?;
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
            Arc::clone(self),
            Arc::new(plan),
            sources,
            selection,
            control,
            binding,
            resume,
            clock,
            follow,
        )
    }
}
