use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1};
use datafusion::common::ScalarValue;
use datafusion::logical_expr::LogicalPlan;
use snafu::ResultExt as _;

use super::Engine;
use crate::follow::{Clock, Cursor, Subscription};
use crate::{parser::Parser, planner::Planner, Result, SqlSnafu};

impl Engine {
    pub async fn prepare(
        &self,
        sql: &str,
        parameters: Vec<ScalarValue>,
    ) -> Result<(LogicalPlan, BTreeSet<String>)> {
        let state = self.catalog(Default::default())?;
        let statement = Parser::parse(sql)?;
        let sources = state
            .resolve_table_references(&statement)
            .context(SqlSnafu)?
            .into_iter()
            .map(|source| source.table().to_owned())
            .collect();
        let plan = Planner::new(&state).build(statement, parameters).await?;
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
