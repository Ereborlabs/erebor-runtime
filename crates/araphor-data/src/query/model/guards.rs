use std::collections::BTreeSet;

use crate::{AnalysisSelectionV1, QueryOwner};

impl QueryOwner {
    pub(super) fn source_revisions(
        selection: &AnalysisSelectionV1,
        revision: u64,
    ) -> Vec<(String, u64)> {
        let mut relations = BTreeSet::new();
        if selection.sources.is_all() || !selection.sources.as_slice().is_empty() {
            relations.extend([
                "events",
                "source_receipts",
                "source_bindings",
                "coverage",
                "expired_ranges",
                "recovery_gaps",
                "replay_floors",
            ]);
        }
        if selection.contexts.is_all()
            || !selection.contexts.as_slice().is_empty()
            || selection.targets
            || selection.notifications
            || !selection.obligations.is_empty()
            || selection.discovery
            || selection.graph
            || !selection.graphs.is_empty()
        {
            relations.insert("context_versions");
        }
        if selection.discovery || !selection.profiles.is_empty() {
            relations.insert("analysis_results");
        }
        if selection.graph || !selection.graphs.is_empty() || selection.notifications {
            relations.extend(["graph_subjects", "graph_relationships", "graph_findings"]);
        }
        if selection.traces.is_all() || !selection.traces.as_slice().is_empty() {
            relations.extend([
                "traces",
                "trace_receipts",
                "trace_output",
                "expired_ranges",
                "recovery_gaps",
                "replay_floors",
            ]);
        }
        if !selection.nodes.is_empty() || !selection.binding_ids.is_empty() {
            relations.insert("source_bindings");
        }
        relations
            .into_iter()
            .map(|name| (name.into(), revision))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{AnalysisSelectionV1, QueryOwner, QueryPlan, QuerySql, Result};

    fn guards(sql: &str) -> Result<Vec<String>> {
        let plan = QueryPlan::model(
            AnalysisSelectionV1::tenant([1; 16]),
            QuerySql::admit(sql, Vec::new(), false)?,
        )?;
        Ok(QueryOwner::source_revisions(&plan.dependencies(1)?, 10)
            .into_iter()
            .map(|(name, revision)| {
                assert_eq!(revision, 10);
                name
            })
            .collect())
    }

    #[test]
    fn sql_model_relation_guards() -> Result<()> {
        assert!(guards("SELECT 1 AS count")?.is_empty());
        assert_eq!(
            guards("SELECT COUNT(*) AS count FROM context_versions")?,
            ["context_versions"]
        );
        let graph = guards("SELECT COUNT(*) AS count FROM findings")?;
        for name in [
            "graph_findings",
            "graph_subjects",
            "graph_relationships",
            "context_versions",
            "coverage",
        ] {
            assert!(graph.iter().any(|relation| relation == name));
        }
        assert!(!graph.iter().any(|name| name == "analysis_results"));
        assert!(guards("SELECT COUNT(*) AS count FROM behaviors")?
            .iter()
            .any(|name| name == "analysis_results"));
        let traces = guards("SELECT COUNT(*) AS count FROM trace_measurements")?;
        for name in [
            "traces",
            "trace_output",
            "trace_receipts",
            "expired_ranges",
            "recovery_gaps",
        ] {
            assert!(traces.iter().any(|relation| relation == name));
        }
        Ok(())
    }
}
