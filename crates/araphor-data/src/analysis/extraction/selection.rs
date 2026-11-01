use super::*;

impl AnalysisSelectionV1 {
    pub fn project(&self, requests: &AnalysisTableRequests) -> Result<Self> {
        let active = |name: &str| requests.contains_key(name);
        let graph = requests.keys().any(|name| {
            matches!(
                name.as_str(),
                "findings"
                    | "relationships"
                    | "graph_subjects"
                    | "graph_branches"
                    | "correlation_packages"
                    | "policy_observations"
                    | "graph_manifest"
            )
        });
        let discovery = active("behaviors");
        let targets = active("targets");
        let context = active("context")
            || active("context_versions")
            || active("notification_routes")
            || active("compiled_policies")
            || targets;
        let mut selection = self.clone();
        if !active("events")
            && !active("coverage")
            && !active("graph_coverage")
            && !active("discovery_state")
            && !active("graph_state")
            && !active("notifications")
            && !graph
            && !discovery
        {
            selection.sources = Selection::Exact(Vec::new());
        }
        if !active("traces") && !active("trace_output") && !active("trace_measurements") {
            selection.traces = Selection::Exact(Vec::new());
        }
        if !context {
            selection.contexts = Selection::Exact(Vec::new());
        }
        selection.select_targets(
            targets,
            targets
                && !active("events")
                && !active("context")
                && !active("context_versions")
                && !active("compiled_policies"),
        )?;
        let profiles = if selection.profiles().is_empty() {
            Selection::All
        } else {
            Selection::Exact(selection.profiles().to_vec())
        };
        selection.select_profiles(if discovery {
            profiles
        } else {
            Selection::Exact(Vec::new())
        })?;
        let traversal = selection.graph_traversal().cloned();
        selection.select_graphs(
            if graph {
                if selection.graphs().is_empty() {
                    Selection::All
                } else {
                    Selection::Exact(selection.graphs().to_vec())
                }
            } else {
                Selection::Exact(Vec::new())
            },
            if graph { traversal } else { None },
        )?;
        let notifications = if selection.notification_keys().is_empty() {
            Selection::All
        } else {
            Selection::Exact(selection.notification_keys().to_vec())
        };
        selection.select_notifications(if active("notifications") {
            notifications
        } else {
            Selection::Exact(Vec::new())
        })?;
        Ok(selection)
    }
}
