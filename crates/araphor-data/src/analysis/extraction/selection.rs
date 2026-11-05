use super::*;

impl AnalysisSelectionV1 {
    fn source_demand(requests: &AnalysisTableRequests) -> bool {
        requests.keys().any(|name| {
            matches!(
                name.as_str(),
                "events"
                    | "coverage"
                    | "graph_coverage"
                    | "discovery_state"
                    | "graph_state"
                    | "notifications"
                    | "behaviors"
                    | "findings"
                    | "relationships"
                    | "graph_subjects"
                    | "graph_branches"
                    | "correlation_packages"
                    | "policy_observations"
                    | "graph_manifest"
            )
        })
    }

    fn trace_demand(requests: &AnalysisTableRequests) -> bool {
        ["traces", "trace_output", "trace_measurements"]
            .iter()
            .any(|name| requests.contains_key(*name))
    }

    pub fn metadata_bytes(&self, requests: &AnalysisTableRequests) -> usize {
        let mut bytes = size_of::<Self>()
            .saturating_add(self.nodes.capacity().saturating_mul(size_of::<String>()))
            .saturating_add(
                self.binding_ids
                    .capacity()
                    .saturating_mul(size_of::<[u8; 16]>()),
            );
        for node in &self.nodes {
            bytes = bytes.saturating_add(node.capacity());
        }
        if Self::source_demand(requests) {
            bytes = bytes.saturating_add(
                self.sources
                    .capacity()
                    .saturating_mul(size_of::<EvidenceIntakeIdentityV1>()),
            );
            for source in self.sources.as_slice() {
                bytes = bytes.saturating_add(source.node_id.capacity());
            }
        }
        if Self::trace_demand(requests) {
            bytes = bytes.saturating_add(
                self.traces
                    .capacity()
                    .saturating_mul(size_of::<TraceIdentityV1>()),
            );
            for trace in self.traces.as_slice() {
                bytes = bytes.saturating_add(trace.node_id.capacity());
            }
        }
        bytes
    }

    pub fn metadata_projection(&self, requests: &AnalysisTableRequests) -> Self {
        let mut selection = Self::new(self.tenant_id, Vec::new());
        if Self::source_demand(requests) {
            selection.sources = self.sources.clone();
        }
        if Self::trace_demand(requests) {
            selection.traces = self.traces.clone();
        }
        selection.nodes = self.nodes.clone();
        selection.binding_ids = self.binding_ids.clone();
        selection.received_from = self.received_from;
        selection.received_until = self.received_until;
        selection.cursor_from = self.cursor_from;
        selection.cursor_until = self.cursor_until;
        selection
    }

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
        if !Self::source_demand(requests) {
            selection.sources = Selection::Exact(Vec::new());
        }
        if !Self::trace_demand(requests) {
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
