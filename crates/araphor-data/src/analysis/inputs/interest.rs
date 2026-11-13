use super::*;
use crate::TraceIdentityV1;

impl InputInterest {
    pub(in crate::analysis) fn covers_read(
        &self,
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        owners: Option<&BTreeSet<String>>,
        ranges: Option<&[(u64, u64)]>,
    ) -> Result<bool> {
        Ok(*selection == self.original.project(requests)?
            && self.requests == *requests
            && (owners.is_none()
                || self
                    .owners
                    .as_ref()
                    .zip(owners)
                    .is_some_and(|(watched, captured)| watched.is_subset(captured)))
            && owners.is_none_or(|owners| {
                [
                    ("targets", "mithril-control/target"),
                    ("compiled_policies", "mithril-control/compiled-policy"),
                    ("notification_routes", crate::NOTIFICATION_ROUTE_OWNER),
                ]
                .iter()
                .all(|(table, owner)| !requests.contains_key(*table) || owners.contains(*owner))
            })
            && ranges.is_none_or(|ranges| ranges == [(0, u64::MAX)]))
    }

    pub(in crate::analysis) fn raw_position(
        &self,
        entry: &crate::analysis::raw::RawEntry,
        span: &crate::analysis::raw::RawRange,
    ) -> Option<StorePositionV1> {
        self.raw_span(&entry.identity, &entry.commit, span)
    }

    pub(in crate::analysis) fn raw_span(
        &self,
        identity: &AnalysisStreamIdentityV1,
        meta: &crate::analysis::raw::RawMeta,
        span: &crate::analysis::raw::RawRange,
    ) -> Option<StorePositionV1> {
        if !self.matches(&InputChange::Raw {
            identity,
            range: Some((span.first, span.last, meta.intake)),
        }) {
            return None;
        }
        let last = match identity {
            AnalysisStreamIdentityV1::Evidence(_)
                if !self.has(&["coverage", "discovery_state", "graph_state"]) =>
            {
                span.last.min(self.selection.cursor_range()?.1)
            }
            _ => span.last,
        };
        Some(StorePositionV1 {
            commit_revision: meta.revision,
            ordinal: span.ordinal + (last - span.first) as u32,
        })
    }

    pub(in crate::analysis) fn new(
        selection: AnalysisSelectionV1,
        requests: AnalysisTableRequests,
        owners: Option<BTreeSet<String>>,
    ) -> Result<Self> {
        let original = selection;
        let mut domains = requests.clone();
        if requests.contains_key("notifications") || requests.contains_key("graph_coverage") {
            domains.entry("findings".into()).or_insert(None);
        }
        let selection = original.project(&domains)?;
        Ok(Self {
            original,
            selection,
            requests,
            owners,
        })
    }

    pub(in crate::analysis) fn allocation_bytes(
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        owners: Option<&BTreeSet<String>>,
    ) -> usize {
        requests
            .iter()
            .fold(selection.allocation_bytes(), |bytes, (name, columns)| {
                bytes.saturating_add(name.capacity()).saturating_add(
                    columns
                        .as_ref()
                        .map_or(0, |columns| columns.len() * size_of::<usize>()),
                )
            })
            .saturating_add(owners.map_or(0, |owners| {
                owners.iter().fold(0usize, |bytes, owner| {
                    bytes.saturating_add(owner.capacity())
                })
            }))
            .saturating_mul(4)
            .saturating_add(8 * size_of::<InputWatch>())
    }

    pub(super) fn has(&self, names: &[&str]) -> bool {
        names.iter().any(|name| self.requests.contains_key(*name))
    }

    pub(super) fn graph_notices(&self) -> bool {
        match self.requests.get("graph_manifest") {
            Some(None) => true,
            Some(Some(columns)) => columns.iter().any(|index| {
                matches!(
                    crate::AnalysisStore::table_schemas()["graph_manifest"]
                        .field(*index)
                        .name()
                        .as_str(),
                    "notice_context_revision" | "notice_coverage_revision"
                )
            }),
            None => false,
        }
    }

    fn source(&self, source: &EvidenceIntakeIdentityV1) -> bool {
        self.selection.includes_source(source)
    }

    fn trace(&self, identity: &TraceIdentityV1) -> bool {
        identity.tenant_id == self.selection.tenant_id
            && (self.selection.nodes.is_empty() || self.selection.nodes.contains(&identity.node_id))
            && (self.selection.traces.is_all()
                || self.selection.traces.as_slice().contains(identity))
    }

    fn context(&self, key: &AnalysisContextKeyV1) -> bool {
        let selected =
            self.selection.contexts.is_all() || self.selection.contexts.as_slice().contains(key);
        let direct = self.has(&["context", "context_versions"])
            && selected
            && (!self.selection.targets_only || key.owner_id == "mithril-control/target")
            && self
                .owners
                .as_ref()
                .is_none_or(|owners| owners.contains(&key.owner_id));
        direct
            || match key.owner_id.as_str() {
                crate::NOTIFICATION_ROUTE_OWNER => self.has(&["notification_routes"]) && selected,
                crate::NOTIFICATION_STATE_OWNER => {
                    self.has(&["notifications"])
                        && (self.selection.obligations.is_all()
                            || self.selection.obligations.as_slice().contains(key))
                }
                "mithril-control/compiled-policy" => self.has(&["compiled_policies"]) && selected,
                "mithril-control/target" => self.has(&["targets"]) && selected,
                _ => false,
            }
    }

    pub(super) fn matches(&self, change: &InputChange<'_>) -> bool {
        match change {
            InputChange::Raw {
                identity: AnalysisStreamIdentityV1::Evidence(source),
                range,
            } => {
                if !self.source(source) {
                    return false;
                }
                if self.has(&["coverage", "discovery_state", "graph_state"]) {
                    return true;
                }
                self.has(&["events"])
                    && range.is_some_and(|(first, last, intake)| {
                        self.selection
                            .time_range()
                            .is_some_and(|(lower, upper)| (lower..=upper).contains(&intake))
                            && self
                                .selection
                                .cursor_range()
                                .is_some_and(|(lower, upper)| first <= upper && lower <= last)
                    })
            }
            InputChange::Raw {
                identity: AnalysisStreamIdentityV1::Diagnostic(identity),
                range,
            } => {
                (self.has(&["traces"])
                    || range.is_some() && self.has(&["trace_output", "trace_measurements"]))
                    && self.trace(identity)
            }
            InputChange::Removal { identity, range } => match identity {
                AnalysisStreamIdentityV1::Evidence(source) => {
                    self.source(source)
                        && (self.has(&["coverage", "discovery_state", "graph_state"])
                            || self.has(&["events"])
                                && range.is_none_or(|(first, last, intake)| {
                                    intake.is_none_or(|intake| {
                                        self.selection.time_range().is_some_and(|(lower, upper)| {
                                            (lower..=upper).contains(&intake)
                                        })
                                    }) && self.selection.cursor_range().is_some_and(
                                        |(lower, upper)| first <= upper && lower <= last,
                                    )
                                }))
                }
                AnalysisStreamIdentityV1::Diagnostic(identity) => {
                    self.has(&["traces", "trace_output", "trace_measurements"])
                        && self.trace(identity)
                }
            },
            InputChange::Context(key) => self.context(key),
            InputChange::Processor(scope) => {
                self.source(&scope.identity)
                    && match scope.processor_id.as_str() {
                        crate::GRAPH_PROCESSOR => {
                            self.has(&["graph_state"])
                                && scope.method_version == u64::from(crate::GRAPH_SCHEMA_VERSION)
                        }
                        "discovery" => {
                            self.has(&["discovery_state"])
                                && scope.method_version
                                    == u64::from(crate::DISCOVERY_SCHEMA_VERSION)
                        }
                        _ => false,
                    }
            }
            InputChange::Profile { scope, result } => {
                self.source(&scope.identity)
                    && (self.has(&["discovery_state"])
                        || self.has(&["behaviors"])
                            && (self.selection.profiles.is_all()
                                || self
                                    .selection
                                    .profiles
                                    .as_slice()
                                    .iter()
                                    .any(|id| id == result)))
            }
            InputChange::Notice { scope, result } => {
                if scope.processor_id == crate::GRAPH_PROCESSOR {
                    self.graph_notices()
                        && self.matches(&InputChange::Graph {
                            tenant: scope.identity.tenant_id,
                            result,
                            source: Some(&scope.identity),
                            witnesses: &[],
                        })
                } else if scope.processor_id == crate::DISCOVERY_PROCESSOR {
                    self.matches(&InputChange::Profile { scope, result })
                } else {
                    false
                }
            }
            InputChange::Graph {
                result,
                source,
                witnesses,
                ..
            } => {
                let graph = self.has(&[
                    "findings",
                    "relationships",
                    "graph_subjects",
                    "graph_branches",
                    "correlation_packages",
                    "policy_observations",
                    "graph_manifest",
                    "graph_coverage",
                ]) && self
                    .selection
                    .graph_traversal
                    .as_ref()
                    .is_none_or(|request| {
                        request.result_ids.is_empty()
                            || request.result_ids.iter().any(|id| id == result)
                    })
                    && (self.selection.graphs.is_all()
                        || self
                            .selection
                            .graphs
                            .as_slice()
                            .iter()
                            .any(|id| id == result));
                let notification = self.has(&["notifications"]);
                if !graph && !notification {
                    return false;
                }
                source.map_or_else(
                    || {
                        witnesses.is_empty()
                            || witnesses.iter().any(|witness| match &witness.identity {
                                AnalysisStreamIdentityV1::Evidence(source) => {
                                    self.original.includes_source(source)
                                }
                                AnalysisStreamIdentityV1::Diagnostic(identity) => {
                                    (self.original.nodes.is_empty()
                                        || self.original.nodes.contains(&identity.node_id))
                                        && (self.original.traces.is_all()
                                            || self.original.traces.as_slice().contains(identity))
                                }
                            })
                    },
                    |source| self.original.includes_source(source),
                )
            }
            InputChange::Trace {
                request, bindings, ..
            } => {
                self.has(&["traces"])
                    && (self.selection.traces.is_all() && self.selection.nodes.is_empty()
                        || bindings.iter().any(|binding| {
                            binding.identity.request_id == *request && self.trace(&binding.identity)
                        }))
            }
        }
    }
}
