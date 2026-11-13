#[cfg(test)]
use snafu::ResultExt as _;

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::ops::Bound;

use araphor_analysis_sdk as sdk;
use araphor_analysis_sdk::RecordBatch;

use super::raw::{RawIdentity, TracePayload, TraceRecord};
use super::segments::InputRange;
use super::{
    AnalysisContextKeyV1, AnalysisGapV1, AnalysisReadControl, AnalysisSourceReceiptV1,
    AnalysisStoreMetaV1, StorePositionV1, MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{
    AnalysisInputTooLargeSnafu, EvidenceIntakeIdentityV1, EvidenceRecord, Result, TraceIdentityV1,
};

type IndexedNotificationGraph = (Vec<u8>, u64, u64, u64, Option<bool>, u64);

pub(in crate::analysis) mod append;
pub use append::AnalysisAppendRead;

pub(in crate::analysis) mod changes;

mod graph;

pub(in crate::analysis) mod raw;
mod selection;

pub(in crate::analysis) mod tables;

#[cfg(test)]
const MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;
#[cfg(test)]
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct AnalysisExtractLimits {
    pub scan_bytes: usize,
    pub input_bytes: usize,
    pub keys: Option<usize>,
    pub page_bytes: usize,
    pub page_rows: usize,
}

impl Default for AnalysisExtractLimits {
    fn default() -> Self {
        Self {
            scan_bytes: usize::MAX,
            input_bytes: usize::MAX,
            keys: None,
            page_bytes: usize::MAX,
            page_rows: MAX_ANALYSIS_PAGE_RECORDS,
        }
    }
}

impl AnalysisExtractLimits {
    pub(in crate::analysis) fn check_keys(&self, selection: &AnalysisSelectionV1) -> Result<()> {
        if self
            .keys
            .is_some_and(|keys| selection.key_count() > keys || selection.nodes.len() > keys)
        {
            return AnalysisInputTooLargeSnafu {
                resource: "selected input keys",
            }
            .fail();
        }
        Ok(())
    }

    fn key_rows(&self, selected: usize) -> Option<i64> {
        self.keys
            .and_then(|keys| i64::try_from(keys.saturating_sub(selected).saturating_add(1)).ok())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum Selection<T> {
    All,
    Exact(Vec<T>),
}

impl<T> Selection<T> {
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Exact(keys) if keys.is_empty())
    }

    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::All => &[],
            Self::Exact(keys) => keys,
        }
    }

    pub fn capacity(&self) -> usize {
        match self {
            Self::All => 0,
            Self::Exact(keys) => keys.capacity(),
        }
    }

    pub fn exact_mut(&mut self) -> Option<&mut Vec<T>> {
        match self {
            Self::All => None,
            Self::Exact(keys) => Some(keys),
        }
    }
}

/// Input selection after tenant authorization. An empty exact list selects no events.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSelectionV1 {
    pub tenant_id: [u8; 16],
    pub sources: Selection<EvidenceIntakeIdentityV1>,
    pub(crate) targets: bool,
    pub(crate) targets_only: bool,
    pub(crate) profiles: Selection<String>,
    pub(crate) graphs: Selection<String>,
    pub(crate) graph_traversal: Option<crate::GraphTraversalV1>,
    pub(crate) obligations: Selection<AnalysisContextKeyV1>,
    pub traces: Selection<TraceIdentityV1>,
    /// Node IDs narrow evidence, coverage, and targets, not context versions.
    pub nodes: Vec<String>,
    pub binding_ids: Vec<[u8; 16]>,
    pub received_from: Bound<u64>,
    pub received_until: Bound<u64>,
    pub cursor_from: Bound<u64>,
    pub cursor_until: Bound<u64>,
    pub contexts: Selection<AnalysisContextKeyV1>,
    pub results: Vec<String>,
}

impl AnalysisSelectionV1 {
    pub fn includes_source(&self, source: &EvidenceIntakeIdentityV1) -> bool {
        source.tenant_id == self.tenant_id
            && (self.nodes.is_empty() || self.nodes.contains(&source.node_id))
            && (self.sources.is_all() || self.sources.as_slice().contains(source))
    }

    pub fn new(tenant_id: [u8; 16], sources: Vec<EvidenceIntakeIdentityV1>) -> Self {
        Self {
            tenant_id,
            sources: Selection::Exact(sources),
            targets: false,
            targets_only: false,
            profiles: Selection::Exact(Vec::new()),
            graphs: Selection::Exact(Vec::new()),
            graph_traversal: None,
            obligations: Selection::Exact(Vec::new()),
            traces: Selection::Exact(Vec::new()),
            nodes: Vec::new(),
            binding_ids: Vec::new(),
            received_from: Bound::Unbounded,
            received_until: Bound::Unbounded,
            cursor_from: Bound::Unbounded,
            cursor_until: Bound::Unbounded,
            contexts: Selection::Exact(Vec::new()),
            results: Vec::new(),
        }
    }

    pub fn tenant(tenant_id: [u8; 16]) -> Self {
        Self {
            sources: Selection::All,
            contexts: Selection::All,
            traces: Selection::All,
            ..Self::new(tenant_id, Vec::new())
        }
    }

    pub fn select_targets(&mut self, enabled: bool, only: bool) -> Result<()> {
        if only && !enabled {
            return Err(crate::PackageErrorCodeV1::Invalid.error("target selection"));
        }
        self.targets = enabled;
        self.targets_only = only;
        Ok(())
    }

    pub fn targets(&self) -> bool {
        self.targets
    }

    pub fn select_profiles(&mut self, profiles: Selection<String>) -> Result<()> {
        let mut selected = self.clone();
        selected.profiles = profiles;
        self.replace_selection(selected)
    }

    pub fn select_graphs(
        &mut self,
        graphs: Selection<String>,
        traversal: Option<crate::GraphTraversalV1>,
    ) -> Result<()> {
        let mut selected = self.clone();
        selected.graphs = graphs;
        selected.graph_traversal = traversal;
        self.replace_selection(selected)
    }

    pub fn graphs(&self) -> &[String] {
        self.graphs.as_slice()
    }

    pub fn profiles(&self) -> &[String] {
        self.profiles.as_slice()
    }

    pub fn notification_keys(&self) -> &[AnalysisContextKeyV1] {
        self.obligations.as_slice()
    }

    pub fn graph_traversal(&self) -> Option<&crate::GraphTraversalV1> {
        self.graph_traversal.as_ref()
    }

    pub fn select_notifications(
        &mut self,
        obligations: Selection<AnalysisContextKeyV1>,
    ) -> Result<()> {
        let mut selected = self.clone();
        selected.obligations = obligations;
        self.replace_selection(selected)
    }

    fn replace_selection(&mut self, selected: Self) -> Result<()> {
        if !selected.valid() {
            return Err(crate::PackageErrorCodeV1::Invalid.error("source selection"));
        }
        *self = selected;
        Ok(())
    }

    pub fn source_revisions(&self, revision: u64) -> Vec<(String, u64)> {
        let mut relations = BTreeSet::new();
        if !self.sources.is_empty() {
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
        if !self.contexts.is_empty()
            || self.targets
            || !self.obligations.is_empty()
            || !self.profiles.is_empty()
            || !self.graphs.is_empty()
        {
            relations.insert("context_versions");
        }
        if !self.profiles.is_empty() {
            relations.insert("analysis_results");
        }
        if !self.graphs.is_empty() || !self.obligations.is_empty() {
            relations.extend(["graph_subjects", "graph_relationships", "graph_findings"]);
        }
        if !self.traces.is_empty() {
            relations.extend([
                "traces",
                "trace_receipts",
                "trace_output",
                "expired_ranges",
                "recovery_gaps",
                "replay_floors",
            ]);
        }
        if !self.nodes.is_empty() || !self.binding_ids.is_empty() {
            relations.insert("source_bindings");
        }
        relations
            .into_iter()
            .map(|name| (name.into(), revision))
            .collect()
    }

    pub fn valid(&self) -> bool {
        self.tenant_id != [0; 16]
            && self.graph_traversal.as_ref().is_none_or(|request| {
                request.validate().is_ok()
                    && request
                        .seeds
                        .iter()
                        .all(|seed| seed.tenant_id == self.tenant_id)
            })
            && (!self.targets_only || self.targets)
            && self.nodes.iter().all(|node| crate::node_id_is_valid(node))
            && self.nodes.iter().collect::<BTreeSet<_>>().len() == self.nodes.len()
            && self.binding_ids.iter().all(|id| *id != [0; 16])
            && self.binding_ids.iter().collect::<BTreeSet<_>>().len() == self.binding_ids.len()
            && self
                .sources
                .as_slice()
                .iter()
                .all(|source| source.tenant_id == self.tenant_id && source.valid())
            && self
                .contexts
                .as_slice()
                .iter()
                .all(|key| key.tenant_id == self.tenant_id && key.valid())
            && self.results.iter().all(|id| !id.is_empty())
            && self.profiles.as_slice().iter().all(|id| !id.is_empty())
            && self.graphs.as_slice().iter().all(|id| !id.is_empty())
            && self.obligations.as_slice().iter().all(|key| {
                key.tenant_id == self.tenant_id
                    && key.owner_id == crate::NOTIFICATION_STATE_OWNER
                    && key.valid()
            })
            && self
                .sources
                .as_slice()
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == self.sources.as_slice().len()
            && self
                .contexts
                .as_slice()
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == self.contexts.as_slice().len()
            && self.results.iter().collect::<BTreeSet<_>>().len() == self.results.len()
            && self
                .profiles
                .as_slice()
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == self.profiles.as_slice().len()
            && self.graphs.as_slice().iter().collect::<BTreeSet<_>>().len()
                == self.graphs.as_slice().len()
            && self
                .obligations
                .as_slice()
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == self.obligations.as_slice().len()
            && self
                .traces
                .as_slice()
                .iter()
                .all(|identity| identity.tenant_id == self.tenant_id && identity.validate().is_ok())
            && self.traces.as_slice().iter().collect::<BTreeSet<_>>().len()
                == self.traces.as_slice().len()
    }

    pub(in crate::analysis) fn key_count(&self) -> usize {
        self.sources.as_slice().len()
            + self.contexts.as_slice().len()
            + self.results.len()
            + self.profiles.as_slice().len()
            + self.graphs.as_slice().len()
            + self.obligations.as_slice().len()
            + self.traces.as_slice().len()
            + self.binding_ids.len()
    }

    pub fn permits_graph(&self, graph: &crate::GraphSnapshotV1) -> bool {
        self.binding_ids.is_empty()
            || graph.input_manifest.evidence.iter().all(|record| {
                graph.findings.iter().any(|finding| {
                    finding.effects.iter().any(|effect| {
                        &effect.evidence == record
                            && effect
                                .binding_id
                                .is_some_and(|binding| self.binding_ids.contains(&binding))
                    })
                })
            })
    }

    pub fn allocation_bytes(&self) -> usize {
        let mut bytes = size_of::<Self>()
            .saturating_add(
                self.sources
                    .capacity()
                    .saturating_mul(size_of::<EvidenceIntakeIdentityV1>()),
            )
            .saturating_add(
                self.contexts
                    .capacity()
                    .saturating_mul(size_of::<AnalysisContextKeyV1>()),
            )
            .saturating_add(self.nodes.capacity().saturating_mul(size_of::<String>()))
            .saturating_add(self.results.capacity().saturating_mul(size_of::<String>()));
        bytes = bytes.saturating_add(self.profiles.capacity().saturating_mul(size_of::<String>()));
        bytes = bytes.saturating_add(self.graphs.capacity().saturating_mul(size_of::<String>()));
        if let Some(request) = &self.graph_traversal {
            bytes = bytes.saturating_add(request.heap_bytes());
        }
        bytes = bytes.saturating_add(
            self.obligations
                .capacity()
                .saturating_mul(size_of::<AnalysisContextKeyV1>()),
        );
        bytes = bytes.saturating_add(
            self.traces
                .capacity()
                .saturating_mul(size_of::<TraceIdentityV1>()),
        );
        bytes = bytes.saturating_add(
            self.binding_ids
                .capacity()
                .saturating_mul(size_of::<[u8; 16]>()),
        );
        for source in self.sources.as_slice() {
            bytes = bytes.saturating_add(source.node_id.capacity());
        }
        for key in self
            .contexts
            .as_slice()
            .iter()
            .chain(self.obligations.as_slice())
        {
            bytes = bytes
                .saturating_add(key.owner_id.capacity())
                .saturating_add(key.entity_key.capacity())
                .saturating_add(key.lifetime_key.capacity());
        }
        for key in self
            .nodes
            .iter()
            .chain(&self.results)
            .chain(self.profiles.as_slice())
            .chain(self.graphs.as_slice())
        {
            bytes = bytes.saturating_add(key.capacity());
        }
        for identity in self.traces.as_slice() {
            bytes = bytes.saturating_add(identity.node_id.capacity());
        }
        bytes
    }

    pub fn time_range(&self) -> Option<(u64, u64)> {
        Self::bounds(self.received_from, self.received_until)
    }

    pub fn cursor_range(&self) -> Option<(u64, u64)> {
        Self::bounds(self.cursor_from, self.cursor_until)
    }

    fn bounds(from: Bound<u64>, until: Bound<u64>) -> Option<(u64, u64)> {
        let first = match from {
            Bound::Unbounded => 0,
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_add(1)?,
        };
        let last = match until {
            Bound::Unbounded => u64::MAX,
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_sub(1)?,
        };
        (first <= last).then_some((first, last))
    }
}

pub type AnalysisTableRequests = BTreeMap<String, Option<BTreeSet<usize>>>;

#[derive(Clone, Copy)]
pub struct AnalysisTableRead<'a> {
    pub requests: &'a AnalysisTableRequests,
    pub event_ranges: Option<&'a [(u64, u64)]>,
    pub mode: AnalysisReadModeV1,
    pub now: u64,
}

impl AnalysisTableRead<'_> {
    pub(in crate::analysis) fn check_inputs(
        &self,
        selection: &AnalysisSelectionV1,
        limits: AnalysisExtractLimits,
        root: &std::path::Path,
    ) -> Result<()> {
        if matches!(self.mode, AnalysisReadModeV1::Changes(after) if after.ordinal != u32::MAX) {
            return crate::Error::reject_path(
                root,
                "the raw change frontier is not a complete commit",
            );
        }
        for (name, columns) in self.requests {
            let Some(columns) = columns else {
                continue;
            };
            let Some(schema) = crate::AnalysisStore::table_schemas().get(name) else {
                return crate::Error::reject_path(root, "the selected table has no Arrow schema");
            };
            if columns.iter().any(|index| *index >= schema.fields().len()) {
                return crate::Error::reject_path(root, "the selected table columns are invalid");
            }
        }
        if self
            .event_ranges
            .is_some_and(|ranges| ranges.iter().any(|(first, last)| first > last))
        {
            return crate::Error::reject_path(root, "the event input range is invalid");
        }
        if !selection.valid() {
            return crate::Error::reject_path(
                root,
                "the extraction selection has invalid, duplicate, or foreign keys",
            );
        }
        if (self.requests.contains_key("discovery_state")
            || self.requests.contains_key("graph_state"))
            && !selection.binding_ids.is_empty()
        {
            return Err(crate::PackageErrorCodeV1::Denied.error("complete processor source scope"));
        }
        if limits.scan_bytes == 0
            || limits.input_bytes == 0
            || limits.page_bytes == 0
            || limits.page_rows == 0
        {
            return crate::Error::reject_path(root, "the extraction limits must be positive");
        }
        Ok(())
    }

    pub(in crate::analysis) fn check_scope(
        &self,
        selected: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
    ) -> Result<()> {
        let mut expected = scope.project(self.requests)?;
        let contains = |outer: Option<(u64, u64)>, inner: Option<(u64, u64)>| {
            inner.is_none()
                || outer
                    .zip(inner)
                    .is_some_and(|((first, last), (start, end))| first <= start && end <= last)
        };
        if !contains(expected.time_range(), selected.time_range())
            || !contains(expected.cursor_range(), selected.cursor_range())
        {
            return Err(crate::PackageErrorCodeV1::Denied.error("managed source bounds"));
        }
        expected.received_from = selected.received_from;
        expected.received_until = selected.received_until;
        expected.cursor_from = selected.cursor_from;
        expected.cursor_until = selected.cursor_until;
        if expected != *selected {
            return Err(crate::PackageErrorCodeV1::Denied.error("managed source selection"));
        }
        Ok(())
    }

    pub fn source_rows(name: &str) -> bool {
        matches!(name, "events" | "context_versions")
    }

    pub fn source_header(name: &str) -> bool {
        matches!(
            name,
            "coverage" | "graph_coverage" | "discovery_state" | "graph_state" | "graph_manifest"
        )
    }

    pub(in crate::analysis) fn reads_raw(&self) -> bool {
        self.requests.iter().any(|(name, columns)| {
            columns.is_some()
                && matches!(
                    name.as_str(),
                    "events" | "trace_output" | "trace_measurements"
                )
        })
    }

    pub(in crate::analysis) fn check_managed_changes(
        &self,
        selection: &AnalysisSelectionV1,
    ) -> Result<()> {
        if !matches!(self.mode, AnalysisReadModeV1::Changes(_)) {
            return Ok(());
        }
        if selection.targets
            || (!selection.contexts.as_slice().is_empty()
                && self.projected("context_versions").is_none())
            || !selection.results.is_empty()
            || !selection.profiles.is_empty()
            || (!selection.graphs.is_empty() && self.projected("graph_manifest").is_none())
            || selection.graph_traversal.is_some()
            || !selection.obligations.is_empty()
        {
            return Err(crate::PackageErrorCodeV1::Invalid.error("managed change selection"));
        }
        if self.requests.iter().any(|(name, columns)| {
            columns.is_some()
                && !Self::source_rows(name)
                && !Self::source_header(name)
                && name != "trace_output"
        }) {
            return Err(crate::PackageErrorCodeV1::Invalid.error("managed change relation"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn projected(&self, name: &str) -> Option<&BTreeSet<usize>> {
        self.requests.get(name).and_then(Option::as_ref)
    }

    pub(in crate::analysis) fn projects_field(&self, relation: &str, field: &str) -> bool {
        let schema = &crate::AnalysisStore::table_schemas()[relation];
        self.projected(relation).is_some_and(|columns| {
            columns
                .iter()
                .any(|index| schema.field(*index).name() == field)
        })
    }

    pub(in crate::analysis) fn needs_event_decode(&self) -> bool {
        let Some(columns) = self.projected("events") else {
            return false;
        };
        let schema = &crate::AnalysisStore::table_schemas()["events"];
        columns.iter().any(|index| {
            !matches!(
                schema.field(*index).name().as_str(),
                "tenant_id"
                    | "node_id"
                    | "node_boot_id"
                    | "label_epoch"
                    | "source_id"
                    | "source_epoch"
                    | "cpu_id"
                    | "source_cursor"
                    | "commit_revision"
                    | "ordinal"
                    | "received_utc_ns"
                    | "received_at"
                    | "framed_record"
            )
        })
    }
}

pub(in crate::analysis) struct ReadBudget<'a> {
    output: &'a mut AnalysisExtractionV1,
    control: &'a AnalysisReadControl,
    row_bytes: Option<&'a mut usize>,
    emitted: usize,
}

impl ReadBudget<'_> {
    pub fn check(&self) -> Result<()> {
        self.control.check()
    }

    pub fn admit(&mut self, bytes: usize) -> Result<bool> {
        self.control.check()?;
        if let Some(used) = &mut self.row_bytes {
            if used.saturating_add(bytes) > self.output.limits.page_bytes {
                if **used == 0 || self.emitted != 0 {
                    return AnalysisInputTooLargeSnafu {
                        resource: "projected row bytes",
                    }
                    .fail();
                }
                return Ok(false);
            }
            **used += bytes;
        }
        self.emitted += 1;
        Ok(true)
    }

    pub fn projected(&mut self, bytes: usize) {
        self.output.projected_bytes += bytes;
    }

    pub fn remaining_bytes(&self) -> usize {
        self.output
            .limits
            .input_bytes
            .saturating_sub(self.output.input_bytes)
    }

    pub fn page_rows(&self) -> usize {
        self.output.limits.page_rows.min(MAX_ANALYSIS_PAGE_RECORDS)
    }

    pub fn grow<U>(&mut self, values: &mut Vec<U>) -> Result<()> {
        let added = AnalysisExtractionV1::grow(
            values,
            self.output.input_bytes,
            self.output.limits.input_bytes,
        )?;
        self.output.charge(added)
    }

    pub fn charge(&mut self, bytes: usize) -> Result<()> {
        self.output.charge(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct AnalysisSourceSnapshotV1 {
    pub receipt: AnalysisSourceReceiptV1,
    pub commit_revision: u64,
    pub expired: Vec<AnalysisGapV1>,
    pub recovery: Vec<AnalysisGapV1>,
    /// Missing source cursors above the ACK through the last durable cursor.
    pub pending: Vec<AnalysisGapV1>,
    pub coverage_report: Option<Vec<u8>>,
    pub typed_report: Option<std::sync::Arc<crate::CoverageReport>>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AnalysisReferenceOriginV1 {
    Context,
    Profile,
    Graph,
    Notification,
    ExplicitResult,
}

#[derive(Debug)]
pub enum AnalysisReferenceV1 {
    Context {
        reference: crate::AnalysisContextRefV1,
        origins: Vec<AnalysisReferenceOriginV1>,
    },
    Result {
        reference: super::PackageResultRefV1,
        origins: Vec<AnalysisReferenceOriginV1>,
    },
}

impl AnalysisReferenceV1 {
    pub fn context(&self) -> Option<&crate::AnalysisContextRefV1> {
        match self {
            Self::Context { reference, .. } => Some(reference),
            Self::Result { .. } => None,
        }
    }

    pub fn result(&self) -> Option<&super::PackageResultRefV1> {
        match self {
            Self::Result { reference, .. } => Some(reference),
            Self::Context { .. } => None,
        }
    }

    pub fn origins(&self) -> &[AnalysisReferenceOriginV1] {
        match self {
            Self::Context { origins, .. } | Self::Result { origins, .. } => origins,
        }
    }

    fn origins_mut(&mut self) -> &mut Vec<AnalysisReferenceOriginV1> {
        match self {
            Self::Context { origins, .. } | Self::Result { origins, .. } => origins,
        }
    }
}

#[derive(Debug)]
pub struct AnalysisExtractionV1 {
    pub discovery_enabled: bool,
    pub graph_enabled: bool,
    pub notification_enabled: bool,
    pub meta: AnalysisStoreMetaV1,
    pub sources: Vec<AnalysisSourceSnapshotV1>,
    pub missing_contexts: Vec<AnalysisContextKeyV1>,
    pub missing_results: Vec<String>,
    pub references: Vec<AnalysisReferenceV1>,
    pub witnesses: Vec<crate::AnalysisWitnessV1>,
    pub replay_floor: Option<StorePositionV1>,
    pub scanned_bytes: usize,
    pub projected_bytes: usize,
    /// Includes retained projection bytes and source metadata.
    pub input_bytes: usize,
    pub(crate) trace_reads: Vec<[u8; 16]>,
    pub(crate) graph_traversal: Option<crate::GraphTraversalReceiptV1>,
    graph_coverage: Vec<(String, sdk::Coverage)>,
    pub(crate) limits: AnalysisExtractLimits,
}

#[derive(Debug)]
pub struct AnalysisPositionPageV1 {
    pub extraction: AnalysisExtractionV1,
    /// Includes scanned rows that did not pass the projection.
    pub scanned_through: StorePositionV1,
    pub exhausted: bool,
    pub tables: BTreeMap<String, Vec<RecordBatch>>,
    pub removals: BTreeMap<super::AnalysisStreamIdentityV1, Vec<AnalysisGapV1>>,
    pub mutable_discovery: bool,
    pub received_min: Option<u64>,
    pub next_change: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub enum AnalysisReadModeV1 {
    Complete,
    Metadata,
    Page(Option<StorePositionV1>),
    Changes(StorePositionV1),
}

impl AnalysisExtractionV1 {
    pub(in crate::analysis) fn new(
        meta: AnalysisStoreMetaV1,
        limits: AnalysisExtractLimits,
    ) -> Self {
        Self {
            discovery_enabled: false,
            graph_enabled: false,
            notification_enabled: false,
            meta,
            sources: Vec::new(),
            missing_contexts: Vec::new(),
            missing_results: Vec::new(),
            references: Vec::new(),
            witnesses: Vec::new(),
            replay_floor: None,
            scanned_bytes: 0,
            projected_bytes: 0,
            input_bytes: 0,
            trace_reads: Vec::new(),
            graph_traversal: None,
            graph_coverage: Vec::new(),
            limits,
        }
    }

    pub fn allocation_bytes(&self) -> usize {
        let mut bytes = size_of::<Self>()
            .saturating_add(
                self.sources
                    .capacity()
                    .saturating_mul(size_of::<AnalysisSourceSnapshotV1>()),
            )
            .saturating_add(
                self.missing_contexts
                    .capacity()
                    .saturating_mul(size_of::<AnalysisContextKeyV1>()),
            )
            .saturating_add(
                self.missing_results
                    .capacity()
                    .saturating_mul(size_of::<String>()),
            )
            .saturating_add(
                self.references
                    .capacity()
                    .saturating_mul(size_of::<AnalysisReferenceV1>()),
            )
            .saturating_add(
                self.witnesses
                    .capacity()
                    .saturating_mul(size_of::<crate::AnalysisWitnessV1>()),
            )
            .saturating_add(
                self.trace_reads
                    .capacity()
                    .saturating_mul(size_of::<[u8; 16]>()),
            )
            .saturating_add(
                self.graph_traversal
                    .as_ref()
                    .map_or(0, crate::GraphTraversalReceiptV1::heap_bytes),
            )
            .saturating_add(
                self.graph_coverage
                    .capacity()
                    .saturating_mul(size_of::<(String, sdk::Coverage)>()),
            );
        for (id, coverage) in &self.graph_coverage {
            bytes = bytes
                .saturating_add(id.capacity())
                .saturating_add(coverage.metadata_bytes());
        }
        for source in &self.sources {
            bytes = bytes
                .saturating_add(source.receipt.identity.node_id.capacity())
                .saturating_add(source.coverage_report.as_ref().map_or(0, Vec::capacity));
            for gaps in [&source.expired, &source.recovery, &source.pending] {
                bytes = bytes
                    .saturating_add(gaps.capacity().saturating_mul(size_of::<AnalysisGapV1>()));
            }
        }
        for key in self.missing_contexts.iter().chain(
            self.references
                .iter()
                .filter_map(AnalysisReferenceV1::context)
                .map(|reference| &reference.key),
        ) {
            bytes = bytes
                .saturating_add(key.owner_id.capacity())
                .saturating_add(key.entity_key.capacity())
                .saturating_add(key.lifetime_key.capacity());
        }
        for result in self.missing_results.iter().chain(
            self.references
                .iter()
                .filter_map(AnalysisReferenceV1::result)
                .map(|reference| &reference.result_id),
        ) {
            bytes = bytes.saturating_add(result.capacity());
        }
        for reference in &self.references {
            let capacity = match reference {
                AnalysisReferenceV1::Context { origins, .. }
                | AnalysisReferenceV1::Result { origins, .. } => origins.capacity(),
            };
            bytes = bytes
                .saturating_add(capacity.saturating_mul(size_of::<AnalysisReferenceOriginV1>()));
        }
        for witness in &self.witnesses {
            bytes = bytes.saturating_add(match &witness.identity {
                super::AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                super::AnalysisStreamIdentityV1::Diagnostic(identity) => {
                    identity.node_id.capacity()
                }
            });
        }
        bytes
    }
}

pub(in crate::analysis) struct SelectedTrace<'a> {
    pub(in crate::analysis) identity: &'a TraceIdentityV1,
    pub(in crate::analysis) target_index: u32,
    pub(in crate::analysis) selected: bool,
}

impl AnalysisExtractionV1 {
    pub(in crate::analysis) fn reference_context(
        &mut self,
        key: &AnalysisContextKeyV1,
        revision: u64,
        origin: AnalysisReferenceOriginV1,
    ) -> Result<()> {
        let index = match self.references.binary_search_by(|entry| match entry {
            AnalysisReferenceV1::Context { reference, .. } => reference.key.cmp(key),
            AnalysisReferenceV1::Result { .. } => std::cmp::Ordering::Greater,
        }) {
            Ok(index) => {
                if self.references[index]
                    .context()
                    .is_none_or(|reference| reference.commit_revision != revision)
                {
                    return Err(crate::AnalysisStateSnafu {
                        path: std::path::Path::new("<extraction>"),
                        reason: "the captured context revision changed",
                    }
                    .build());
                }
                return self.reference_origin(index, origin);
            }
            Err(index) => index,
        };
        let key = key.clone();
        self.charge(
            key.owner_id.capacity() + key.entity_key.capacity() + key.lifetime_key.capacity(),
        )?;
        let added = Self::grow(
            &mut self.references,
            self.input_bytes,
            self.limits.input_bytes,
        )?;
        self.charge(added)?;
        self.references.insert(
            index,
            AnalysisReferenceV1::Context {
                reference: crate::AnalysisContextRefV1 {
                    key,
                    commit_revision: revision,
                },
                origins: Vec::new(),
            },
        );
        self.reference_origin(index, origin)
    }

    pub(in crate::analysis) fn reference_result(
        &mut self,
        id: &str,
        revision: u64,
        origin: AnalysisReferenceOriginV1,
    ) -> Result<()> {
        let index = match self.references.binary_search_by(|entry| match entry {
            AnalysisReferenceV1::Context { .. } => std::cmp::Ordering::Less,
            AnalysisReferenceV1::Result { reference, .. } => reference.result_id.as_str().cmp(id),
        }) {
            Ok(index) => {
                if self.references[index]
                    .result()
                    .is_none_or(|reference| reference.commit_revision != revision)
                {
                    return Err(crate::AnalysisStateSnafu {
                        path: std::path::Path::new("<extraction>"),
                        reason: "the captured result revision changed",
                    }
                    .build());
                }
                return self.reference_origin(index, origin);
            }
            Err(index) => index,
        };
        let result_id = id.to_owned();
        self.charge(result_id.capacity())?;
        let added = Self::grow(
            &mut self.references,
            self.input_bytes,
            self.limits.input_bytes,
        )?;
        self.charge(added)?;
        self.references.insert(
            index,
            AnalysisReferenceV1::Result {
                reference: super::PackageResultRefV1 {
                    result_id,
                    commit_revision: revision,
                },
                origins: Vec::new(),
            },
        );
        self.reference_origin(index, origin)
    }

    fn reference_origin(&mut self, index: usize, origin: AnalysisReferenceOriginV1) -> Result<()> {
        let position = match self.references[index].origins().binary_search(&origin) {
            Ok(_) => return Ok(()),
            Err(index) => index,
        };
        let added = Self::grow(
            self.references[index].origins_mut(),
            self.input_bytes,
            self.limits.input_bytes,
        )?;
        self.charge(added)?;
        self.references[index]
            .origins_mut()
            .insert(position, origin);
        Ok(())
    }

    pub(in crate::analysis) fn inherit_witness(
        &mut self,
        witness: crate::AnalysisWitnessV1,
    ) -> Result<()> {
        let index = match self.witnesses.binary_search_by(|prior| {
            prior
                .identity
                .cmp(&witness.identity)
                .then(prior.cursor.cmp(&witness.cursor))
        }) {
            Ok(index) => {
                self.witnesses[index].expires_utc_ns = self.witnesses[index]
                    .expires_utc_ns
                    .min(witness.expires_utc_ns);
                return Ok(());
            }
            Err(index) => index,
        };
        self.charge(match &witness.identity {
            super::AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
            super::AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.capacity(),
        })?;
        let added = Self::grow(
            &mut self.witnesses,
            self.input_bytes,
            self.limits.input_bytes,
        )?;
        self.charge(added)?;
        self.witnesses.insert(index, witness);
        Ok(())
    }

    pub fn trace_reads(&self) -> &[[u8; 16]] {
        &self.trace_reads
    }
    pub fn graph_traversal(&self) -> Option<&crate::GraphTraversalReceiptV1> {
        self.graph_traversal.as_ref()
    }
    pub fn graph_coverage(&self, id: &str) -> Option<&sdk::Coverage> {
        self.graph_coverage
            .binary_search_by(|entry| entry.0.as_str().cmp(id))
            .ok()
            .map(|index| &self.graph_coverage[index].1)
    }
    pub(in crate::analysis) fn sink<'a>(
        &'a mut self,
        control: &'a AnalysisReadControl,
    ) -> ReadBudget<'a> {
        self.row_budget(control, None)
    }

    pub(in crate::analysis) fn row_budget<'a>(
        &'a mut self,
        control: &'a AnalysisReadControl,
        row_bytes: Option<&'a mut usize>,
    ) -> ReadBudget<'a> {
        ReadBudget {
            output: self,
            control,
            row_bytes,
            emitted: 0,
        }
    }

    pub(in crate::analysis) fn grow<U>(
        values: &mut Vec<U>,
        used: usize,
        limit: usize,
    ) -> Result<usize> {
        if values.len() < values.capacity() {
            return Ok(0);
        }
        let error = || {
            AnalysisInputTooLargeSnafu {
                resource: "selected input bytes",
            }
            .build()
        };
        let width = size_of::<U>();
        if width == 0 {
            values.try_reserve_exact(1).map_err(|_| error())?;
            return Ok(0);
        }
        let available = limit.checked_sub(used).ok_or_else(error)?;
        let previous = values.capacity();
        let capacity = previous
            .saturating_mul(2)
            .max(4)
            .min(previous.saturating_add(available / width));
        if capacity <= previous {
            return Err(error());
        }
        let requested = (capacity - previous)
            .checked_mul(width)
            .filter(|bytes| *bytes <= available)
            .ok_or_else(error)?;
        values
            .try_reserve_exact(requested / width)
            .map_err(|_| error())?;
        (values.capacity() - previous)
            .checked_mul(width)
            .filter(|bytes| *bytes <= available)
            .ok_or_else(error)
    }

    pub(in crate::analysis) fn charge(&mut self, bytes: usize) -> Result<()> {
        self.input_bytes = self
            .input_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.input_bytes)
            .ok_or_else(|| {
                AnalysisInputTooLargeSnafu {
                    resource: "selected input bytes",
                }
                .build()
            })?;
        Ok(())
    }

    pub(in crate::analysis) fn scan(&mut self, bytes: usize) -> Result<()> {
        self.scanned_bytes = self
            .scanned_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.scan_bytes)
            .ok_or_else(|| {
                AnalysisInputTooLargeSnafu {
                    resource: "scanned segment bytes",
                }
                .build()
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::AnalysisStore;
    const KEY_LIMIT: usize = 1024;
    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn read(
        store: &AnalysisStore,
        selection: &AnalysisSelectionV1,
        requested: &[(&str, &[&str])],
        mode: AnalysisReadModeV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisPositionPageV1> {
        let columns = requested
            .iter()
            .map(|(name, fields)| {
                let schema = &crate::AnalysisStore::table_schemas()[*name];
                let indices = fields
                    .iter()
                    .map(|field| {
                        schema
                            .index_of(field)
                            .map_err(araphor_analysis_sdk::Error::from)
                            .context(crate::AnalysisContractSnafu)
                    })
                    .collect::<Result<BTreeSet<_>>>()?;
                Ok(((*name).to_owned(), Some(indices)))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        store.read_tables(
            selection,
            AnalysisTableRead {
                requests: &columns,
                event_ranges: None,
                mode,
                now: 0,
            },
            limits,
            control,
        )
    }

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: "n".into(),
            ..crate::analysis::tests::identity()
        }
    }

    #[test]
    fn extraction_default_budgets_unbounded() -> TestResult {
        let limits = AnalysisExtractLimits::default();
        assert_eq!(limits.scan_bytes, usize::MAX);
        assert_eq!(limits.input_bytes, usize::MAX);
        assert_eq!(limits.page_bytes, usize::MAX);
        assert_eq!(limits.keys, None);
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("data"))?;
        let mut output = read(
            &store,
            &AnalysisSelectionV1::new([1; 16], Vec::new()),
            &[],
            AnalysisReadModeV1::Metadata,
            limits,
            &AnalysisReadControl::default(),
        )?
        .extraction;
        let before = output.input_bytes;
        output.scan(MAX_SCAN_BYTES + 1)?;
        output.charge(MAX_INPUT_BYTES + 1)?;
        assert_eq!(output.scanned_bytes, MAX_SCAN_BYTES + 1);
        assert_eq!(output.input_bytes, before + MAX_INPUT_BYTES + 1);
        assert!(output.scan(usize::MAX).is_err());
        assert!(output.charge(usize::MAX).is_err());
        let control = AnalysisReadControl::default();
        let mut row_bytes = 0;
        assert!(output
            .row_budget(&control, Some(&mut row_bytes))
            .admit(crate::analysis::MAX_ANALYSIS_PAGE_BYTES + 1)?);
        assert_eq!(row_bytes, crate::analysis::MAX_ANALYSIS_PAGE_BYTES + 1);
        Ok(())
    }

    #[test]
    fn analysis_trace_key_limits() -> TestResult {
        let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
        selection.traces = Selection::Exact(
            (1_u128..=1024)
                .map(|execution| TraceIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "trace-node".into(),
                    node_boot_id: [2; 16],
                    request_id: [3; 16],
                    execution_id: execution.to_be_bytes(),
                    source_sha256: [4; 32],
                })
                .collect(),
        );
        assert!(selection.valid());
        let limits = AnalysisExtractLimits {
            keys: Some(KEY_LIMIT),
            ..Default::default()
        };
        limits.check_keys(&selection)?;
        selection.binding_ids.push([5; 16]);
        assert!(selection.valid());
        assert!(limits.check_keys(&selection).is_err());
        selection
            .traces
            .exact_mut()
            .ok_or("exact traces absent")?
            .pop();
        assert!(selection.valid());
        limits.check_keys(&selection)?;
        selection.binding_ids.push([5; 16]);
        assert!(!selection.valid());
        selection.binding_ids = vec![[0; 16]];
        assert!(!selection.valid());
        selection.binding_ids = vec![[5; 16]];
        selection.traces.exact_mut().ok_or("exact traces absent")?[0].tenant_id = [2; 16];
        assert!(!selection.valid());
        Ok(())
    }

    #[test]
    fn analysis_selection_key_limits() {
        let mut selection = AnalysisSelectionV1::new([1; 16], vec![identity(1)]);
        selection.contexts = Selection::Exact(vec![AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "context".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        }]);
        selection.results.push("result".into());
        selection.profiles = Selection::Exact(vec!["profile".into()]);
        selection.graphs = Selection::Exact(vec!["graph".into()]);
        selection.obligations = Selection::Exact(vec![AnalysisContextKeyV1 {
            owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
            ..selection.contexts.as_slice()[0].clone()
        }]);
        selection.binding_ids.push([5; 16]);
        selection.traces = Selection::Exact(
            (1..=KEY_LIMIT as u128 - 7)
                .map(|execution| TraceIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "trace-node".into(),
                    node_boot_id: [2; 16],
                    request_id: [3; 16],
                    execution_id: execution.to_be_bytes(),
                    source_sha256: [4; 32],
                })
                .collect(),
        );
        selection.nodes = (0..KEY_LIMIT)
            .map(|index| format!("node-{index}"))
            .collect();
        let limits = AnalysisExtractLimits {
            keys: Some(KEY_LIMIT),
            ..Default::default()
        };
        assert!(selection.valid());
        assert!(limits.check_keys(&selection).is_ok());
        selection.results.push("extra".into());
        assert!(selection.valid());
        assert!(limits.check_keys(&selection).is_err());
        selection.results.pop();
        assert!(selection.valid());
        assert!(limits.check_keys(&selection).is_ok());
        selection.nodes.push("extra-node".into());
        assert!(selection.valid());
        assert!(limits.check_keys(&selection).is_err());
        let mut scoped = AnalysisSelectionV1::new([1; 16], vec![identity(1)]);
        scoped.graphs = Selection::Exact(vec!["graph:one".into(), "graph:two".into()]);
        assert!(scoped.valid());
        assert_eq!(scoped.key_count(), 3);
        assert!(matches!(
            (AnalysisExtractLimits {
                keys: Some(2),
                ..Default::default()
            })
            .check_keys(&scoped),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input keys",
                ..
            })
        ));
    }

    #[test]
    fn analysis_selection_states() {
        let mut tenant = AnalysisSelectionV1::tenant([1; 16]);
        assert!(tenant.sources.is_all());
        assert!(tenant.contexts.is_all());
        assert!(tenant.traces.is_all());
        assert!(tenant.sources.exact_mut().is_none());
        assert!(tenant.contexts.exact_mut().is_none());
        assert!(tenant.traces.exact_mut().is_none());
        assert!(tenant.valid());
        assert_eq!(tenant.allocation_bytes(), size_of::<AnalysisSelectionV1>());

        let exact = AnalysisSelectionV1::new([1; 16], Vec::with_capacity(8));
        assert!(!exact.sources.is_all());
        assert!(!exact.contexts.is_all());
        assert!(!exact.traces.is_all());
        assert!(exact.sources.as_slice().is_empty());
        assert!(exact.valid());
        assert_eq!(
            exact.allocation_bytes(),
            size_of::<AnalysisSelectionV1>() + 8 * size_of::<EvidenceIntakeIdentityV1>()
        );
    }

    #[test]
    fn configured_counters_bound() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let empty = read(
            &store,
            &AnalysisSelectionV1::new([1; 16], Vec::new()),
            &[],
            AnalysisReadModeV1::Metadata,
            Default::default(),
            &AnalysisReadControl::default(),
        )?;
        let mut output = empty.extraction;
        output.limits.scan_bytes = MAX_SCAN_BYTES;
        output.limits.input_bytes = MAX_INPUT_BYTES;
        output.scan(MAX_SCAN_BYTES)?;
        assert!(matches!(
            output.scan(1),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "scanned segment bytes",
                ..
            })
        ));
        output.charge(MAX_INPUT_BYTES - output.input_bytes)?;
        assert!(matches!(
            output.charge(1),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input bytes",
                ..
            })
        ));
        assert!(output.charge(usize::MAX).is_err());
        assert!(output.scan(usize::MAX).is_err());
        Ok(())
    }
}
