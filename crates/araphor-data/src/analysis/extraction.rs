use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::ops::Bound;

use duckdb::arrow::{datatypes::SchemaRef, record_batch::RecordBatch};
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::raw::{RawIdentity, TracePayload, TraceRecord};
use super::segments::SegmentRange;
use super::{
    AnalysisContextKeyV1, AnalysisGapV1, AnalysisReadControl, AnalysisSourceReceiptV1,
    AnalysisStore, AnalysisStoreMetaV1, StorePositionV1, MAX_ANALYSIS_PAGE_BYTES,
    MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{
    AnalysisDatabaseSnafu, AnalysisInputTooLargeSnafu, EvidenceIntakeIdentityV1, EvidenceRecord,
    Result, TraceIdentityV1,
};

mod changes;
mod discovery;
mod graph;
mod package;
mod tables;

const MAX_EXTRACT_KEYS: usize = 1024;
const MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct AnalysisExtractLimits {
    pub scan_bytes: usize,
    pub input_bytes: usize,
    pub page_bytes: usize,
    pub page_rows: usize,
}

impl Default for AnalysisExtractLimits {
    fn default() -> Self {
        Self {
            scan_bytes: MAX_SCAN_BYTES,
            input_bytes: MAX_INPUT_BYTES,
            page_bytes: MAX_ANALYSIS_PAGE_BYTES,
            page_rows: MAX_ANALYSIS_PAGE_RECORDS,
        }
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
            && self.nodes.len() <= MAX_EXTRACT_KEYS
            && self.nodes.iter().all(|node| crate::node_id_is_valid(node))
            && self.nodes.iter().collect::<BTreeSet<_>>().len() == self.nodes.len()
            && self.key_count() <= MAX_EXTRACT_KEYS
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
            && self
                .results
                .iter()
                .all(|id| !id.is_empty() && id.len() <= 256)
            && self
                .profiles
                .as_slice()
                .iter()
                .all(|id| !id.is_empty() && id.len() <= 256)
            && self
                .graphs
                .as_slice()
                .iter()
                .all(|id| !id.is_empty() && id.len() <= 256)
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

    fn key_count(&self) -> usize {
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

pub struct AnalysisTableRead<'a> {
    pub requests: &'a AnalysisTableRequests,
    pub event_ranges: Option<&'a [(u64, u64)]>,
    pub inputs: Option<AnalysisInputTables<'a>>,
    pub mode: AnalysisReadModeV1,
    pub now: u64,
}

impl AnalysisTableRead<'_> {
    fn projected(&self, name: &str) -> Option<&BTreeSet<usize>> {
        self.requests.get(name).and_then(Option::as_ref)
    }

    fn needs_event_decode(&self) -> bool {
        let Some(columns) = self.projected("events") else {
            return false;
        };
        let schema = &AnalysisStore::table_schemas()["events"];
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

#[derive(Clone, Copy)]
pub struct AnalysisInputTables<'a> {
    pub authorized: &'a AnalysisSelectionV1,
    pub scope: &'a str,
    pub outputs: &'a [(araphor_analysis_sdk::OutputRef, SchemaRef)],
    pub limits: araphor_analysis_sdk::Limits,
}

pub(super) struct ReadBudget<'a> {
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

#[derive(Debug)]
pub struct AnalysisSourceSnapshotV1 {
    pub receipt: AnalysisSourceReceiptV1,
    pub expired: Vec<AnalysisGapV1>,
    pub recovery: Vec<AnalysisGapV1>,
    /// Missing source cursors above the ACK through the last durable cursor.
    pub pending: Vec<AnalysisGapV1>,
    pub coverage_report: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AnalysisReferenceOriginV1 {
    Context,
    Profile,
    Graph,
    Notification,
    ExplicitResult,
    Package(usize),
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
    pub(crate) limits: AnalysisExtractLimits,
}

#[derive(Debug)]
pub struct AnalysisPositionPageV1 {
    pub extraction: AnalysisExtractionV1,
    /// Includes scanned rows that did not pass the projection.
    pub scanned_through: StorePositionV1,
    pub exhausted: bool,
    pub tables: BTreeMap<String, Vec<RecordBatch>>,
    pub packages: BTreeMap<usize, (SchemaRef, Vec<RecordBatch>, araphor_analysis_sdk::Coverage)>,
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
            );
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

struct SelectedTrace<'a> {
    identity: &'a TraceIdentityV1,
    target_index: u32,
    selected: bool,
}

impl AnalysisExtractionV1 {
    fn reference_context(
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

    fn reference_result(
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

    fn inherit_witness(&mut self, witness: crate::AnalysisWitnessV1) -> Result<()> {
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
    fn sink<'a>(&'a mut self, control: &'a AnalysisReadControl) -> ReadBudget<'a> {
        self.row_budget(control, None)
    }

    fn row_budget<'a>(
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

    fn grow<U>(values: &mut Vec<U>, used: usize, limit: usize) -> Result<usize> {
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

    fn charge(&mut self, bytes: usize) -> Result<()> {
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

    fn scan(&mut self, bytes: usize) -> Result<()> {
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

impl AnalysisStore {
    pub(super) fn resolve_selection<'a>(
        &self,
        snapshot: &Connection,
        selection: &'a AnalysisSelectionV1,
        control: &AnalysisReadControl,
        limit: usize,
    ) -> Result<(Cow<'a, AnalysisSelectionV1>, usize)> {
        control.check()?;
        if !selection.valid() {
            return self.reject("the extraction selection has invalid, duplicate, or foreign keys");
        }
        if (selection.graphs.is_all()
            || !selection.graphs.as_slice().is_empty()
            || selection.graph_traversal.is_some())
            && !self.graph_enabled()
        {
            return crate::AnalysisUnavailableSnafu {
                relation: "graph owner disabled",
            }
            .fail();
        }
        if (selection.obligations.is_all() || !selection.obligations.as_slice().is_empty())
            && !self
                .notification_owner
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return crate::AnalysisUnavailableSnafu {
                relation: "notification owner disabled",
            }
            .fail();
        }
        if !selection.sources.is_all()
            && !selection.contexts.is_all()
            && !selection.traces.is_all()
            && !selection.targets_only
            && !selection.profiles.is_all()
            && !selection.graphs.is_all()
            && !selection.obligations.is_all()
            && selection.nodes.is_empty()
        {
            return Ok((Cow::Borrowed(selection), 0));
        }
        let error = || {
            AnalysisInputTooLargeSnafu {
                resource: "selected input keys",
            }
            .build()
        };
        if selection.allocation_bytes() > limit {
            return Err(error());
        }
        let mut resolved = selection.clone();
        resolved.sources = Selection::Exact(match resolved.sources {
            Selection::All => Vec::new(),
            Selection::Exact(keys) => keys,
        });
        resolved.contexts = Selection::Exact(match resolved.contexts {
            Selection::All => Vec::new(),
            Selection::Exact(keys) => keys,
        });
        resolved.traces = Selection::Exact(match resolved.traces {
            Selection::All => Vec::new(),
            Selection::Exact(keys) => keys,
        });
        resolved.profiles = Selection::Exact(match resolved.profiles {
            Selection::All => Vec::new(),
            Selection::Exact(keys) => keys,
        });
        resolved.graphs = Selection::Exact(match resolved.graphs {
            Selection::All => Vec::new(),
            Selection::Exact(keys) => keys,
        });
        resolved.obligations = Selection::Exact(match resolved.obligations {
            Selection::All => Vec::new(),
            Selection::Exact(keys) => keys,
        });
        if selection.targets_only {
            resolved
                .contexts
                .exact_mut()
                .ok_or_else(|| self.state_error("the resolved context selection is not exact"))?
                .retain(|key| key.owner_id == "mithril-control/target");
        }
        resolved
            .sources
            .exact_mut()
            .ok_or_else(|| self.state_error("the resolved source selection is not exact"))?
            .retain(|source| resolved.nodes.is_empty() || resolved.nodes.contains(&source.node_id));
        resolved
            .traces
            .exact_mut()
            .ok_or_else(|| self.state_error("the resolved trace selection is not exact"))?
            .retain(|identity| {
                resolved.nodes.is_empty() || resolved.nodes.contains(&identity.node_id)
            });
        let mut bytes = resolved.allocation_bytes();
        if bytes > limit {
            return Err(error());
        }
        if selection.sources.is_all() {
            let mut after = None;
            loop {
                control.check()?;
                let page =
                    self.source_page_from(snapshot, selection.tenant_id, after.as_ref(), control)?;
                if page.is_empty() {
                    break;
                }
                after = page.last().cloned();
                for source in page {
                    control.check()?;
                    if !resolved.nodes.is_empty() && !resolved.nodes.contains(&source.node_id) {
                        continue;
                    }
                    if resolved.key_count() == MAX_EXTRACT_KEYS {
                        return Err(error());
                    }
                    let sources = resolved.sources.exact_mut().ok_or_else(|| {
                        self.state_error("the resolved source selection is not exact")
                    })?;
                    let added = AnalysisExtractionV1::grow(sources, bytes, limit)?;
                    bytes = bytes
                        .checked_add(added)
                        .and_then(|bytes| bytes.checked_add(source.node_id.capacity()))
                        .filter(|bytes| *bytes <= limit)
                        .ok_or_else(error)?;
                    sources.push(source);
                }
            }
        }
        if selection.contexts.is_all() {
            let remaining = MAX_EXTRACT_KEYS - resolved.key_count();
            let mut statement = snapshot.prepare(
                "SELECT owner_id, entity_key, lifetime_key, owner_revision FROM context_versions
                 WHERE tenant_id = ? AND (NOT ? OR owner_id = 'mithril-control/target')
                 ORDER BY owner_id, entity_key, lifetime_key, owner_revision LIMIT ?",
            ).context(AnalysisDatabaseSnafu { operation: "prepare tenant context keys" })?;
            let rows = statement
                .query_map(
                    params![
                        selection.tenant_id.as_slice(),
                        selection.targets_only,
                        (remaining + 1) as u32
                    ],
                    |row| {
                        Ok(AnalysisContextKeyV1 {
                            tenant_id: selection.tenant_id,
                            owner_id: row.get(0)?,
                            entity_key: row.get(1)?,
                            lifetime_key: row.get(2)?,
                            owner_revision: row.get(3)?,
                        })
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read tenant context keys",
                })?;
            for row in rows {
                control.check()?;
                let key = row.context(AnalysisDatabaseSnafu {
                    operation: "decode tenant context key",
                })?;
                if !key.valid() {
                    return self.reject("the tenant context key is invalid");
                }
                if resolved.contexts.as_slice().len() == remaining {
                    return Err(error());
                }
                let contexts = resolved.contexts.exact_mut().ok_or_else(|| {
                    self.state_error("the resolved context selection is not exact")
                })?;
                let added = AnalysisExtractionV1::grow(contexts, bytes, limit)?;
                bytes = bytes
                    .checked_add(added)
                    .and_then(|bytes| bytes.checked_add(key.owner_id.capacity()))
                    .and_then(|bytes| bytes.checked_add(key.entity_key.capacity()))
                    .and_then(|bytes| bytes.checked_add(key.lifetime_key.capacity()))
                    .filter(|bytes| *bytes <= limit)
                    .ok_or_else(error)?;
                contexts.push(key);
            }
        }
        if selection.traces.is_all() {
            let mut statement = snapshot.prepare(
                "SELECT request_id FROM traces WHERE tenant_id = ? AND NOT read_revoked ORDER BY request_id LIMIT 257",
            ).context(AnalysisDatabaseSnafu { operation: "prepare tenant trace keys" })?;
            let rows = statement
                .query_map(params![selection.tenant_id.as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read tenant trace keys",
                })?;
            for row in rows {
                control.check()?;
                let request: [u8; 16] = row
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode tenant trace key",
                    })?
                    .try_into()
                    .map_err(|_| self.state_error("the tenant trace key is invalid"))?;
                let (state, intent) =
                    Self::read_trace_intent(snapshot, &self.root, selection.tenant_id, request)?
                        .ok_or_else(|| self.state_error("the tenant trace is absent"))?;
                if state.read_revoked {
                    return crate::AnalysisReadDeniedSnafu.fail();
                }
                for binding in intent.bindings {
                    let identity = binding.identity;
                    if !resolved.nodes.is_empty() && !resolved.nodes.contains(&identity.node_id) {
                        continue;
                    }
                    if !resolved.binding_ids.is_empty()
                        && !resolved.binding_ids.contains(&binding.binding_id)
                    {
                        continue;
                    }
                    if resolved.key_count() == MAX_EXTRACT_KEYS {
                        return Err(error());
                    }
                    let traces = resolved.traces.exact_mut().ok_or_else(|| {
                        self.state_error("the resolved trace selection is not exact")
                    })?;
                    let added = AnalysisExtractionV1::grow(traces, bytes, limit)?;
                    bytes = bytes
                        .checked_add(added)
                        .and_then(|bytes| bytes.checked_add(identity.node_id.capacity()))
                        .filter(|bytes| *bytes <= limit)
                        .ok_or_else(error)?;
                    traces.push(identity);
                }
            }
        }
        if selection.profiles.is_all() {
            let mut statement = snapshot
                .prepare(
                    "SELECT result_id FROM analysis_results
                 WHERE tenant_id = ? AND processor_id = 'discovery'
                   AND method_version = ? AND stream_key = ?
                 QUALIFY ROW_NUMBER() OVER (
                     PARTITION BY interval_id
                     ORDER BY profile_revision DESC, commit_revision DESC, result_id DESC
                 ) = 1
                 ORDER BY result_id LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare discovery profile keys",
                })?;
            for source in resolved.sources.as_slice() {
                control.check()?;
                let remaining = MAX_EXTRACT_KEYS - resolved.key_count();
                let rows = statement
                    .query_map(
                        params![
                            selection.tenant_id.as_slice(),
                            crate::DISCOVERY_SCHEMA_VERSION as u64,
                            source.key().as_slice(),
                            (remaining + 1) as u32
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read discovery profile keys",
                    })?;
                for row in rows {
                    control.check()?;
                    let id = row.context(AnalysisDatabaseSnafu {
                        operation: "decode discovery profile key",
                    })?;
                    if id.is_empty() || id.len() > 256 {
                        return self.reject("the discovery profile key is invalid");
                    }
                    if resolved.key_count() == MAX_EXTRACT_KEYS {
                        return Err(error());
                    }
                    let profiles = resolved.profiles.exact_mut().ok_or_else(|| {
                        self.state_error("the resolved profile selection is not exact")
                    })?;
                    let added = AnalysisExtractionV1::grow(profiles, bytes, limit)?;
                    bytes = bytes
                        .checked_add(added)
                        .and_then(|bytes| bytes.checked_add(id.capacity()))
                        .filter(|bytes| *bytes <= limit)
                        .ok_or_else(error)?;
                    profiles.push(id);
                }
            }
            let profiles = resolved
                .profiles
                .exact_mut()
                .ok_or_else(|| self.state_error("the resolved profile selection is not exact"))?;
            profiles.sort();
            profiles.dedup();
        }
        if selection.graphs.is_all() {
            let mut statement = snapshot.prepare(
                "SELECT result_id FROM analysis_results
                 WHERE tenant_id = ? AND processor_id = ? AND method_version = ? AND stream_key = ?
                 QUALIFY ROW_NUMBER() OVER (PARTITION BY first_cursor ORDER BY commit_revision DESC) = 1
                 ORDER BY commit_revision, result_id LIMIT ?",
            ).context(AnalysisDatabaseSnafu { operation: "prepare graph result keys" })?;
            for source in resolved.sources.as_slice() {
                control.check()?;
                let remaining = MAX_EXTRACT_KEYS - resolved.key_count();
                let rows = statement
                    .query_map(
                        params![
                            selection.tenant_id.as_slice(),
                            crate::GRAPH_PROCESSOR,
                            crate::GRAPH_SCHEMA_VERSION,
                            source.key().as_slice(),
                            (remaining + 1) as u32
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read graph result keys",
                    })?;
                for row in rows {
                    control.check()?;
                    let id = row.context(AnalysisDatabaseSnafu {
                        operation: "decode graph result key",
                    })?;
                    if id.is_empty() || id.len() > 256 {
                        return self.reject("the graph result key is invalid");
                    }
                    if resolved.key_count() == MAX_EXTRACT_KEYS {
                        return Err(error());
                    }
                    let graphs = resolved.graphs.exact_mut().ok_or_else(|| {
                        self.state_error("the resolved graph selection is not exact")
                    })?;
                    let added = AnalysisExtractionV1::grow(graphs, bytes, limit)?;
                    bytes = bytes
                        .checked_add(added)
                        .and_then(|bytes| bytes.checked_add(id.capacity()))
                        .filter(|bytes| *bytes <= limit)
                        .ok_or_else(error)?;
                    graphs.push(id);
                }
            }
        }
        if selection.obligations.is_all() {
            let remaining = MAX_EXTRACT_KEYS - resolved.key_count();
            let mut statement = snapshot
                .prepare(
                    "SELECT entity_key, lifetime_key, owner_revision FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ?
                 QUALIFY ROW_NUMBER() OVER (PARTITION BY entity_key, lifetime_key
                     ORDER BY owner_revision DESC, commit_revision DESC) = 1
                 ORDER BY entity_key, lifetime_key LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare notification keys",
                })?;
            let rows = statement
                .query_map(
                    params![
                        selection.tenant_id.as_slice(),
                        crate::NOTIFICATION_STATE_OWNER,
                        (remaining + 1) as u32
                    ],
                    |row| {
                        Ok(AnalysisContextKeyV1 {
                            tenant_id: selection.tenant_id,
                            owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
                            entity_key: row.get(0)?,
                            lifetime_key: row.get(1)?,
                            owner_revision: row.get(2)?,
                        })
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read notification keys",
                })?;
            for row in rows {
                control.check()?;
                let key = row.context(AnalysisDatabaseSnafu {
                    operation: "decode notification key",
                })?;
                if !key.valid() {
                    return self.reject("the notification key is invalid");
                }
                if resolved.key_count() == MAX_EXTRACT_KEYS {
                    return Err(error());
                }
                let obligations = resolved.obligations.exact_mut().ok_or_else(|| {
                    self.state_error("the resolved notification selection is not exact")
                })?;
                let added = AnalysisExtractionV1::grow(obligations, bytes, limit)?;
                bytes = bytes
                    .checked_add(added)
                    .and_then(|bytes| {
                        bytes.checked_add(
                            key.owner_id.capacity()
                                + key.entity_key.capacity()
                                + key.lifetime_key.capacity(),
                        )
                    })
                    .filter(|bytes| *bytes <= limit)
                    .ok_or_else(error)?;
                obligations.push(key);
            }
        }
        control.check()?;
        Ok((Cow::Owned(resolved), bytes))
    }

    pub fn table_schemas() -> &'static BTreeMap<String, SchemaRef> {
        tables::Capture::schemas()
    }

    pub fn read_tables(
        &self,
        selection: &AnalysisSelectionV1,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisPositionPageV1> {
        control.check()?;
        let packages = read.inputs;
        let mode = match read.mode {
            AnalysisReadModeV1::Complete
                if !read.requests.keys().any(|name| {
                    matches!(
                        name.as_str(),
                        "events" | "trace_output" | "trace_measurements"
                    )
                }) && packages.is_none_or(|inputs| inputs.outputs.is_empty()) =>
            {
                AnalysisReadModeV1::Metadata
            }
            mode => mode,
        };
        if matches!(mode, AnalysisReadModeV1::Changes(after) if after.ordinal != u32::MAX) {
            return self.reject("the raw change frontier is not a complete commit");
        }
        if packages.is_some()
            && matches!(
                mode,
                AnalysisReadModeV1::Page(_) | AnalysisReadModeV1::Changes(_)
            )
        {
            return self.reject("a position read cannot include model inputs");
        }
        for (name, columns) in read.requests {
            let Some(columns) = columns else {
                continue;
            };
            let Some(schema) = Self::table_schemas().get(name) else {
                return self.reject("the selected table has no Arrow schema");
            };
            if columns.iter().any(|index| *index >= schema.fields().len()) {
                return self.reject("the selected table columns are invalid");
            }
        }
        if read
            .event_ranges
            .is_some_and(|ranges| ranges.iter().any(|(first, last)| first > last))
        {
            return self.reject("the event input range is invalid");
        }
        if !selection.valid() {
            return self.reject("the extraction selection has invalid, duplicate, or foreign keys");
        }
        if read.requests.contains_key("discovery_state") && !selection.binding_ids.is_empty() {
            return Err(crate::PackageErrorCodeV1::Denied.error("complete discovery source scope"));
        }
        if packages.is_some_and(|inputs| inputs.authorized.tenant_id != selection.tenant_id) {
            return Err(crate::PackageErrorCodeV1::Denied.error("dependency tenant"));
        }
        if limits.scan_bytes == 0
            || limits.input_bytes == 0
            || limits.page_bytes == 0
            || limits.page_rows == 0
        {
            return self.reject("the extraction limits must be positive");
        }
        let decode_events = !selection.binding_ids.is_empty() || read.needs_event_decode();
        let checked_catalog = read.projected("events").is_some_and(|columns| {
            let schema = &Self::table_schemas()["events"];
            columns.iter().any(|index| {
                let name = schema.field(*index).name();
                matches!(
                    name.as_str(),
                    "catalog_profile_id"
                        | "catalog_profile_version"
                        | "catalog_policy_document_digest"
                ) || name.starts_with("catalog_key_")
            })
        });
        let coordinator = self.read_coordinator(control)?;
        let explicit_traces = !selection.traces.is_all() && !selection.traces.as_slice().is_empty();
        let unscoped_notifications = selection.sources.is_all()
            && selection.nodes.is_empty()
            && selection.binding_ids.is_empty();
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |snapshot| {
            let meta = Self::read_meta_from(snapshot, &self.root.join("analysis.duckdb"))?;
            let (selection, key_bytes) =
                self.resolve_selection(snapshot, selection, control, limits.input_bytes)?;
            let selection = selection.as_ref();
            let mut capture = tables::Capture::new(&read, selection);
            let end = StorePositionV1 {
                commit_revision: meta.commit_revision,
                ordinal: u32::MAX,
            };
            let mut after = match mode {
                AnalysisReadModeV1::Complete | AnalysisReadModeV1::Metadata => None,
                AnalysisReadModeV1::Page(after) => after,
                AnalysisReadModeV1::Changes(after) => Some(after),
            };
            if after.is_some_and(|position| position > end) {
                return self.reject("the position read starts beyond the captured revision");
            }
            // The revision fixes raw selection. The lease prevents segment deletion.
            drop(coordinator);
            let mut output = AnalysisExtractionV1 {
                discovery_enabled: self.discovery_enabled(),
                graph_enabled: self.graph_enabled(),
                notification_enabled: self.notification_owner.load(std::sync::atomic::Ordering::Acquire),
                meta,
                sources: Vec::new(),
                missing_contexts: Vec::new(),
                missing_results: Vec::new(),
                references: Vec::new(),
                witnesses: Vec::new(),
                scanned_bytes: 0,
                projected_bytes: 0,
                input_bytes: 0,
                trace_reads: Vec::new(),
                graph_traversal: None,
                limits,
                replay_floor: Self::replay_floor_from(snapshot, selection.tenant_id)?,
            };
            output.charge(size_of::<AnalysisExtractionV1>())?;
            output.charge(key_bytes)?;
            if matches!(mode, AnalysisReadModeV1::Page(_) | AnalysisReadModeV1::Changes(_)) {
                if let (Some(position), Some(floor)) = (after, output.replay_floor) {
                    if position < floor {
                        return crate::AnalysisReplayExpiredSnafu { position, floor }.fail();
                    }
                }
            }
            for identity in selection.sources.as_slice() {
                control.check()?;
                let key = identity.key();
                let receipt = Self::read_receipt_from(snapshot, &self.root, identity, &key)?
                    .ok_or_else(|| self.state_error("the selected source is absent"))?;
                output.charge(receipt.identity.node_id.capacity())?;
                let expired = self.extract_gaps(snapshot, identity, false, control, &mut output)?;
                let recovery = self.extract_gaps(snapshot, identity, true, control, &mut output)?;
                self.check_selected_source(snapshot, &receipt, &expired, control)?;
                let pending = control.lock(|| self.raw.try_lock())?.pending_gaps(
                    &receipt,
                    output.meta.commit_revision,
                    control,
                )?;
                output.charge(pending.capacity() * size_of::<AnalysisGapV1>())?;
                let coverage_report = self.read_coverage_from(snapshot, &receipt)?;
                output.charge(coverage_report.as_ref().map_or(0, Vec::capacity))?;
                let added = AnalysisExtractionV1::grow(
                    &mut output.sources,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?;
                output.charge(added)?;
                self.extract_discovery_state(snapshot, &receipt, &read, &mut output, &mut capture, control)?;
                output.sources.push(AnalysisSourceSnapshotV1 {
                    receipt,
                    expired,
                    recovery,
                    pending,
                    coverage_report,
                });
            }
            let mut trace_info = Vec::new();
            for identity in selection.traces.as_slice() {
                control.check()?;
                let (state, intent) = Self::read_trace_intent(
                    snapshot,
                    &self.root,
                    identity.tenant_id,
                    identity.request_id,
                )?
                .ok_or_else(|| self.state_error("the selected trace is absent"))?;
                if state.read_revoked {
                    return crate::AnalysisReadDeniedSnafu.fail();
                }
                let index = intent
                    .bindings
                    .iter()
                    .position(|binding| &binding.identity == identity)
                    .ok_or_else(|| self.state_error("the selected trace binding changed"))?;
                let selected = selection.binding_ids.is_empty()
                    || selection
                        .binding_ids
                        .contains(&intent.bindings[index].binding_id);
                let receipt = self.read_trace_receipt(snapshot, identity)?;
                if receipt.commit_revision > output.meta.commit_revision {
                    return self.reject("the selected trace receipt exceeds its snapshot");
                }
                let added = AnalysisExtractionV1::grow(
                    &mut trace_info,
                    output.input_bytes,
                    limits.input_bytes,
                )?;
                output.charge(added)?;
                trace_info.push(SelectedTrace {
                    identity,
                    target_index: index as u32,
                    selected,
                });
                if !selected {
                    continue;
                }
                if explicit_traces
                    && !matches!(mode, AnalysisReadModeV1::Metadata)
                    && receipt.retained_floor > 0
                {
                    if let Some(floor) = output.replay_floor {
                        let position = after.unwrap_or(StorePositionV1 {
                            commit_revision: 0,
                            ordinal: 0,
                        });
                        if position < floor {
                            return crate::AnalysisReplayExpiredSnafu { position, floor }.fail();
                        }
                    } else {
                        return crate::RetainedRangeExpiredSnafu {
                            first_cursor: 1_u64,
                            last_cursor: receipt.retained_floor,
                        }
                        .fail();
                    }
                }
                if !output.trace_reads.contains(&identity.request_id) {
                    let added = AnalysisExtractionV1::grow(
                        &mut output.trace_reads,
                        output.input_bytes,
                        limits.input_bytes,
                    )?;
                    output.charge(added)?;
                    output.trace_reads.push(identity.request_id);
                }
                if !matches!(mode, AnalysisReadModeV1::Changes(_)) {
                    capture.trace(&state, &intent, index as u32, &receipt, &mut output.sink(control))?;
                }
            }
            let removals = if let AnalysisReadModeV1::Changes(after) = mode {
                self.raw_removals(snapshot, selection, &trace_info, after, control, &mut output)?
            } else {
                Vec::new()
            };
            let mut removals = removals.into_iter().peekable();
            let mut scanned = 0;
            let mut row_bytes = 0_usize;
            let mut exhausted = false;
            'scan: loop {
                control.check()?;
                if matches!(mode, AnalysisReadModeV1::Metadata) {
                    after = Some(end);
                    exhausted = true;
                    break;
                }
                let limit = match mode {
                    AnalysisReadModeV1::Complete | AnalysisReadModeV1::Metadata | AnalysisReadModeV1::Changes(_) => {
                        usize::MAX
                    }
                    AnalysisReadModeV1::Page(_) => limits.page_rows - scanned,
                };
                if limit == 0 {
                    exhausted = self
                        .selected_position(selection, after, end.commit_revision, 1, control)?
                        .is_none();
                    if exhausted {
                        after = Some(end);
                    }
                    break;
                }
                let selected =
                    self.selected_position(selection, after, end.commit_revision, limit, control)?;
                let Some((identity, cpu, range)) = selected else {
                    after = Some(end);
                    exhausted = true;
                    break;
                };
                if matches!(mode, AnalysisReadModeV1::Page(_))
                    && output.scanned_bytes != 0
                    && output.scanned_bytes.saturating_add(range.scan_bytes) > limits.scan_bytes
                {
                    break;
                }
                output.scan(range.scan_bytes)?;
                for record in range.read(&self.root)? {
                    control.check()?;
                    while let Some(removal) = removals.next_if(|removal| {
                        removal.revision < record.position.commit_revision
                    }) {
                        output.remove_raw(&mut capture, &removal, control)?;
                    }
                    let page_bytes = matches!(mode, AnalysisReadModeV1::Page(_)).then_some(&mut row_bytes);
                    let consumed = match &identity {
                        RawIdentity::Evidence(identity) => {
                            let decoded = decode_events
                            .then(|| EvidenceRecord::try_from(record.framed_record.as_slice()))
                            .transpose()?;
                            let selected = selection.binding_ids.is_empty()
                                || decoded
                                    .as_ref()
                                    .and_then(|record| record.decision_context.as_ref())
                                    .is_some_and(|context| {
                                        selection.binding_ids.iter().any(|id| {
                                            id.as_slice() == context.binding_id.as_slice()
                                        })
                                    });
                            if selected {
                                capture.event(identity,
                                    cpu.ok_or_else(|| self.state_error("the selected evidence CPU is absent"))?,
                                    range.intake, &record, decoded.as_ref(),
                                    checked_catalog,
                                    &mut output.row_budget(control, page_bytes))?
                            } else {
                                true
                            }
                        }
                        RawIdentity::Diagnostic(identity) => {
                            let trace = trace_info
                                .iter()
                                .find(|trace| trace.identity == identity)
                                .ok_or_else(|| {
                                    self.state_error("the selected trace identity is absent")
                                })?;
                            if !trace.selected {
                                scanned += 1;
                                after = Some(record.position);
                                continue;
                            }
                            let payload = TraceRecord::read(&record.framed_record, &self.root)?;
                            let (kind, bytes) = match &payload {
                                TracePayload::Metadata(bytes) => ("metadata", bytes),
                                TracePayload::Data(bytes) => ("data", bytes),
                                TracePayload::Diagnostic(bytes) => ("diagnostic", bytes),
                                TracePayload::Terminal(bytes) => {
                                    let terminal = TraceRecord::terminal(bytes, &self.root)?;
                                    if terminal.execution_id != identity.execution_id
                                        || terminal.last_sequence + 1 != record.cursor
                                    {
                                        return self.reject(
                                            "the selected trace terminal identity changed",
                                        );
                                    }
                                    ("terminal", bytes)
                                }
                            };
                            capture.frame(identity, trace.target_index, record.cursor,
                                record.position, kind, bytes,
                                &mut output.row_budget(control, page_bytes))?
                        }
                    };
                    if !consumed {
                        break 'scan;
                    }
                    #[cfg(any(test, feature = "test-fixtures"))]
                    control.test_read_step()?;
                    scanned += 1;
                    after = Some(record.position);
                }
            }
            if matches!(mode, AnalysisReadModeV1::Changes(_)) {
                for removal in removals {
                    output.remove_raw(&mut capture, &removal, control)?;
                }
                control.check()?;
                return capture.finish(output, end, true, control);
            }
            if let Some(packages) = packages {
                self.extract_packages(
                    snapshot,
                    packages,
                    matches!(mode, AnalysisReadModeV1::Metadata),
                    control,
                    &mut output,
                    &mut capture,
                )?;
            }
            for key in selection.contexts.as_slice() {
                control.check()?;
                match Self::read_context_from(snapshot, &self.root, key)? {
                    Some((context, revision)) => {
                        output.reference_context(&context.key, revision, AnalysisReferenceOriginV1::Context)?;
                        capture.context(&context, revision, &mut output.sink(control))?;
                    }
                    None => {
                        let key = key.clone();
                        output.charge(
                            key.owner_id.capacity()
                                + key.entity_key.capacity()
                                + key.lifetime_key.capacity(),
                        )?;
                        let added = AnalysisExtractionV1::grow(
                            &mut output.missing_contexts,
                            output.input_bytes,
                            output.limits.input_bytes,
                        )?;
                        output.charge(added)?;
                        output.missing_contexts.push(key);
                    }
                }
            }
            for id in selection.profiles.as_slice() {
                control.check()?;
                let body = self
                    .read_result_from(snapshot, selection.tenant_id, id)?
                    .ok_or_else(|| self.state_error("the selected discovery profile is absent"))?;
                output.charge(body.capacity())?;
                let revision: u64 = snapshot
                    .query_row(
                        "SELECT commit_revision FROM analysis_results
                     WHERE tenant_id = ? AND processor_id = 'discovery' AND result_id = ?",
                        params![selection.tenant_id.as_slice(), id],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read discovery profile revision",
                    })?;
                let discovery_enabled = output.discovery_enabled;
                output.reference_result(id, revision, AnalysisReferenceOriginV1::Profile)?;
                capture.profile(id, &body, revision, selection.sources.as_slice(),
                    discovery_enabled, &mut output.sink(control))?;
            }
            if let Some(request) = &selection.graph_traversal {
                self.traverse_graphs(snapshot, selection, request, &mut output, control, &mut capture)?;
            }
            for id in selection.graphs.as_slice().iter().filter(|_| selection.graph_traversal.is_none()) {
                control.check()?;
                let (key, revision): (Vec<u8>, u64) = snapshot.query_row(
                    "SELECT stream_key, commit_revision FROM analysis_results
                     WHERE tenant_id = ? AND processor_id = ? AND method_version = ? AND result_id = ?
                        AND stream_key IS NOT NULL",
                    params![selection.tenant_id.as_slice(), crate::GRAPH_PROCESSOR, crate::GRAPH_SCHEMA_VERSION, id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                ).context(AnalysisDatabaseSnafu { operation: "read graph result metadata" })?;
                let source = selection.sources.as_slice().iter().find(|source| source.key() == key)
                    .ok_or_else(|| self.state_error("the graph result source is not selected"))?;
                let subjects = read.projected("graph_subjects").is_some();
                let edges = read.projected("relationships").is_some();
                let header = self.graph_input(snapshot, selection.tenant_id, id, &mut output, control)?;
                let mut graph = header.snapshot;
                if graph.scope.identity != *source { return self.reject("the graph source differs from its index"); }
                if !selection.permits_graph(&graph) { continue; }
                let sensitivity = self.graph_sensitivity(snapshot, &graph.input_manifest, control)?;
                if subjects {
                    graph.graph.subjects = super::graph_rows::GraphRows::read_subjects(snapshot, id, Some(control))?;
                    if graph.graph.subjects.len() != header.subject_count {
                        return self.reject("the selected graph subject count differs");
                    }
                }
                if edges {
                    graph.graph.edges = super::graph_rows::GraphRows::read_edges(snapshot, id, Some(control))?;
                    if graph.graph.edges.len() != header.edge_count {
                        return self.reject("the selected graph relationship count differs");
                    }
                }
                graph.validate()?;
                output.reference_result(id, revision, AnalysisReferenceOriginV1::Graph)?;
                capture.graph(id, &graph, header.subject_count, header.edge_count,
                    revision, sensitivity, None, &mut output.sink(control))?;
            }
            for key in selection.obligations.as_slice() {
                control.check()?;
                let (context, revision) = Self::read_context_from(snapshot, &self.root, key)?
                    .ok_or_else(|| self.state_error("the selected notification state is absent"))?;
                output.scan(context.body.len())?;
                output.charge(context.body.capacity().saturating_mul(2))?;
                let obligation = crate::NotificationObligationV1::try_from(&context)?;
                let finding = if let Some(reference) = &obligation.finding {
                    let metadata: Option<(Vec<u8>, u64)> = snapshot.query_row(
                        "SELECT stream_key, commit_revision FROM analysis_results
                         WHERE tenant_id = ? AND processor_id = ? AND method_version = ? AND result_id = ?
                            AND stream_key IS NOT NULL",
                        params![selection.tenant_id.as_slice(), crate::GRAPH_PROCESSOR,
                            crate::GRAPH_SCHEMA_VERSION, reference.result_id], |row| Ok((row.get(0)?, row.get(1)?)),
                    ).optional().context(AnalysisDatabaseSnafu {
                        operation: "read notification graph source",
                    })?;
                    if let Some((source_key, graph_revision)) = metadata {
                        let Some(source) = selection.sources.as_slice().iter().find(|source| source.key() == source_key) else { continue; };
                        let header = self.graph_input(snapshot, selection.tenant_id,
                            &reference.result_id, &mut output, control)?;
                        let mut graph = header.snapshot;
                        if graph.scope.identity != *source { return self.reject("the notification graph source differs from its index"); }
                        if !selection.permits_graph(&graph) { continue; }
                        output.reference_result(&reference.result_id, graph_revision, AnalysisReferenceOriginV1::Notification)?;
                        graph.findings.iter().position(|finding| finding.finding_id == reference.finding_id)
                            .map(|index| graph.findings.swap_remove(index))
                    } else if unscoped_notifications { None } else { continue; }
                } else if unscoped_notifications { None } else { continue; };
                if !selection.binding_ids.is_empty() && finding.as_ref().is_none_or(|finding| {
                    finding.effects.is_empty() || finding.effects.iter().any(|effect| {
                        effect.binding_id.is_none_or(|binding| !selection.binding_ids.contains(&binding))
                    })
                }) { continue; }
                output.reference_context(&context.key, revision, AnalysisReferenceOriginV1::Notification)?;
                capture.notification(&obligation, finding.as_ref(), revision, &mut output.sink(control))?;
            }
            for id in &selection.results {
                control.check()?;
                match self.read_result_from(snapshot, selection.tenant_id, id)? {
                    Some(_body) => {
                        let revision: u64 = snapshot.query_row(
                            "SELECT commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                            params![selection.tenant_id.as_slice(), id],
                            |row| row.get(0),
                        ).context(AnalysisDatabaseSnafu { operation: "read retained result revision" })?;
                        output.reference_result(id, revision, AnalysisReferenceOriginV1::ExplicitResult)?;

                    }
                    None => {
                        let id = id.clone();
                        output.charge(id.capacity())?;
                        let added = AnalysisExtractionV1::grow(
                            &mut output.missing_results,
                            output.input_bytes,
                            output.limits.input_bytes,
                        )?;
                        output.charge(added)?;
                        output.missing_results.push(id);
                    }
                }
            }
            if packages.is_some() {
                self.extract_provenance(snapshot, selection.tenant_id, &mut output, control)?;
            }
            control.check()?;
            capture.finish(output, after.unwrap_or(StorePositionV1 {
                    commit_revision: 0,
                    ordinal: 0,
                }), exhausted, control)
        })
    }

    fn selected_position(
        &self,
        selection: &AnalysisSelectionV1,
        after: Option<StorePositionV1>,
        revision: u64,
        limit: usize,
        control: &AnalysisReadControl,
    ) -> Result<Option<(RawIdentity, Option<u32>, SegmentRange)>> {
        control
            .lock(|| self.raw.try_lock())?
            .select_position(selection, after, revision, limit, control)
    }

    fn graph_sensitivity(
        &self,
        snapshot: &Connection,
        revision: &crate::GraphRevisionV1,
        control: &AnalysisReadControl,
    ) -> Result<crate::ContextSensitivityV1> {
        let mut sensitivity = crate::ContextSensitivityV1::Tenant;
        for key in &revision.context {
            control.check()?;
            let label: Option<String> = snapshot
                .query_row(
                    "SELECT sensitivity FROM context_versions WHERE tenant_id = ? AND owner_id = ?
                 AND entity_key = ? AND lifetime_key = ? AND owner_revision = ?",
                    params![
                        key.tenant_id.as_slice(),
                        key.owner_id,
                        key.entity_key.as_slice(),
                        key.lifetime_key.as_slice(),
                        key.owner_revision
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read graph context sensitivity",
                })?;
            let label =
                label.ok_or_else(|| self.state_error("the graph context version is absent"))?;
            let label = crate::ContextSensitivityV1::try_from(label.as_str())
                .map_err(|_| self.state_error("the graph context sensitivity is invalid"))?;
            if label == crate::ContextSensitivityV1::HostRestricted {
                sensitivity = label;
            }
        }
        Ok(sensitivity)
    }

    fn check_selected_source(
        &self,
        snapshot: &Connection,
        receipt: &AnalysisSourceReceiptV1,
        expired: &[AnalysisGapV1],
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let identity = &receipt.identity;
        let revision = Self::read_meta_from(snapshot, &self.root)?.commit_revision;
        let retained = control.lock(|| self.raw.try_lock())?.record_count(
            &identity.key(),
            1,
            receipt.contiguous_cursor,
            revision,
        );
        let covered = expired.iter().try_fold(retained, |count, gap| {
            gap.last_cursor
                .checked_sub(gap.first_cursor)
                .and_then(|bytes| bytes.checked_add(1))
                .and_then(|bytes| count.checked_add(bytes))
        });
        if covered != Some(receipt.contiguous_cursor) {
            return self.reject("the selected source has an unrecorded input gap");
        }
        Ok(())
    }

    fn extract_gaps(
        &self,
        snapshot: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        recovery: bool,
        control: &AnalysisReadControl,
        output: &mut AnalysisExtractionV1,
    ) -> Result<Vec<AnalysisGapV1>> {
        // Expired ranges have no time proof. A time filter cannot hide these gaps.
        let sql = if recovery {
            "SELECT first_cursor, last_cursor, commit_revision FROM recovery_gaps
             WHERE stream_key = ? AND tenant_id = ? ORDER BY first_cursor"
        } else {
            "SELECT first_cursor, last_cursor, commit_revision FROM expired_ranges
             WHERE stream_key = ? AND tenant_id = ? ORDER BY first_cursor"
        };
        let mut statement = snapshot.prepare(sql).context(AnalysisDatabaseSnafu {
            operation: "prepare selected coverage gaps",
        })?;
        let rows = statement
            .query_map(
                params![identity.key().as_slice(), identity.tenant_id.as_slice()],
                |row| {
                    Ok(AnalysisGapV1 {
                        first_cursor: row.get(0)?,
                        last_cursor: row.get(1)?,
                        commit_revision: row.get(2)?,
                    })
                },
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read selected coverage gaps",
            })?;
        let mut gaps = Vec::new();
        for row in rows {
            control.check()?;
            let added = AnalysisExtractionV1::grow(
                &mut gaps,
                output.input_bytes,
                output.limits.input_bytes,
            )?;
            output.charge(added)?;
            gaps.push(row.context(AnalysisDatabaseSnafu {
                operation: "decode selected coverage gap",
            })?);
        }
        Ok(gaps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisContextVersionV1, AnalysisResultCommitV1, ContextSensitivityV1,
        EvidenceRetentionOwner, ProcessorClassV1, ProcessorScopeV1, RetentionLimitsV1,
        ValidatedEvidenceBatchV1,
    };
    use araphor_analysis_sdk::arrow_array::{Array, BinaryArray, UInt32Array, UInt64Array};

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
                let schema = &AnalysisStore::table_schemas()[*name];
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
                inputs: None,
                mode,
                now: 0,
            },
            limits,
            control,
        )
    }

    fn unsigned(page: &AnalysisPositionPageV1, table: &str, field: &str) -> TestResult<Vec<u64>> {
        let mut values = Vec::new();
        for batch in page.tables.get(table).into_iter().flatten() {
            let array = batch
                .column_by_name(field)
                .ok_or("unsigned column absent")?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("column is not UInt64")?;
            assert_eq!(array.null_count(), 0);
            values.extend_from_slice(array.values());
        }
        Ok(values)
    }

    fn binary(page: &AnalysisPositionPageV1, table: &str, field: &str) -> TestResult<Vec<Vec<u8>>> {
        let mut values = Vec::new();
        for batch in page.tables.get(table).into_iter().flatten() {
            let array = batch
                .column_by_name(field)
                .ok_or("binary column absent")?
                .as_any()
                .downcast_ref::<BinaryArray>()
                .ok_or("column is not Binary")?;
            assert_eq!(array.null_count(), 0);
            for value in array {
                values.push(value.ok_or("binary value is null")?.to_vec());
            }
        }
        Ok(values)
    }

    fn positions(page: &AnalysisPositionPageV1) -> TestResult<Vec<StorePositionV1>> {
        let mut values = Vec::new();
        for batch in page.tables.get("events").into_iter().flatten() {
            let revisions = batch
                .column_by_name("commit_revision")
                .ok_or("commit revision absent")?
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("commit revision is not UInt64")?;
            let ordinals = batch
                .column_by_name("ordinal")
                .ok_or("ordinal absent")?
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or("ordinal is not UInt32")?;
            values.extend((0..batch.num_rows()).map(|index| StorePositionV1 {
                commit_revision: revisions.value(index),
                ordinal: ordinals.value(index),
            }));
        }
        Ok(values)
    }

    fn row_count(page: &AnalysisPositionPageV1, table: &str) -> usize {
        page.tables
            .get(table)
            .into_iter()
            .flatten()
            .map(RecordBatch::num_rows)
            .sum()
    }

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: "n".into(),
            ..crate::analysis::tests::identity()
        }
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
        selection.binding_ids.push([5; 16]);
        assert!(!selection.valid());
        selection
            .traces
            .exact_mut()
            .ok_or("exact traces absent")?
            .pop();
        assert!(selection.valid());
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
        selection.binding_ids.push([5; 16]);
        selection.traces = Selection::Exact(
            (1..=MAX_EXTRACT_KEYS as u128 - 5)
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
        selection.nodes = (0..MAX_EXTRACT_KEYS)
            .map(|index| format!("node-{index}"))
            .collect();
        assert!(selection.valid());
        selection.results.push("extra".into());
        assert!(!selection.valid());
        selection.results.pop();
        assert!(selection.valid());
        selection.nodes.push("extra-node".into());
        assert!(!selection.valid());
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
    fn analysis_exact_builtin_selection() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        store.enable_graph_owner()?;
        store.enable_notification_owner()?;
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
        let key = AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        };
        let mut exact = AnalysisSelectionV1::new([1; 16], Vec::new());
        exact.select_profiles(Selection::Exact(vec!["profile:exact".into()]))?;
        exact.select_graphs(Selection::Exact(vec!["graph:exact".into()]), None)?;
        exact.select_notifications(Selection::Exact(vec![key.clone()]))?;
        let mut reader = store.reader_until(&control)?;
        control.run(&mut reader, |snapshot| {
            let (resolved, bytes) =
                store.resolve_selection(snapshot, &exact, &control, usize::MAX)?;
            assert!(matches!(resolved, Cow::Borrowed(_)));
            assert_eq!(resolved.as_ref(), &exact);
            assert_eq!(bytes, 0);

            let mut expanded_sources = exact.clone();
            expanded_sources.sources = Selection::All;
            let (resolved, bytes) =
                store.resolve_selection(snapshot, &expanded_sources, &control, usize::MAX)?;
            assert_eq!(resolved.profiles(), &["profile:exact"]);
            assert_eq!(resolved.graphs(), &["graph:exact"]);
            assert_eq!(resolved.notification_keys(), &[key]);
            assert!(bytes >= resolved.allocation_bytes());
            Ok(())
        })?;
        drop(reader);

        let relations = exact.source_revisions(7);
        for expected in ["context_versions", "analysis_results", "graph_findings"] {
            assert!(relations
                .iter()
                .any(|(name, revision)| name == expected && *revision == 7));
        }
        let disabled = AnalysisSelectionV1::new([1; 16], Vec::new());
        store.release_graph_owner();
        store.release_notification_owner();
        let mut reader = store.reader_until(&control)?;
        control.run(&mut reader, |snapshot| {
            assert!(store
                .resolve_selection(snapshot, &disabled, &control, usize::MAX)
                .is_ok());
            for selection in [
                {
                    let mut selection = disabled.clone();
                    selection.select_graphs(Selection::Exact(vec!["graph:exact".into()]), None)?;
                    selection
                },
                {
                    let mut selection = disabled.clone();
                    selection.select_notifications(exact.obligations.clone())?;
                    selection
                },
            ] {
                assert!(matches!(
                    store.resolve_selection(snapshot, &selection, &control, usize::MAX),
                    Err(crate::Error::AnalysisUnavailable { .. })
                ));
            }
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn analysis_exact_graph_history() -> TestResult {
        use super::super::graph_rows::{tests::fixture::CommitFixture, GraphRows};

        let fixture = CommitFixture::new()?;
        fixture.store.commit_graph(&fixture.request, true)?;
        let mut snapshot = fixture.snapshot.clone();
        snapshot.previous_result_id = Some(fixture.request.result_id.clone());
        snapshot.graph.edges.clear();
        let mut replacement = fixture.request.clone();
        replacement.result_id = "graph:replacement".into();
        replacement.expected_cursor = replacement.consumed_cursor;
        replacement.created_utc_ns += 1;
        replacement.body = serde_json::to_vec(&snapshot)?;
        fixture.store.commit_graph(&replacement, false)?;
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
        let source = fixture.snapshot.scope.identity.clone();
        let ids = vec![
            fixture.request.result_id.clone(),
            replacement.result_id.clone(),
        ];
        let mut exact = AnalysisSelectionV1::new(source.tenant_id, vec![source]);
        exact.select_graphs(Selection::Exact(ids.clone()), None)?;
        let mut reader = fixture.store.reader_until(&control)?;
        control.run(&mut reader, |reader| {
            let (resolved, _) =
                fixture
                    .store
                    .resolve_selection(reader, &exact, &control, usize::MAX)?;
            assert_eq!(resolved.graphs(), ids);
            let mut read = Vec::new();
            GraphRows::visit_headers(
                reader,
                exact.tenant_id,
                resolved.graphs(),
                usize::MAX,
                &control,
                |id, _, _, _| {
                    read.push(id.to_owned());
                    Ok(())
                },
            )?;
            read.sort();
            let mut expected = ids.clone();
            expected.sort();
            assert_eq!(read, expected);

            let mut all = exact.clone();
            all.select_graphs(Selection::All, None)?;
            let (resolved, _) =
                fixture
                    .store
                    .resolve_selection(reader, &all, &control, usize::MAX)?;
            assert_eq!(resolved.graphs(), &[replacement.result_id]);
            Ok(())
        })?;
        Ok(())
    }

    fn batch(first: u64, count: usize, received: u64) -> Result<ValidatedEvidenceBatchV1> {
        records(
            first,
            received,
            (first..first + count as u64).map(|cursor| EvidenceRecord {
                observed_boottime_ns: cursor,
                ..Default::default()
            }),
        )
    }

    fn records(
        first: u64,
        received: u64,
        records: impl IntoIterator<Item = EvidenceRecord>,
    ) -> Result<ValidatedEvidenceBatchV1> {
        let mut framed = Vec::new();
        let mut ends = Vec::new();
        for record in records {
            framed.extend(Vec::<u8>::try_from(&record)?);
            ends.push(framed.len());
        }
        Ok(ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: first,
            last_cursor: first + ends.len() as u64 - 1,
            intake_utc_ns: received,
            framed_records: framed.into(),
            frame_ends: ends,
        })
    }

    fn padded_batch(
        first: u64,
        count: usize,
        received: u64,
        frame_bytes: usize,
    ) -> ValidatedEvidenceBatchV1 {
        use prost::Message as _;

        let mut framed = Vec::new();
        let mut ends = Vec::new();
        for cursor in first..first + count as u64 {
            let record = EvidenceRecord {
                observed_boottime_ns: cursor,
                decision_context: Some(crate::EvidenceDecisionContext {
                    catalog_json: vec![7; frame_bytes - 128],
                    ..Default::default()
                }),
                ..Default::default()
            };
            let mut payload = record.encode_to_vec();
            let mut padding = vec![0; frame_bytes - 8 - payload.len()];
            let overhead = prost::encoding::bytes::encoded_len(100, &padding) - padding.len();
            padding.truncate(padding.len() - overhead);
            prost::encoding::bytes::encode(100, &padding, &mut payload);
            assert_eq!(payload.len() + 8, frame_bytes);
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend(payload);
            frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
            assert!(EvidenceRecord::try_from(frame.as_slice()).is_ok());
            framed.extend(frame);
            ends.push(framed.len());
        }
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: first,
            last_cursor: first + count as u64 - 1,
            intake_utc_ns: received,
            framed_records: framed.into(),
            frame_ends: ends,
        }
    }

    #[test]
    fn query_input_pending_positions() -> TestResult {
        use prost::Message as _;

        let directory = tempfile::tempdir()?;
        let store = std::sync::Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(11, 10, 10)?)?;
        let report = crate::CoverageReport {
            source_id: identity.source_id.to_vec(),
            source_epoch: identity.source_epoch,
            revision: 1,
            ..Default::default()
        }
        .encode_to_vec();
        store.accept_validated_coverage(crate::ValidatedCoverageV1 {
            identity: identity.clone(),
            cpu_id: 0,
            revision: 1,
            encoded_report: report.clone(),
        })?;
        assert!(store.read_page(&identity, 1)?.records.is_empty());
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let fields = [(
            "events",
            &[
                "source_cursor",
                "received_utc_ns",
                "commit_revision",
                "ordinal",
            ][..],
        )];
        let complete = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(row_count(&complete, "events"), 10);
        assert!(complete.exhausted);
        let before = store.meta()?;
        let control = AnalysisReadControl::default();
        let writer = std::sync::Arc::clone(&store);
        let source = identity.clone();
        control.on_read_step(move || {
            writer.accept_validated_batch(source, batch(1, 10, 20)?)?;
            Ok(())
        })?;
        let first = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(None),
            AnalysisExtractLimits::default(),
            &control,
        )?;
        assert_eq!(first.extraction.meta, before);
        assert!(first.exhausted);
        assert_eq!(first.extraction.sources[0].receipt.contiguous_cursor, 0);
        assert_eq!(
            first.extraction.sources[0].coverage_report.as_deref(),
            Some(report.as_slice())
        );
        assert_eq!(first.extraction.sources[0].pending.len(), 1);
        assert_eq!(
            (
                first.extraction.sources[0].pending[0].first_cursor,
                first.extraction.sources[0].pending[0].last_cursor
            ),
            (1, 10)
        );
        assert_eq!(
            unsigned(&first, "events", "source_cursor")?,
            (11..=20).collect::<Vec<_>>()
        );
        assert_eq!(unsigned(&first, "events", "received_utc_ns")?, vec![10; 10]);
        let mut ordered_positions = positions(&first)?;
        let next = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(Some(first.scanned_through)),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(next.exhausted);
        assert_eq!(next.extraction.sources[0].receipt.contiguous_cursor, 20);
        assert!(next.extraction.sources[0].pending.is_empty());
        assert_eq!(
            unsigned(&next, "events", "source_cursor")?,
            (1..=10).collect::<Vec<_>>()
        );
        assert_eq!(unsigned(&next, "events", "received_utc_ns")?, vec![20; 10]);
        assert!(positions(&next)?
            .iter()
            .all(|position| *position > first.scanned_through));
        ordered_positions.extend(positions(&next)?);
        assert!(ordered_positions.windows(2).all(|pair| pair[0] < pair[1]));
        let ordered = store.read_page(&identity, 1)?;
        assert_eq!(
            ordered
                .records
                .iter()
                .map(|record| record.cursor)
                .collect::<Vec<_>>(),
            (1..=20).collect::<Vec<_>>()
        );
        assert_eq!(ordered.records[10].position, ordered_positions[0]);
        assert_eq!(ordered.records[0].position, ordered_positions[10]);
        let meta = store.meta()?;
        store.accept_validated_batch(identity.clone(), batch(11, 10, 10)?)?;
        assert_eq!(store.meta()?, meta);
        let retry = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(Some(next.scanned_through)),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(retry.exhausted && row_count(&retry, "events") == 0);
        assert_eq!(retry.scanned_through, next.scanned_through);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn query_scope_position_pages() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        let other = EvidenceIntakeIdentityV1 {
            source_epoch: 2,
            ..identity.clone()
        };
        let foreign = EvidenceIntakeIdentityV1 {
            tenant_id: [2; 16],
            ..identity.clone()
        };
        store.accept_validated_batch(identity.clone(), batch(1, 257, 10)?)?;
        let first_revision = store.meta()?.commit_revision;
        store.accept_validated_batch(foreign, batch(1, 1, 10)?)?;
        store.accept_validated_batch(other.clone(), batch(1, 1, 20)?)?;
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![other, identity.clone()]);
        let first = read(
            &store,
            &selection,
            &[("events", &[])],
            AnalysisReadModeV1::Page(None),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(!first.exhausted);
        assert_eq!(row_count(&first, "events"), 256);
        assert!(first.tables["events"]
            .iter()
            .all(|batch| batch.num_columns() == 0));
        assert_eq!(
            first.scanned_through,
            StorePositionV1 {
                commit_revision: first_revision,
                ordinal: 255
            }
        );
        let next = read(
            &store,
            &selection,
            &[(
                "events",
                &[
                    "source_epoch",
                    "source_cursor",
                    "commit_revision",
                    "ordinal",
                ],
            )],
            AnalysisReadModeV1::Page(Some(first.scanned_through)),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(next.exhausted);
        assert_eq!(unsigned(&next, "events", "source_epoch")?, vec![1, 2]);
        assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![257, 1]);
        let seen = positions(&next)?;
        assert!(seen[0] > first.scanned_through);
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            next.scanned_through.commit_revision,
            store.meta()?.commit_revision
        );
        assert_eq!(next.scanned_through.ordinal, u32::MAX);
        Ok(())
    }

    #[test]
    fn query_input_sparse_positions() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        for cursor in [3, 7] {
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, 1)?)?;
        }
        store.accept_validated_batch(identity.clone(), batch(1, 10, 2)?)?;
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let fields = [(
            "events",
            &["source_cursor", "commit_revision", "ordinal"][..],
        )];
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(None),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        let expected = [3, 7, 1, 2, 4, 5, 6, 8, 9, 10];
        assert!(page.exhausted);
        assert_eq!(page.scanned_through.ordinal, u32::MAX);
        assert_eq!(unsigned(&page, "events", "source_cursor")?, expected);
        for (index, position) in positions(&page)?.into_iter().enumerate() {
            let next = read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Page(Some(position)),
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
            )?;
            assert!(next.exhausted);
            assert_eq!(
                unsigned(&next, "events", "source_cursor")?,
                expected[index + 1..]
            );
        }
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("source absent")?
                .contiguous_cursor,
            10
        );
        Ok(())
    }

    #[test]
    fn query_input_page_resume() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(
            identity.clone(),
            records(
                1,
                1,
                (1..=3).map(|cursor| EvidenceRecord {
                    observed_boottime_ns: cursor,
                    decision_context: Some(crate::EvidenceDecisionContext {
                        binding_id: vec![if cursor == 2 { 2 } else { 1 }; 16],
                        catalog_json: vec![cursor as u8; 768],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            )?,
        )?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity]);
        selection.binding_ids.push([1; 16]);
        let fields = [(
            "events",
            &[
                "source_cursor",
                "catalog_json",
                "commit_revision",
                "ordinal",
            ][..],
        )];
        let limits = AnalysisExtractLimits {
            page_bytes: 1024,
            ..Default::default()
        };
        let first = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(None),
            limits,
            &AnalysisReadControl::default(),
        )?;
        assert!(!first.exhausted);
        assert_eq!(unsigned(&first, "events", "source_cursor")?, vec![1]);
        assert_eq!(
            binary(&first, "events", "catalog_json")?,
            vec![vec![1; 768]]
        );
        let first_position = positions(&first)?[0];
        assert_eq!(
            first.scanned_through,
            StorePositionV1 {
                ordinal: 1,
                ..first_position
            }
        );
        let next = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(Some(first.scanned_through)),
            limits,
            &AnalysisReadControl::default(),
        )?;
        assert!(next.exhausted);
        assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![3]);
        assert_eq!(binary(&next, "events", "catalog_json")?, vec![vec![3; 768]]);
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Page(None),
                AnalysisExtractLimits {
                    page_bytes: 767,
                    ..limits
                },
                &AnalysisReadControl::default()
            ),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "projected row bytes",
                ..
            })
        ));
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_rotation() -> TestResult {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir()?;
        let store = std::sync::Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let first = identity(1);
        let rotating = EvidenceIntakeIdentityV1 {
            source_epoch: 2,
            ..first.clone()
        };
        store.accept_validated_batch(first.clone(), batch(1, 1, 10)?)?;
        for cursor in [1, 33, 65] {
            store.accept_validated_batch(
                rotating.clone(),
                padded_batch(cursor, 32, 10, 128 * 1024),
            )?;
        }
        let before = store.meta()?;
        let selection = AnalysisSelectionV1::new(first.tenant_id, vec![first, rotating.clone()]);
        let (start, started) = mpsc::channel();
        let (rotate, rotation) = mpsc::channel();
        store.set_commit_hook(
            super::super::AnalysisCommitStage::BeforeRotation,
            move || {
                rotate
                    .send(())
                    .map_err(|_| crate::AnalysisReadCancelledSnafu.build())
            },
        )?;
        let fields = [("events", &["source_epoch", "source_cursor"][..])];
        std::thread::scope(|scope| -> TestResult {
            let writer_store = std::sync::Arc::clone(&store);
            let writer = scope.spawn(move || {
                started.recv_timeout(Duration::from_secs(2)).map_err(|_| {
                    writer_store.state_error("the reader did not reach its barrier")
                })?;
                writer_store.accept_validated_batch(rotating, padded_batch(97, 32, 10, 128 * 1024))
            });
            let control = AnalysisReadControl::default();
            control.on_read_step(move || {
                start
                    .send(())
                    .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                rotation
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
                Ok(())
            })?;
            let output = read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits::default(),
                &control,
            );
            assert_eq!(
                writer.join().map_err(|_| "writer panicked")??,
                crate::EvidenceStoreOutcomeV1::Accepted
            );
            let output = output?;
            assert_eq!(output.extraction.meta, before);
            assert_eq!(output.extraction.sources[1].receipt.contiguous_cursor, 96);
            let cursors = unsigned(&output, "events", "source_cursor")?;
            assert_eq!(
                cursors,
                std::iter::once(1).chain(1..=96).collect::<Vec<_>>()
            );
            assert_eq!(
                unsigned(&output, "events", "source_epoch")?,
                std::iter::once(1)
                    .chain(std::iter::repeat_n(2, 96))
                    .collect::<Vec<_>>()
            );
            Ok(())
        })?;
        let later = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            later.extraction.meta.commit_revision,
            before.commit_revision + 1
        );
        assert_eq!(later.extraction.sources[1].receipt.contiguous_cursor, 128);
        assert_eq!(
            unsigned(&later, "events", "source_cursor")?,
            std::iter::once(1).chain(1..=128).collect::<Vec<_>>()
        );
        assert_eq!(
            unsigned(&later, "events", "source_epoch")?,
            std::iter::once(1)
                .chain(std::iter::repeat_n(2, 128))
                .collect::<Vec<_>>()
        );
        assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 3);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_lock_waits() -> TestResult {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1)?)?;
        let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
        let reader = store.reader()?;
        for access in 0..3 {
            for cancelled in [false, true] {
                let (ready, held) = mpsc::channel();
                let (release, released) = mpsc::channel();
                let (waiting, blocked) = mpsc::channel();
                let control = if cancelled {
                    AnalysisReadControl::default()
                } else {
                    AnalysisReadControl::with_timeout(Duration::from_millis(50))?
                };
                *control
                    .wait_signal
                    .lock()
                    .map_err(|_| "wait signal poisoned")? = Some(waiting);
                std::thread::scope(|scope| -> TestResult {
                    let store = &store;
                    let control = &control;
                    let holder = scope.spawn(move || -> Result<()> {
                        let _raw = store
                            .raw
                            .lock()
                            .map_err(|_| store.state_error("raw lock poisoned"))?;
                        ready
                            .send(())
                            .map_err(|_| store.state_error("the lock check stopped"))?;
                        blocked.recv_timeout(Duration::from_secs(2)).map_err(|_| {
                            store.state_error("the reader did not wait for raw access")
                        })?;
                        if cancelled {
                            control.cancel()?;
                        }
                        released.recv_timeout(Duration::from_secs(3)).map_err(|_| {
                            store.state_error("the reader did not return while raw access was held")
                        })?;
                        Ok(())
                    });
                    held.recv_timeout(Duration::from_secs(2))?;
                    let result = match access {
                        0 => store
                            .selected_position(
                                &AnalysisSelectionV1::new(
                                    identity.tenant_id,
                                    vec![identity.clone()],
                                ),
                                None,
                                1,
                                1,
                                control,
                            )
                            .map(|_| ()),
                        1 => store.check_selected_source(reader.get()?, &receipt, &[], control),
                        _ => store.read_coordinator(control).map(|_| ()),
                    };
                    let _sent = release.send(());
                    holder.join().map_err(|_| "lock holder panicked")??;
                    assert!(match result {
                        Err(crate::Error::AnalysisReadCancelled { .. }) => cancelled,
                        Err(crate::Error::AnalysisReadDeadline { .. }) => !cancelled,
                        _ => false,
                    });
                    Ok(())
                })?;
            }
        }
        drop(reader);
        store.accept_validated_batch(identity.clone(), batch(2, 1, 2)?)?;
        assert_eq!(store.read_page(&identity, 1)?.records.len(), 2);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_selection() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        for (cursor, received) in [(1, 10), (2, 30), (3, 20)] {
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, received)?)?;
        }
        let foreign = EvidenceIntakeIdentityV1 {
            tenant_id: [9; 16],
            ..identity.clone()
        };
        store.accept_validated_batch(foreign.clone(), batch(1, 1, 20)?)?;
        let before = store.meta()?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(20);
        selection.received_until = Bound::Excluded(30);
        let fields = [(
            "events",
            &["tenant_id", "source_cursor", "received_utc_ns", "cpu_id"][..],
        )];
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(page.extraction.meta, before);
        assert!(page.exhausted);
        assert_eq!(
            page.extraction.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .filter(|entry| entry.identity == identity && entry.commit.intake == 20)
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(unsigned(&page, "events", "source_cursor")?, vec![3]);
        assert_eq!(unsigned(&page, "events", "received_utc_ns")?, vec![20]);
        assert_eq!(
            binary(&page, "events", "tenant_id")?,
            vec![identity.tenant_id.to_vec()]
        );
        let mut cpus = Vec::new();
        for batch in &page.tables["events"] {
            let values = batch
                .column_by_name("cpu_id")
                .ok_or("CPU column absent")?
                .as_any()
                .downcast_ref::<UInt32Array>()
                .ok_or("CPU column is not UInt32")?;
            cpus.extend_from_slice(values.values());
        }
        assert_eq!(cpus, vec![0]);
        assert_eq!(page.extraction.projected_bytes, (5 + 16) + 9 + 9 + 5);
        assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 3);
        assert_eq!(store.meta()?, before);
        for (from, until) in [
            (Bound::Excluded(u64::MAX), Bound::Unbounded),
            (Bound::Unbounded, Bound::Excluded(0)),
            (Bound::Included(31), Bound::Included(30)),
        ] {
            selection.received_from = from;
            selection.received_until = until;
            let empty = read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(row_count(&empty, "events"), 0);
            assert_eq!(empty.extraction.scanned_bytes, 0);
        }
        selection.sources = Selection::Exact(Vec::new());
        let empty = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(row_count(&empty, "events"), 0);
        selection.sources = Selection::Exact(vec![foreign]);
        assert!(read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )
        .is_err());
        selection.sources = Selection::Exact(vec![identity.clone(), identity]);
        assert!(read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )
        .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_tenant_snapshot() -> TestResult {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let first = identity(1);
        store.accept_validated_batch(first.clone(), batch(1, 1, 10)?)?;
        store.accept_validated_batch(identity(2), batch(1, 1, 10)?)?;
        let next = EvidenceIntakeIdentityV1 {
            source_id: [4; 16],
            node_boot_id: [5; 16],
            ..first.clone()
        };
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: first.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![42],
        };
        let selection = AnalysisSelectionV1::tenant(first.tenant_id);
        let fields = [
            ("events", &["source_id"][..]),
            ("context_versions", &["body"][..]),
        ];
        let before = store.meta()?;
        let control = AnalysisReadControl::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let writer = Arc::clone(&store);
        let late = next.clone();
        control.on_read_step(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            writer.accept_validated_batch(late, batch(1, 1, 20)?)?;
            writer.commit_context(&context)?;
            Ok(())
        })?;
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control,
        )?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(page.extraction.meta, before);
        assert_eq!(page.extraction.sources.len(), 1);
        assert_eq!(
            binary(&page, "events", "source_id")?,
            vec![first.source_id.to_vec()]
        );
        assert_eq!(row_count(&page, "context_versions"), 0);
        assert!(page.extraction.missing_contexts.is_empty());
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(page.extraction.sources.len(), 2);
        assert_eq!(
            binary(&page, "events", "source_id")?,
            vec![first.source_id.to_vec(), next.source_id.to_vec()]
        );
        assert_eq!(binary(&page, "context_versions", "body")?, vec![vec![42]]);
        let empty = read(
            &store,
            &AnalysisSelectionV1::new(first.tenant_id, vec![]),
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            row_count(&empty, "events") + row_count(&empty, "context_versions"),
            0
        );
        Ok(())
    }

    #[test]
    fn analysis_tenant_key_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let first = identity(1);
        store.accept_validated_batch(first.clone(), batch(1, 1, 10)?)?;
        let mut selection = AnalysisSelectionV1::tenant(first.tenant_id);
        selection.contexts = Selection::Exact(
            (0..MAX_EXTRACT_KEYS - 1)
                .map(|revision| AnalysisContextKeyV1 {
                    tenant_id: first.tenant_id,
                    owner_id: "policy".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![2],
                    owner_revision: revision as u64,
                })
                .collect(),
        );
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
        let fields = [
            ("events", &["source_cursor"][..]),
            ("context_versions", &["body"][..]),
        ];
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Metadata,
            AnalysisExtractLimits::default(),
            &control,
        )?;
        assert_eq!(page.extraction.sources.len(), 1);
        assert_eq!(page.extraction.missing_contexts.len(), MAX_EXTRACT_KEYS - 1);
        assert_eq!(page.extraction.scanned_bytes, 0);
        assert!(page.exhausted);
        let next = EvidenceIntakeIdentityV1 {
            source_id: [4; 16],
            ..first.clone()
        };
        store.accept_validated_batch(next, batch(1, 1, 20)?)?;
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Metadata,
                AnalysisExtractLimits::default(),
                &control
            ),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input keys",
                ..
            })
        ));
        let selection = AnalysisSelectionV1::tenant(first.tenant_id);
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits {
                    input_bytes: size_of::<AnalysisSelectionV1>() - 1,
                    ..Default::default()
                },
                &control
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits::default(),
                &cancelled
            ),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        let mut invalid = selection.clone();
        invalid.sources = Selection::Exact(vec![first.clone(), first.clone()]);
        assert!(!invalid.valid());
        let mut invalid = selection.clone();
        invalid.nodes = vec![first.node_id.clone(), first.node_id];
        assert!(!invalid.valid());
        let mut invalid = selection;
        invalid.nodes.push(String::new());
        assert!(!invalid.valid());
        Ok(())
    }

    #[test]
    fn analysis_extract_snapshot() -> TestResult {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 10)?)?;
        let scope = ProcessorScopeV1 {
            processor_id: "p".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let context = AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: identity.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 0,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![42],
        };
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.contexts = Selection::Exact(vec![context.key.clone()]);
        selection.results.push("late".into());
        let key = context.key.clone();
        let before = store.meta()?;
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let writer = Arc::clone(&store);
        let source = identity.clone();
        control.on_read_step(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            writer.accept_validated_batch(source, batch(2, 1, 5)?)?;
            writer.commit_context(&context)?;
            writer.commit_result(&AnalysisResultCommitV1 {
                body: vec![43],
                created_utc_ns: 20,
                ..crate::analysis::tests::result(scope, "late".into())
            })?;
            Ok(())
        })?;
        let fields = [
            ("events", &["source_cursor"][..]),
            ("context_versions", &["body"][..]),
        ];
        let first = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control,
        )?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.extraction.meta, before);
        assert_eq!(first.extraction.sources[0].receipt.contiguous_cursor, 1);
        assert_eq!(first.extraction.missing_contexts, vec![key]);
        assert_eq!(first.extraction.missing_results, vec!["late"]);
        assert_eq!(unsigned(&first, "events", "source_cursor")?, vec![1]);
        assert_eq!(row_count(&first, "context_versions"), 0);
        assert!(first
            .extraction
            .references
            .iter()
            .all(|entry| entry.result().is_none()));
        let result_revision = store.meta()?.commit_revision;
        let next = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control,
        )?;
        assert!(
            next.extraction.missing_contexts.is_empty()
                && next.extraction.missing_results.is_empty()
        );
        assert_eq!(next.extraction.meta, store.meta()?);
        assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![1, 2]);
        assert_eq!(binary(&next, "context_versions", "body")?, vec![vec![42]]);
        let reference = next
            .extraction
            .references
            .iter()
            .find(|entry| entry.result().is_some())
            .ok_or("result reference absent")?;
        let result = reference.result().ok_or("result reference absent")?;
        assert_eq!(result.result_id, "late");
        assert_eq!(result.commit_revision, result_revision);
        assert_eq!(
            reference.origins(),
            &[AnalysisReferenceOriginV1::ExplicitResult]
        );
        assert_eq!(
            store.read_result(identity.tenant_id, "late")?,
            Some(vec![43])
        );
        selection.received_from = Bound::Included(100);
        let later = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control,
        )?;
        assert_eq!(later.extraction.scanned_bytes, 0);
        assert_eq!(row_count(&later, "events"), 0);
        assert_eq!(binary(&later, "context_versions", "body")?, vec![vec![42]]);
        let reference = later
            .extraction
            .references
            .iter()
            .find_map(AnalysisReferenceV1::result)
            .ok_or("result reference absent")?;
        assert_eq!(reference.result_id, "late");
        assert_eq!(reference.commit_revision, result_revision);
        assert!(
            later.extraction.missing_contexts.is_empty()
                && later.extraction.missing_results.is_empty()
        );
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_range_pages() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        for cursor in 1..=257 {
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, 10)?)?;
        }
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let fields = [("events", &["source_cursor"][..])];
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            page.extraction.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert!(page.exhausted);
        assert_eq!(
            unsigned(&page, "events", "source_cursor")?,
            (1..=257).collect::<Vec<_>>()
        );
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits {
                    input_bytes: page.extraction.projected_bytes,
                    ..Default::default()
                },
                &AnalysisReadControl::default()
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        let mut selection = AnalysisSelectionV1::new(
            identity.tenant_id,
            (1..=MAX_EXTRACT_KEYS)
                .map(|epoch| EvidenceIntakeIdentityV1 {
                    source_epoch: epoch as u64,
                    ..identity.clone()
                })
                .collect(),
        );
        assert!(selection.valid());
        selection
            .sources
            .exact_mut()
            .ok_or("exact sources absent")?
            .push(EvidenceIntakeIdentityV1 {
                source_epoch: MAX_EXTRACT_KEYS as u64 + 1,
                ..identity
            });
        assert!(!selection.valid());
        Ok(())
    }

    #[test]
    fn analysis_extract_file_faults() -> TestResult {
        use std::os::unix::fs::FileExt as _;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1)?)?;
        let (path, offset) = {
            let reader = store.reader()?;
            let ranges = store.raw_ranges(reader.get()?, &identity, 1, 1, 1)?;
            let range = ranges.first().ok_or("batch absent")?;
            (
                SegmentRange::path(&store.root, range.segment_id),
                range.byte_start,
            )
        };
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity]);
        let fields = [("events", &["source_cursor"][..])];
        let hidden = directory.path().join("hidden.seg");
        std::fs::rename(&path, &hidden)?;
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default()
            ),
            Err(crate::Error::Io { .. })
        ));
        std::fs::rename(&hidden, &path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;
        let mut original = [0];
        file.read_exact_at(&mut original, offset)?;
        file.write_all_at(&[original[0] ^ 0xff], offset)?;
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default()
            ),
            Err(crate::Error::AnalysisState { .. })
        ));
        file.write_all_at(&original, offset)?;
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(unsigned(&page, "events", "source_cursor")?, vec![1]);
        assert!(page.exhausted);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_gaps() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: Some(1024),
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1)?)?;
        store.backup(&store.root.join("backups/sealed"))?;
        store.accept_validated_batch(identity.clone(), batch(2, 1, 100)?)?;
        EvidenceRetentionOwner::new(&store).retain(&identity, 3)?;
        store.record_recovery_floor(&identity, 4)?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(99);
        let fields = [("events", &["source_cursor"][..])];
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(page.extraction.input_bytes >= owned_bytes(&page));
        assert_eq!(unsigned(&page, "events", "source_cursor")?, vec![2]);
        assert_eq!(
            page.extraction.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .filter(|entry| entry.commit.intake == 20 || entry.commit.intake == 100)
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(page.extraction.sources[0].expired.len(), 1);
        assert_eq!(
            (
                page.extraction.sources[0].expired[0].first_cursor,
                page.extraction.sources[0].expired[0].last_cursor
            ),
            (1, 1)
        );
        assert_eq!(
            (
                page.extraction.sources[0].recovery[0].first_cursor,
                page.extraction.sources[0].recovery[0].last_cursor
            ),
            (3, 4)
        );
        store
            .raw
            .lock()
            .map_err(|_| "raw lock poisoned")?
            .ranges
            .remove(&(identity.key(), 2));
        assert!(read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )
        .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    fn owned_bytes(page: &AnalysisPositionPageV1) -> usize {
        page.extraction.allocation_bytes()
            + page
                .tables
                .values()
                .map(|batches| {
                    batches.capacity() * size_of::<RecordBatch>()
                        + batches
                            .iter()
                            .map(|batch| {
                                batch.num_columns()
                                    * size_of::<araphor_analysis_sdk::arrow_array::ArrayRef>()
                                    + batch.get_array_memory_size()
                            })
                            .sum::<usize>()
                })
                .sum::<usize>()
    }

    #[test]
    fn query_input_allocation_bounds() -> TestResult {
        use prost::Message as _;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(11, 4, 10)?)?;
        store.accept_validated_coverage(crate::ValidatedCoverageV1 {
            identity: identity.clone(),
            cpu_id: 0,
            revision: 1,
            encoded_report: crate::CoverageReport {
                source_id: identity.source_id.to_vec(),
                source_epoch: identity.source_epoch,
                revision: 1,
                ..Default::default()
            }
            .encode_to_vec(),
        })?;
        store.record_recovery_floor(&identity, 5)?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        for revision in 0..4 {
            selection
                .contexts
                .exact_mut()
                .ok_or("exact contexts absent")?
                .push(AnalysisContextKeyV1 {
                    tenant_id: identity.tenant_id,
                    owner_id: "missing".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![2],
                    owner_revision: revision,
                });
            selection.results.push(format!("missing-{revision}"));
        }
        let fields = [
            ("events", &["source_cursor"][..]),
            ("context_versions", &["body"][..]),
        ];
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(page.extraction.input_bytes >= owned_bytes(&page));
        assert_eq!(
            unsigned(&page, "events", "source_cursor")?,
            vec![11, 12, 13, 14]
        );
        assert_eq!(page.extraction.sources[0].pending.len(), 1);
        assert_eq!(page.extraction.sources[0].recovery.len(), 1);
        assert_eq!(page.extraction.missing_contexts.len(), 4);
        assert_eq!(page.extraction.missing_results.len(), 4);
        let before = store.meta()?;
        let mut rejected = 0;
        let mut admitted = MAX_INPUT_BYTES;
        while rejected + 1 < admitted {
            let limit = rejected + (admitted - rejected) / 2;
            match read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits {
                    input_bytes: limit,
                    ..Default::default()
                },
                &AnalysisReadControl::default(),
            ) {
                Ok(page) => {
                    assert!(page.extraction.input_bytes <= limit);
                    assert!(page.extraction.input_bytes >= owned_bytes(&page));
                    assert_eq!(row_count(&page, "events"), 4);
                    admitted = limit;
                }
                Err(crate::Error::AnalysisInputTooLarge { .. }) => rejected = limit,
                Err(error) => return Err(error.into()),
            }
        }
        let page = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits {
                input_bytes: admitted,
                ..Default::default()
            },
            &AnalysisReadControl::default(),
        )?;
        assert!(page.extraction.input_bytes <= admitted);
        assert!(page.extraction.input_bytes >= owned_bytes(&page));
        assert_eq!(
            unsigned(&page, "events", "source_cursor")?,
            vec![11, 12, 13, 14]
        );
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits {
                    input_bytes: admitted - 1,
                    ..Default::default()
                },
                &AnalysisReadControl::default()
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.maintenance.try_write().is_ok());
        let recovered = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            unsigned(&recovered, "events", "source_cursor")?,
            vec![11, 12, 13, 14]
        );
        Ok(())
    }

    #[test]
    fn analysis_extract_limits() -> TestResult {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 257, 1)?)?;
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let fields = [("events", &["source_cursor"][..])];
        let before = store.meta()?;
        let complete = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            unsigned(&complete, "events", "source_cursor")?,
            (1..=257).collect::<Vec<_>>()
        );
        assert!(complete.exhausted);
        let first = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(None),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(row_count(&first, "events"), 256);
        assert!(!first.exhausted);
        let next = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(Some(first.scanned_through)),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(unsigned(&next, "events", "source_cursor")?, vec![257]);
        assert!(next.exhausted);
        assert!(next.scanned_through > first.scanned_through);
        assert_eq!(
            complete.extraction.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        let control = Arc::new(AnalysisReadControl::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let cancel = Arc::clone(&control);
        control.on_read_step(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            cancel.cancel()
        })?;
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Complete,
                AnalysisExtractLimits::default(),
                &control
            ),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let empty = read(
            &store,
            &AnalysisSelectionV1::new(identity.tenant_id, vec![]),
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(row_count(&empty, "events"), 0);
        let mut output = empty.extraction;
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
        let first = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Page(None),
            AnalysisExtractLimits {
                page_bytes: 9,
                ..Default::default()
            },
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(unsigned(&first, "events", "source_cursor")?, vec![1]);
        assert_eq!(first.extraction.projected_bytes, 9);
        assert!(!first.exhausted);
        let next = read(
            &store,
            &selection,
            &[("events", &[])],
            AnalysisReadModeV1::Page(Some(first.scanned_through)),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(row_count(&next, "events"), 256);
        assert!(next.tables["events"]
            .iter()
            .all(|batch| batch.num_columns() == 0));
        assert!(next.exhausted);
        assert!(next.scanned_through > first.scanned_through);
        assert!(matches!(
            read(
                &store,
                &selection,
                &fields,
                AnalysisReadModeV1::Page(None),
                AnalysisExtractLimits {
                    page_bytes: 8,
                    ..Default::default()
                },
                &AnalysisReadControl::default()
            ),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "projected row bytes",
                ..
            })
        ));
        assert_eq!(store.meta()?, before);
        assert!(store.maintenance.try_write().is_ok());
        store.checkpoint()?;
        Ok(())
    }

    #[test]
    #[ignore = "release history scan qualification"]
    fn analysis_extract_history() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: Some(1),
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        let identity = identity(1);
        let frame_bytes = 128 * 1024;
        for group in 0..18 {
            store.accept_validated_batch(
                identity.clone(),
                padded_batch(
                    group * 32 + 1,
                    32,
                    if group == 17 { 20 } else { 10 },
                    frame_bytes,
                ),
            )?;
        }
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(20);
        let fields = [("events", &["source_cursor"][..])];
        let started = std::time::Instant::now();
        let recent = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        let recent_us = started.elapsed().as_micros();
        assert_eq!(
            recent.extraction.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .filter(|entry| entry.commit.intake == 20)
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(row_count(&recent, "events"), 32);
        assert_eq!(recent.extraction.projected_bytes, 32 * 9);
        selection.received_from = Bound::Unbounded;
        let started = std::time::Instant::now();
        let sparse = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        let sparse_us = started.elapsed().as_micros();
        assert_eq!(
            sparse.extraction.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        let cursors = unsigned(&sparse, "events", "source_cursor")?;
        assert_eq!(cursors, (1..=576).collect::<Vec<_>>());
        assert_eq!(
            cursors
                .iter()
                .copied()
                .filter(|cursor| cursor % 32 == 1)
                .collect::<Vec<_>>(),
            (0..18).map(|group| group * 32 + 1).collect::<Vec<_>>()
        );
        assert_eq!(sparse.extraction.projected_bytes, 576 * 9);
        let full = read(
            &store,
            &selection,
            &[("events", &["catalog_json"])],
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        );
        assert!(
            matches!(
                full,
                Err(crate::Error::AnalysisInputTooLarge {
                    resource: "selected input bytes",
                    ..
                })
            ),
            "{:?}",
            full.as_ref().map(|page| &page.extraction)
        );
        assert!(store.maintenance.try_write().is_ok());
        let scope = ProcessorScopeV1 {
            processor_id: "history".into(),
            method_version: 1,
            identity: identity.clone(),
        };
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let started = std::time::Instant::now();
        store.commit_result(&AnalysisResultCommitV1 {
            consumed_cursor: 18 * 32,
            body: vec![1],
            created_utc_ns: 21,
            witnesses: (0..18)
                .map(|group| crate::AnalysisWitnessV1 {
                    identity: identity.clone().into(),
                    cursor: group * 32 + 1,
                    expires_utc_ns: 100,
                })
                .collect(),
            ..crate::analysis::tests::result(scope, "sparse-history".into())
        })?;
        let pin_commit_us = started.elapsed().as_micros();
        let started = std::time::Instant::now();
        let usage = store.witness_usage(identity.tenant_id, 22)?;
        let usage_us = started.elapsed().as_micros();
        let header_bytes = super::super::SegmentFile::encode_identity(&identity)?.len() as u64;
        assert_eq!(std::fs::read_dir(store.root.join("segments"))?.count(), 6);
        assert_eq!(
            usage.segment_bytes,
            sparse.extraction.scanned_bytes as u64 + 6 * header_bytes
        );
        assert_eq!(usage.referenced_bytes, 18 * frame_bytes as u64);
        assert_eq!(
            usage.extra_segment_bytes,
            usage.segment_bytes - usage.referenced_bytes
        );
        assert_eq!(usage.charged_bytes, usage.segment_bytes);
        assert_eq!(
            EvidenceRetentionOwner::new(&store)
                .retain(&identity, 50)?
                .removed_records,
            0
        );
        eprintln!(
            "witness_bytes={} segment_bytes={} extra_bytes={} pin_commit_us={} usage_us={}",
            usage.referenced_bytes,
            usage.segment_bytes,
            usage.extra_segment_bytes,
            pin_commit_us,
            usage_us
        );
        eprintln!("history_bytes={} recent_scan={} recent_input={} recent_us={} sparse_scan={} sparse_input={} sparse_us={} debug={}",
            72 * 1024 * 1024, recent.extraction.scanned_bytes, recent.extraction.input_bytes, recent_us,
            sparse.extraction.scanned_bytes, sparse.extraction.input_bytes, sparse_us, cfg!(debug_assertions));
        Ok(())
    }
}
