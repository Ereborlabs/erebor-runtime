use std::borrow::Cow;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::ops::Bound;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::raw::{RawIdentity, TracePayload, TraceRecord};
use super::segments::SegmentRange;
use super::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisGapV1, AnalysisReadControl,
    AnalysisRecordV1, AnalysisSourceReceiptV1, AnalysisStore, AnalysisStoreMetaV1, StorePositionV1,
    MAX_ANALYSIS_PAGE_BYTES, MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{
    AnalysisDatabaseSnafu, AnalysisInputTooLargeSnafu, EvidenceIntakeIdentityV1, EvidenceRecord,
    Result, TraceIdentityV1, TraceIntentV1, TraceOutputReceiptV1, TraceStateV1,
};

mod changes;
mod graph;
mod package;

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
        let first = match self.received_from {
            Bound::Unbounded => 0,
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_add(1)?,
        };
        let last = match self.received_until {
            Bound::Unbounded => u64::MAX,
            Bound::Included(value) => value,
            Bound::Excluded(value) => value.checked_sub(1)?,
        };
        (first <= last).then_some((first, last))
    }
}

/// Input for trusted row and field projection. This callback is not a client API.
pub enum AnalysisInputV1<'a> {
    Event {
        identity: &'a EvidenceIntakeIdentityV1,
        cpu_id: u32,
        received_utc_ns: u64,
        record: &'a AnalysisRecordV1,
        decoded: Option<&'a EvidenceRecord>,
    },
    RawRemoval {
        identity: &'a super::AnalysisStreamIdentityV1,
        first_cursor: u64,
        last_cursor: u64,
        position: StorePositionV1,
    },
    Context(&'a AnalysisContextVersionV1),
    Profile {
        result_id: &'a str,
        body: &'a [u8],
        commit_revision: u64,
        sources: &'a [EvidenceIntakeIdentityV1],
        discovery_enabled: bool,
    },
    Graph {
        result_id: &'a str,
        graph: &'a crate::GraphSnapshotV1,
        subject_count: usize,
        relationship_count: usize,
        commit_revision: u64,
        sensitivity: crate::ContextSensitivityV1,
        traversal_depths: Option<&'a [(crate::GraphSubjectKeyV1, u32)]>,
    },
    Notification {
        obligation: &'a crate::NotificationObligationV1,
        finding: Option<&'a crate::FindingV1>,
        commit_revision: u64,
    },
    Trace {
        state: &'a TraceStateV1,
        intent: &'a TraceIntentV1,
        target_index: u32,
        receipt: &'a TraceOutputReceiptV1,
    },
    TraceOutput {
        identity: &'a TraceIdentityV1,
        target_index: u32,
        sequence: u64,
        position: StorePositionV1,
        kind: &'static str,
        bytes: &'a [u8],
    },
    Result {
        result_id: &'a str,
        body: &'a [u8],
    },
    PackageOutput {
        reference: &'a araphor_analysis_sdk::OutputRef,
        result: &'a super::PackageResultV1,
        dataset: Option<&'a araphor_analysis_sdk::wire::Dataset>,
        coverage: &'a araphor_analysis_sdk::Coverage,
    },
}

pub trait AnalysisProjection {
    fn decodes_events(&self) -> bool {
        false
    }

    fn graph_subjects(&self) -> bool {
        true
    }

    fn graph_relationships(&self) -> bool {
        true
    }

    fn graph_headers(&self) -> bool {
        false
    }

    fn project(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_>,
    ) -> Result<bool>;
}

pub struct ProjectionSink<'a> {
    output: &'a mut AnalysisExtractionV1,
    control: &'a AnalysisReadControl,
    row_bytes: Option<&'a mut usize>,
    emitted: usize,
}

impl ProjectionSink<'_> {
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
}

enum ExtractMode {
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
    pub fn sink<'a>(&'a mut self, control: &'a AnalysisReadControl) -> ProjectionSink<'a> {
        ProjectionSink {
            output: self,
            control,
            row_bytes: None,
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

    fn project(
        &mut self,
        projection: &mut dyn AnalysisProjection,
        input: AnalysisInputV1<'_>,
        control: &AnalysisReadControl,
        row_bytes: Option<&mut usize>,
    ) -> Result<bool> {
        projection.project(
            input,
            &mut ProjectionSink {
                output: self,
                control,
                row_bytes,
                emitted: 0,
            },
        )
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

    pub fn extract_rows<P: AnalysisProjection>(
        &self,
        selection: &AnalysisSelectionV1,
        packages: Option<(
            &AnalysisSelectionV1,
            &str,
            &[araphor_analysis_sdk::OutputRef],
        )>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        mut project: P,
    ) -> Result<(AnalysisPositionPageV1, P)> {
        let page = self.extract_mode(
            selection,
            packages,
            ExtractMode::Complete,
            limits,
            control,
            &mut project,
        )?;
        Ok((page, project))
    }

    pub fn position_rows<P: AnalysisProjection>(
        &self,
        selection: &AnalysisSelectionV1,
        after: Option<StorePositionV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        mut project: P,
    ) -> Result<(AnalysisPositionPageV1, P)> {
        let page = self.extract_mode(
            selection,
            None,
            ExtractMode::Page(after),
            limits,
            control,
            &mut project,
        )?;
        Ok((page, project))
    }

    /// Read raw inserts and retirements through one captured revision.
    /// This read does not emit changes to context, result, or trace state rows.
    pub fn change_rows<P: AnalysisProjection>(
        &self,
        selection: &AnalysisSelectionV1,
        after: StorePositionV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        mut project: P,
    ) -> Result<(AnalysisPositionPageV1, P)> {
        if after.ordinal != u32::MAX {
            return self.reject("the raw change frontier is not a complete commit");
        }
        let page = self.extract_mode(
            selection,
            None,
            ExtractMode::Changes(after),
            limits,
            control,
            &mut project,
        )?;
        Ok((page, project))
    }

    pub fn metadata_rows<P: AnalysisProjection>(
        &self,
        selection: &AnalysisSelectionV1,
        packages: Option<(
            &AnalysisSelectionV1,
            &str,
            &[araphor_analysis_sdk::OutputRef],
        )>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        mut project: P,
    ) -> Result<(AnalysisPositionPageV1, P)> {
        let page = self.extract_mode(
            selection,
            packages,
            ExtractMode::Metadata,
            limits,
            control,
            &mut project,
        )?;
        Ok((page, project))
    }

    fn extract_mode(
        &self,
        selection: &AnalysisSelectionV1,
        packages: Option<(
            &AnalysisSelectionV1,
            &str,
            &[araphor_analysis_sdk::OutputRef],
        )>,
        mode: ExtractMode,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        project: &mut dyn AnalysisProjection,
    ) -> Result<AnalysisPositionPageV1> {
        control.check()?;
        if !selection.valid() {
            return self.reject("the extraction selection has invalid, duplicate, or foreign keys");
        }
        if packages.is_some_and(|(authorized, _, _)| authorized.tenant_id != selection.tenant_id) {
            return Err(crate::PackageErrorCodeV1::Denied.error("dependency tenant"));
        }
        if limits.scan_bytes == 0
            || limits.input_bytes == 0
            || limits.page_bytes == 0
            || limits.page_rows == 0
        {
            return self.reject("the extraction limits must be positive");
        }
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
            let end = StorePositionV1 {
                commit_revision: meta.commit_revision,
                ordinal: u32::MAX,
            };
            let mut after = match mode {
                ExtractMode::Complete | ExtractMode::Metadata => None,
                ExtractMode::Page(after) => after,
                ExtractMode::Changes(after) => Some(after),
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
            if matches!(mode, ExtractMode::Page(_) | ExtractMode::Changes(_)) {
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
                    && !matches!(mode, ExtractMode::Metadata)
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
                if !matches!(mode, ExtractMode::Changes(_)) {
                    output.project(
                        project,
                        AnalysisInputV1::Trace {
                            state: &state,
                            intent: &intent,
                            target_index: index as u32,
                            receipt: &receipt,
                        },
                        control,
                        None,
                    )?;
                }
            }
            let removals = if let ExtractMode::Changes(after) = mode {
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
                if matches!(mode, ExtractMode::Metadata) {
                    after = Some(end);
                    exhausted = true;
                    break;
                }
                let limit = match mode {
                    ExtractMode::Complete | ExtractMode::Metadata | ExtractMode::Changes(_) => {
                        usize::MAX
                    }
                    ExtractMode::Page(_) => limits.page_rows - scanned,
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
                if matches!(mode, ExtractMode::Page(_))
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
                        output.remove_raw(project, &removal, control)?;
                    }
                    let page_bytes = matches!(mode, ExtractMode::Page(_)).then_some(&mut row_bytes);
                    let consumed = match &identity {
                        RawIdentity::Evidence(identity) => {
                            let decoded = (!selection.binding_ids.is_empty()
                                || project.decodes_events())
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
                                output.project(
                                    project,
                                    AnalysisInputV1::Event {
                                        identity,
                                        cpu_id: cpu.ok_or_else(|| {
                                            self.state_error("the selected evidence CPU is absent")
                                        })?,
                                        received_utc_ns: range.intake,
                                        record: &record,
                                        decoded: decoded.as_ref(),
                                    },
                                    control,
                                    page_bytes,
                                )?
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
                            output.project(
                                project,
                                AnalysisInputV1::TraceOutput {
                                    identity,
                                    target_index: trace.target_index,
                                    sequence: record.cursor,
                                    position: record.position,
                                    kind,
                                    bytes,
                                },
                                control,
                                page_bytes,
                            )?
                        }
                    };
                    if !consumed {
                        if matches!(mode, ExtractMode::Changes(_)) {
                            return AnalysisInputTooLargeSnafu {
                                resource: "complete change input",
                            }
                            .fail();
                        }
                        break 'scan;
                    }
                    scanned += 1;
                    after = Some(record.position);
                }
            }
            if matches!(mode, ExtractMode::Changes(_)) {
                for removal in removals {
                    output.remove_raw(project, &removal, control)?;
                }
                control.check()?;
                return Ok(AnalysisPositionPageV1 {
                    extraction: output,
                    scanned_through: end,
                    exhausted: true,
                });
            }
            if let Some(packages) = packages {
                self.extract_packages(
                    snapshot,
                    packages,
                    matches!(mode, ExtractMode::Metadata),
                    control,
                    &mut output,
                    project,
                )?;
            }
            for key in selection.contexts.as_slice() {
                control.check()?;
                match Self::read_context_from(snapshot, &self.root, key)? {
                    Some((context, revision)) => {
                        output.reference_context(&context.key, revision, AnalysisReferenceOriginV1::Context)?;
                        output.project(
                            project,
                            AnalysisInputV1::Context(&context),
                            control,
                            None,
                        )?;
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
                output.project(
                    project,
                    AnalysisInputV1::Profile {
                        result_id: id,
                        body: &body,
                        commit_revision: revision,
                        sources: selection.sources.as_slice(),
                        discovery_enabled,
                    },
                    control,
                    None,
                )?;
            }
            if let Some(request) = &selection.graph_traversal {
                self.traverse_graphs(snapshot, selection, request, &mut output, control, project)?;
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
                let subjects = project.graph_subjects();
                let edges = project.graph_relationships();
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
                output.project(project, AnalysisInputV1::Graph {
                    result_id: id, graph: &graph, commit_revision: revision, sensitivity,
                    subject_count: header.subject_count,
                    relationship_count: header.edge_count,
                    traversal_depths: None,
                }, control, None)?;
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
                output.project(project, AnalysisInputV1::Notification {
                    obligation: &obligation, finding: finding.as_ref(), commit_revision: revision,
                }, control, None)?;
            }
            for id in &selection.results {
                control.check()?;
                match self.read_result_from(snapshot, selection.tenant_id, id)? {
                    Some(body) => {
                        let revision: u64 = snapshot.query_row(
                            "SELECT commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
                            params![selection.tenant_id.as_slice(), id],
                            |row| row.get(0),
                        ).context(AnalysisDatabaseSnafu { operation: "read retained result revision" })?;
                        output.reference_result(id, revision, AnalysisReferenceOriginV1::ExplicitResult)?;
                        output.project(
                            project,
                            AnalysisInputV1::Result {
                                result_id: id,
                                body: &body,
                            },
                            control,
                            None,
                        )?;
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
            Ok(AnalysisPositionPageV1 {
                extraction: output,
                scanned_through: after.unwrap_or(StorePositionV1 {
                    commit_revision: 0,
                    ordinal: 0,
                }),
                exhausted,
            })
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
        AnalysisResultCommitV1, ContextSensitivityV1, EvidenceRetentionOwner, ProcessorClassV1,
        ProcessorScopeV1, RetentionLimitsV1, ValidatedEvidenceBatchV1,
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    struct Bytes<F> {
        project: F,
        rows: Vec<Box<[u8]>>,
        page_bytes: usize,
    }

    impl<F> Bytes<F> {
        fn new(project: F) -> Self {
            Self {
                project,
                rows: Vec::new(),
                page_bytes: MAX_ANALYSIS_PAGE_BYTES,
            }
        }
    }

    impl<F> AnalysisProjection for Bytes<F>
    where
        F: FnMut(AnalysisInputV1<'_>) -> Result<Option<Vec<u8>>>,
    {
        fn project(
            &mut self,
            input: AnalysisInputV1<'_>,
            sink: &mut ProjectionSink<'_>,
        ) -> Result<bool> {
            let Some(row) = (self.project)(input)? else {
                return Ok(true);
            };
            let row = row.into_boxed_slice();
            let bytes = row
                .len()
                .checked_add(size_of::<Box<[u8]>>())
                .filter(|bytes| *bytes <= self.page_bytes)
                .ok_or_else(|| {
                    AnalysisInputTooLargeSnafu {
                        resource: "projected row bytes",
                    }
                    .build()
                })?;
            if !sink.admit(bytes)? {
                return Ok(false);
            }
            sink.charge(row.len())?;
            sink.grow(&mut self.rows)?;
            sink.projected(row.len());
            self.rows.push(row);
            Ok(true)
        }
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

    fn batch(first: u64, count: usize, received: u64) -> ValidatedEvidenceBatchV1 {
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: first,
            last_cursor: first + count as u64 - 1,
            intake_utc_ns: received,
            framed_records: vec![7; count].into(),
            frame_ends: (1..=count).collect(),
        }
    }

    #[test]
    fn query_input_pending_positions() -> TestResult {
        use prost::Message as _;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(11, 10, 10))?;
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
        let (
            _,
            Bytes {
                rows: complete_rows,
                ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                Ok(Some(vec![record.cursor as u8]))
            }),
        )?;
        assert_eq!(complete_rows.len(), 10);
        let before = store.meta()?;
        let mut positions = Vec::new();
        let (
            first,
            Bytes {
                rows: first_rows, ..
            },
        ) = store.position_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event {
                    record,
                    received_utc_ns,
                    ..
                } = input
                else {
                    return store.reject("unexpected relation");
                };
                if record.cursor == 11 {
                    store.accept_validated_batch(identity.clone(), batch(1, 10, 20))?;
                }
                assert_eq!(received_utc_ns, 10);
                positions.push(record.position);
                Ok(Some(vec![record.cursor as u8]))
            }),
        )?;
        assert!(first.exhausted);
        assert_eq!(first.extraction.meta, before);
        let source = &first.extraction.sources[0];
        assert_eq!(source.receipt.contiguous_cursor, 0);
        assert_eq!(source.coverage_report.as_ref(), Some(&report));
        assert_eq!(source.pending.len(), 1);
        assert_eq!(
            (
                source.pending[0].first_cursor,
                source.pending[0].last_cursor
            ),
            (1, 10)
        );
        assert_eq!(
            first_rows.iter().map(|row| row[0]).collect::<Vec<_>>(),
            (11..=20).collect::<Vec<_>>()
        );
        let (
            next,
            Bytes {
                rows: next_rows, ..
            },
        ) = store.position_rows(
            &selection,
            Some(first.scanned_through),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event {
                    record,
                    received_utc_ns,
                    ..
                } = input
                else {
                    return store.reject("unexpected relation");
                };
                assert!(record.position > first.scanned_through);
                assert_eq!(received_utc_ns, 20);
                positions.push(record.position);
                Ok(Some(vec![record.cursor as u8]))
            }),
        )?;
        assert!(next.exhausted);
        assert_eq!(next.extraction.sources[0].receipt.contiguous_cursor, 20);
        assert!(next.extraction.sources[0].pending.is_empty());
        assert_eq!(
            next_rows.iter().map(|row| row[0]).collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        let ordered = store.read_page(&identity, 1)?;
        assert_eq!(
            ordered
                .records
                .iter()
                .map(|record| record.cursor)
                .collect::<Vec<_>>(),
            (1..=20).collect::<Vec<_>>()
        );
        assert_eq!(ordered.records[10].position, positions[0]);
        assert_eq!(ordered.records[0].position, positions[10]);
        let meta = store.meta()?;
        store.accept_validated_batch(identity.clone(), batch(11, 10, 10))?;
        assert_eq!(store.meta()?, meta);
        let (
            retry,
            Bytes {
                rows: retry_rows, ..
            },
        ) = store.position_rows(
            &selection,
            Some(next.scanned_through),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| {
                store.reject("an exact retry produced another query row")
            }),
        )?;
        assert!(retry.exhausted && retry_rows.is_empty());
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
        store.accept_validated_batch(identity.clone(), batch(1, 257, 10))?;
        store.accept_validated_batch(foreign, batch(1, 1, 10))?;
        store.accept_validated_batch(other.clone(), batch(1, 1, 20))?;
        let selection =
            AnalysisSelectionV1::new(identity.tenant_id, vec![other.clone(), identity.clone()]);
        let mut seen = Vec::new();
        let (
            first,
            Bytes {
                rows: first_rows, ..
            },
        ) = store.position_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event {
                    identity: source,
                    record,
                    ..
                } = input
                else {
                    return store.reject("unexpected relation");
                };
                assert_eq!(source, &identity);
                seen.push(record.position);
                Ok(None)
            }),
        )?;
        assert!(!first.exhausted);
        assert_eq!(seen.len(), 256);
        assert!(first_rows.is_empty());
        assert_eq!(first.scanned_through, seen[255]);
        let (
            next,
            Bytes {
                rows: next_rows, ..
            },
        ) = store.position_rows(
            &selection,
            Some(first.scanned_through),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event {
                    identity: source,
                    record,
                    ..
                } = input
                else {
                    return store.reject("unexpected relation");
                };
                assert_eq!(source.tenant_id, identity.tenant_id);
                seen.push(record.position);
                Ok(Some(vec![source.source_epoch as u8]))
            }),
        )?;
        assert!(next.exhausted);
        assert_eq!(
            next_rows.iter().map(|row| row[0]).collect::<Vec<_>>(),
            vec![1, 2]
        );
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
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, 1))?;
        }
        store.accept_validated_batch(identity.clone(), batch(1, 10, 2))?;
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let mut positions = Vec::new();
        let (
            page,
            Bytes {
                rows: page_rows, ..
            },
        ) = store.position_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                positions.push(record.position);
                Ok(Some(vec![record.cursor as u8]))
            }),
        )?;
        let expected = [3, 7, 1, 2, 4, 5, 6, 8, 9, 10];
        assert!(page.exhausted);
        assert_eq!(page.scanned_through.ordinal, u32::MAX);
        assert_eq!(
            page_rows.iter().map(|row| row[0]).collect::<Vec<_>>(),
            expected
        );
        for (index, position) in positions.iter().enumerate() {
            let (
                page,
                Bytes {
                    rows: page_rows, ..
                },
            ) = store.position_rows(
                &selection,
                Some(*position),
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|input: AnalysisInputV1<'_>| {
                    let AnalysisInputV1::Event { record, .. } = input else {
                        return store.reject("unexpected relation");
                    };
                    Ok(Some(vec![record.cursor as u8]))
                }),
            )?;
            assert!(page.exhausted);
            assert_eq!(
                page_rows.iter().map(|row| row[0]).collect::<Vec<_>>(),
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
        store.accept_validated_batch(identity.clone(), batch(1, 3, 1))?;
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity]);
        let mut positions = Vec::new();
        let (
            first,
            Bytes {
                rows: first_rows, ..
            },
        ) = store.position_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                positions.push(record.position);
                Ok((record.cursor != 2).then(|| vec![record.cursor as u8; 600 * 1024]))
            }),
        )?;
        assert!(!first.exhausted);
        assert_eq!(first_rows.len(), 1);
        assert_eq!(first_rows[0][0], 1);
        assert_eq!(first.scanned_through, positions[1]);
        let (
            next,
            Bytes {
                rows: next_rows, ..
            },
        ) = store.position_rows(
            &selection,
            Some(first.scanned_through),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                assert_eq!(record.cursor, 3);
                Ok(Some(vec![3; 600 * 1024]))
            }),
        )?;
        assert!(next.exhausted);
        assert_eq!(next_rows.len(), 1);
        assert_eq!(next_rows[0][0], 3);
        assert!(store
            .position_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![0; MAX_ANALYSIS_PAGE_BYTES]))),
            )
            .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_rotation() -> TestResult {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let first = identity(1);
        let rotating = EvidenceIntakeIdentityV1 {
            source_epoch: 2,
            ..first.clone()
        };
        store.accept_validated_batch(first.clone(), batch(1, 1, 10))?;
        let large = ValidatedEvidenceBatchV1 {
            framed_records: vec![7; crate::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES].into(),
            frame_ends: vec![crate::MAX_EVIDENCE_COMMIT_PAYLOAD_BYTES],
            ..batch(1, 1, 10)
        };
        for cursor in 1..=3 {
            store.accept_validated_batch(
                rotating.clone(),
                ValidatedEvidenceBatchV1 {
                    first_cursor: cursor,
                    last_cursor: cursor,
                    ..large.clone()
                },
            )?;
        }
        let before = store.meta()?;
        let selection =
            AnalysisSelectionV1::new(first.tenant_id, vec![first.clone(), rotating.clone()]);
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
        std::thread::scope(|scope| -> TestResult {
            let store = &store;
            let rotating = &rotating;
            let writer = scope.spawn(move || {
                started
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| store.state_error("the reader did not reach its barrier"))?;
                store.accept_validated_batch(
                    rotating.clone(),
                    ValidatedEvidenceBatchV1 {
                        first_cursor: 4,
                        last_cursor: 4,
                        ..large
                    },
                )
            });
            let output = store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|input: AnalysisInputV1<'_>| {
                    let AnalysisInputV1::Event {
                        identity, record, ..
                    } = input
                    else {
                        return store.reject("unexpected relation");
                    };
                    if identity == &first {
                        start
                            .send(())
                            .map_err(|_| store.state_error("the writer left its barrier"))?;
                        rotation.recv_timeout(Duration::from_secs(2)).map_err(|_| {
                            store.state_error("the writer did not request rotation")
                        })?;
                    }
                    Ok(Some(vec![identity.source_epoch as u8, record.cursor as u8]))
                }),
            );
            assert_eq!(
                writer.join().map_err(|_| "writer panicked")??,
                crate::EvidenceStoreOutcomeV1::Accepted
            );
            let (
                output,
                Bytes {
                    rows: output_rows, ..
                },
            ) = output?;
            let output = output.extraction;
            assert_eq!(output.meta, before);
            assert_eq!(output.sources[1].receipt.contiguous_cursor, 3);
            let rows: Vec<_> = output_rows.iter().map(|row| row.as_ref()).collect();
            assert_eq!(rows, [&[1, 1], &[2, 1], &[2, 2], &[2, 3]]);
            Ok(())
        })?;
        let (
            later,
            Bytes {
                rows: later_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event {
                    identity, record, ..
                } = input
                else {
                    return store.reject("unexpected relation");
                };
                Ok(Some(vec![identity.source_epoch as u8, record.cursor as u8]))
            }),
        )?;
        let later = later.extraction;
        assert_eq!(later.meta.commit_revision, before.commit_revision + 1);
        assert_eq!(later.sources[1].receipt.contiguous_cursor, 4);
        let rows: Vec<_> = later_rows.iter().map(|row| row.as_ref()).collect();
        assert_eq!(rows, [&[1, 1], &[2, 1], &[2, 2], &[2, 3], &[2, 4]]);
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
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1))?;
        let receipt = store.source_receipt(&identity)?.ok_or("receipt absent")?;
        let reader = store.reader()?;
        for access in 0..3 {
            for cancelled in [false, true] {
                let (ready, held) = mpsc::channel();
                let (release, released) = mpsc::channel();
                let (waiting, blocked) = mpsc::channel();
                let control = AnalysisReadControl::default();
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
        store.accept_validated_batch(identity.clone(), batch(2, 1, 2))?;
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
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, received))?;
        }
        let foreign = EvidenceIntakeIdentityV1 {
            tenant_id: [9; 16],
            ..identity.clone()
        };
        store.accept_validated_batch(foreign.clone(), batch(1, 1, 20))?;
        let before = store.meta()?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(20);
        selection.received_until = Bound::Excluded(30);
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event {
                    identity: source,
                    cpu_id,
                    record,
                    received_utc_ns,
                    decoded,
                } = input
                else {
                    return store.reject("unexpected relation");
                };
                assert!(decoded.is_none());
                assert_eq!(source, &identity);
                assert_eq!(cpu_id, 0);
                assert_eq!(received_utc_ns, 20);
                Ok(Some(record.cursor.to_be_bytes().to_vec()))
            }),
        )?;
        let output = output.extraction;
        assert_eq!(output.meta, before);
        assert_eq!(
            output.scanned_bytes,
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
        assert_eq!(output.projected_bytes, 8);
        assert_eq!(output_rows[0].as_ref(), &3_u64.to_be_bytes());
        assert_eq!(output.sources[0].receipt.contiguous_cursor, 3);
        assert_eq!(store.meta()?, before);
        for (from, until) in [
            (Bound::Excluded(u64::MAX), Bound::Unbounded),
            (Bound::Unbounded, Bound::Excluded(0)),
            (Bound::Included(31), Bound::Included(30)),
        ] {
            selection.received_from = from;
            selection.received_until = until;
            let (
                empty,
                Bytes {
                    rows: empty_rows, ..
                },
            ) = store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| store.reject("empty range decoded input")),
            )?;
            let empty = empty.extraction;
            assert!(empty_rows.is_empty());
            assert_eq!(empty.scanned_bytes, 0);
        }
        selection.sources = Selection::Exact(Vec::new());
        assert!(store
            .extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(
                    |_: AnalysisInputV1<'_>| store.reject("empty source scope is not a wildcard")
                ),
            )?
            .1
            .rows
            .is_empty());
        selection.sources = Selection::Exact(vec![foreign]);
        assert!(store
            .extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
            )
            .is_err());
        selection.sources = Selection::Exact(vec![identity.clone(), identity]);
        assert!(store
            .extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
            )
            .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_tenant_snapshot() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let first = identity(1);
        store.accept_validated_batch(first.clone(), batch(1, 1, 10))?;
        store.accept_validated_batch(identity(2), batch(1, 1, 10))?;
        let mut next = first.clone();
        next.source_id = [4; 16];
        next.node_boot_id = [5; 16];
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
        let before = store.meta()?;
        let mut calls = 0;
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event { identity, .. } = input else {
                    return store.reject("a late context entered the snapshot");
                };
                assert_eq!(identity, &first);
                calls += 1;
                store.accept_validated_batch(next.clone(), batch(1, 1, 20))?;
                store.commit_context(&context)?;
                Ok(Some(vec![7]))
            }),
        )?;
        let output = output.extraction;
        assert_eq!(calls, 1);
        assert_eq!(output.meta, before);
        assert_eq!(output.sources.len(), 1);
        assert_eq!(output_rows.len(), 1);
        assert!(output.missing_contexts.is_empty());
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                Ok(Some(match input {
                    AnalysisInputV1::Event { identity, .. } => vec![identity.source_id[0]],
                    AnalysisInputV1::Context(context) => context.body.clone(),
                    _ => return store.reject("an unselected result entered the snapshot"),
                }))
            }),
        )?;
        let output = output.extraction;
        assert_eq!(output.sources.len(), 2);
        assert_eq!(output_rows.len(), 3);
        assert_eq!(output_rows[0].as_ref(), &[first.source_id[0]]);
        assert_eq!(output_rows[1].as_ref(), &[next.source_id[0]]);
        assert_eq!(output_rows[2].as_ref(), &[42]);
        let empty = AnalysisSelectionV1::new(first.tenant_id, vec![]);
        assert!(store
            .extract_rows(
                &empty,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| {
                    store.reject("an empty explicit list selected input")
                }),
            )?
            .1
            .rows
            .is_empty());
        Ok(())
    }

    #[test]
    fn analysis_tenant_key_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let first = identity(1);
        store.accept_validated_batch(first.clone(), batch(1, 1, 10))?;
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
        let (output, _) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &control,
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
        )?;
        let output = output.extraction;
        assert_eq!(output.sources.len(), 1);
        assert_eq!(output.missing_contexts.len(), MAX_EXTRACT_KEYS - 1);
        let mut next = first.clone();
        next.source_id = [4; 16];
        store.accept_validated_batch(next, batch(1, 1, 20))?;
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &control,
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
            ),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input keys",
                ..
            })
        ));
        let selection = AnalysisSelectionV1::tenant(first.tenant_id);
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits {
                    input_bytes: size_of::<AnalysisSelectionV1>() - 1,
                    ..Default::default()
                },
                &control,
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None))
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &cancelled,
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
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
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 10))?;
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
        let before = store.meta()?;
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
        let mut calls = 0;
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &control,
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("late metadata entered snapshot");
                };
                assert_eq!(record.cursor, 1);
                calls += 1;
                store.accept_validated_batch(identity.clone(), batch(2, 1, 5))?;
                store.commit_context(&context)?;
                store.commit_result(&AnalysisResultCommitV1 {
                    body: vec![43],
                    created_utc_ns: 20,
                    ..crate::analysis::tests::result(scope.clone(), "late".into())
                })?;
                Ok(Some(vec![1]))
            }),
        )?;
        let output = output.extraction;
        assert_eq!(calls, 1);
        assert_eq!(output.meta, before);
        assert_eq!(output.sources[0].receipt.contiguous_cursor, 1);
        assert_eq!(output.missing_contexts, vec![context.key]);
        assert_eq!(output.missing_results, vec!["late"]);
        assert_eq!(output_rows.len(), 1);
        assert_eq!(output_rows[0].as_ref(), &[1]);
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &control,
            Bytes::new(|input: AnalysisInputV1<'_>| {
                Ok(Some(match input {
                    AnalysisInputV1::Event { record, .. } => vec![record.cursor as u8],
                    AnalysisInputV1::Context(context) => context.body.clone(),
                    AnalysisInputV1::Result { body, .. } => body.to_vec(),
                    AnalysisInputV1::Trace { .. }
                    | AnalysisInputV1::PackageOutput { .. }
                    | AnalysisInputV1::RawRemoval { .. }
                    | AnalysisInputV1::TraceOutput { .. }
                    | AnalysisInputV1::Profile { .. }
                    | AnalysisInputV1::Graph { .. }
                    | AnalysisInputV1::Notification { .. } => {
                        return store.reject("unselected input entered an evidence-only snapshot");
                    }
                }))
            }),
        )?;
        let output = output.extraction;
        assert!(output.missing_contexts.is_empty() && output.missing_results.is_empty());
        assert_eq!(output.meta, store.meta()?);
        assert_eq!(output_rows.len(), 4);
        assert_eq!(output_rows[0].as_ref(), &[1]);
        assert_eq!(output_rows[1].as_ref(), &[2]);
        assert_eq!(output_rows[2].as_ref(), &[42]);
        assert_eq!(output_rows[3].as_ref(), &[43]);
        selection.received_from = Bound::Included(100);
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &control,
            Bytes::new(|input: AnalysisInputV1<'_>| {
                Ok(Some(match input {
                    AnalysisInputV1::Context(context) => context.body.clone(),
                    AnalysisInputV1::Result { body, .. } => body.to_vec(),
                    _ => return store.reject("old event entered a new window"),
                }))
            }),
        )?;
        let output = output.extraction;
        assert_eq!(output.scanned_bytes, 0);
        assert_eq!(output_rows.len(), 2);
        assert_eq!(output_rows[0].as_ref(), &[42]);
        assert_eq!(output_rows[1].as_ref(), &[43]);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_range_pages() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        for cursor in 1..=257 {
            store.accept_validated_batch(identity.clone(), batch(cursor, 1, 10))?;
        }
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok(Some(record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            }),
        )?;
        let output = output.extraction;
        assert_eq!(
            output.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| { Ok(Some(vec![0; 512 * 1024])) }),
            ),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input bytes",
                ..
            })
        ));
        let rows: Vec<_> = output_rows.iter().collect();
        assert_eq!(rows.len(), 257);
        for (index, row) in rows.into_iter().enumerate() {
            assert_eq!(row.as_ref(), &(index as u64 + 1).to_be_bytes());
        }
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
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1))?;
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
        let hidden = directory.path().join("hidden.seg");
        std::fs::rename(&path, &hidden)?;
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
            ),
            Err(crate::Error::Io { .. })
        ));
        std::fs::rename(&hidden, &path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.write_all_at(&[8], offset)?;
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
            ),
            Err(crate::Error::AnalysisState { .. })
        ));
        file.write_all_at(&[7], offset)?;
        let (
            _,
            Bytes {
                rows: result_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![7]))),
        )?;
        assert_eq!(result_rows[0].as_ref(), &[7]);
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_gaps() -> TestResult {
        let directory = tempfile::tempdir()?;
        let limits = RetentionLimitsV1 {
            raw_max_age_ns: 1,
            raw_max_bytes: 1024,
        };
        let store = AnalysisStore::open_with_limits(
            directory.path().join("analysis"),
            limits,
            Default::default(),
        )?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 1, 1))?;
        store.backup(&store.root.join("backups/sealed"))?;
        store.accept_validated_batch(identity.clone(), batch(2, 1, 100))?;
        EvidenceRetentionOwner::new(&store).retain(&identity, 3)?;
        store.record_recovery_floor(&identity, 4)?;
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(99);
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![2]))),
        )?;
        let output = output.extraction;
        assert_eq!(output.input_bytes, owned_bytes(&output, &output_rows));
        assert_eq!(
            output.scanned_bytes,
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
        assert_eq!(output.sources[0].expired.len(), 1);
        assert_eq!(
            (
                output.sources[0].expired[0].first_cursor,
                output.sources[0].expired[0].last_cursor
            ),
            (1, 1)
        );
        assert_eq!(
            (
                output.sources[0].recovery[0].first_cursor,
                output.sources[0].recovery[0].last_cursor
            ),
            (3, 4)
        );
        store
            .raw
            .lock()
            .map_err(|_| "raw lock poisoned")?
            .ranges
            .remove(&(identity.key(), 2));
        assert!(store
            .extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(None)),
            )
            .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    fn owned_bytes(output: &AnalysisExtractionV1, rows: &Vec<Box<[u8]>>) -> usize {
        size_of::<AnalysisExtractionV1>()
            + output.sources.capacity() * size_of::<AnalysisSourceSnapshotV1>()
            + output.missing_contexts.capacity() * size_of::<AnalysisContextKeyV1>()
            + output.missing_results.capacity() * size_of::<String>()
            + rows.capacity() * size_of::<Box<[u8]>>()
            + rows.iter().map(|row| row.len()).sum::<usize>()
            + output
                .sources
                .iter()
                .map(|source| {
                    source.receipt.identity.node_id.capacity()
                        + (source.expired.capacity()
                            + source.recovery.capacity()
                            + source.pending.capacity())
                            * size_of::<AnalysisGapV1>()
                        + source.coverage_report.as_ref().map_or(0, Vec::capacity)
                })
                .sum::<usize>()
            + output
                .missing_contexts
                .iter()
                .map(|key| {
                    key.owner_id.capacity()
                        + key.entity_key.capacity()
                        + key.lifetime_key.capacity()
                })
                .sum::<usize>()
            + output
                .missing_results
                .iter()
                .map(String::capacity)
                .sum::<usize>()
    }

    #[test]
    fn query_input_allocation_bounds() -> TestResult {
        use prost::Message as _;

        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(11, 4, 10))?;
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
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![1]))),
        )?;
        let output = output.extraction;
        let required = owned_bytes(&output, &output_rows);
        assert_eq!(output.input_bytes, required);
        assert_eq!(output_rows.len(), 4);
        assert_eq!(output.sources[0].pending.len(), 1);
        assert_eq!(output.sources[0].recovery.len(), 1);
        assert_eq!(output.missing_contexts.len(), 4);
        assert_eq!(output.missing_results.len(), 4);
        drop(output);
        for limit in [required, required - 1] {
            let result = store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits {
                    input_bytes: limit,
                    ..Default::default()
                },
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![1]))),
            );
            if limit == required {
                let (page, rows) = result?;
                let output = page.extraction;
                assert_eq!(output.input_bytes, required);
                assert_eq!(output.input_bytes, owned_bytes(&output, &rows.rows));
            } else {
                assert!(matches!(
                    result,
                    Err(crate::Error::AnalysisInputTooLarge {
                        resource: "selected input bytes",
                        ..
                    })
                ));
            }
        }
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    #[test]
    fn analysis_extract_limits() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity(1);
        store.accept_validated_batch(identity.clone(), batch(1, 257, 1))?;
        let selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        let before = store.meta()?;
        let (
            output,
            Bytes {
                rows: output_rows, ..
            },
        ) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![1]))),
        )?;
        let output = output.extraction;
        assert_eq!(output_rows.len(), 257);
        let (first, rows) = store.position_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![1]))),
        )?;
        assert_eq!(rows.rows.len(), 256);
        assert!(!first.exhausted);
        let (next, rows) = store.position_rows(
            &selection,
            Some(first.scanned_through),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![1]))),
        )?;
        assert_eq!(rows.rows.len(), 1);
        assert!(next.exhausted);
        assert!(next.scanned_through > first.scanned_through);
        assert_eq!(
            output.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        let control = AnalysisReadControl::default();
        let mut calls = 0;
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &control,
                Bytes::new(|_: AnalysisInputV1<'_>| {
                    calls += 1;
                    control.cancel()?;
                    Ok(Some(vec![1]))
                }),
            ),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(calls, 1);
        let (output, _) = store.extract_rows(
            &AnalysisSelectionV1::new(identity.tenant_id, vec![]),
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| store.reject("empty selection")),
        )?;
        let mut output = output.extraction;
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
        let (first, rows) = store.position_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                Ok(Some(if record.cursor == 1 {
                    vec![0; MAX_ANALYSIS_PAGE_BYTES - size_of::<Box<[u8]>>()]
                } else {
                    Vec::new()
                }))
            }),
        )?;
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(
            rows.rows[0].len() + size_of::<Box<[u8]>>(),
            MAX_ANALYSIS_PAGE_BYTES
        );
        assert!(!first.exhausted);
        let (next, rows) = store.position_rows(
            &selection,
            Some(first.scanned_through),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(Vec::new()))),
        )?;
        assert_eq!(rows.rows.len(), 256);
        assert!(rows.rows.iter().all(|row| row.is_empty()));
        assert!(next.exhausted);
        assert!(next.scanned_through > first.scanned_through);
        assert!(matches!(
            store.extract_rows(
                &selection,
                None,
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                Bytes::new(|_: AnalysisInputV1<'_>| Ok(Some(vec![
                    0;
                    MAX_ANALYSIS_PAGE_BYTES
                        - size_of::<Box<[u8]>>()
                        + 1
                ]))),
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
            raw_max_age_ns: 1,
            raw_max_bytes: 1,
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
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: group * 32 + 1,
                    last_cursor: (group + 1) * 32,
                    intake_utc_ns: if group == 17 { 20 } else { 10 },
                    framed_records: vec![7; 32 * frame_bytes].into(),
                    frame_ends: (1..=32).map(|index| index * frame_bytes).collect(),
                },
            )?;
        }
        let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
        selection.received_from = Bound::Included(20);
        let started = std::time::Instant::now();
        let (recent, _) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok(Some(record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            }),
        )?;
        let recent = recent.extraction;
        let recent_us = started.elapsed().as_micros();
        assert_eq!(
            recent.scanned_bytes,
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
        assert_eq!(recent.projected_bytes, 32 * 8);
        selection.received_from = Bound::Unbounded;
        let started = std::time::Instant::now();
        let (sparse, _) = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok((record.cursor % 32 == 1).then(|| record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            }),
        )?;
        let sparse = sparse.extraction;
        let sparse_us = started.elapsed().as_micros();
        assert_eq!(
            sparse.scanned_bytes,
            store
                .raw
                .lock()
                .map_err(|_| "raw lock poisoned")?
                .entries
                .values()
                .map(|entry| entry.frame_bytes)
                .sum::<usize>()
        );
        assert_eq!(sparse.projected_bytes, 18 * 8);
        let full = store.extract_rows(
            &selection,
            None,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            Bytes::new(|input: AnalysisInputV1<'_>| match input {
                AnalysisInputV1::Event { record, .. } => Ok(Some(record.framed_record.clone())),
                _ => store.reject("unexpected relation"),
            }),
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
            full.as_ref().map(|(page, _)| &page.extraction)
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
            sparse.scanned_bytes as u64 + 6 * header_bytes
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
        eprintln!(
            "history_bytes={} recent_scan={} recent_input={} recent_us={} sparse_scan={} sparse_input={} sparse_us={} debug={}",
            72 * 1024 * 1024,
            recent.scanned_bytes,
            recent.input_bytes,
            recent_us,
            sparse.scanned_bytes,
            sparse.input_bytes,
            sparse_us,
            cfg!(debug_assertions)
        );
        Ok(())
    }
}
