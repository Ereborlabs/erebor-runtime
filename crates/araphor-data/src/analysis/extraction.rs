use std::borrow::Cow;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::ops::Bound;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::raw::{RawIdentity, TracePayload, TraceRecord};
use super::segments::SegmentRange;
use super::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisGapV1, AnalysisReadControl,
    AnalysisRecordV1, AnalysisSourceReceiptV1, AnalysisStore, AnalysisStoreMetaV1, StorePositionV1,
    MAX_ANALYSIS_PAGE_BYTES, MAX_ANALYSIS_PAGE_RECORDS,
};
use crate::{
    AnalysisDatabaseSnafu, AnalysisInputTooLargeSnafu, EvidenceIntakeIdentityV1, Result,
    TraceFrameKindV1, TraceFrameV1, TraceIdentityV1, TraceIntentV1, TraceMeasurementV1,
    TraceOutputReceiptV1, TraceRecipeV1, TraceStateV1,
};

const MAX_EXTRACT_KEYS: usize = 1024;
const MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AnalysisExtractLimits {
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

/// Input selection after tenant authorization. An empty explicit list selects no events.
#[derive(Clone, Debug)]
pub struct AnalysisSelectionV1 {
    pub tenant_id: [u8; 16],
    pub sources: Vec<EvidenceIntakeIdentityV1>,
    pub all_sources: bool,
    pub all_contexts: bool,
    pub(crate) targets: bool,
    pub(crate) targets_only: bool,
    pub(crate) discovery: bool,
    pub(crate) discovery_context: bool,
    pub(crate) profiles: Vec<String>,
    pub traces: Vec<TraceIdentityV1>,
    pub all_traces: bool,
    pub(crate) measurements: bool,
    /// Node IDs narrow evidence, coverage, and targets, not context versions.
    pub nodes: Vec<String>,
    pub binding_ids: Vec<[u8; 16]>,
    pub received_from: Bound<u64>,
    pub received_until: Bound<u64>,
    pub contexts: Vec<AnalysisContextKeyV1>,
    pub results: Vec<String>,
}

impl AnalysisSelectionV1 {
    pub fn new(tenant_id: [u8; 16], sources: Vec<EvidenceIntakeIdentityV1>) -> Self {
        Self {
            tenant_id,
            sources,
            all_sources: false,
            all_contexts: false,
            targets: false,
            targets_only: false,
            discovery: false,
            discovery_context: false,
            profiles: Vec::new(),
            traces: Vec::new(),
            all_traces: false,
            measurements: false,
            nodes: Vec::new(),
            binding_ids: Vec::new(),
            received_from: Bound::Unbounded,
            received_until: Bound::Unbounded,
            contexts: Vec::new(),
            results: Vec::new(),
        }
    }

    pub fn tenant(tenant_id: [u8; 16]) -> Self {
        Self {
            all_sources: true,
            all_contexts: true,
            all_traces: true,
            ..Self::new(tenant_id, Vec::new())
        }
    }

    pub(crate) fn valid(&self) -> bool {
        self.tenant_id != [0; 16]
            && (!self.targets_only || self.targets)
            && (!self.all_sources || self.sources.is_empty())
            && (!self.all_contexts || self.contexts.is_empty())
            && (!self.all_traces || self.traces.is_empty())
            && self.nodes.len() <= MAX_EXTRACT_KEYS
            && self.nodes.iter().all(|node| crate::node_id_is_valid(node))
            && self.nodes.iter().collect::<BTreeSet<_>>().len() == self.nodes.len()
            && [
                self.sources.len(),
                self.contexts.len(),
                self.results.len(),
                self.profiles.len(),
                self.traces.len(),
                self.binding_ids.len(),
            ]
            .into_iter()
            .try_fold(MAX_EXTRACT_KEYS, usize::checked_sub)
            .is_some()
            && self.binding_ids.iter().all(|id| *id != [0; 16])
            && self.binding_ids.iter().collect::<BTreeSet<_>>().len() == self.binding_ids.len()
            && self
                .sources
                .iter()
                .all(|source| source.tenant_id == self.tenant_id && source.valid())
            && self
                .contexts
                .iter()
                .all(|key| key.tenant_id == self.tenant_id && key.valid())
            && self
                .results
                .iter()
                .all(|id| !id.is_empty() && id.len() <= 256)
            && self
                .profiles
                .iter()
                .all(|id| !id.is_empty() && id.len() <= 256)
            && self.sources.iter().collect::<BTreeSet<_>>().len() == self.sources.len()
            && self.contexts.iter().collect::<BTreeSet<_>>().len() == self.contexts.len()
            && self.results.iter().collect::<BTreeSet<_>>().len() == self.results.len()
            && self.profiles.iter().collect::<BTreeSet<_>>().len() == self.profiles.len()
            && self
                .traces
                .iter()
                .all(|identity| identity.tenant_id == self.tenant_id && identity.validate().is_ok())
            && self.traces.iter().collect::<BTreeSet<_>>().len() == self.traces.len()
    }

    fn allocation_bytes(&self) -> usize {
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
        for source in &self.sources {
            bytes = bytes.saturating_add(source.node_id.capacity());
        }
        for key in &self.contexts {
            bytes = bytes
                .saturating_add(key.owner_id.capacity())
                .saturating_add(key.entity_key.capacity())
                .saturating_add(key.lifetime_key.capacity());
        }
        for key in self.nodes.iter().chain(&self.results).chain(&self.profiles) {
            bytes = bytes.saturating_add(key.capacity());
        }
        for identity in &self.traces {
            bytes = bytes.saturating_add(identity.node_id.capacity());
        }
        bytes
    }

    pub(crate) fn time_range(&self) -> Option<(u64, u64)> {
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
    },
    Context(&'a AnalysisContextVersionV1),
    DiscoveryContext(&'a AnalysisContextVersionV1),
    Behavior {
        profile: &'a crate::DiscoveryProfileV1,
        commit_revision: u64,
        atom: Option<&'a crate::BehaviorAtomV1>,
        discovery_enabled: bool,
    },
    Target {
        context: &'a AnalysisContextVersionV1,
        fact: &'a crate::WorkloadTargetFactV1,
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
    TraceMeasurement {
        identity: &'a TraceIdentityV1,
        measurement: &'a TraceMeasurementV1,
    },
    Result {
        result_id: &'a str,
        body: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisRelationV1 {
    Events,
    Context,
    DiscoveryContext,
    Behaviors,
    Targets,
    Results,
    Traces,
    TraceOutput,
    TraceMeasurements,
}

#[derive(Debug)]
pub struct AnalysisInputPageV1<T = Box<[u8]>> {
    pub relation: AnalysisRelationV1,
    pub rows: Vec<T>,
    pub input_bytes: usize,
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

#[derive(Debug)]
pub struct AnalysisExtractionV1<T = Box<[u8]>> {
    pub discovery_enabled: bool,
    pub meta: AnalysisStoreMetaV1,
    pub sources: Vec<AnalysisSourceSnapshotV1>,
    pub missing_contexts: Vec<AnalysisContextKeyV1>,
    pub missing_results: Vec<String>,
    pub pages: Vec<AnalysisInputPageV1<T>>,
    pub replay_floor: Option<StorePositionV1>,
    pub scanned_bytes: usize,
    pub projected_bytes: usize,
    /// Includes projected bytes, row descriptors, page headers, and coverage metadata.
    pub input_bytes: usize,
    pub(crate) trace_reads: Vec<[u8; 16]>,
    pub(crate) limits: AnalysisExtractLimits,
}

#[derive(Debug)]
pub struct AnalysisPositionPageV1<T = Box<[u8]>> {
    pub extraction: AnalysisExtractionV1<T>,
    /// Includes scanned rows that did not pass the projection.
    pub scanned_through: StorePositionV1,
    pub exhausted: bool,
}

enum ExtractMode {
    Complete,
    Metadata,
    Page(Option<StorePositionV1>),
}

impl<T> AnalysisExtractionV1<T> {
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

    fn push(&mut self, relation: AnalysisRelationV1, (row, heap): (T, usize)) -> Result<()> {
        let bytes = heap
            .checked_add(size_of::<T>())
            .filter(|bytes| *bytes <= self.limits.page_bytes)
            .ok_or_else(|| {
                AnalysisInputTooLargeSnafu {
                    resource: "projected row bytes",
                }
                .build()
            })?;
        let new_page = self.pages.last().is_none_or(|page| {
            page.relation != relation
                || page.rows.len() == self.limits.page_rows
                || page
                    .input_bytes
                    .checked_add(bytes)
                    .is_none_or(|total| total > self.limits.page_bytes)
        });
        self.charge(heap)?;
        if new_page {
            let added = Self::grow(&mut self.pages, self.input_bytes, self.limits.input_bytes)?;
            self.charge(added)?;
            self.pages.push(AnalysisInputPageV1 {
                relation,
                rows: Vec::new(),
                input_bytes: 0,
            });
        }
        let missing = || {
            crate::AnalysisStateSnafu {
                path: std::path::Path::new("<extraction>"),
                reason: "the charged input page is absent",
            }
            .build()
        };
        let page = self.pages.last_mut().ok_or_else(missing)?;
        let added = Self::grow(&mut page.rows, self.input_bytes, self.limits.input_bytes)?;
        self.charge(added)?;
        self.projected_bytes += heap;
        let page = self.pages.last_mut().ok_or_else(missing)?;
        page.input_bytes += bytes;
        page.rows.push(row);
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
        if !selection.all_sources
            && !selection.all_contexts
            && !selection.all_traces
            && !selection.targets_only
            && !selection.discovery
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
        resolved.all_sources = false;
        resolved.all_contexts = false;
        resolved.all_traces = false;
        resolved.discovery = false;
        if selection.targets_only {
            resolved
                .contexts
                .retain(|key| key.owner_id == "mithril-control/target");
        }
        resolved
            .sources
            .retain(|source| resolved.nodes.is_empty() || resolved.nodes.contains(&source.node_id));
        resolved.traces.retain(|identity| {
            resolved.nodes.is_empty() || resolved.nodes.contains(&identity.node_id)
        });
        let mut bytes = resolved.allocation_bytes();
        if bytes > limit {
            return Err(error());
        }
        if selection.all_sources {
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
                    if resolved.sources.len()
                        + resolved.contexts.len()
                        + resolved.results.len()
                        + resolved.profiles.len()
                        + resolved.traces.len()
                        + resolved.binding_ids.len()
                        == MAX_EXTRACT_KEYS
                    {
                        return Err(error());
                    }
                    let added =
                        AnalysisExtractionV1::<()>::grow(&mut resolved.sources, bytes, limit)?;
                    bytes = bytes
                        .checked_add(added)
                        .and_then(|bytes| bytes.checked_add(source.node_id.capacity()))
                        .filter(|bytes| *bytes <= limit)
                        .ok_or_else(error)?;
                    resolved.sources.push(source);
                }
            }
        }
        if selection.all_contexts {
            let remaining = MAX_EXTRACT_KEYS
                - resolved.sources.len()
                - resolved.results.len()
                - resolved.profiles.len()
                - resolved.traces.len()
                - resolved.binding_ids.len();
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
                if resolved.contexts.len() == remaining {
                    return Err(error());
                }
                let added = AnalysisExtractionV1::<()>::grow(&mut resolved.contexts, bytes, limit)?;
                bytes = bytes
                    .checked_add(added)
                    .and_then(|bytes| bytes.checked_add(key.owner_id.capacity()))
                    .and_then(|bytes| bytes.checked_add(key.entity_key.capacity()))
                    .and_then(|bytes| bytes.checked_add(key.lifetime_key.capacity()))
                    .filter(|bytes| *bytes <= limit)
                    .ok_or_else(error)?;
                resolved.contexts.push(key);
            }
        }
        if selection.all_traces {
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
                    return crate::QueryDeniedSnafu.fail();
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
                    if resolved.sources.len()
                        + resolved.contexts.len()
                        + resolved.results.len()
                        + resolved.profiles.len()
                        + resolved.traces.len()
                        + resolved.binding_ids.len()
                        == MAX_EXTRACT_KEYS
                    {
                        return Err(error());
                    }
                    let added =
                        AnalysisExtractionV1::<()>::grow(&mut resolved.traces, bytes, limit)?;
                    bytes = bytes
                        .checked_add(added)
                        .and_then(|bytes| bytes.checked_add(identity.node_id.capacity()))
                        .filter(|bytes| *bytes <= limit)
                        .ok_or_else(error)?;
                    resolved.traces.push(identity);
                }
            }
        }
        if selection.discovery {
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
            for source in &resolved.sources {
                control.check()?;
                let remaining = MAX_EXTRACT_KEYS
                    - resolved.sources.len()
                    - resolved.contexts.len()
                    - resolved.results.len()
                    - resolved.profiles.len()
                    - resolved.traces.len()
                    - resolved.binding_ids.len();
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
                    if resolved.sources.len()
                        + resolved.contexts.len()
                        + resolved.results.len()
                        + resolved.profiles.len()
                        + resolved.traces.len()
                        + resolved.binding_ids.len()
                        == MAX_EXTRACT_KEYS
                    {
                        return Err(error());
                    }
                    let added =
                        AnalysisExtractionV1::<()>::grow(&mut resolved.profiles, bytes, limit)?;
                    bytes = bytes
                        .checked_add(added)
                        .and_then(|bytes| bytes.checked_add(id.capacity()))
                        .filter(|bytes| *bytes <= limit)
                        .ok_or_else(error)?;
                    resolved.profiles.push(id);
                }
            }
            resolved.profiles.sort();
            resolved.profiles.dedup();
        }
        control.check()?;
        Ok((Cow::Owned(resolved), bytes))
    }

    /// Project permitted rows and fields without caller I/O. No partial input escapes an error.
    pub fn extract(
        &self,
        selection: &AnalysisSelectionV1,
        control: &AnalysisReadControl,
        mut project: impl FnMut(AnalysisInputV1<'_>) -> Result<Option<Vec<u8>>>,
    ) -> Result<AnalysisExtractionV1> {
        self.extract_mode(
            selection,
            ExtractMode::Complete,
            AnalysisExtractLimits::default(),
            control,
            |input| {
                project(input).map(|row| {
                    row.map(|row| {
                        let bytes = row.len();
                        (row.into_boxed_slice(), bytes)
                    })
                })
            },
        )
        .map(|page| page.extraction)
    }

    /// Read a bounded page in durable commit order, including pending source ranges.
    pub fn read_positions(
        &self,
        selection: &AnalysisSelectionV1,
        after: Option<StorePositionV1>,
        control: &AnalysisReadControl,
        mut project: impl FnMut(AnalysisInputV1<'_>) -> Result<Option<Vec<u8>>>,
    ) -> Result<AnalysisPositionPageV1> {
        self.extract_mode(
            selection,
            ExtractMode::Page(after),
            AnalysisExtractLimits::default(),
            control,
            |input| {
                project(input).map(|row| {
                    row.map(|row| {
                        let bytes = row.len();
                        (row.into_boxed_slice(), bytes)
                    })
                })
            },
        )
    }

    pub(crate) fn extract_rows<T>(
        &self,
        selection: &AnalysisSelectionV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        project: impl FnMut(AnalysisInputV1<'_>) -> Result<Option<(T, usize)>>,
    ) -> Result<AnalysisPositionPageV1<T>> {
        self.extract_mode(selection, ExtractMode::Complete, limits, control, project)
    }

    pub(crate) fn position_rows<T>(
        &self,
        selection: &AnalysisSelectionV1,
        after: Option<StorePositionV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        project: impl FnMut(AnalysisInputV1<'_>) -> Result<Option<(T, usize)>>,
    ) -> Result<AnalysisPositionPageV1<T>> {
        self.extract_mode(
            selection,
            ExtractMode::Page(after),
            limits,
            control,
            project,
        )
    }

    pub(crate) fn metadata_rows<T>(
        &self,
        selection: &AnalysisSelectionV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        project: impl FnMut(AnalysisInputV1<'_>) -> Result<Option<(T, usize)>>,
    ) -> Result<AnalysisPositionPageV1<T>> {
        self.extract_mode(selection, ExtractMode::Metadata, limits, control, project)
    }

    fn extract_mode<T>(
        &self,
        selection: &AnalysisSelectionV1,
        mode: ExtractMode,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        mut project: impl FnMut(AnalysisInputV1<'_>) -> Result<Option<(T, usize)>>,
    ) -> Result<AnalysisPositionPageV1<T>> {
        control.check()?;
        if !selection.valid() {
            return self.reject("the extraction selection has invalid, duplicate, or foreign keys");
        }
        if limits.scan_bytes == 0
            || limits.input_bytes == 0
            || limits.page_bytes == 0
            || limits.page_rows == 0
        {
            return self.reject("the extraction limits must be positive");
        }
        let coordinator = self.read_coordinator(control)?;
        let explicit_traces = !selection.all_traces && !selection.traces.is_empty();
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
            };
            if after.is_some_and(|position| position > end) {
                return self.reject("the position read starts beyond the captured revision");
            }
            // The revision fixes raw selection. The lease prevents segment deletion.
            drop(coordinator);
            let mut output = AnalysisExtractionV1 {
                discovery_enabled: self.discovery_enabled(),
                meta,
                sources: Vec::new(),
                missing_contexts: Vec::new(),
                missing_results: Vec::new(),
                pages: Vec::new(),
                scanned_bytes: 0,
                projected_bytes: 0,
                input_bytes: 0,
                trace_reads: Vec::new(),
                limits,
                replay_floor: Self::replay_floor_from(snapshot, selection.tenant_id)?,
            };
            output.charge(size_of::<AnalysisExtractionV1<T>>())?;
            output.charge(key_bytes)?;
            if let (ExtractMode::Page(Some(position)), Some(floor)) = (&mode, output.replay_floor) {
                if *position < floor {
                    return crate::QueryCursorExpiredSnafu {
                        position: *position,
                        floor,
                    }
                    .fail();
                }
            }
            for identity in &selection.sources {
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
                let added = AnalysisExtractionV1::<T>::grow(
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
            for identity in &selection.traces {
                control.check()?;
                let (state, intent) = Self::read_trace_intent(
                    snapshot,
                    &self.root,
                    identity.tenant_id,
                    identity.request_id,
                )?
                .ok_or_else(|| self.state_error("the selected trace is absent"))?;
                if state.read_revoked {
                    return crate::QueryDeniedSnafu.fail();
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
                let added = AnalysisExtractionV1::<T>::grow(
                    &mut trace_info,
                    output.input_bytes,
                    limits.input_bytes,
                )?;
                output.charge(added)?;
                trace_info.push((
                    index as u32,
                    selected,
                    TraceRecipeV1::identify(&intent.source)?,
                ));
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
                            return crate::QueryCursorExpiredSnafu { position, floor }.fail();
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
                    let added = AnalysisExtractionV1::<T>::grow(
                        &mut output.trace_reads,
                        output.input_bytes,
                        limits.input_bytes,
                    )?;
                    output.charge(added)?;
                    output.trace_reads.push(identity.request_id);
                }
                if let Some(row) = project(AnalysisInputV1::Trace {
                    state: &state,
                    intent: &intent,
                    target_index: index as u32,
                    receipt: &receipt,
                })? {
                    output.push(AnalysisRelationV1::Traces, row)?;
                }
            }
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
                    ExtractMode::Complete | ExtractMode::Metadata => usize::MAX,
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
                    let row = match &identity {
                        RawIdentity::Evidence(identity) => {
                            let selected = selection.binding_ids.is_empty()
                                || crate::EvidenceRecord::try_from(
                                    record.framed_record.as_slice(),
                                )?
                                .decision_context
                                .as_ref()
                                .is_some_and(|context| {
                                    selection
                                        .binding_ids
                                        .iter()
                                        .any(|id| id.as_slice() == context.binding_id.as_slice())
                                });
                            if selected {
                                project(AnalysisInputV1::Event {
                                    identity,
                                    cpu_id: cpu.ok_or_else(|| {
                                        self.state_error("the selected evidence CPU is absent")
                                    })?,
                                    received_utc_ns: range.intake,
                                    record: &record,
                                })?
                                .map(|row| (AnalysisRelationV1::Events, row))
                            } else {
                                None
                            }
                        }
                        RawIdentity::Diagnostic(identity) => {
                            let index = selection
                                .traces
                                .iter()
                                .position(|selected| selected == identity)
                                .ok_or_else(|| {
                                    self.state_error("the selected trace identity is absent")
                                })?;
                            let (target_index, selected, recipe) = trace_info[index];
                            if !selected {
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
                            if selection.measurements && kind == "data" {
                                if let Some(recipe) = recipe {
                                    let frame = TraceFrameV1 {
                                        execution_id: identity.execution_id,
                                        sequence: record.cursor,
                                        kind: TraceFrameKindV1::Data,
                                        bytes: bytes.clone(),
                                    };
                                    if let Some(measurements) = recipe.measurements(&frame) {
                                        for measurement in measurements {
                                            control.check()?;
                                            if let Some(row) =
                                                project(AnalysisInputV1::TraceMeasurement {
                                                    identity,
                                                    measurement: &measurement,
                                                })?
                                            {
                                                output.push(
                                                    AnalysisRelationV1::TraceMeasurements,
                                                    row,
                                                )?;
                                            }
                                        }
                                    }
                                }
                            }
                            project(AnalysisInputV1::TraceOutput {
                                identity,
                                target_index,
                                sequence: record.cursor,
                                position: record.position,
                                kind,
                                bytes,
                            })?
                            .map(|row| (AnalysisRelationV1::TraceOutput, row))
                        }
                    };
                    if let Some((relation, row)) = row {
                        let bytes = row.1.saturating_add(size_of::<T>());
                        if matches!(mode, ExtractMode::Page(_))
                            && row_bytes.saturating_add(bytes) > limits.page_bytes
                        {
                            if row_bytes == 0 {
                                return AnalysisInputTooLargeSnafu {
                                    resource: "projected row bytes",
                                }
                                .fail();
                            }
                            break 'scan;
                        }
                        output.push(relation, row)?;
                        row_bytes += bytes;
                    }
                    scanned += 1;
                    after = Some(record.position);
                }
            }
            for key in &selection.contexts {
                control.check()?;
                match Self::read_context_from(snapshot, &self.root, key)? {
                    Some((context, _)) => {
                        if let Some(row) = project(AnalysisInputV1::Context(&context))? {
                            output.push(AnalysisRelationV1::Context, row)?;
                        }
                        if selection.discovery_context {
                            if let Some(row) = project(AnalysisInputV1::DiscoveryContext(&context))?
                            {
                                output.push(AnalysisRelationV1::DiscoveryContext, row)?;
                            }
                        }
                        if selection.targets && context.key.owner_id == "mithril-control/target" {
                            control.check()?;
                            let fact = serde_json::from_slice::<crate::WorkloadTargetFactV1>(
                                &context.body,
                            )
                            .map_err(|_| {
                                self.state_error("the retained target context is invalid")
                            })?;
                            if (!selection.nodes.is_empty()
                                && !selection.nodes.contains(&fact.node_id))
                                || (!selection.binding_ids.is_empty()
                                    && !fact.kubernetes.as_ref().is_some_and(|identity| {
                                        uuid::Uuid::parse_str(&identity.binding_id).is_ok_and(
                                            |id| selection.binding_ids.contains(id.as_bytes()),
                                        )
                                    }))
                            {
                                continue;
                            }
                            if let Some(row) = project(AnalysisInputV1::Target {
                                context: &context,
                                fact: &fact,
                            })? {
                                output.push(AnalysisRelationV1::Targets, row)?;
                            }
                        }
                    }
                    None => {
                        let key = key.clone();
                        output.charge(
                            key.owner_id.capacity()
                                + key.entity_key.capacity()
                                + key.lifetime_key.capacity(),
                        )?;
                        let added = AnalysisExtractionV1::<T>::grow(
                            &mut output.missing_contexts,
                            output.input_bytes,
                            output.limits.input_bytes,
                        )?;
                        output.charge(added)?;
                        output.missing_contexts.push(key);
                    }
                }
            }
            for id in &selection.profiles {
                control.check()?;
                let body = self
                    .read_result_from(snapshot, selection.tenant_id, id)?
                    .ok_or_else(|| self.state_error("the selected discovery profile is absent"))?;
                output.charge(body.capacity())?;
                let profile = crate::DiscoveryProfileV1::try_from(body.as_slice())?;
                if profile.profile_id != *id || !selection.sources.contains(&profile.scope.identity)
                {
                    return self.reject("the discovery profile scope differs from its selection");
                }
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
                if selection.binding_ids.is_empty() {
                    if let Some(row) = project(AnalysisInputV1::Behavior {
                        profile: &profile,
                        commit_revision: revision,
                        atom: None,
                        discovery_enabled: output.discovery_enabled,
                    })? {
                        output.push(AnalysisRelationV1::Behaviors, row)?;
                    }
                }
                for atom in &profile.snapshot.atoms {
                    control.check()?;
                    if !selection.binding_ids.is_empty()
                        && !selection.binding_ids.contains(&atom.key.binding_id)
                    {
                        continue;
                    }
                    if let Some(row) = project(AnalysisInputV1::Behavior {
                        profile: &profile,
                        commit_revision: revision,
                        atom: Some(atom),
                        discovery_enabled: output.discovery_enabled,
                    })? {
                        output.push(AnalysisRelationV1::Behaviors, row)?;
                    }
                }
            }
            for id in &selection.results {
                control.check()?;
                match self.read_result_from(snapshot, selection.tenant_id, id)? {
                    Some(body) => {
                        if let Some(row) = project(AnalysisInputV1::Result {
                            result_id: id,
                            body: &body,
                        })? {
                            output.push(AnalysisRelationV1::Results, row)?;
                        }
                    }
                    None => {
                        let id = id.clone();
                        output.charge(id.capacity())?;
                        let added = AnalysisExtractionV1::<T>::grow(
                            &mut output.missing_results,
                            output.input_bytes,
                            output.limits.input_bytes,
                        )?;
                        output.charge(added)?;
                        output.missing_results.push(id);
                    }
                }
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

    fn extract_gaps<T>(
        &self,
        snapshot: &Connection,
        identity: &EvidenceIntakeIdentityV1,
        recovery: bool,
        control: &AnalysisReadControl,
        output: &mut AnalysisExtractionV1<T>,
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
            let added = AnalysisExtractionV1::<T>::grow(
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

    fn identity(tenant: u8) -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [tenant; 16],
            node_id: "n".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        }
    }

    #[test]
    fn analysis_trace_key_limits() {
        let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
        selection.traces = (1_u128..=1024)
            .map(|execution| TraceIdentityV1 {
                tenant_id: [1; 16],
                node_id: "trace-node".into(),
                node_boot_id: [2; 16],
                request_id: [3; 16],
                execution_id: execution.to_be_bytes(),
                source_sha256: [4; 32],
            })
            .collect();
        assert!(selection.valid());
        selection.binding_ids.push([5; 16]);
        assert!(!selection.valid());
        selection.traces.pop();
        assert!(selection.valid());
        selection.binding_ids.push([5; 16]);
        assert!(!selection.valid());
        selection.binding_ids = vec![[0; 16]];
        assert!(!selection.valid());
        selection.binding_ids = vec![[5; 16]];
        selection.traces[0].tenant_id = [2; 16];
        assert!(!selection.valid());
    }

    #[test]
    fn analysis_selection_key_limits() {
        let mut selection = AnalysisSelectionV1::new([1; 16], vec![identity(1)]);
        selection.contexts.push(AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "context".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        });
        selection.results.push("result".into());
        selection.profiles.push("profile".into());
        selection.binding_ids.push([5; 16]);
        selection.traces = (1..=MAX_EXTRACT_KEYS as u128 - 5)
            .map(|execution| TraceIdentityV1 {
                tenant_id: [1; 16],
                node_id: "trace-node".into(),
                node_boot_id: [2; 16],
                request_id: [3; 16],
                execution_id: execution.to_be_bytes(),
                source_sha256: [4; 32],
            })
            .collect();
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
        let complete = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            let AnalysisInputV1::Event { record, .. } = input else {
                return store.reject("unexpected relation");
            };
            Ok(Some(vec![record.cursor as u8]))
        })?;
        assert_eq!(complete.pages[0].rows.len(), 10);
        let before = store.meta()?;
        let mut positions = Vec::new();
        let first =
            store.read_positions(&selection, None, &AnalysisReadControl::default(), |input| {
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
            })?;
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
            first.extraction.pages[0]
                .rows
                .iter()
                .map(|row| row[0])
                .collect::<Vec<_>>(),
            (11..=20).collect::<Vec<_>>()
        );
        let next = store.read_positions(
            &selection,
            Some(first.scanned_through),
            &AnalysisReadControl::default(),
            |input| {
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
            },
        )?;
        assert!(next.exhausted);
        assert_eq!(next.extraction.sources[0].receipt.contiguous_cursor, 20);
        assert!(next.extraction.sources[0].pending.is_empty());
        assert_eq!(
            next.extraction.pages[0]
                .rows
                .iter()
                .map(|row| row[0])
                .collect::<Vec<_>>(),
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
        let retry = store.read_positions(
            &selection,
            Some(next.scanned_through),
            &AnalysisReadControl::default(),
            |_| store.reject("an exact retry produced another query row"),
        )?;
        assert!(retry.exhausted && retry.extraction.pages.is_empty());
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
        let first =
            store.read_positions(&selection, None, &AnalysisReadControl::default(), |input| {
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
            })?;
        assert!(!first.exhausted);
        assert_eq!(seen.len(), 256);
        assert!(first.extraction.pages.is_empty());
        assert_eq!(first.scanned_through, seen[255]);
        let next = store.read_positions(
            &selection,
            Some(first.scanned_through),
            &AnalysisReadControl::default(),
            |input| {
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
            },
        )?;
        assert!(next.exhausted);
        assert_eq!(
            next.extraction.pages[0]
                .rows
                .iter()
                .map(|row| row[0])
                .collect::<Vec<_>>(),
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
        let page =
            store.read_positions(&selection, None, &AnalysisReadControl::default(), |input| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                positions.push(record.position);
                Ok(Some(vec![record.cursor as u8]))
            })?;
        let expected = [3, 7, 1, 2, 4, 5, 6, 8, 9, 10];
        assert_eq!(
            page.extraction.pages[0]
                .rows
                .iter()
                .map(|row| row[0])
                .collect::<Vec<_>>(),
            expected
        );
        for (index, position) in positions.iter().enumerate() {
            let page = store.read_positions(
                &selection,
                Some(*position),
                &AnalysisReadControl::default(),
                |input| {
                    let AnalysisInputV1::Event { record, .. } = input else {
                        return store.reject("unexpected relation");
                    };
                    Ok(Some(vec![record.cursor as u8]))
                },
            )?;
            assert!(page.exhausted);
            assert_eq!(
                page.extraction
                    .pages
                    .iter()
                    .flat_map(|page| &page.rows)
                    .map(|row| row[0])
                    .collect::<Vec<_>>(),
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
        let first =
            store.read_positions(&selection, None, &AnalysisReadControl::default(), |input| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                positions.push(record.position);
                Ok((record.cursor != 2).then(|| vec![record.cursor as u8; 600 * 1024]))
            })?;
        assert!(!first.exhausted);
        assert_eq!(first.extraction.pages[0].rows.len(), 1);
        assert_eq!(first.extraction.pages[0].rows[0][0], 1);
        assert_eq!(first.scanned_through, positions[1]);
        let next = store.read_positions(
            &selection,
            Some(first.scanned_through),
            &AnalysisReadControl::default(),
            |input| {
                let AnalysisInputV1::Event { record, .. } = input else {
                    return store.reject("unexpected relation");
                };
                assert_eq!(record.cursor, 3);
                Ok(Some(vec![3; 600 * 1024]))
            },
        )?;
        assert!(next.exhausted);
        assert_eq!(next.extraction.pages[0].rows.len(), 1);
        assert_eq!(next.extraction.pages[0].rows[0][0], 3);
        assert!(store
            .read_positions(&selection, None, &AnalysisReadControl::default(), |_| Ok(
                Some(vec![0; MAX_ANALYSIS_PAGE_BYTES])
            ))
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
            let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
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
                    rotation
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|_| store.state_error("the writer did not request rotation"))?;
                }
                Ok(Some(vec![identity.source_epoch as u8, record.cursor as u8]))
            });
            assert_eq!(
                writer.join().map_err(|_| "writer panicked")??,
                crate::EvidenceStoreOutcomeV1::Accepted
            );
            let output = output?;
            assert_eq!(output.meta, before);
            assert_eq!(output.sources[1].receipt.contiguous_cursor, 3);
            let rows: Vec<_> = output
                .pages
                .iter()
                .flat_map(|page| &page.rows)
                .map(|row| row.as_ref())
                .collect();
            assert_eq!(rows, [&[1, 1], &[2, 1], &[2, 2], &[2, 3]]);
            Ok(())
        })?;
        let later = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            let AnalysisInputV1::Event {
                identity, record, ..
            } = input
            else {
                return store.reject("unexpected relation");
            };
            Ok(Some(vec![identity.source_epoch as u8, record.cursor as u8]))
        })?;
        assert_eq!(later.meta.commit_revision, before.commit_revision + 1);
        assert_eq!(later.sources[1].receipt.contiguous_cursor, 4);
        let rows: Vec<_> = later
            .pages
            .iter()
            .flat_map(|page| &page.rows)
            .map(|row| row.as_ref())
            .collect();
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
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            let AnalysisInputV1::Event {
                identity: source,
                cpu_id,
                record,
                received_utc_ns,
            } = input
            else {
                return store.reject("unexpected relation");
            };
            assert_eq!(source, &identity);
            assert_eq!(cpu_id, 0);
            assert_eq!(received_utc_ns, 20);
            Ok(Some(record.cursor.to_be_bytes().to_vec()))
        })?;
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
        assert_eq!(output.pages[0].rows[0].as_ref(), &3_u64.to_be_bytes());
        assert_eq!(output.sources[0].receipt.contiguous_cursor, 3);
        assert_eq!(store.meta()?, before);
        for (from, until) in [
            (Bound::Excluded(u64::MAX), Bound::Unbounded),
            (Bound::Unbounded, Bound::Excluded(0)),
            (Bound::Included(31), Bound::Included(30)),
        ] {
            selection.received_from = from;
            selection.received_until = until;
            let empty = store.extract(&selection, &AnalysisReadControl::default(), |_| {
                store.reject("empty range decoded input")
            })?;
            assert!(empty.pages.is_empty());
            assert_eq!(empty.scanned_bytes, 0);
        }
        selection.sources.clear();
        assert!(store
            .extract(&selection, &AnalysisReadControl::default(), |_| store
                .reject("empty source scope is not a wildcard"))?
            .pages
            .is_empty());
        selection.sources.push(foreign);
        assert!(store
            .extract(&selection, &AnalysisReadControl::default(), |_| Ok(None))
            .is_err());
        selection.sources = vec![identity.clone(), identity];
        assert!(store
            .extract(&selection, &AnalysisReadControl::default(), |_| Ok(None))
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
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            let AnalysisInputV1::Event { identity, .. } = input else {
                return store.reject("a late context entered the snapshot");
            };
            assert_eq!(identity, &first);
            calls += 1;
            store.accept_validated_batch(next.clone(), batch(1, 1, 20))?;
            store.commit_context(&context)?;
            Ok(Some(vec![7]))
        })?;
        assert_eq!(calls, 1);
        assert_eq!(output.meta, before);
        assert_eq!(output.sources.len(), 1);
        assert_eq!(output.pages.len(), 1);
        assert!(output.missing_contexts.is_empty());
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            Ok(Some(match input {
                AnalysisInputV1::Event { identity, .. } => vec![identity.source_id[0]],
                AnalysisInputV1::Context(context) => context.body.clone(),
                _ => return store.reject("an unselected result entered the snapshot"),
            }))
        })?;
        assert_eq!(output.sources.len(), 2);
        assert_eq!(output.pages.len(), 2);
        assert_eq!(output.pages[0].rows.len(), 2);
        assert_eq!(output.pages[1].rows[0].as_ref(), &[42]);
        let empty = AnalysisSelectionV1::new(first.tenant_id, vec![]);
        assert!(store
            .extract(&empty, &AnalysisReadControl::default(), |_| {
                store.reject("an empty explicit list selected input")
            })?
            .pages
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
        selection.all_contexts = false;
        selection.contexts = (0..MAX_EXTRACT_KEYS - 1)
            .map(|revision| AnalysisContextKeyV1 {
                tenant_id: first.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision as u64,
            })
            .collect();
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
        let output = store.extract(&selection, &control, |_| Ok(None))?;
        assert_eq!(output.sources.len(), 1);
        assert_eq!(output.missing_contexts.len(), MAX_EXTRACT_KEYS - 1);
        let mut next = first.clone();
        next.source_id = [4; 16];
        store.accept_validated_batch(next, batch(1, 1, 20))?;
        assert!(matches!(
            store.extract(&selection, &control, |_| Ok(None)),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input keys",
                ..
            })
        ));
        let selection = AnalysisSelectionV1::tenant(first.tenant_id);
        assert!(matches!(
            store.extract_rows(
                &selection,
                AnalysisExtractLimits {
                    input_bytes: size_of::<AnalysisSelectionV1>() - 1,
                    ..Default::default()
                },
                &control,
                |_| Ok(None::<((), usize)>)
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.extract(&selection, &cancelled, |_| Ok(None)),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        let mut invalid = selection.clone();
        invalid.sources.push(first.clone());
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
        selection.contexts.push(context.key.clone());
        selection.results.push("late".into());
        let before = store.meta()?;
        let mut calls = 0;
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            let AnalysisInputV1::Event { record, .. } = input else {
                return store.reject("late metadata entered snapshot");
            };
            assert_eq!(record.cursor, 1);
            calls += 1;
            store.accept_validated_batch(identity.clone(), batch(2, 1, 5))?;
            store.commit_context(&context)?;
            store.commit_result(&AnalysisResultCommitV1 {
                scope: scope.clone(),
                expected_cursor: 0,
                consumed_cursor: 1,
                coverage_revision: 0,
                context_revision: 0,
                result_id: "late".into(),
                body: vec![43],
                created_utc_ns: 20,
                witnesses: vec![],
                context_refs: vec![],
            })?;
            Ok(Some(vec![1]))
        })?;
        assert_eq!(calls, 1);
        assert_eq!(output.meta, before);
        assert_eq!(output.sources[0].receipt.contiguous_cursor, 1);
        assert_eq!(output.missing_contexts, vec![context.key]);
        assert_eq!(output.missing_results, vec!["late"]);
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            Ok(Some(match input {
                AnalysisInputV1::Event { record, .. } => vec![record.cursor as u8],
                AnalysisInputV1::Context(context) => context.body.clone(),
                AnalysisInputV1::Result { body, .. } => body.to_vec(),
                AnalysisInputV1::Trace { .. }
                | AnalysisInputV1::TraceOutput { .. }
                | AnalysisInputV1::TraceMeasurement { .. }
                | AnalysisInputV1::Target { .. }
                | AnalysisInputV1::DiscoveryContext(_)
                | AnalysisInputV1::Behavior { .. } => {
                    return store.reject("unselected input entered an evidence-only snapshot")
                }
            }))
        })?;
        assert!(output.missing_contexts.is_empty() && output.missing_results.is_empty());
        assert_eq!(output.meta, store.meta()?);
        assert_eq!(output.pages.len(), 3);
        assert_eq!(output.pages[0].rows.len(), 2);
        assert_eq!(output.pages[1].rows[0].as_ref(), &[42]);
        assert_eq!(output.pages[2].rows[0].as_ref(), &[43]);
        selection.received_from = Bound::Included(100);
        let output = store.extract(&selection, &AnalysisReadControl::default(), |input| {
            Ok(Some(match input {
                AnalysisInputV1::Context(context) => context.body.clone(),
                AnalysisInputV1::Result { body, .. } => body.to_vec(),
                _ => return store.reject("old event entered a new window"),
            }))
        })?;
        assert_eq!(output.scanned_bytes, 0);
        assert_eq!(output.pages.len(), 2);
        assert_eq!(output.pages[0].relation, AnalysisRelationV1::Context);
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
        let output = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok(Some(record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            },
        )?;
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
            store.extract(&selection, &AnalysisReadControl::default(), |_| {
                Ok(Some(vec![0; 512 * 1024]))
            }),
            Err(crate::Error::AnalysisInputTooLarge {
                resource: "selected input bytes",
                ..
            })
        ));
        let rows: Vec<_> = output.pages.iter().flat_map(|page| &page.rows).collect();
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
        selection.sources.push(EvidenceIntakeIdentityV1 {
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
            store.extract(&selection, &AnalysisReadControl::default(), |_| Ok(None)),
            Err(crate::Error::Io { .. })
        ));
        std::fs::rename(&hidden, &path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.write_all_at(&[8], offset)?;
        assert!(matches!(
            store.extract(&selection, &AnalysisReadControl::default(), |_| Ok(None)),
            Err(crate::Error::AnalysisState { .. })
        ));
        file.write_all_at(&[7], offset)?;
        let result = store.extract(&selection, &AnalysisReadControl::default(), |_| {
            Ok(Some(vec![7]))
        })?;
        assert_eq!(result.pages[0].rows[0].as_ref(), &[7]);
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
        let output = store.extract(&selection, &AnalysisReadControl::default(), |_| {
            Ok(Some(vec![2]))
        })?;
        assert_eq!(output.input_bytes, owned_bytes(&output));
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
            .extract(&selection, &AnalysisReadControl::default(), |_| Ok(None))
            .is_err());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }

    fn owned_bytes(output: &AnalysisExtractionV1) -> usize {
        size_of::<AnalysisExtractionV1>()
            + output.pages.capacity() * size_of::<AnalysisInputPageV1>()
            + output.sources.capacity() * size_of::<AnalysisSourceSnapshotV1>()
            + output.missing_contexts.capacity() * size_of::<AnalysisContextKeyV1>()
            + output.missing_results.capacity() * size_of::<String>()
            + output
                .pages
                .iter()
                .map(|page| {
                    page.rows.capacity() * size_of::<Box<[u8]>>()
                        + page.rows.iter().map(|row| row.len()).sum::<usize>()
                })
                .sum::<usize>()
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
            selection.contexts.push(AnalysisContextKeyV1 {
                tenant_id: identity.tenant_id,
                owner_id: "missing".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision,
            });
            selection.results.push(format!("missing-{revision}"));
        }
        let output = store.extract(&selection, &AnalysisReadControl::default(), |_| {
            Ok(Some(vec![1]))
        })?;
        let required = owned_bytes(&output);
        assert_eq!(output.input_bytes, required);
        assert_eq!(output.pages[0].rows.len(), 4);
        assert_eq!(output.sources[0].pending.len(), 1);
        assert_eq!(output.sources[0].recovery.len(), 1);
        assert_eq!(output.missing_contexts.len(), 4);
        assert_eq!(output.missing_results.len(), 4);
        drop(output);
        for limit in [required, required - 1] {
            let result = store.extract_rows(
                &selection,
                AnalysisExtractLimits {
                    input_bytes: limit,
                    ..Default::default()
                },
                &AnalysisReadControl::default(),
                |_| Ok(Some((vec![1].into_boxed_slice(), 1))),
            );
            if limit == required {
                let output = result?.extraction;
                assert_eq!(output.input_bytes, required);
                assert_eq!(output.input_bytes, owned_bytes(&output));
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
        let output = store.extract(&selection, &AnalysisReadControl::default(), |_| {
            Ok(Some(vec![1]))
        })?;
        assert_eq!(
            output
                .pages
                .iter()
                .map(|page| page.rows.len())
                .collect::<Vec<_>>(),
            vec![256, 1]
        );
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
            store.extract(&selection, &control, |_| {
                calls += 1;
                control.cancel()?;
                Ok(Some(vec![1]))
            }),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        assert_eq!(calls, 1);
        let mut output = store.extract(
            &AnalysisSelectionV1::new(identity.tenant_id, vec![]),
            &AnalysisReadControl::default(),
            |_| store.reject("empty selection"),
        )?;
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
        let mut output = store.extract(
            &AnalysisSelectionV1::new(identity.tenant_id, vec![]),
            &AnalysisReadControl::default(),
            |_| store.reject("empty selection"),
        )?;
        output.push(
            AnalysisRelationV1::Events,
            (
                vec![0; MAX_ANALYSIS_PAGE_BYTES - size_of::<Box<[u8]>>()].into_boxed_slice(),
                MAX_ANALYSIS_PAGE_BYTES - size_of::<Box<[u8]>>(),
            ),
        )?;
        assert_eq!(output.pages[0].input_bytes, MAX_ANALYSIS_PAGE_BYTES);
        output.push(AnalysisRelationV1::Events, (Box::default(), 0))?;
        assert_eq!(output.pages.len(), 2);
        assert!(matches!(
            output.push(
                AnalysisRelationV1::Events,
                (
                    vec![0; MAX_ANALYSIS_PAGE_BYTES - size_of::<Box<[u8]>>() + 1]
                        .into_boxed_slice(),
                    MAX_ANALYSIS_PAGE_BYTES - size_of::<Box<[u8]>>() + 1,
                )
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
        let recent = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok(Some(record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            },
        )?;
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
        let sparse = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => {
                    Ok((record.cursor % 32 == 1).then(|| record.cursor.to_be_bytes().to_vec()))
                }
                _ => store.reject("unexpected relation"),
            },
        )?;
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
        let full = store.extract(
            &selection,
            &AnalysisReadControl::default(),
            |input| match input {
                AnalysisInputV1::Event { record, .. } => Ok(Some(record.framed_record.clone())),
                _ => store.reject("unexpected relation"),
            },
        );
        assert!(
            matches!(
                full,
                Err(crate::Error::AnalysisInputTooLarge {
                    resource: "selected input bytes",
                    ..
                })
            ),
            "{full:?}"
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
            scope,
            expected_cursor: 0,
            consumed_cursor: 18 * 32,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "sparse-history".into(),
            body: vec![1],
            created_utc_ns: 21,
            witnesses: (0..18)
                .map(|group| crate::AnalysisWitnessV1 {
                    identity: identity.clone().into(),
                    cursor: group * 32 + 1,
                    expires_utc_ns: 100,
                })
                .collect(),
            context_refs: vec![],
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
        eprintln!("history_bytes={} recent_scan={} recent_input={} recent_us={} sparse_scan={} sparse_input={} sparse_us={} debug={}",
            72 * 1024 * 1024, recent.scanned_bytes, recent.input_bytes, recent_us,
            sparse.scanned_bytes, sparse.input_bytes, sparse_us, cfg!(debug_assertions));
        Ok(())
    }
}
