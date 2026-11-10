use std::sync::Arc;

use super::*;


mod native;

/// Read bounded pages from one native append subscription.
#[derive(Default)]
pub struct AnalysisAppendRead {
    retained: Option<AppendState>,
}

struct AppendState {
    header: Arc<AppendHeader>,
    range: AppendRange,
}

struct AppendHeader {
    input: AnalysisSelectionV1,
    selection: AnalysisSelectionV1,
    requests: AnalysisTableRequests,
    events: Option<Vec<(u64, u64)>>,
    meta: AnalysisStoreMetaV1,
    sources: Vec<AnalysisSourceSnapshotV1>,
    traces: Vec<AppendTrace>,
    trace_reads: Vec<[u8; 16]>,
    discovery_enabled: bool,
    graph_enabled: bool,
    notification_enabled: bool,
    input_bytes: usize,
    decode_events: bool,
    checked_catalog: bool,
}

struct AppendTrace {
    identity: TraceIdentityV1,
    target_index: u32,
    selected: bool,
}

pub(in crate::analysis) struct AppendRange {
    identity: RawIdentity,
    cpu: Option<u32>,
    range: SegmentRange,
    after: Option<StorePositionV1>,
}

pub(in crate::analysis) struct AppendCapture<'a> {
    input: &'a AnalysisSelectionV1,
    header: Option<Arc<AppendHeader>>,
    pub(super) range: Option<AppendRange>,
    charge: &'a mut dyn FnMut(usize) -> Result<()>,
}

impl AppendRange {
    pub(super) fn new(
        identity: RawIdentity,
        cpu: Option<u32>,
        range: SegmentRange,
        after: Option<StorePositionV1>,
    ) -> Self {
        Self {
            identity,
            cpu,
            range,
            after,
        }
    }

    fn contains(&self, after: Option<StorePositionV1>) -> bool {
        after >= self.after && after.is_none_or(|after| after < self.range.end())
    }

    pub(super) fn window(
        &self,
        after: Option<StorePositionV1>,
        limit: usize,
    ) -> Option<(RawIdentity, Option<u32>, SegmentRange)> {
        Some((
            self.identity.clone(),
            self.cpu,
            self.range.window(after, limit)?,
        ))
    }
}

impl AppendCapture<'_> {
    #[expect(clippy::too_many_arguments)]
    pub(super) fn retain(
        &mut self,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        traces: &[SelectedTrace<'_>],
        output: &mut AnalysisExtractionV1,
        decode_events: bool,
        checked_catalog: bool,
        range: &SegmentRange,
        identity: RawIdentity,
        cpu: Option<u32>,
        after: Option<StorePositionV1>,
    ) -> Result<()> {
        if self.header.is_none() {
            self.capture(
                selection,
                read,
                traces,
                output,
                decode_events,
                checked_catalog,
                range,
            )?;
        }
        self.range = Some(AppendRange::new(identity, cpu, range.clone(), after));
        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn capture(
        &mut self,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        traces: &[SelectedTrace<'_>],
        output: &mut AnalysisExtractionV1,
        decode_events: bool,
        checked_catalog: bool,
        range: &SegmentRange,
    ) -> Result<()> {
        let input_bytes = output.input_bytes;
        let bytes = output
            .allocation_bytes()
            .saturating_add(self.input.allocation_bytes())
            .saturating_add(selection.allocation_bytes())
            .saturating_add(
                std::mem::size_of::<AppendHeader>() + std::mem::size_of::<AppendRange>(),
            )
            .saturating_add(range.metadata_bytes())
            .saturating_add(
                selection
                    .sources
                    .as_slice()
                    .iter()
                    .map(|source| source.node_id.capacity())
                    .max()
                    .unwrap_or(0),
            )
            .saturating_add(
                read.requests
                    .iter()
                    .map(|(name, columns)| {
                        name.capacity()
                            + 8 * std::mem::size_of::<usize>()
                            + columns.as_ref().map_or(0, |columns| {
                                columns.len() * 4 * std::mem::size_of::<usize>()
                            })
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                read.event_ranges
                    .map_or(0, |events| std::mem::size_of_val(events)),
            )
            .saturating_add(traces.len() * std::mem::size_of::<AppendTrace>())
            .saturating_add(
                traces
                    .iter()
                    .map(|trace| trace.identity.node_id.capacity())
                    .sum::<usize>(),
            );
        output.charge(bytes)?;
        (self.charge)(bytes)?;
        self.header = Some(Arc::new(AppendHeader {
            input: self.input.clone(),
            selection: selection.clone(),
            requests: read.requests.clone(),
            events: read.event_ranges.map(<[_]>::to_vec),
            meta: output.meta.clone(),
            sources: output.sources.clone(),
            traces: traces
                .iter()
                .map(|trace| AppendTrace {
                    identity: trace.identity.clone(),
                    target_index: trace.target_index,
                    selected: trace.selected,
                })
                .collect(),
            trace_reads: output.trace_reads.clone(),
            discovery_enabled: output.discovery_enabled,
            graph_enabled: output.graph_enabled,
            notification_enabled: output.notification_enabled,
            input_bytes,
            decode_events,
            checked_catalog,
        }));
        Ok(())
    }
}

impl AppendHeader {
    fn output(
        &self,
        limits: AnalysisExtractLimits,
        replay_floor: Option<StorePositionV1>,
    ) -> Result<AnalysisExtractionV1> {
        if self.input_bytes > limits.input_bytes {
            return AnalysisInputTooLargeSnafu {
                resource: "selected input bytes",
            }
            .fail();
        }
        Ok(AnalysisExtractionV1 {
            discovery_enabled: self.discovery_enabled,
            graph_enabled: self.graph_enabled,
            notification_enabled: self.notification_enabled,
            meta: self.meta.clone(),
            sources: self.sources.clone(),
            missing_contexts: Vec::new(),
            missing_results: Vec::new(),
            references: Vec::new(),
            witnesses: Vec::new(),
            replay_floor,
            scanned_bytes: 0,
            projected_bytes: 0,
            input_bytes: self.input_bytes,
            trace_reads: self.trace_reads.clone(),
            graph_traversal: None,
            graph_coverage: Vec::new(),
            limits,
        })
    }
}


