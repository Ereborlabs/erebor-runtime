use std::sync::Arc;

use super::*;

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

impl AnalysisStore {
    /// Read an events or trace-output append page with the same input scope.
    #[expect(clippy::too_many_arguments)]
    pub fn read_append_tables_filtered(
        &self,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        mut read: AnalysisTableRead<'_>,
        after: Option<StorePositionV1>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        cursor: &mut AnalysisAppendRead,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(AnalysisPositionPageV1, AnalysisStoreMetaV1)> {
        read.mode = AnalysisReadModeV1::Page(after);
        read.check_scope(selection, scope)?;
        let raw = read.reads_raw()
            && read
                .requests
                .keys()
                .all(|name| matches!(name.as_str(), "events" | "trace_output"));
        if let Some(state) = cursor.retained.as_ref().filter(|state| {
            raw && state.range.contains(after)
                && state.header.input == *selection
                && state.header.requests == *read.requests
                && state.header.events.as_deref() == read.event_ranges
        }) {
            return self.read_append_page(state, after, read.now, limits, control);
        }
        cursor.retained = None;
        charge(0)?;
        let mut retained = AppendCapture {
            input: selection,
            header: None,
            range: None,
            charge,
        };
        let result = self.read_tables_inner(
            selection,
            scope,
            None,
            None,
            read,
            limits,
            control,
            None,
            None,
            raw.then_some(&mut retained),
        );
        match result {
            Ok((page, _)) => {
                cursor.retained = retained
                    .header
                    .take()
                    .zip(retained.range.take())
                    .map(|(header, range)| AppendState { header, range });
                if cursor.retained.is_none() {
                    (retained.charge)(0)?;
                }
                let meta = page.extraction.meta.clone();
                Ok((page, meta))
            }
            Err(error) => {
                (retained.charge)(0)?;
                Err(error)
            }
        }
    }

    fn read_append_page(
        &self,
        state: &AppendState,
        after: Option<StorePositionV1>,
        now: u64,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<(AnalysisPositionPageV1, AnalysisStoreMetaV1)> {
        let started = std::time::Instant::now();
        control.check()?;
        let (coordinator, mut reader) = self.coordinated_reader(control)?;
        let mut journal_work = (0, 0, 0, 0, 0, std::time::Duration::ZERO);
        let result = control.run(&mut reader, |snapshot| {
            let meta = Self::read_meta_from(snapshot, &self.root.join("analysis.duckdb"))?;
            let header = &state.header;
            let replay_floor = Self::replay_floor_from(snapshot, header.selection.tenant_id)?;
            drop(coordinator);
            #[cfg(test)]
            control.test_snapshot()?;
            if let (Some(position), Some(floor)) = (after, replay_floor) {
                if position < floor {
                    return crate::AnalysisReplayExpiredSnafu { position, floor }.fail();
                }
            }
            for trace in &header.traces {
                control.check()?;
                let (state, intent) = Self::read_trace_intent(
                    snapshot,
                    &self.root,
                    trace.identity.tenant_id,
                    trace.identity.request_id,
                )?
                .ok_or_else(|| self.state_error("the selected trace is absent"))?;
                if state.read_revoked {
                    return crate::AnalysisReadDeniedSnafu.fail();
                }
                if !intent
                    .bindings
                    .iter()
                    .any(|binding| binding.identity == trace.identity)
                {
                    return Err(self.state_error("the selected trace binding changed"));
                }
            }
            let read = AnalysisTableRead {
                requests: &header.requests,
                event_ranges: header.events.as_deref(),
                mode: AnalysisReadModeV1::Page(after),
                now,
            };
            let mut output = header.output(limits, replay_floor)?;
            output.charge(header.traces.len() * std::mem::size_of::<SelectedTrace<'_>>())?;
            let traces = header
                .traces
                .iter()
                .map(|trace| SelectedTrace {
                    identity: &trace.identity,
                    target_index: trace.target_index,
                    selected: trace.selected,
                })
                .collect::<Vec<_>>();
            let mut capture = tables::Capture::new(&read, &header.selection);
            let end = StorePositionV1 {
                commit_revision: header.meta.commit_revision,
                ordinal: u32::MAX,
            };
            let (after, exhausted) = self.scan_raw(
                &mut raw::RawScan {
                    selection: &header.selection,
                    read: &read,
                    traces: &traces,
                    mode: read.mode,
                    end,
                    after,
                    decode_events: header.decode_events,
                    checked_catalog: header.checked_catalog,
                    instance: None,
                    frozen: Some(&state.range),
                    retain: None,
                },
                &mut output,
                &mut capture,
                &mut Vec::new().into_iter().peekable(),
                control,
                &mut journal_work,
            )?;
            control.check()?;
            let page = capture.finish(
                output,
                after.unwrap_or(StorePositionV1 {
                    commit_revision: 0,
                    ordinal: 0,
                }),
                exhausted,
                control,
            )?;
            Ok((page, meta))
        });
        if let Ok((page, _)) = &result {
            erebor_telemetry::debug!(
                stage = "capture",
                operation = "complete",
                instance_id = "",
                cut_revision = page.extraction.meta.commit_revision,
                source_name = "journal",
                read_count = journal_work.0,
                rows = journal_work.1,
                bytes = journal_work.2,
                frame_rows = journal_work.3,
                body_bytes = journal_work.4,
                journal_s = journal_work.5.as_secs_f64(),
                elapsed_s = started.elapsed().as_secs_f64(),
                "Source capture completed"
            );
        }
        result
    }
}
