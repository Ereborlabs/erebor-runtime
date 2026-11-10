use super::*;

pub(in crate::analysis) type JournalWork = (u64, u64, u64, u64, u64, std::time::Duration);

pub(in crate::analysis) struct RawScan<'a, 'c> {
    pub(in crate::analysis) selection: &'a AnalysisSelectionV1,
    pub(in crate::analysis) read: &'a AnalysisTableRead<'a>,
    pub(in crate::analysis) traces: &'a [SelectedTrace<'a>],
    pub(in crate::analysis) mode: AnalysisReadModeV1,
    pub(in crate::analysis) end: StorePositionV1,
    pub(in crate::analysis) after: Option<StorePositionV1>,
    pub(in crate::analysis) decode_events: bool,
    pub(in crate::analysis) checked_catalog: bool,
    pub(in crate::analysis) instance: Option<&'a str>,
    pub(in crate::analysis) frozen: Option<&'a super::append::AppendRange>,
    pub(in crate::analysis) retain: Option<&'a mut super::append::AppendCapture<'c>>,
}



impl RawScan<'_, '_> {
    pub(in crate::analysis) fn read(
        &mut self,
        root: &std::path::Path,
        mut select: impl FnMut(
            &AnalysisSelectionV1,
            Option<StorePositionV1>,
            u64,
            usize,
            &AnalysisReadControl,
        ) -> Result<Option<(RawIdentity, Option<u32>, SegmentRange)>>,
        budget: &mut ReadBudget<'_>,
        capture: &mut tables::Capture<'_>,
        removals: &mut std::iter::Peekable<std::vec::IntoIter<changes::RemovedRange>>,
        journal_work: &mut JournalWork,
    ) -> Result<(Option<StorePositionV1>, bool)> {
        let control = budget.control;
        let output = &mut *budget.output;
        let mut after = self.after;
        let mut scanned = 0;
        let mut row_bytes = 0_usize;
        let mut exhausted = false;
        'scan: loop {
            control.check()?;
            if matches!(self.mode, AnalysisReadModeV1::Metadata) {
                after = Some(self.end);
                exhausted = true;
                break;
            }
            let limit = match self.mode {
                AnalysisReadModeV1::Complete
                | AnalysisReadModeV1::Metadata
                | AnalysisReadModeV1::Changes(_) => usize::MAX,
                AnalysisReadModeV1::Page(_) => output.limits.page_rows - scanned,
            };
            if limit == 0 {
                exhausted =
                    select(self.selection, after, self.end.commit_revision, 1, control)?.is_none();
                if exhausted {
                    after = Some(self.end);
                }
                break;
            }
            let selected = match self.frozen {
                Some(range) => range.window(after, limit),
                None => select(
                    self.selection,
                    after,
                    self.end.commit_revision,
                    limit,
                    control,
                )?,
            };
            let Some((identity, cpu, range)) = selected else {
                after = Some(self.end);
                exhausted = true;
                break;
            };
            if matches!(self.mode, AnalysisReadModeV1::Page(_))
                && output.scanned_bytes != 0
                && output.scanned_bytes.saturating_add(range.scan_bytes) > output.limits.scan_bytes
            {
                break;
            }
            output.scan(range.scan_bytes)?;
            if let Some(retain) = &mut self.retain {
                retain.retain(
                    self.selection,
                    self.read,
                    self.traces,
                    output,
                    self.decode_events,
                    self.checked_catalog,
                    &range,
                    identity.clone(),
                    cpu,
                    after,
                )?;
            }
            let read_at = std::time::Instant::now();
            let (records, frame_rows, body_bytes) = range.read(root)?;
            let read_time = read_at.elapsed();
            journal_work.5 += read_time;
            journal_work.0 = journal_work.0.saturating_add(1);
            journal_work.1 = journal_work.1.saturating_add(records.len() as u64);
            journal_work.2 = journal_work.2.saturating_add(range.scan_bytes as u64);
            journal_work.3 = journal_work.3.saturating_add(frame_rows as u64);
            journal_work.4 = journal_work.4.saturating_add(body_bytes as u64);
            erebor_telemetry::debug!(stage="capture",operation="journal_read",
                instance_id=%self.instance.unwrap_or(""),
                cut_revision=output.meta.commit_revision,
                source_name=match identity {RawIdentity::Evidence(_)=>"events",RawIdentity::Diagnostic(_)=>"trace_output"},
                rows=records.len(),bytes=range.scan_bytes,
                frame_rows,body_bytes,elapsed_s=read_time.as_secs_f64(),
                first_cursor=records.first().map_or(0,|record|record.cursor),
                last_cursor=records.last().map_or(0,|record|record.cursor),
                "Journal range read completed");
            for record in records {
                control.check()?;
                while let Some(removal) =
                    removals.next_if(|removal| removal.revision < record.position.commit_revision)
                {
                    output.remove_raw(capture, &removal, control)?;
                }
                let page_bytes =
                    matches!(self.mode, AnalysisReadModeV1::Page(_)).then_some(&mut row_bytes);
                let consumed = match &identity {
                    RawIdentity::Evidence(identity) => {
                        let decoded = self
                            .decode_events
                            .then(|| EvidenceRecord::try_from(record.framed_record.as_slice()))
                            .transpose()?;
                        let selected = self.selection.binding_ids.is_empty()
                            || decoded
                                .as_ref()
                                .and_then(|record| record.decision_context.as_ref())
                                .is_some_and(|context| {
                                    self.selection
                                        .binding_ids
                                        .iter()
                                        .any(|id| id.as_slice() == context.binding_id.as_slice())
                                });
                        if selected {
                            capture.event(
                                identity,
                                cpu.ok_or_else(|| {
                                    crate::AnalysisStateSnafu {
                                        path: root,
                                        reason: "the selected evidence CPU is absent",
                                    }
                                    .build()
                                })?,
                                range.intake,
                                &record,
                                decoded.as_ref(),
                                self.checked_catalog,
                                &mut output.row_budget(control, page_bytes),
                            )?
                        } else {
                            true
                        }
                    }
                    RawIdentity::Diagnostic(identity) => {
                        let trace = self
                            .traces
                            .iter()
                            .find(|trace| trace.identity == identity)
                            .ok_or_else(|| {
                                crate::AnalysisStateSnafu {
                                    path: root,
                                    reason: "the selected trace identity is absent",
                                }
                                .build()
                            })?;
                        if !trace.selected {
                            scanned += 1;
                            after = Some(record.position);
                            continue;
                        }
                        let payload = TraceRecord::read(&record.framed_record, root)?;
                        let (kind, bytes) = match &payload {
                            TracePayload::Metadata(bytes) => ("metadata", bytes),
                            TracePayload::Data(bytes) => ("data", bytes),
                            TracePayload::Diagnostic(bytes) => ("diagnostic", bytes),
                            TracePayload::Terminal(bytes) => {
                                let terminal = TraceRecord::terminal(bytes, root)?;
                                if terminal.execution_id != identity.execution_id
                                    || terminal.last_sequence + 1 != record.cursor
                                {
                                    return crate::Error::reject_path(
                                        root,
                                        "the selected trace terminal identity changed",
                                    );
                                }
                                ("terminal", bytes)
                            }
                        };
                        capture.frame(
                            identity,
                            trace.target_index,
                            record.cursor,
                            record.position,
                            kind,
                            bytes,
                            &mut output.row_budget(control, page_bytes),
                        )?
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

            if self.frozen.is_some() {
                exhausted =
                    select(self.selection, after, self.end.commit_revision, 1, control)?.is_none();
                if exhausted {
                    after = Some(self.end);
                }
                break;
            }
        }
        if exhausted {
            while let Some(removal) =
                removals.next_if(|removal| removal.revision <= self.end.commit_revision)
            {
                output.remove_raw(capture, &removal, control)?;
            }
        }
        Ok((after, exhausted))
    }
}
