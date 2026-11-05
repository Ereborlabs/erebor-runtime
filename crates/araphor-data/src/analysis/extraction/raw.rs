use super::*;

pub(super) type JournalWork = (u64, u64, u64, u64, u64, std::time::Duration);

pub(super) struct RawScan<'a, 'c> {
    pub(super) selection: &'a AnalysisSelectionV1,
    pub(super) read: &'a AnalysisTableRead<'a>,
    pub(super) traces: &'a [SelectedTrace<'a>],
    pub(super) mode: AnalysisReadModeV1,
    pub(super) end: StorePositionV1,
    pub(super) after: Option<StorePositionV1>,
    pub(super) decode_events: bool,
    pub(super) checked_catalog: bool,
    pub(super) instance: Option<&'a str>,
    pub(super) frozen: Option<&'a super::append::AppendRange>,
    pub(super) retain: Option<&'a mut super::append::AppendCapture<'c>>,
}

impl AnalysisStore {
    pub(super) fn scan_raw(
        &self,
        scan: &mut RawScan<'_, '_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut tables::Capture<'_>,
        removals: &mut std::iter::Peekable<std::vec::IntoIter<changes::RemovedRange>>,
        control: &AnalysisReadControl,
        journal_work: &mut JournalWork,
    ) -> Result<(Option<StorePositionV1>, bool)> {
        let mut after = scan.after;
        let mut scanned = 0;
        let mut row_bytes = 0_usize;
        let mut exhausted = false;
        'scan: loop {
            control.check()?;
            if matches!(scan.mode, AnalysisReadModeV1::Metadata) {
                after = Some(scan.end);
                exhausted = true;
                break;
            }
            let limit = match scan.mode {
                AnalysisReadModeV1::Complete
                | AnalysisReadModeV1::Metadata
                | AnalysisReadModeV1::Changes(_) => usize::MAX,
                AnalysisReadModeV1::Page(_) => output.limits.page_rows - scanned,
            };
            if limit == 0 {
                exhausted = self
                    .selected_position(scan.selection, after, scan.end.commit_revision, 1, control)?
                    .is_none();
                if exhausted {
                    after = Some(scan.end);
                }
                break;
            }
            let selected = match scan.frozen {
                Some(range) => range.window(after, limit),
                None => self.selected_position(
                    scan.selection,
                    after,
                    scan.end.commit_revision,
                    limit,
                    control,
                )?,
            };
            let Some((identity, cpu, range)) = selected else {
                after = Some(scan.end);
                exhausted = true;
                break;
            };
            if matches!(scan.mode, AnalysisReadModeV1::Page(_))
                && output.scanned_bytes != 0
                && output.scanned_bytes.saturating_add(range.scan_bytes) > output.limits.scan_bytes
            {
                break;
            }
            output.scan(range.scan_bytes)?;
            if let Some(retain) = &mut scan.retain {
                retain.retain(
                    scan.selection,
                    scan.read,
                    scan.traces,
                    output,
                    scan.decode_events,
                    scan.checked_catalog,
                    &range,
                    identity.clone(),
                    cpu,
                    after,
                )?;
            }
            let read_at = std::time::Instant::now();
            let (records, frame_rows, body_bytes) = range.read(&self.root)?;
            let read_time = read_at.elapsed();
            journal_work.5 += read_time;
            journal_work.0 = journal_work.0.saturating_add(1);
            journal_work.1 = journal_work.1.saturating_add(records.len() as u64);
            journal_work.2 = journal_work.2.saturating_add(range.scan_bytes as u64);
            journal_work.3 = journal_work.3.saturating_add(frame_rows as u64);
            journal_work.4 = journal_work.4.saturating_add(body_bytes as u64);
            erebor_telemetry::debug!(stage="capture",operation="journal_read",
                instance_id=%scan.instance.unwrap_or(""),
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
                    matches!(scan.mode, AnalysisReadModeV1::Page(_)).then_some(&mut row_bytes);
                let consumed = match &identity {
                    RawIdentity::Evidence(identity) => {
                        let decoded = scan
                            .decode_events
                            .then(|| EvidenceRecord::try_from(record.framed_record.as_slice()))
                            .transpose()?;
                        let selected = scan.selection.binding_ids.is_empty()
                            || decoded
                                .as_ref()
                                .and_then(|record| record.decision_context.as_ref())
                                .is_some_and(|context| {
                                    scan.selection
                                        .binding_ids
                                        .iter()
                                        .any(|id| id.as_slice() == context.binding_id.as_slice())
                                });
                        if selected {
                            capture.event(
                                identity,
                                cpu.ok_or_else(|| {
                                    self.state_error("the selected evidence CPU is absent")
                                })?,
                                range.intake,
                                &record,
                                decoded.as_ref(),
                                scan.checked_catalog,
                                &mut output.row_budget(control, page_bytes),
                            )?
                        } else {
                            true
                        }
                    }
                    RawIdentity::Diagnostic(identity) => {
                        let trace = scan
                            .traces
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
                                    return self
                                        .reject("the selected trace terminal identity changed");
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

            if scan.frozen.is_some() {
                exhausted = self
                    .selected_position(scan.selection, after, scan.end.commit_revision, 1, control)?
                    .is_none();
                if exhausted {
                    after = Some(scan.end);
                }
                break;
            }
        }
        Ok((after, exhausted))
    }
}
