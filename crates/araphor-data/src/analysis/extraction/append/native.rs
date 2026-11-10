use super::*;
use crate::analysis::native::NativeStore;

impl NativeStore {
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
        let raw = read.reads_raw() && read.requests.keys().all(|name| name == "events");
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
        let result = self.view().and_then(|view| {
            self.read_tables_with(
                &view,
                selection,
                scope,
                read,
                limits,
                control,
                None,
                raw.then_some(&mut retained),
                |_| Ok(()),
            )
        });
        match result {
            Ok((page, ())) => {
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
        let header = &state.header;
        let read = AnalysisTableRead {
            requests: &header.requests,
            event_ranges: header.events.as_deref(),
            mode: AnalysisReadModeV1::Page(after),
            now,
        };
        let mut output = header.output(limits, None)?;
        let mut capture = tables::Capture::new(&read, &header.selection);
        let (through, exhausted, meta) = self.scan_append(
            &mut raw::RawScan {
                selection: &header.selection,
                read: &read,
                traces: &[],
                mode: read.mode,
                end: StorePositionV1 {
                    commit_revision: header.meta.commit_revision,
                    ordinal: u32::MAX,
                },
                after,
                decode_events: header.decode_events,
                checked_catalog: header.checked_catalog,
                instance: None,
                frozen: Some(&state.range),
                retain: None,
            },
            &mut output,
            &mut capture,
            control,
        )?;
        let page = capture.finish(
            output,
            through.unwrap_or(StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            }),
            exhausted,
            control,
        )?;
        Ok((page, meta))
    }
}
