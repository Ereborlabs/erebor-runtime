use std::{collections::BTreeSet, mem::size_of};

use super::{DataView, NativeStore};
use crate::analysis::extraction::{
    raw::{JournalWork, RawScan},
    tables::Capture,
};
use crate::{
    AnalysisExtractLimits, AnalysisExtractionV1, AnalysisPositionPageV1, AnalysisReadControl,
    AnalysisReadModeV1, AnalysisSelectionV1, AnalysisTableRead, NativeStateSnafu,
    PackageErrorCodeV1 as Code, Result, StorePositionV1,
};

mod context;
mod graph;
mod source;

impl NativeStore {
    pub fn read_tables(
        &self,
        selection: &AnalysisSelectionV1,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<AnalysisPositionPageV1> {
        let view = self.view()?;
        self.read_tables_at(&view, selection, read, limits, control, None)
    }

    pub fn read_tables_at(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<AnalysisPositionPageV1> {
        self.read_tables_with(
            view,
            selection,
            selection,
            read,
            limits,
            control,
            owners,
            |_| Ok(()),
        )
        .map(|(page, ())| page)
    }

    pub fn read_tables_filtered(
        &self,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<AnalysisPositionPageV1> {
        read.check_scope(selection, scope)?;
        self.read_tables_with(
            self.view()?.as_ref(),
            selection,
            scope,
            read,
            limits,
            control,
            owners,
            |_| Ok(()),
        )
        .map(|(page, ())| page)
    }

    pub(in crate::analysis::native) fn read_tables_with<T>(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
        prepare: impl FnOnce(&mut AnalysisExtractionV1) -> Result<T>,
    ) -> Result<(AnalysisPositionPageV1, T)> {
        control.check()?;
        read.check_inputs(selection, limits, &self.root)?;
        let _lease = self.maintenance.read_until(control)?;
        self.check()?;
        if view.store_uuid != self.view()?.store_uuid {
            return NativeStateSnafu {
                field: "read store identity",
            }
            .fail();
        }
        for name in read.requests.keys() {
            if !matches!(
                name.as_str(),
                "events"
                    | "coverage"
                    | "context_versions"
                    | "context"
                    | "notification_routes"
                    | "compiled_policies"
                    | "targets"
                    | "catalog"
                    | "trace_recipes"
                    | "findings"
                    | "graph_manifest"
            ) {
                return Err(Code::Unsupported.error("native table owner"));
            }
        }
        let projected = selection.project(read.requests)?;
        if !projected.results.is_empty()
            || !projected.traces.is_empty()
            || !projected.profiles().is_empty()
            || projected.graph_traversal().is_some()
            || !projected.notification_keys().is_empty()
        {
            return Err(Code::Unsupported.error("native selection owner"));
        }
        limits.check_keys(&projected)?;
        if projected.allocation_bytes() > limits.input_bytes {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "selected input keys",
            }
            .fail();
        }
        let mut selected = projected;
        let mut output = AnalysisExtractionV1::new(view.meta(), limits);
        output.charge(size_of::<AnalysisExtractionV1>() + selected.allocation_bytes())?;
        if let Some(owners) = owners {
            for owner in owners {
                output.charge(owner.len() + size_of::<String>())?;
            }
        }
        let prepared = prepare(&mut output)?;
        self.select_sources(view, &mut selected, &mut output, control)?;
        self.select_graphs(view, &mut selected, &mut output, control)?;
        limits.check_keys(&selected)?;
        let mode = match read.mode {
            AnalysisReadModeV1::Complete if !read.reads_raw() => AnalysisReadModeV1::Metadata,
            other => other,
        };
        let end = StorePositionV1 {
            commit_revision: view.revision,
            ordinal: u32::MAX,
        };
        let after = match mode {
            AnalysisReadModeV1::Page(after) => after,
            AnalysisReadModeV1::Changes(after) => Some(after),
            _ => None,
        };
        if after.is_some_and(|after| after > end) {
            return crate::AnalysisStore::reject_path(
                &self.root,
                "the position read starts beyond the captured revision",
            );
        }
        let mut capture = Capture::new(&read, &selected);
        let decode = !selected.binding_ids.is_empty() || read.needs_event_decode();
        let checked = read.projected("events").is_some_and(|columns| {
            let schema = &crate::AnalysisStore::table_schemas()["events"];
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
        let mut scan = RawScan {
            selection: &selected,
            read: &read,
            traces: &[],
            mode,
            end,
            after,
            decode_events: decode,
            checked_catalog: checked,
            instance: None,
            frozen: None,
            retain: None,
        };
        let mut work: JournalWork = Default::default();
        let (through, exhausted) = scan.read(
            &self.root,
            |selection, after, revision, limit, control| {
                self.raw
                    .until(control)?
                    .select_position_at(&view.raw, selection, after, revision, limit, control)
            },
            &mut output.sink(control),
            &mut capture,
            &mut Vec::new().into_iter().peekable(),
            &mut work,
        )?;
        context::ContextRead::new(view, &mut output, control).capture(
            &selected,
            &read,
            owners,
            &mut capture,
        )?;
        self.extract_graphs(
            view,
            &selected,
            scope,
            &read,
            &mut output,
            &mut capture,
            control,
        )?;
        let through = if matches!(mode, AnalysisReadModeV1::Changes(_)) {
            end
        } else {
            through.unwrap_or(StorePositionV1 {
                commit_revision: 0,
                ordinal: 0,
            })
        };
        Ok((
            capture.finish(output, through, exhausted, control)?,
            prepared,
        ))
    }
}
