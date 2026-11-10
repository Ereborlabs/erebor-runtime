use std::{collections::BTreeSet, mem::size_of};

use super::{DataView, NativeStore};
use crate::analysis::extraction::{
    append::AppendCapture,
    raw::{JournalWork, RawScan},
    tables::Capture,
};
use crate::{
    AnalysisExtractLimits, AnalysisExtractionV1, AnalysisPositionPageV1, AnalysisReadControl,
    AnalysisReadModeV1, AnalysisSelectionV1, AnalysisTableRead, NativeStateSnafu,
    PackageErrorCodeV1 as Code, Result, StorePositionV1,
};

mod context;
mod discovery;
mod graph;
mod graph_state;
mod source;

impl NativeStore {
    pub fn subscription_metadata(
        &self,
        scope: &AnalysisSelectionV1,
        demands: &crate::AnalysisTableRequests,
        now: u64,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> Result<(AnalysisSelectionV1, AnalysisPositionPageV1)> {
        control.check()?;
        if demands.iter().any(|(name, columns)| {
            columns.is_some() || !crate::AnalysisStore::table_schemas().contains_key(name)
        }) {
            return Err(Code::Invalid.error("subscription metadata scope"));
        }
        let bytes = scope.metadata_bytes(demands);
        if bytes > limits.input_bytes {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "subscription metadata scope",
            }
            .fail();
        }
        let selection = scope.metadata_projection(demands);
        let read = AnalysisTableRead {
            requests: demands,
            event_ranges: None,
            mode: AnalysisReadModeV1::Metadata,
            now,
        };
        let view = self.view()?;
        let (page, ()) = self.read_tables_with(
            &view,
            &selection,
            scope,
            read,
            limits,
            control,
            None,
            None,
            None,
            |output| output.charge(bytes),
        )?;
        Ok((selection, page))
    }

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
            None,
            None,
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
            None,
            None,
            |_| Ok(()),
        )
        .map(|(page, ())| page)
    }

    pub(in crate::analysis) fn read_tables_with<T>(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        scope: &AnalysisSelectionV1,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
        retain: Option<&mut AppendCapture<'_>>,
        target: Option<&crate::ManagedInstance>,
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
                    | "discovery_state"
                    | "graph_state"
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
        output.graph_enabled = true;
        output.discovery_enabled = self
            .discovery_owners
            .load(std::sync::atomic::Ordering::Acquire)
            != 0;
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
            retain,
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
        self.extract_graph_state(view, &selected, &read, &mut output, &mut capture, control)?;
        self.extract_discovery_state(
            view,
            &selected,
            &read,
            target,
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

    pub(in crate::analysis) fn scan_append(
        &self,
        scan: &mut RawScan<'_, '_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<(Option<StorePositionV1>, bool, crate::AnalysisStoreMetaV1)> {
        control.check()?;
        let _lease = self.maintenance.read_until(control)?;
        let view = self.view()?;
        let (through, exhausted) = scan.read(
            &self.root,
            |selection, after, revision, limit, control| {
                self.raw
                    .until(control)?
                    .select_position_at(&view.raw, selection, after, revision, limit, control)
            },
            &mut output.sink(control),
            capture,
            &mut Vec::new().into_iter().peekable(),
            &mut JournalWork::default(),
        )?;
        Ok((through, exhausted, view.meta()))
    }
}
