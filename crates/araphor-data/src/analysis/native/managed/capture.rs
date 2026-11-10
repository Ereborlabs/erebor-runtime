use std::collections::{BTreeMap, BTreeSet};

use super::super::{DataView, NativeStore};
use super::{CallHead, InstanceRecord, Records, VersionRecord};
use crate::analysis::managed::{Capture, SourceScope};
use crate::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1,
    AnalysisTableRead, ManagedCapture, ManagedPage, ManagedRead, ManagedSourceRead,
    NativeStateSnafu, PackageErrorCodeV1 as Code, Result,
};

impl NativeStore {
    pub fn read_managed_tables_filtered(
        &self,
        selection: &AnalysisSelectionV1,
        managed: &ManagedRead,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<ManagedPage> {
        if selection.tenant_id != managed.instance.spec.tenant
            || !matches!(
                read.mode,
                AnalysisReadModeV1::Complete
                    | AnalysisReadModeV1::Metadata
                    | AnalysisReadModeV1::Changes(_)
            )
        {
            return Err(Code::Invalid.error("managed capture scope"));
        }
        let scope = managed
            .instance
            .spec
            .destination
            .selection(&managed.instance.grant.selection)?;
        read.check_scope(selection, &scope)?;
        read.check_managed_changes(selection)?;
        let view = self.view()?;
        let mut page = self.read_tables_at(&view, selection, read, limits, control, owners)?;
        let mut state = view.capture_managed(
            managed,
            &read,
            selection,
            &mut page.extraction,
            owners,
            control,
        )?;
        state.seal(selection, &page.extraction);
        state.seal_source(&mut page, control)?;
        Ok(ManagedPage { page, state })
    }
}

impl DataView {
    fn capture_managed(
        &self,
        request: &ManagedRead,
        read: &AnalysisTableRead<'_>,
        selection: &AnalysisSelectionV1,
        output: &mut crate::AnalysisExtractionV1,
        owners: Option<&BTreeSet<String>>,
        control: &AnalysisReadControl,
    ) -> Result<ManagedCapture> {
        let expected = request.expected();
        let before = output.input_bytes;
        if expected.removed || request.instance.removed {
            return Err(Code::Conflict.error("managed instance removed"));
        }
        if request.follow
            && matches!(
                &request.instance.spec.destination,
                crate::ManagedDestination::Graph { .. }
            )
            && (request.expected.is_some()
                || request.rebuild
                || request.completed.is_none()
                || !request.instance.running)
        {
            return Err(Code::Invalid.error("managed Graph follow mode"));
        }
        let current = self
            .managed_instance(expected.spec.tenant, &expected.spec.id, control)?
            .filter(|current| current == expected)
            .ok_or_else(|| Code::Conflict.error("managed capture generation"))?;
        let instance = request.instance.clone();
        let id = Records::find(
            &InstanceRecord::identity(instance.spec.tenant, &instance.spec.id)?,
            |key| Records::read(key, &self.snapshot),
        )?
        .ok_or_else(|| Code::Missing.error("managed capture instance"))?;
        let bytes = Records::charged_payload(
            &VersionRecord::key(id, instance.generation),
            |key| Records::read(key, &self.snapshot),
            &mut |bytes| output.charge(bytes),
        )?
        .ok_or_else(|| Code::Missing.error("managed version"))?;
        let version: VersionRecord = Records::decode(&bytes)?;
        let version = version.check(
            instance.spec.tenant,
            &instance.spec.id,
            instance.generation,
            self.metadata_revision,
        )?;
        if instance.spec != version.spec
            || instance.grant.selection != version.scope
            || instance.grant != current.grant
            || instance.progress != current.progress
            || instance.running != current.running
            || instance.lifecycle != current.lifecycle
        {
            return Err(Code::Conflict.error("managed target version"));
        }
        let completed = self.managed_completed(id, current.generation)?;
        if request
            .completed
            .is_some_and(|expected| expected != completed)
        {
            return Err(Code::Conflict.error("managed capture completion"));
        }
        let mut prior = BTreeMap::new();
        for call in instance.spec.manifest.calls.keys() {
            control.check()?;
            let bytes = Records::charged_payload(
                &InstanceRecord::call_key(id, *call),
                |key| Records::read(key, &self.snapshot),
                &mut |bytes| output.charge(bytes),
            )?
            .ok_or_else(|| Code::Missing.error("managed call head"))?;
            let head: CallHead = Records::decode(&bytes)?;
            if head.revision != 0 || head.result.is_some() || instance.progress != 0 {
                return Err(Code::Unsupported.error("native managed result owner"));
            }
            prior.insert(*call, None);
        }
        let source = if let Some(mode) = &request.source {
            match (mode, read.mode) {
                (ManagedSourceRead::Initial, AnalysisReadModeV1::Complete)
                    if instance.progress == 0
                        || request.rebuild
                        || instance.generation != current.generation => {}
                (ManagedSourceRead::Changes(_), AnalysisReadModeV1::Changes(_)) => {
                    return Err(Code::Unsupported.error("native managed source parent"))
                }
                _ => return Err(Code::Conflict.error("managed source read mode")),
            }
            Some(
                SourceScope::capture(
                    &instance,
                    &output.meta,
                    mode.clone(),
                    read,
                    selection,
                    owners,
                )?
                .ok_or_else(|| Code::Unsupported.error("managed source projection"))?,
            )
        } else {
            None
        };
        let contract = Capture {
            tenant: instance.spec.tenant,
            instance: instance.spec.id.clone(),
            grant: instance.grant.clone(),
            generation: instance.generation,
            expected_generation: current.generation,
            progress: instance.progress,
            completed,
            running: instance.running,
            lifecycle: instance.lifecycle,
            rebuild: request.rebuild,
            follow: request.follow,
            prior,
            store: output.meta.store_uuid,
            schema: output.meta.schema_version,
            recovery: output.meta.recovery_epoch,
            revision: output.meta.commit_revision,
            time_utc_ns: read.now,
            sources: Vec::new(),
            dependencies: Vec::new(),
            witnesses: Vec::new(),
            contexts: Vec::new(),
            traces: Vec::new(),
        };
        if contract
            .prior
            .keys()
            .ne(instance.spec.manifest.calls.keys())
        {
            return NativeStateSnafu {
                field: "managed captured calls",
            }
            .fail();
        }
        let graph = request
            .execution
            .as_ref()
            .and_then(|owner| owner.graph_input(request, &output.meta));
        if let Some(graph) = &graph {
            output.charge(graph.metadata_bytes())?;
        }
        Ok(ManagedCapture {
            graph,
            execution: request.execution.clone(),
            instance,
            contract,
            prior: BTreeMap::new(),
            bytes: output.input_bytes.saturating_sub(before),
            source,
        })
    }
}
