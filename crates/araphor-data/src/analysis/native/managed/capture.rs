use std::collections::{BTreeMap, BTreeSet};

use super::super::{DataView, NativeStore};
use super::{CallHead, InstanceRecord, Records, VersionRecord};
use crate::analysis::managed::{Capture, SourceScope};
use crate::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1,
    AnalysisTableRead, ManagedAttempt, ManagedCapture, ManagedPage, ManagedRead, ManagedSourceRead,
    NativeStateSnafu, PackageErrorCodeV1 as Code, Result,
};

impl NativeStore {
    pub fn read_managed_reference(
        &self,
        selection: &AnalysisSelectionV1,
        reference: &ManagedAttempt,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<ManagedPage> {
        control.check()?;
        if selection.tenant_id != reference.instance().spec.tenant {
            return Err(Code::Denied.error("managed reference tenant"));
        }
        let scope = reference
            .instance()
            .spec
            .destination
            .selection(&reference.instance().grant.selection)?;
        read.check_scope(selection, &scope)?;
        let physical = self.view()?;
        let selected = reference.source_meta();
        if physical.store_uuid != selected.store_uuid
            || physical.schema_version != selected.schema_version
            || physical.recovery_epoch < selected.recovery_epoch
            || physical.revision < selected.commit_revision
        {
            return Err(Code::Conflict.error("managed journal identity"));
        }
        if !reference.0.capture.traces.is_empty() {
            return Err(Code::Unsupported.error("native managed trace owner"));
        }
        self.check_captured_progress(&reference.0.capture)?;
        let view = self.read_at(selected.commit_revision)?;
        let (mut page, mut state) = self.read_tables_with(
            &view,
            selection,
            &scope,
            read,
            limits,
            control,
            owners,
            None,
            |output| {
                output.meta = selected;
                let mut state = ManagedCapture::from(reference);
                if read.now == reference.request().time_utc_ns {
                    let mode = match read.mode {
                        AnalysisReadModeV1::Complete => Some(ManagedSourceRead::Initial),
                        AnalysisReadModeV1::Changes(after) => {
                            let parent = self
                                .managed_parent(reference, control)?
                                .filter(|parent| parent.position == after)
                                .ok_or_else(|| {
                                    Code::Invalid.error("managed reference source cut")
                                })?;
                            Some(ManagedSourceRead::Changes(parent))
                        }
                        _ => None,
                    };
                    if let Some(mode) = mode {
                        let mut meta = output.meta.clone();
                        meta.recovery_epoch = physical.recovery_epoch;
                        state.source = SourceScope::capture(
                            &state.instance,
                            &meta,
                            mode,
                            &read,
                            selection,
                            owners,
                        )?;
                        if matches!(read.mode, AnalysisReadModeV1::Changes(_))
                            && state.source.is_none()
                        {
                            return Err(Code::Unsupported.error("managed source projection"));
                        }
                        if let (Some(source), Some(receipt)) = (&state.source, reference.receipt())
                        {
                            source.commit_proof(std::sync::Arc::new(receipt.selected.clone()));
                        }
                    }
                }
                if !state.rebuild() {
                    for (call, prior) in &state.contract.prior {
                        let Some(prior) = prior else { continue };
                        let prior = view.managed_prior(
                            &state.instance,
                            *call,
                            &prior.result_id,
                            prior.commit_revision,
                            output,
                            control,
                        )?;
                        state.prior.insert(*call, std::sync::Arc::new(prior));
                    }
                }
                state.bytes = output.input_bytes;
                Ok(state)
            },
        )?;
        state.seal_source(&mut page, control)?;
        Ok(ManagedPage { page, state })
    }

    pub fn read_managed_tables_filtered(
        &self,
        selection: &AnalysisSelectionV1,
        managed: &ManagedRead,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<ManagedPage> {
        self.capture_managed_tables(selection, managed, read, limits, control, owners, None)
    }

    pub fn read_managed_subscribed(
        &self,
        inputs: &crate::InputSubscription,
        selection: &AnalysisSelectionV1,
        managed: &ManagedRead,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> Result<ManagedPage> {
        self.capture_managed_tables(
            selection,
            managed,
            read,
            limits,
            control,
            owners,
            Some(inputs),
        )
    }

    fn capture_managed_tables(
        &self,
        selection: &AnalysisSelectionV1,
        managed: &ManagedRead,
        read: AnalysisTableRead<'_>,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
        inputs: Option<&crate::InputSubscription>,
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
        let (mut page, mut state) = self.read_tables_with(
            &view,
            selection,
            &scope,
            read,
            limits,
            control,
            owners,
            None,
            |output| view.capture_managed(managed, &read, selection, output, owners, control),
        )?;
        state.seal(selection, &page.extraction);
        state.seal_source(&mut page, control)?;
        if let Some(inputs) = inputs {
            state.contract.input =
                Some(inputs.capture_inputs(self, &view, managed, selection, &read, &page, owners)?);
        }
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
        let mut states = BTreeMap::new();
        let retained = request
            .execution
            .as_ref()
            .map(|execution| execution.calls(request, &output.meta))
            .unwrap_or_default();
        for call in instance.spec.manifest.calls.keys() {
            control.check()?;
            let compatible = instance.spec.same_call(&current.spec, *call);
            let head = Records::charged_payload(
                &InstanceRecord::call_key(id, *call),
                |key| Records::read(key, &self.snapshot),
                &mut |bytes| output.charge(bytes),
            )?
            .map(|bytes| Records::decode::<CallHead>(&bytes))
            .transpose()?;
            if !compatible
                && head.as_ref().is_some_and(|head| head.result.is_some())
                && !request.rebuild
            {
                return Err(Code::Conflict.error("managed update requires rebuild"));
            }
            let head = head.filter(|_| compatible).unwrap_or(CallHead {
                revision: 0,
                result: None,
            });
            let reference = if let Some(name) = head.result {
                if !request.rebuild {
                    if let Some(state) = retained
                        .get(call)
                        .filter(|state| state.revision == head.revision && state.result == name)
                    {
                        output.charge(state.allocated_bytes())?;
                        prior.insert(*call, std::sync::Arc::clone(state));
                    } else {
                        let state = self.managed_prior(
                            &instance,
                            *call,
                            &name,
                            head.revision,
                            output,
                            control,
                        )?;
                        prior.insert(*call, std::sync::Arc::new(state));
                    }
                }
                Some(crate::analysis::PackageResultRefV1 {
                    result_id: name,
                    commit_revision: head.revision,
                })
            } else {
                if head.revision != 0 {
                    return Err(Code::Invalid.error("managed empty state"));
                }
                None
            };
            states.insert(*call, reference);
        }
        let source = if let Some(mode) = &request.source {
            let head = self.managed_source_at(&current, control)?;
            match (mode, read.mode) {
                (ManagedSourceRead::Initial, AnalysisReadModeV1::Complete)
                    if head.is_none()
                        || request.rebuild
                        || instance.generation != current.generation => {}
                (ManagedSourceRead::Changes(parent), AnalysisReadModeV1::Changes(after))
                    if head.as_ref().is_some_and(|head| head.0 == *parent)
                        && after == parent.position =>
                {
                    let attempt = &head
                        .as_ref()
                        .ok_or_else(|| Code::Missing.error("managed source parent"))?
                        .1;
                    if attempt.capture.store != output.meta.store_uuid
                        || attempt.capture.schema != output.meta.schema_version
                        || attempt.capture.recovery == 0
                        || attempt.capture.recovery > output.meta.recovery_epoch
                        || attempt.capture.generation != instance.generation
                    {
                        return Err(Code::Conflict.error("managed source store basis"));
                    }
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
            prior: states,
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
            input: None,
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
            prior,
            bytes: output.input_bytes.saturating_sub(before),
            source,
        })
    }
}
