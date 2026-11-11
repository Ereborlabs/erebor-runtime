use super::*;
use crate::analysis::native::{
    progress::{profile::IntervalHead, Processor, ResultRecord},
    records::Records,
};
use crate::{
    AnalysisReferenceOriginV1, DiscoveryHistoryRowV1, DiscoveryProfileV1, DiscoverySnapshotRowV1,
    DiscoveryStateRowV1,
};
use snafu::ResultExt as _;

impl NativeStore {
    pub(super) fn extract_discovery_state(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        target: Option<&crate::ManagedInstance>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let Some(projected) = read.projected("discovery_state") else {
            return Ok(());
        };
        let schema = &crate::AnalysisStore::table_schemas()["discovery_state"];
        let decode = projected.iter().any(|index| {
            matches!(
                schema.field(*index).name().as_str(),
                "facts_revision"
                    | "coverage_revision"
                    | "created_utc_ns"
                    | "updated_utc_ns"
                    | "sealed"
                    | "input_bytes"
                    | "incomplete"
                    | "gaps"
                    | "context_refs"
                    | "snapshot"
                    | "current_compatible"
            )
        });
        for identity in selection.sources.as_slice() {
            control.check()?;
            let Some(receipt) = view.source_receipt(identity)? else {
                continue;
            };
            let scope = crate::ProcessorScopeV1 {
                processor_id: crate::DISCOVERY_PROCESSOR.into(),
                method_version: u64::from(crate::DISCOVERY_SCHEMA_VERSION),
                identity: identity.clone(),
            };
            let processor = Processor::read(
                &scope,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |bytes| output.charge(bytes),
            )?;
            output.charge(size_of::<DiscoveryStateRowV1>() + identity.node_id.len())?;
            let mut state = DiscoveryStateRowV1 {
                tenant_id: identity.tenant_id,
                node_id: identity.node_id.clone(),
                node_boot_id: identity.node_boot_id,
                label_epoch: identity.label_epoch,
                source_id: identity.source_id,
                source_epoch: identity.source_epoch,
                cpu_id: receipt.cpu_id,
                contiguous_cursor: receipt.contiguous_cursor,
                input_unbounded: capture.input_unbounded(),
                retained_floor: receipt.retained_floor,
                source_coverage_revision: receipt.coverage_revision,
                method_version: scope.method_version,
                processor_present: processor.is_some(),
                processor_class: processor.as_ref().map(|(_, state)| {
                    match state.class {
                        crate::ProcessorClassV1::Optional => "optional",
                        crate::ProcessorClassV1::Required => "required",
                    }
                    .into()
                }),
                start_cursor: processor.as_ref().map(|(_, state)| state.start),
                consumed_cursor: processor.as_ref().map(|(_, state)| state.consumed),
                resume_floor: processor.as_ref().map(|(_, state)| state.resumed),
                context_revision: processor.as_ref().map(|(_, state)| state.context),
                retired: processor
                    .as_ref()
                    .map(|(_, state)| state.retirement.is_some()),
                current_result_id: processor
                    .as_ref()
                    .and_then(|(_, state)| state.head.as_ref().map(|head| head.result_id.clone())),
                result_commit_revision: processor
                    .as_ref()
                    .and_then(|(_, state)| state.head.as_ref().map(|head| head.commit_revision)),
                current_compatible: false,
                notice_facts_revision: None,
                notice_coverage_revision: None,
                interval_id: None,
                profile_revision: None,
                facts_revision: None,
                coverage_revision: None,
                created_utc_ns: None,
                updated_utc_ns: None,
                sealed: None,
                input_bytes: None,
                incomplete: None,
                gaps: None,
                context_refs: None,
                snapshot: None,
                history: Vec::new(),
            };
            if let Some(head) = processor
                .as_ref()
                .and_then(|(_, state)| state.head.as_ref())
            {
                let (id, result) = ResultRecord::read_header(
                    &head.result_id,
                    view.metadata_revision,
                    |key| Records::read(key, &view.snapshot),
                    &mut |bytes| output.charge(bytes),
                )?
                .ok_or_else(|| Code::Missing.error("discovery current result"))?;
                if result.revision != head.commit_revision || result.request.scope != scope {
                    return Err(Code::Invalid.error("discovery current result"));
                }
                let (facts, coverage) =
                    view.profile_notice(id, &result, &mut |bytes| output.charge(bytes))?;
                state.interval_id = result.header.interval_id.clone();
                state.profile_revision = result.header.profile_revision;
                state.notice_facts_revision = Some(facts);
                state.notice_coverage_revision = Some(coverage);
                output.reference_result(
                    &head.result_id,
                    head.commit_revision,
                    AnalysisReferenceOriginV1::Profile,
                )?;
                if decode {
                    output.charge(
                        usize::try_from(result.body_bytes)
                            .unwrap_or(usize::MAX)
                            .saturating_mul(4),
                    )?;
                    let body = result.body(
                        id,
                        |key| Records::read(key, &view.snapshot),
                        &mut |bytes| output.charge(bytes),
                    )?;
                    let profile = DiscoveryProfileV1::try_from(body.as_slice())?;
                    if profile.profile_id != head.result_id
                        || profile.scope != scope
                        || Some(&profile.interval_id) != state.interval_id.as_ref()
                        || Some(profile.revision) != state.profile_revision
                    {
                        return Err(Code::Invalid.error("discovery current profile"));
                    }
                    if let Some(target) = target.filter(|_| {
                        read.projects_field("discovery_state", "current_compatible")
                            && result.producer.is_some()
                    }) {
                        state.current_compatible = view
                            .profile_producer(
                                &target.grant.selection,
                                &profile,
                                &result,
                                &mut |bytes| output.charge(bytes),
                            )?
                            .0
                            .matches(&target.spec);
                    }
                    state.facts_revision = Some(profile.facts_revision);
                    state.coverage_revision = Some(profile.coverage_revision);
                    state.created_utc_ns = Some(profile.created_utc_ns);
                    state.updated_utc_ns = Some(profile.updated_utc_ns);
                    state.sealed = Some(profile.sealed);
                    state.input_bytes = Some(profile.input_bytes);
                    state.incomplete = Some(profile.incomplete);
                    state.gaps = Some(profile.gaps);
                    state.context_refs = Some(profile.context_refs);
                    state.snapshot = Some(DiscoverySnapshotRowV1::from_snapshot(profile.snapshot)?);
                }
            }
            if read.projects_field("discovery_state", "gaps") {
                let mut gaps = state.gaps.take().unwrap_or_default();
                gaps.extend(view.processor_gaps(
                    &scope,
                    state.consumed_cursor.unwrap_or(0),
                    control,
                    &mut |bytes| output.charge(bytes),
                )?);
                gaps.sort_by_key(|gap| (gap.first_cursor, gap.last_cursor, gap.commit_revision));
                gaps.dedup();
                if gaps
                    .windows(2)
                    .any(|pair| pair[0].last_cursor >= pair[1].first_cursor)
                {
                    return Err(Code::Invalid.error("discovery gaps overlap"));
                }
                state.gaps = Some(gaps);
            }
            if read.projects_field("discovery_state", "history") {
                if let Some((owner, _)) = &processor {
                    let prefix = Processor::key(IntervalHead::PREFIX, *owner);
                    for entry in view.snapshot.prefix(&prefix) {
                        control.check()?;
                        let (key, _) = entry.context(crate::NativeStorageSnafu {
                            operation: "read discovery intervals",
                        })?;
                        let bytes = Records::charged_payload(
                            &key,
                            |key| Records::read(key, &view.snapshot),
                            &mut |bytes| output.charge(bytes),
                        )?
                        .ok_or_else(|| Code::Missing.error("discovery interval"))?;
                        let head: IntervalHead = Records::decode(&bytes)?;
                        let (id, result) = ResultRecord::read(
                            &head.result.result_id,
                            view.metadata_revision,
                            |key| Records::read(key, &view.snapshot),
                            &mut |bytes| output.charge(bytes),
                        )?
                        .ok_or_else(|| Code::Missing.error("discovery history result"))?;
                        output.charge(result.request.body.len().saturating_mul(4))?;
                        let profile = DiscoveryProfileV1::try_from(result.request.body.as_slice())?;
                        if result.revision != head.result.commit_revision
                            || profile.scope != scope
                            || profile.profile_id != head.result.result_id
                            || profile.revision != head.profile
                            || key[prefix.len()..] != *profile.interval_id.as_bytes()
                        {
                            return Err(Code::Invalid.error("discovery interval head"));
                        }
                        if !profile.sealed {
                            continue;
                        }
                        let compatible =
                            if let Some(target) = target.filter(|_| result.producer.is_some()) {
                                view.profile_producer(
                                    &target.grant.selection,
                                    &profile,
                                    &result,
                                    &mut |bytes| output.charge(bytes),
                                )?
                                .0
                                .matches(&target.spec)
                            } else {
                                false
                            };
                        let (facts, coverage) =
                            view.profile_notice(id, &result, &mut |bytes| output.charge(bytes))?;
                        output.reference_result(
                            &profile.profile_id,
                            result.revision,
                            AnalysisReferenceOriginV1::Profile,
                        )?;
                        output.sink(control).grow(&mut state.history)?;
                        state.history.push(DiscoveryHistoryRowV1 {
                            result_id: profile.profile_id,
                            commit_revision: result.revision,
                            notice_facts_revision: facts,
                            notice_coverage_revision: coverage,
                            compatible,
                            interval_id: profile.interval_id,
                            profile_revision: profile.revision,
                            facts_revision: profile.facts_revision,
                            coverage_revision: profile.coverage_revision,
                            created_utc_ns: profile.created_utc_ns,
                            updated_utc_ns: profile.updated_utc_ns,
                            input_bytes: profile.input_bytes,
                            incomplete: profile.incomplete,
                            gaps: profile.gaps,
                            context_refs: profile.context_refs,
                            snapshot: DiscoverySnapshotRowV1::from_snapshot(profile.snapshot)?,
                        });
                    }
                }
            }
            capture.discovery_state(&state, &mut output.sink(control))?;
        }
        Ok(())
    }
}
