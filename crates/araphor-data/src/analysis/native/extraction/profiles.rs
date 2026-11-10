use super::*;
use crate::analysis::native::{
    progress::{profile::IntervalHead, Processor, ResultRecord},
    records::Records,
};
use crate::{AnalysisReferenceOriginV1, DiscoveryProfileV1, Selection};
use snafu::ResultExt as _;

impl NativeStore {
    pub(super) fn select_profiles(
        &self,
        view: &DataView,
        selection: &mut AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if !selection.profiles.is_all() {
            return Ok(());
        }
        let mut profiles = Vec::new();
        for source in selection.sources.as_slice() {
            control.check()?;
            let scope = crate::ProcessorScopeV1 {
                processor_id: crate::DISCOVERY_PROCESSOR.into(),
                method_version: crate::DISCOVERY_SCHEMA_VERSION as u64,
                identity: source.clone(),
            };
            let Some((owner, _)) = Processor::read(
                &scope,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |bytes| output.charge(bytes),
            )?
            else {
                continue;
            };
            let prefix = Processor::key(IntervalHead::PREFIX, owner);
            for entry in view.snapshot.prefix(&prefix) {
                control.check()?;
                let (key, _) = entry.context(crate::NativeStorageSnafu {
                    operation: "read selected profile heads",
                })?;
                let saved = output.input_bytes;
                let bytes = Records::charged_payload(
                    &key,
                    |key| Records::read(key, &view.snapshot),
                    &mut |bytes| output.charge(bytes),
                )?
                .ok_or_else(|| Code::Missing.error("selected profile head"))?;
                let head: IntervalHead = Records::decode(&bytes)?;
                let (_, result) = ResultRecord::read_header(
                    &head.result.result_id,
                    view.metadata_revision,
                    |key| Records::read(key, &view.snapshot),
                    &mut |bytes| output.charge(bytes),
                )?
                .ok_or_else(|| Code::Missing.error("selected interval profile"))?;
                if result.revision != head.result.commit_revision
                    || result.request.scope != scope
                    || result.header.profile_revision != Some(head.profile)
                    || result
                        .header
                        .interval_id
                        .as_ref()
                        .is_none_or(|interval| key[prefix.len()..] != *interval.as_bytes())
                {
                    return Err(Code::Invalid.error("selected interval profile head"));
                }
                drop(bytes);
                output.input_bytes = saved;
                if output
                    .limits
                    .keys
                    .is_some_and(|limit| selection.key_count() + profiles.len() >= limit)
                {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "selected input keys",
                    }
                    .fail();
                }
                output.charge(AnalysisExtractionV1::grow(
                    &mut profiles,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?)?;
                output.charge(head.result.result_id.capacity())?;
                profiles.push(head.result.result_id);
            }
        }
        profiles.sort();
        profiles.dedup();
        selection.profiles = Selection::Exact(profiles);
        Ok(())
    }

    pub(super) fn extract_profiles(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        output: &mut AnalysisExtractionV1,
        capture: &mut Capture<'_>,
        managed: bool,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        if read.projected("behaviors").is_none() {
            return Ok(());
        }
        for name in selection.profiles() {
            control.check()?;
            let (id, result) = ResultRecord::read_header(
                name,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |bytes| output.charge(bytes),
            )?
            .ok_or_else(|| Code::Missing.error("selected profile"))?;
            if result.request.scope.identity.tenant_id != selection.tenant_id
                || !selection
                    .sources
                    .as_slice()
                    .contains(&result.request.scope.identity)
            {
                return Err(Code::Missing.error("selected profile"));
            }
            if result.request.scope.processor_id != crate::DISCOVERY_PROCESSOR
                || result.request.scope.method_version != crate::DISCOVERY_SCHEMA_VERSION as u64
            {
                return Err(Code::Invalid.error("selected profile processor"));
            }
            output.charge(
                usize::try_from(result.body_bytes)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(4),
            )?;
            let body = result.body(id, |key| Records::read(key, &view.snapshot), &mut |bytes| {
                output.charge(bytes)
            })?;
            let profile = DiscoveryProfileV1::try_from(body.as_slice())?;
            if profile.scope != result.request.scope || profile.profile_id != *name {
                return Err(Code::Invalid.error("selected profile identity"));
            }
            view.check_result_pins(id, &result.request.witnesses, &mut |bytes| {
                output.charge(bytes)
            })?;
            capture.profile(
                name,
                &profile,
                result.revision,
                selection.sources.as_slice(),
                output.discovery_enabled,
                &mut output.sink(control),
            )?;
            output.reference_result(name, result.revision, AnalysisReferenceOriginV1::Profile)?;
            for reference in &result.request.context_refs {
                if reference.key.tenant_id != selection.tenant_id {
                    return Err(Code::Invalid.error("profile context tenant"));
                }
                output.reference_context(
                    &reference.key,
                    reference.commit_revision,
                    AnalysisReferenceOriginV1::Profile,
                )?;
            }
            if managed {
                for witness in result.request.witnesses {
                    output.inherit_witness(witness)?;
                }
            }
        }
        Ok(())
    }
}
