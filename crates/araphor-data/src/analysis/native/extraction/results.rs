use super::*;
use crate::analysis::native::{
    managed::results::{ResultBody, StoredResult},
    progress::ResultRecord,
    records::Records,
};
use crate::AnalysisReferenceOriginV1;

impl NativeStore {
    pub(super) fn extract_results(
        &self,
        view: &DataView,
        selection: &AnalysisSelectionV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        for name in &selection.results {
            control.check()?;
            let managed = StoredResult::load(
                selection.tenant_id,
                name,
                |key| Records::read(key, &view.snapshot),
                &mut |bytes| output.charge(bytes),
            )?;
            let progress = ResultRecord::read_header(
                name,
                view.metadata_revision,
                |key| Records::read(key, &view.snapshot),
                &mut |bytes| output.charge(bytes),
            )?;
            if managed.is_some() && progress.is_some() {
                return Err(Code::Invalid.error("multiple result owners"));
            }
            let retained = if let Some((id, result)) =
                managed.filter(|(_, result)| result.tenant == selection.tenant_id)
            {
                result.check_identity(selection.tenant_id, name, view.metadata_revision)?;
                view.qualify_result(&result, control, &mut |bytes| output.charge(bytes))?;
                let (witnesses, contexts, derived) = match result.body {
                    ResultBody::Call(record) => (record.witnesses, record.contexts, record.derived),
                    ResultBody::Selected(step) => (step.witnesses, step.contexts, step.derived),
                };
                Some((id, result.revision, witnesses, contexts, derived))
            } else if let Some((id, result)) = progress.filter(|(_, result)| {
                result.request.scope.identity.tenant_id == selection.tenant_id
            }) {
                if result.request.scope.processor_id == crate::DISCOVERY_PROCESSOR {
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
                    let profile = crate::DiscoveryProfileV1::try_from(body.as_slice())?;
                    if !profile.sealed {
                        if result.producer.is_none() {
                            return Err(Code::Unsupported.error("mutable discovery input"));
                        }
                        view.profile_producer(
                            &AnalysisSelectionV1::tenant(selection.tenant_id),
                            &profile,
                            &result,
                            &mut |bytes| output.charge(bytes),
                        )?;
                    }
                }
                Some((
                    id,
                    result.revision,
                    result.request.witnesses,
                    result.request.context_refs,
                    Vec::new(),
                ))
            } else {
                None
            };
            let Some((id, revision, witnesses, contexts, derived)) = retained else {
                let added = AnalysisExtractionV1::grow(
                    &mut output.missing_results,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?;
                output.charge(added)?;
                output.charge(name.len())?;
                output.missing_results.push(name.clone());
                continue;
            };
            output.reference_result(name, revision, AnalysisReferenceOriginV1::ExplicitResult)?;
            view.check_result_pins(id, &witnesses, &mut |bytes| output.charge(bytes))?;
            for witness in witnesses {
                if witness.identity.tenant() != selection.tenant_id {
                    return Err(Code::Invalid.error("retained witness tenant"));
                }
                output.inherit_witness(witness)?;
            }
            for reference in contexts.into_iter().chain(derived) {
                if reference.key.tenant_id != selection.tenant_id {
                    return Err(Code::Invalid.error("retained context tenant"));
                }
                output.reference_context(
                    &reference.key,
                    reference.commit_revision,
                    AnalysisReferenceOriginV1::ExplicitResult,
                )?;
            }
        }
        Ok(())
    }
}
