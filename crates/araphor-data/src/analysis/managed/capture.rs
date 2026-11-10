
use araphor_analysis_sdk as sdk;

use snafu::ResultExt as _;

use super :: super :: { AnalysisExtractionV1 , AnalysisSelectionV1 } ;
use super::model::*;
use crate :: { AnalysisReadControl , PackageErrorCodeV1 as Code , Result } ;



impl ManagedCapture {
    pub(in crate::analysis) fn seal(
        &mut self,
        selection: &AnalysisSelectionV1,
        output: &AnalysisExtractionV1,
    ) {
        self.bytes = self.bytes.saturating_add(output.allocation_bytes());
        self.contract.sources = selection.source_revisions(output.meta.commit_revision);
        self.contract.dependencies = output
            .references
            .iter()
            .filter_map(|entry| entry.result().cloned())
            .collect();
        self.contract
            .dependencies
            .sort_by(|left, right| left.result_id.cmp(&right.result_id));
        self.contract.dependencies.dedup();
        self.contract.contexts = output
            .references
            .iter()
            .filter(|entry| {
                !self.source.as_ref().is_some_and(|source| {
                    source
                        .projection()
                        .get("context_versions")
                        .is_some_and(Option::is_some)
                }) || entry
                    .origins()
                    .iter()
                    .any(|origin| !matches!(origin, crate::AnalysisReferenceOriginV1::Context))
            })
            .filter_map(|entry| entry.context().cloned())
            .collect();
        self.contract
            .contexts
            .sort_by(|left, right| left.key.cmp(&right.key));
        self.contract.contexts.dedup();
        self.contract.witnesses = output
            .witnesses
            .iter()
            .filter(|witness| {
                !self.source.as_ref().is_some_and(|source| {
                    source
                        .projection()
                        .get("events")
                        .is_some_and(Option::is_some)
                }) || !matches!(
                    &witness.identity,
                    crate::AnalysisStreamIdentityV1::Evidence(_)
                )
            })
            .cloned()
            .collect();
        self.contract.traces = output.trace_reads().to_vec();
    }
}

impl ManagedPrior {
    pub(in crate::analysis) fn decode_checkpoint(
        packet: Option<&sdk::wire::Checkpoint>,
        model: &sdk::Model,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Option<sdk::Checkpoint>> {
        let checkpoint = packet
            .map(|state| -> Result<sdk::Checkpoint> {
                control.check()?;
                let bytes = state.datasets.iter().try_fold(0usize, |bytes, data| {
                    let next = sdk::wire::Dataset::decoding_bytes(&data.arrow_ipc)
                        .context(crate::AnalysisContractSnafu)?;
                    bytes
                        .checked_add(next)
                        .ok_or_else(|| Code::Limit.error("managed prior decode"))
                })?;
                let before = output.input_bytes;
                output.charge(bytes)?;
                let decoded = state
                    .decode_model(model)
                    .context(crate::AnalysisContractSnafu)?;
                output.input_bytes = before;
                output.charge(
                    decoded
                        .datasets
                        .capacity()
                        .saturating_mul(std::mem::size_of::<sdk::Dataset>()),
                )?;
                for data in &decoded.datasets {
                    output.charge(data.allocated_bytes())?;
                }
                Ok(decoded)
            })
            .transpose()?;
        model
            .validate_checkpoint(checkpoint.as_ref(), true)
            .context(crate::AnalysisContractSnafu)?;
        Ok(checkpoint)
    }
}
