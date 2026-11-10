use araphor_analysis_sdk as sdk;

use snafu::ResultExt as _;



use super::model::Step;
use crate :: { PackageErrorCodeV1 as Code , Result } ;



impl Step {
    pub(in crate::analysis) fn prepare(
        attempt: &super::ManagedAttempt,
        evidence: &super::source::SourceEvidence,
        data: &sdk::Dataset,
        schema: &sdk::Schema,
    ) -> Result<Self> {
        if schema != &attempt.1.spec.manifest.selected_schema {
            return Err(Code::Invalid.error("managed selected schema"));
        }
        Self::check_selected(data, schema)?;
        Ok(Self {
            instance: attempt.1.spec.id.clone(),
            attempt: attempt.0.request.id.clone(),
            rows: data.rows(),
            dependencies: attempt.0.capture.dependencies.clone(),
            witnesses: evidence.witnesses.clone(),
            contexts: evidence.contexts.clone(),
            derived: Vec::new(),
            origins: Vec::new(),
            proofs: Vec::new(),
            source: None,
        })
    }
    fn check_selected(data: &sdk::Dataset, schema: &sdk::Schema) -> Result<()> {
        let mut rows = 0_u64;
        for batch in &data.batches {
            rows = rows
                .checked_add(batch.num_rows() as u64)
                .ok_or_else(|| Code::Invalid.error("native selected row count"))?;
            if batch.schema().as_ref() != schema {
                return Err(Code::Invalid.error("native selected schema"));
            }
            for column in batch.columns() {
                column
                    .to_data()
                    .validate_full()
                    .context(crate::PackageArrowSnafu)?;
            }
        }
        Ok(())
    }
}
