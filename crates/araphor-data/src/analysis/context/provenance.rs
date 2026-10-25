use duckdb::Connection;

use super::*;

impl AnalysisStore {
    pub(in crate::analysis) fn validate_context_packages(
        reader: &Connection,
        context: &AnalysisContextVersionV1,
    ) -> Result<()> {
        let Some(reference) = context.package_provenance()? else {
            return Ok(());
        };
        let artifacts = Self::package_artifacts_from(
            reader,
            context.key.tenant_id,
            &reference.root,
            &crate::AnalysisReadControl::default(),
        )?;
        reference.validate(artifacts)
    }

    pub(super) fn validate_stored_context_packages(
        reader: &Connection,
        context: &AnalysisContextVersionV1,
    ) -> Result<()> {
        Self::validate_context_packages(reader, context).map_err(crate::Error::stored_artifact)
    }
}
