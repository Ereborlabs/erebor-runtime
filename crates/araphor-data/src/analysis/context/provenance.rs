use duckdb::Connection;

use super::*;
use crate::PackageRefV1;

#[derive(Clone)]
pub(in crate::analysis) struct ValidatedProvenance {
    body: Vec<u8>,
    revisions: Vec<(PackageRefV1, [u8; 32])>,
}

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

    pub(super) fn check_cached_provenance(
        &self,
        reader: &Connection,
        context: &AnalysisContextVersionV1,
    ) -> Result<()> {
        let Some(reference) = context
            .package_provenance()
            .map_err(crate::Error::stored_artifact)?
        else {
            return Ok(());
        };
        let cached = self
            .package_provenance
            .lock()
            .map_err(|_| self.state_error("the package provenance cache lock is poisoned"))?
            .get(&context.key)
            .cloned();
        if let Some(cached) = cached {
            let mut current = cached.body == context.body;
            for (key, fingerprint) in &cached.revisions {
                let row = Self::package_from(
                    reader,
                    context.key.tenant_id,
                    &key.package_id,
                    &key.revision,
                )
                .map_err(crate::Error::stored_artifact)?;
                current &= row.is_some_and(|row| row.fingerprint() == *fingerprint);
            }
            if current {
                return Ok(());
            }
            return Self::validate_context_packages(reader, context)
                .map_err(crate::Error::stored_artifact);
        }
        let mut revisions = Vec::new();
        let artifacts = Self::package_artifacts_inspect_from(
            reader,
            context.key.tenant_id,
            &reference.root,
            &crate::AnalysisReadControl::default(),
            |row| {
                revisions.push((
                    PackageRefV1 {
                        package_id: row.package_id.clone(),
                        revision: row.revision.clone(),
                    },
                    row.fingerprint(),
                ));
            },
        )
        .map_err(crate::Error::stored_artifact)?;
        reference
            .validate(artifacts)
            .map_err(crate::Error::stored_artifact)?;
        revisions.sort_by(|left, right| left.0.cmp(&right.0));
        let validated = ValidatedProvenance {
            body: context.body.clone(),
            revisions,
        };
        let mut cache = self
            .package_provenance
            .lock()
            .map_err(|_| self.state_error("the package provenance cache lock is poisoned"))?;
        cache.entry(context.key.clone()).or_insert(validated);
        Ok(())
    }
}
