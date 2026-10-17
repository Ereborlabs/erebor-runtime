use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{
    AnalysisExtractionV1, AnalysisInputV1, AnalysisProjection, AnalysisReadControl,
    AnalysisReferenceOriginV1, AnalysisReferenceV1, AnalysisSelectionV1, AnalysisStore,
};
use crate::analysis::{PackageCommitV1, PackageKeyV1};
use crate::{
    AnalysisDatabaseSnafu, InstalledContext, PackageEncodingSnafu, PackageErrorCodeV1 as Code,
    Result, ResultContext,
};

impl AnalysisStore {
    pub(super) fn extract_packages(
        &self,
        reader: &Connection,
        packages: (&AnalysisSelectionV1, &str, &[sdk::OutputRef]),
        metadata: bool,
        control: &AnalysisReadControl,
        output: &mut AnalysisExtractionV1,
        project: &mut dyn AnalysisProjection,
    ) -> Result<()> {
        let (selection, scope, references) = packages;
        if !selection.valid() || scope.is_empty() || scope.len() > 256 {
            return Err(Code::Invalid.error("dependency selection"));
        }
        if references.len() > 64 {
            return Err(Code::Limit.error("model dependencies"));
        }
        for reference in references {
            for name in [&reference.package, &reference.export, &reference.output] {
                crate::validate_package_name(name)?;
            }
            if reference.revision.is_empty()
                || reference.revision.len() > 4096
                || reference.revision.chars().any(char::is_control)
            {
                return Err(Code::Invalid.error("dependency revision"));
            }
        }
        for (index, reference) in references.iter().enumerate() {
            control.check()?;
            let same = |other: &sdk::OutputRef| {
                other.package == reference.package
                    && other.revision == reference.revision
                    && other.export == reference.export
            };
            if references[..index].iter().any(&same) {
                continue;
            }
            let key = PackageKeyV1 {
                tenant_id: selection.tenant_id,
                scope_id: scope.into(),
                package_id: reference.package.clone(),
                export: reference.export.clone(),
            };
            let activation_bytes: Option<u64> = reader
                .query_row(
                    "SELECT octet_length(metadata) FROM package_activations
                     WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?",
                    params![
                        key.tenant_id.as_slice(),
                        key.scope_id,
                        key.package_id,
                        key.export
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "bound dependency activation",
                })?;
            let activation_bytes =
                activation_bytes.ok_or_else(|| Code::Incomplete.error("dependency activation"))?;
            output.charge(usize::try_from(activation_bytes).unwrap_or(usize::MAX))?;
            let active = Self::activation_from(reader, &key)?
                .filter(|active| active.active && active.revision == reference.revision)
                .ok_or_else(|| Code::Incomplete.error("dependency activation"))?;
            let id = active
                .result_id
                .as_ref()
                .ok_or_else(|| Code::Incomplete.error("dependency result"))?;
            let header: Option<(u64, String, u64)> = reader
                .query_row(
                    "SELECT x.commit_revision, r.window_id,
                    octet_length(r.commit_meta) + octet_length(x.body)
                    + CASE WHEN ? THEN 0 ELSE octet_length(x.request_meta)
                        + octet_length(r.datasets) + octet_length(r.checkpoint) END
                 FROM package_results r JOIN analysis_results x USING (result_id)
                 JOIN package_heads h ON h.tenant_id = r.tenant_id AND h.scope_id = r.scope_id
                    AND h.package_id = r.package_id AND h.export_name = r.export_name
                    AND h.window_id = r.window_id AND h.result_id = r.result_id
                 WHERE r.tenant_id = ? AND r.result_id = ? AND r.scope_id = ? AND r.package_id = ?
                    AND r.export_name = ? AND r.revision = ? AND NOT r.stale
                    AND x.tenant_id = r.tenant_id AND x.processor_id = 'analysis-package'
                    AND x.commit_revision = ?",
                    params![
                        metadata,
                        key.tenant_id.as_slice(),
                        id,
                        key.scope_id,
                        key.package_id,
                        key.export,
                        reference.revision,
                        active.checkpoint_revision
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "bound current dependency result",
                })?;
            let (revision, window, bytes) =
                header.ok_or_else(|| Code::Incomplete.error("dependency freshness"))?;
            output.charge(usize::try_from(bytes).unwrap_or(usize::MAX))?;
            if metadata {
                let (manifest, body): (Vec<u8>, Vec<u8>) = reader.query_row(
                    "SELECT r.commit_meta, x.body FROM package_results r
                     JOIN analysis_results x USING (result_id) WHERE r.tenant_id = ? AND r.result_id = ?",
                    params![key.tenant_id.as_slice(), id], |row| Ok((row.get(0)?, row.get(1)?)),
                ).context(AnalysisDatabaseSnafu {
                    operation: "read dependency metadata",
                })?;
                let commit: PackageCommitV1 =
                    serde_json::from_slice(&manifest).context(PackageEncodingSnafu)?;
                if commit.result_id != *id
                    || commit.activation.key != key
                    || commit.activation.revision != reference.revision
                    || commit.window_id != window
                {
                    return self.reject("the retained dependency contract differs");
                }
                let installed: InstalledContext =
                    serde_json::from_slice(&commit.activation.metadata)
                        .context(PackageEncodingSnafu)?;
                installed.grant.permitted_by(selection)?;
                let _: ResultContext =
                    serde_json::from_slice(&body).context(PackageEncodingSnafu)?;
                for (index, _) in references
                    .iter()
                    .enumerate()
                    .filter(|(_, reference)| same(reference))
                {
                    output.reference_result(
                        id,
                        revision,
                        AnalysisReferenceOriginV1::Package(index),
                    )?;
                }
                continue;
            }
            let result = Self::package_result_from(reader, key.tenant_id, id, &self.root)?
                .filter(|result| {
                    !result.stale
                        && result.commit_revision == revision
                        && result.commit.activation.key == key
                        && result.commit.activation.revision == reference.revision
                })
                .ok_or_else(|| Code::Incomplete.error("dependency freshness"))?;
            let installed: InstalledContext =
                serde_json::from_slice(&result.commit.activation.metadata)
                    .context(PackageEncodingSnafu)?;
            installed.grant.permitted_by(selection)?;
            let context: ResultContext =
                serde_json::from_slice(&result.commit.metadata).context(PackageEncodingSnafu)?;
            let packet: sdk::wire::Output =
                serde_json::from_slice(&result.commit.datasets).context(PackageEncodingSnafu)?;
            for (index, _) in references
                .iter()
                .enumerate()
                .filter(|(_, reference)| same(reference))
            {
                output.reference_result(id, revision, AnalysisReferenceOriginV1::Package(index))?;
            }
            for (index, reference) in references.iter().enumerate() {
                if !same(reference) || references[..index].contains(reference) {
                    continue;
                }
                control.check()?;
                let mut matches = packet
                    .datasets
                    .iter()
                    .filter(|dataset| dataset.name == reference.output);
                let dataset = matches
                    .next()
                    .ok_or_else(|| Code::Invalid.error("dependency dataset"))?;
                if matches.next().is_some() {
                    return Err(Code::Invalid.error("duplicate dependency dataset"));
                }
                if !output.project(
                    project,
                    AnalysisInputV1::PackageOutput {
                        reference,
                        result: &result,
                        dataset: Some(dataset),
                        coverage: &context.coverage,
                    },
                    control,
                    None,
                )? {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "selected package output",
                    }
                    .fail();
                }
            }
        }
        control.check()
    }

    pub(super) fn extract_provenance(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        let count = output
            .references
            .iter()
            .filter_map(AnalysisReferenceV1::result)
            .count();
        if count > 64 {
            return self.reject("the package evidence sources exceed their count limit");
        }
        for index in 0..count {
            control.check()?;
            let entry = output
                .references
                .iter()
                .filter(|entry| entry.result().is_some())
                .nth(index)
                .ok_or_else(|| self.state_error("the captured result reference is absent"))?;
            let reference = entry
                .result()
                .ok_or_else(|| self.state_error("the captured result reference differs"))?
                .clone();
            let origins = entry.origins().to_vec();
            output.charge(
                reference.result_id.capacity()
                    + origins.capacity() * std::mem::size_of::<AnalysisReferenceOriginV1>(),
            )?;
            let length: u64 = reader
                .query_row(
                    "SELECT octet_length(CASE WHEN x.processor_id = 'analysis-package'
                    THEN p.commit_meta ELSE x.request_meta END)
                    + CASE WHEN x.processor_id = 'discovery' THEN octet_length(x.body) ELSE 0 END
                 FROM analysis_results x LEFT JOIN package_results p USING (result_id)
                 WHERE x.tenant_id = ? AND x.result_id = ? AND x.commit_revision = ?",
                    params![
                        tenant.as_slice(),
                        reference.result_id,
                        reference.commit_revision
                    ],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "bound captured evidence manifest",
                })?;
            output.charge(usize::try_from(length).unwrap_or(usize::MAX))?;
            if self.package_source_revision(reader, tenant, &reference.result_id)?
                != reference.commit_revision
            {
                return self.reject("the captured result revision changed");
            }
            let (processor, manifest): (String, Vec<u8>) = reader
                .query_row(
                    "SELECT x.processor_id, CASE WHEN x.processor_id = 'analysis-package'
                    THEN p.commit_meta ELSE x.request_meta END
                 FROM analysis_results x LEFT JOIN package_results p USING (result_id)
                 WHERE x.tenant_id = ? AND x.result_id = ? AND x.commit_revision = ?",
                    params![
                        tenant.as_slice(),
                        reference.result_id,
                        reference.commit_revision
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read captured evidence manifest",
                })?;
            let (witnesses, contexts) = Self::decode_evidence(&processor, &manifest)?;
            for witness in witnesses {
                if witness.identity.tenant() != tenant {
                    return self.reject("the captured evidence witness has a foreign tenant");
                }
                output.inherit_witness(witness)?;
            }
            for reference in contexts {
                if reference.key.tenant_id != tenant {
                    return self.reject("the captured evidence context has a foreign tenant");
                }
                for origin in &origins {
                    output.reference_context(&reference.key, reference.commit_revision, *origin)?;
                }
            }
            if output.witnesses.len() > 8192
                || output
                    .references
                    .iter()
                    .filter_map(AnalysisReferenceV1::context)
                    .count()
                    > 256
            {
                return self.reject("the package evidence references exceed their count limit");
            }
        }
        Ok(())
    }
}
