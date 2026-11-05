use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::{
    AnalysisExtractionV1, AnalysisReadControl, AnalysisReferenceOriginV1, AnalysisReferenceV1,
    AnalysisStore,
};
use crate::{AnalysisDatabaseSnafu, Result};

impl AnalysisStore {
    pub(super) fn extract_provenance(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        output: &mut AnalysisExtractionV1,
        capture: &super::tables::Capture<'_>,
        control: &AnalysisReadControl,
        owners: &mut crate::analysis::managed::OwnerRead<'_>,
    ) -> Result<()> {
        owners.check_reader(reader, tenant)?;
        let count = output
            .references
            .iter()
            .filter_map(AnalysisReferenceV1::result)
            .count();
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
            let native: bool = reader
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM managed_graph_publications WHERE result_id=?)
                    OR EXISTS(SELECT 1 FROM managed_source_publications WHERE result_id=?)",
                    params![reference.result_id, reference.result_id],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "classify native captured publication",
                })?;
            if self.package_source_revision(reader, tenant, &reference.result_id)?
                != reference.commit_revision
            {
                return self.reject("the captured result revision changed");
            }
            if native
                && !capture.graph_provenance()
                && origins.as_slice() == [AnalysisReferenceOriginV1::Graph]
            {
                continue;
            }
            if let Some(findings) = native
                .then(|| capture.finding_basis(&reference.result_id))
                .flatten()
                .filter(|_| {
                    origins.iter().all(|origin| {
                        matches!(
                            origin,
                            AnalysisReferenceOriginV1::Graph
                                | AnalysisReferenceOriginV1::Notification
                        )
                    })
                })
            {
                let (witnesses, contexts, _) = Self::finding_basis_on(
                    reader,
                    tenant,
                    &reference.result_id,
                    findings,
                    control,
                    &mut |scan, input| {
                        output.scan(scan)?;
                        output.charge(input)
                    },
                    false,
                    owners,
                )?;
                for witness in witnesses {
                    output.inherit_witness(witness)?;
                }
                for reference in contexts {
                    for origin in &origins {
                        output.reference_context(
                            &reference.key,
                            reference.commit_revision,
                            *origin,
                        )?;
                    }
                }
                continue;
            }
            let length: u64 = reader
                .query_row(
                    "SELECT octet_length(x.request_meta)
                    + CASE WHEN x.processor_id = 'discovery' THEN octet_length(x.body) ELSE 0 END
                 FROM analysis_results x
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
                    "SELECT x.processor_id, x.request_meta
                 FROM analysis_results x
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
            if !capture.graph_provenance()
                && processor == crate::GRAPH_PROCESSOR
                && origins.as_slice() == [AnalysisReferenceOriginV1::Graph]
            {
                continue;
            }
            let local = (processor == crate::GRAPH_PROCESSOR
                && origins.iter().all(|origin| {
                    matches!(
                        origin,
                        AnalysisReferenceOriginV1::Graph | AnalysisReferenceOriginV1::Notification
                    )
                }))
            .then(|| capture.finding_basis(&reference.result_id))
            .flatten();
            let (witnesses, contexts) = if let Some(findings) = local {
                super::super::graph_rows::GraphRows::finding_provenance(
                    reader,
                    &self.root,
                    &reference,
                    super::super::graph::GraphRequestMeta::decode(&manifest)?,
                    findings,
                    Some(control),
                    &mut |scan, input| {
                        output.scan(scan)?;
                        output.charge(input)
                    },
                )?
            } else {
                Self::decode_evidence(
                    reader,
                    &reference,
                    &processor,
                    &manifest,
                    Some(control),
                    &mut |scan, input| {
                        output.scan(scan)?;
                        output.charge(input)
                    },
                )?
            };
            let inherit_raw = capture.graph_witnesses()
                || processor != crate::GRAPH_PROCESSOR
                || origins.as_slice() != [AnalysisReferenceOriginV1::Graph];
            for witness in witnesses {
                if witness.identity.tenant() != tenant {
                    return self.reject("the captured evidence witness has a foreign tenant");
                }
                if inherit_raw {
                    output.inherit_witness(witness)?;
                }
            }
            for reference in contexts {
                if reference.key.tenant_id != tenant {
                    return self.reject("the captured evidence context has a foreign tenant");
                }
                for origin in &origins {
                    output.reference_context(&reference.key, reference.commit_revision, *origin)?;
                }
            }
        }
        Ok(())
    }
}
