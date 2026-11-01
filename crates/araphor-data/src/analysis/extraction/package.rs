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
        graph_witnesses: bool,
        control: &AnalysisReadControl,
    ) -> Result<()> {
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
            let (witnesses, contexts) = Self::decode_evidence(&processor, &manifest)?;
            let inherit_raw = graph_witnesses
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
