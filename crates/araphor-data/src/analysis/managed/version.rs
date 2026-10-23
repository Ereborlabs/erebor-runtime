use duckdb::{params, OptionalExt as _};
use snafu::ResultExt as _;

use super::{ManagedInstance, ManagedSpec};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

impl AnalysisStore {
    pub fn managed_version(
        &self,
        tenant: [u8; 16],
        id: &str,
        generation: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedSpec> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            Self::managed_version_from(reader, tenant, id, generation)
        })
    }

    pub fn prepare_managed_version(
        &self,
        expected: &ManagedInstance,
        spec: &ManagedSpec,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        spec.validate()?;
        if spec.tenant != expected.spec.tenant || spec.id != expected.spec.id {
            return Err(Code::Conflict.error("managed update identity"));
        }
        let bytes = serde_json::to_vec(spec).context(crate::PackageEncodingSnafu)?;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed version admission",
            })?;
        let current = Self::managed_instance_from(&transaction, spec.tenant, &spec.id)?
            .ok_or_else(|| Code::Missing.error("managed update instance"))?;
        if current.removed || current != *expected {
            return crate::AnalysisConflictSnafu.fail();
        }
        Self::check_managed_pending(&transaction, spec.tenant, &spec.id, expected.generation)?;
        Self::check_managed_images(&transaction, spec)?;
        let saved: Option<u64> = transaction.query_row(
            "SELECT generation FROM managed_versions WHERE tenant_id = ? AND instance_id = ? AND spec = ? AND scope = ? ORDER BY generation DESC LIMIT 1",
            params![spec.tenant.as_slice(), spec.id, bytes,
                serde_json::to_vec(&current.grant.selection).context(crate::PackageEncodingSnafu)?], |row| row.get(0),
        ).optional().context(AnalysisDatabaseSnafu { operation: "find exact managed version" })?;
        let generation = if let Some(generation) = saved {
            if generation != expected.generation {
                Self::check_managed_pending(&transaction, spec.tenant, &spec.id, generation)?;
            }
            check()?;
            generation
        } else {
            Self::check_managed_addressable(&transaction, spec)?;
            let revision = self.package_next(&transaction)?;
            transaction
                .execute(
                    "INSERT INTO managed_versions VALUES (?, ?, ?, ?, ?)",
                    params![
                        spec.tenant.as_slice(),
                        spec.id,
                        revision,
                        bytes,
                        serde_json::to_vec(&current.grant.selection)
                            .context(crate::PackageEncodingSnafu)?
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "retain managed candidate version",
                })?;
            self.check_logical(&transaction, spec.tenant, false)?;
            Self::record_revision(&transaction, revision, &["managed_versions"])?;
            check()?;
            self.commit_metadata(transaction, "commit managed candidate version")?;
            self.revision.send_replace(revision);
            revision
        };
        Ok(ManagedInstance {
            spec: spec.clone(),
            generation,
            ..current
        })
    }
}
