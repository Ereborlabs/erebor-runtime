use duckdb::params;
use snafu::ResultExt as _;

use super::{ManagedInstance, ManagedSpec};
use crate::{
    AnalysisDatabaseSnafu, AnalysisStore, PackageErrorCodeV1 as Code, PackageGrantV1, Result,
};

impl AnalysisStore {
    /// Stop and join the Host worker before this call.
    pub fn remove_managed(
        &self,
        expected: &ManagedInstance,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed removal",
            })?;
        let mut current =
            Self::managed_instance_from(&transaction, expected.spec.tenant, &expected.spec.id)?
                .ok_or_else(|| Code::Missing.error("managed removal instance"))?;
        if current != *expected {
            return crate::AnalysisConflictSnafu.fail();
        }
        Self::check_managed_idle(&transaction, current.spec.tenant, &current.spec.id)?;
        if current.removed {
            check()?;
            return Ok(current);
        }
        let revision = self.package_next(&transaction)?;
        transaction.execute(
            "UPDATE managed_instances SET running = false, removed = true, lifecycle = ?, failure = NULL WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
            params![revision, current.spec.tenant.as_slice(), current.spec.id, current.lifecycle],
        ).context(AnalysisDatabaseSnafu { operation: "remove current managed instance" })?;
        transaction.execute(
            "UPDATE managed_calls SET state_revision = 0, result_id = NULL WHERE tenant_id = ? AND instance_id = ?",
            params![current.spec.tenant.as_slice(), current.spec.id],
        ).context(AnalysisDatabaseSnafu { operation: "clear removed managed heads" })?;
        self.check_logical(&transaction, current.spec.tenant, false)?;
        Self::record_revision(
            &transaction,
            revision,
            &["managed_instances", "managed_calls"],
        )?;
        check()?;
        self.commit_metadata(transaction, "commit managed removal")?;
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        current.running = false;
        current.removed = true;
        current.lifecycle = revision;
        Ok(current)
    }

    pub fn recreate_managed(
        &self,
        expected: &ManagedInstance,
        spec: &ManagedSpec,
        grant: &PackageGrantV1,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        spec.validate()?;
        grant.validate()?;
        if !expected.removed
            || spec.tenant != expected.spec.tenant
            || spec.id != expected.spec.id
            || grant.selection.tenant_id != spec.tenant
        {
            return Err(Code::Conflict.error("managed recreation identity"));
        }
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed recreation",
            })?;
        let current = Self::managed_instance_from(&transaction, spec.tenant, &spec.id)?
            .ok_or_else(|| Code::Missing.error("managed recreation instance"))?;
        if current != *expected {
            return crate::AnalysisConflictSnafu.fail();
        }
        Self::check_managed_idle(&transaction, spec.tenant, &spec.id)?;
        Self::check_managed_images(&transaction, spec)?;
        Self::check_managed_addressable(&transaction, spec)?;
        let revision = self.package_next(&transaction)?;
        transaction
            .execute(
                "INSERT INTO managed_versions VALUES (?, ?, ?, ?, ?)",
                params![
                    spec.tenant.as_slice(),
                    spec.id,
                    revision,
                    serde_json::to_vec(spec).context(crate::PackageEncodingSnafu)?,
                    serde_json::to_vec(&grant.selection).context(crate::PackageEncodingSnafu)?
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "retain recreated managed version",
            })?;
        transaction.execute(
            "UPDATE managed_instances SET authority = ?, generation = ?, progress = 0, running = false, removed = false, lifecycle = ?, failure = NULL WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
            params![serde_json::to_vec(grant).context(crate::PackageEncodingSnafu)?, revision,
                revision, spec.tenant.as_slice(), spec.id, expected.lifecycle],
        ).context(AnalysisDatabaseSnafu { operation: "recreate removed managed instance" })?;
        transaction
            .execute(
                "DELETE FROM managed_calls WHERE tenant_id = ? AND instance_id = ?",
                params![spec.tenant.as_slice(), spec.id],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "replace recreated call heads",
            })?;
        for call in spec.manifest.calls.keys() {
            transaction
                .execute(
                    "INSERT INTO managed_calls VALUES (?, ?, ?, 0, NULL)",
                    params![spec.tenant.as_slice(), spec.id, call],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert recreated call head",
                })?;
        }
        self.check_logical(&transaction, spec.tenant, false)?;
        Self::record_revision(
            &transaction,
            revision,
            &["managed_versions", "managed_instances", "managed_calls"],
        )?;
        check()?;
        self.commit_metadata(transaction, "commit managed recreation")?;
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        Ok(ManagedInstance {
            spec: spec.clone(),
            grant: grant.clone(),
            generation: revision,
            progress: 0,
            running: false,
            removed: false,
            lifecycle: revision,
        })
    }
}
