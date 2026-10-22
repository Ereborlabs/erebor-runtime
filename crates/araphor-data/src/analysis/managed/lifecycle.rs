use std::sync::{atomic::Ordering, Arc};

use duckdb::params;
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::ManagedInstance;
use crate::{AnalysisDatabaseSnafu, PackageErrorCodeV1 as Code, PackageGrantV1, Result};

pub struct ManagedLease(Arc<AnalysisStore>);

impl Drop for ManagedLease {
    fn drop(&mut self) {
        self.0.managed_owner.store(false, Ordering::Release);
    }
}

impl AnalysisStore {
    /// Stop and join the original execution before this call.
    pub fn renew_managed(
        &self,
        expected: &ManagedInstance,
        grant: &PackageGrantV1,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        grant.validate()?;
        if grant.selection != expected.grant.selection {
            return Err(Code::Conflict.error("managed renewal selection"));
        }
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed renewal",
            })?;
        let mut instance =
            Self::managed_instance_from(&transaction, expected.spec.tenant, &expected.spec.id)?
                .ok_or_else(|| Code::Missing.error("managed renewal instance"))?;
        if instance != *expected || instance.running {
            return crate::AnalysisConflictSnafu.fail();
        }
        Self::check_managed_pending(&transaction, expected.spec.tenant, &expected.spec.id)?;
        if instance.grant == *grant {
            check()?;
            return Ok(instance);
        }
        Self::check_managed_images(&transaction, &instance.spec)?;
        let revision = self.package_next(&transaction)?;
        let changed = transaction.execute(
            "UPDATE managed_instances SET authority = ?, lifecycle = ? WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
            params![serde_json::to_vec(grant).context(crate::PackageEncodingSnafu)?, revision,
                expected.spec.tenant.as_slice(), expected.spec.id, expected.lifecycle],
        ).context(AnalysisDatabaseSnafu { operation: "renew managed authority" })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        self.check_logical(&transaction, expected.spec.tenant, false)?;
        Self::record_revision(&transaction, revision, &["managed_instances"])?;
        check()?;
        self.commit_metadata(transaction, "commit managed renewal")?;
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        instance.grant = grant.clone();
        instance.lifecycle = revision;
        Ok(instance)
    }

    pub fn lease_managed(self: &Arc<Self>) -> Result<ManagedLease> {
        if self
            .managed_owner
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Code::Conflict.error("managed host owner"));
        }
        Ok(ManagedLease(Arc::clone(self)))
    }

    /// A current no-op checks the caller. A stale lifecycle conflicts.
    pub fn set_managed_running(
        &self,
        tenant: [u8; 16],
        id: &str,
        expected: u64,
        running: bool,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        self.change_managed(tenant, id, expected, running, None, check)
    }

    pub fn suspend_managed(
        &self,
        expected: &ManagedInstance,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        self.change_managed(
            expected.spec.tenant,
            &expected.spec.id,
            expected.lifecycle,
            false,
            Some(expected),
            check,
        )
    }

    fn change_managed(
        &self,
        tenant: [u8; 16],
        id: &str,
        expected: u64,
        running: bool,
        captured: Option<&ManagedInstance>,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        if tenant == [0; 16] || id.is_empty() || id.chars().any(char::is_control) {
            return Err(Code::Invalid.error("managed lifecycle key"));
        }
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed lifecycle",
            })?;
        let mut instance = Self::managed_instance_from(&transaction, tenant, id)?
            .ok_or_else(|| Code::Missing.error("managed lifecycle instance"))?;
        if instance.lifecycle != expected
            || captured.is_some_and(|captured| {
                captured.generation != instance.generation || captured.progress != instance.progress
            })
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if instance.running == running {
            check()?;
            return Ok(instance);
        }
        let revision = self.package_next(&transaction)?;
        let failure = captured
            .map(|_| super::status::Failure {
                code: Code::Denied,
                progress: instance.progress,
                revision,
            })
            .map(|failure| serde_json::to_vec(&failure).context(crate::PackageEncodingSnafu))
            .transpose()?;
        let changed = transaction.execute(
            "UPDATE managed_instances SET running = ?, lifecycle = ?, failure = CASE WHEN ? THEN ? ELSE failure END WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
            params![running, revision, captured.is_some(), failure, tenant.as_slice(), id, expected],
        ).context(AnalysisDatabaseSnafu { operation: "change managed running state" })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        self.check_logical(&transaction, tenant, false)?;
        Self::record_revision(&transaction, revision, &["managed_instances"])?;
        check()?;
        self.commit_metadata(transaction, "commit managed lifecycle")?;
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        instance.running = running;
        instance.lifecycle = revision;
        Ok(instance)
    }
}
