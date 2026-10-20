use duckdb::params;
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::ManagedInstance;
use crate::{AnalysisDatabaseSnafu, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    /// A current no-op checks the caller. A stale lifecycle conflicts.
    pub fn set_managed_running(
        &self,
        tenant: [u8; 16],
        id: &str,
        expected: u64,
        running: bool,
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
        if instance.lifecycle != expected {
            return crate::AnalysisConflictSnafu.fail();
        }
        check()?;
        if instance.running == running {
            return Ok(instance);
        }
        let revision = self.package_next(&transaction)?;
        let changed = transaction.execute(
            "UPDATE managed_instances SET running = ?, lifecycle = ? WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
            params![running, revision, tenant.as_slice(), id, expected],
        ).context(AnalysisDatabaseSnafu { operation: "change managed running state" })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        self.check_logical(&transaction, tenant, false)?;
        Self::record_revision(&transaction, revision, &["managed_instances"])?;
        self.commit_metadata(transaction, "commit managed lifecycle")?;
        self.revision.send_replace(revision);
        self.activations.send_replace(revision);
        instance.running = running;
        instance.lifecycle = revision;
        Ok(instance)
    }
}
