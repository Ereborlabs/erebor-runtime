use duckdb::params;
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::{ManagedAttempt, ManagedExit, ManagedTerminal};
use crate::{AnalysisDatabaseSnafu, PackageErrorCodeV1 as Code, Result};

impl AnalysisStore {
    /// Join the original execution before this call. A loaded pending claim cannot finish.
    pub fn finish_managed(
        &self,
        supplied: &ManagedAttempt,
        exit: ManagedExit,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedTerminal> {
        let spec = &supplied.1.spec;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin managed terminal state",
            })?;
        let mut attempt = Self::managed_attempt_from(
            &transaction,
            spec.tenant,
            &spec.id,
            &supplied.0.request.id,
        )?
        .ok_or_else(|| Code::Missing.error("managed terminal attempt"))?;
        if supplied.0.request != attempt.request
            || supplied.0.capture != attempt.capture
            || supplied.0.registered != attempt.registered
            || attempt.receipt.is_some()
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if let Some(terminal) = &attempt.terminal {
            if terminal.exit != exit {
                return crate::AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(terminal.clone());
        }
        self.check_managed_claim(supplied)?;
        let meta = Self::read_meta_from(&transaction, &self.root.join("analysis.duckdb"))?;
        if meta.store_uuid != attempt.capture.store
            || meta.schema_version != attempt.capture.schema
            || meta.recovery_epoch != attempt.capture.recovery
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let instance = Self::managed_instance_from(&transaction, spec.tenant, &spec.id)?
            .ok_or_else(|| Code::Missing.error("managed terminal instance"))?;
        if instance.spec != *spec || instance.generation != attempt.capture.generation {
            return crate::AnalysisConflictSnafu.fail();
        }
        let revision = self.package_next(&transaction)?;
        let suspended = exit == ManagedExit::Failed(Code::Denied)
            && instance.running
            && instance.lifecycle == attempt.capture.lifecycle
            && instance.progress == attempt.capture.progress;
        let terminal = ManagedTerminal {
            instance: spec.id.clone(),
            attempt: attempt.request.id.clone(),
            revision,
            exit,
            suspended,
        };
        attempt.terminal = Some(terminal.clone());
        let changed = transaction.execute(
            "UPDATE managed_attempts SET contract = ?, completed = ? WHERE tenant_id = ? AND instance_id = ? AND attempt_id = ? AND completed = 0",
            params![serde_json::to_vec(&attempt).context(crate::PackageEncodingSnafu)?, revision,
                spec.tenant.as_slice(), spec.id, attempt.request.id],
        ).context(AnalysisDatabaseSnafu { operation: "finish known managed attempt" })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        if suspended {
            let changed = transaction.execute(
                "UPDATE managed_instances SET running = false, lifecycle = ? WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ? AND progress = ? AND running",
                params![revision, spec.tenant.as_slice(), spec.id, instance.lifecycle, instance.progress],
            ).context(AnalysisDatabaseSnafu { operation: "suspend denied managed instance" })?;
            if changed != 1 {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        self.check_logical(&transaction, spec.tenant, false)?;
        Self::record_revision(
            &transaction,
            revision,
            if suspended {
                &["managed_attempts", "managed_instances"]
            } else {
                &["managed_attempts"]
            },
        )?;
        check()?;
        self.commit_metadata(transaction, "commit managed terminal state")?;
        self.revision.send_replace(revision);
        if suspended {
            self.activations.send_replace(revision);
        }
        Ok(terminal)
    }
}
