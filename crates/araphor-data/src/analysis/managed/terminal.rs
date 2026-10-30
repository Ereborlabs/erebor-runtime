use super::codec::ManagedCodec;
use duckdb::{params, Transaction};
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::{model::Attempt, ManagedAttempt, ManagedExit, ManagedTerminal};
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
        if Self::managed_version_from(
            &transaction,
            spec.tenant,
            &spec.id,
            attempt.capture.generation,
        )? != *spec
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        let revision = self.package_next(&transaction)?;
        let failure = match exit {
            ManagedExit::Failed(code)
                if instance.generation == attempt.capture.generation
                    && instance.generation == attempt.capture.expected_generation
                    && instance.running == attempt.capture.running
                    && instance.lifecycle == attempt.capture.lifecycle
                    && instance.progress == attempt.capture.progress =>
            {
                Some(super::status::Failure {
                    origin: super::status::FailureOrigin::Attempt,
                    code,
                    progress: instance.progress,
                    revision,
                })
            }
            _ => None,
        };
        let suspended =
            exit == ManagedExit::Failed(Code::Denied) && instance.running && failure.is_some();
        let terminal =
            Self::managed_terminal_rows(&transaction, &mut attempt, revision, exit, suspended)?;
        if let Some(failure) = &failure {
            let changed = transaction.execute(
                "UPDATE managed_instances SET failure = ?, running = CASE WHEN ? THEN false ELSE running END, lifecycle = CASE WHEN ? THEN ? ELSE lifecycle END WHERE tenant_id = ? AND instance_id = ? AND generation = ? AND lifecycle = ? AND progress = ? AND running = ?",
                params![ManagedCodec::encode(failure).context(crate::ManagedEncodingSnafu)?, suspended, suspended, revision, spec.tenant.as_slice(), spec.id, instance.generation, instance.lifecycle, instance.progress, instance.running],
            ).context(AnalysisDatabaseSnafu { operation: "record managed failure" })?;
            if changed != 1 {
                return crate::AnalysisConflictSnafu.fail();
            }
        }
        self.check_revision_limits(&transaction, spec.tenant)?;
        Self::record_revision(
            &transaction,
            revision,
            if failure.is_some() {
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

    fn managed_terminal_rows(
        transaction: &Transaction<'_>,
        attempt: &mut Attempt,
        revision: u64,
        exit: ManagedExit,
        suspended: bool,
    ) -> Result<ManagedTerminal> {
        if attempt.receipt.is_some() || attempt.terminal.is_some() {
            return crate::AnalysisConflictSnafu.fail();
        }
        let terminal = ManagedTerminal {
            instance: attempt.capture.instance.clone(),
            attempt: attempt.request.id.clone(),
            revision,
            exit,
            suspended,
        };
        attempt.terminal = Some(terminal.clone());
        let changed = transaction.execute(
            "UPDATE managed_attempts SET contract = ?, completed = ? WHERE tenant_id = ? AND instance_id = ? AND attempt_id = ? AND completed = 0",
            params![ManagedCodec::encode(attempt).context(crate::ManagedEncodingSnafu)?, revision,
                attempt.capture.tenant.as_slice(), attempt.capture.instance, attempt.request.id],
        ).context(AnalysisDatabaseSnafu { operation: "finish known managed attempt" })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        Ok(terminal)
    }

    pub(in crate::analysis) fn recover_managed_startup(&self) -> Result<()> {
        let mut writer = self.writer_access()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin interrupted managed settlement",
            })?;
        let pending = {
            let mut statement = transaction
                .prepare(
                    "SELECT a.tenant_id, a.instance_id, a.attempt_id
                 FROM managed_attempts a JOIN managed_instances i USING (tenant_id, instance_id)
                 WHERE a.completed = 0 AND a.generation = i.generation
                 ORDER BY a.tenant_id, a.instance_id, a.attempt_id",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare interrupted managed attempts",
                })?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read interrupted managed attempts",
                })?;
            rows.collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode interrupted managed rows",
                })?
        };
        let mut tenants = std::collections::BTreeSet::new();
        let mut final_revision = None;
        for (tenant, instance, id) in pending {
            let tenant = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("managed attempt tenant"))?;
            let mut attempt = Self::managed_attempt_from(&transaction, tenant, &instance, &id)?
                .ok_or_else(|| Code::Missing.error("managed recovery attempt"))?;
            if attempt.request.frontier.is_none() {
                continue;
            }
            if final_revision.is_none() {
                self.require_capacity(true)?;
            }
            let revision = self.package_next(&transaction)?;
            Self::managed_terminal_rows(
                &transaction,
                &mut attempt,
                revision,
                ManagedExit::Cancelled,
                false,
            )?;
            Self::record_revision(&transaction, revision, &["managed_attempts"])?;
            tenants.insert(tenant);
            final_revision = Some(revision);
        }
        let Some(revision) = final_revision else {
            return Ok(());
        };
        for tenant in tenants {
            self.check_revision_limits(&transaction, tenant)?;
        }
        self.commit_metadata(transaction, "commit interrupted managed settlement")?;
        self.revision.send_replace(revision);
        Ok(())
    }
}
