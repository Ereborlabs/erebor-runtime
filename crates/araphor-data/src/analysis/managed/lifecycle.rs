use super::codec::ManagedCodec;
use std::sync::{atomic::Ordering, Arc};

use duckdb::params;
use snafu::ResultExt as _;

use super::super::AnalysisStore;
use super::{ManagedInstance, ManagedResume};
use crate::{AnalysisDatabaseSnafu, PackageErrorCodeV1 as Code, PackageGrantV1, Result};

pub struct ManagedLease(Arc<AnalysisStore>);

#[derive(Clone, Copy)]
enum Change<'a> {
    Running(bool),
    Suspend(&'a ManagedInstance),
    Stop(&'a ManagedInstance),
    Admission(&'a ManagedResume, Code),
}

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
        if instance != *expected || instance.running || instance.removed {
            return crate::AnalysisConflictSnafu.fail();
        }
        Self::check_managed_pending(
            &transaction,
            expected.spec.tenant,
            &expected.spec.id,
            expected.generation,
        )?;
        if instance.grant == *grant {
            check()?;
            return Ok(instance);
        }
        Self::check_managed_images(&transaction, &instance.spec)?;
        let revision = self.package_next(&transaction)?;
        let changed = transaction.execute(
            "UPDATE managed_instances SET authority = ?, lifecycle = ? WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
            params![ManagedCodec::encode(grant).context(crate::ManagedEncodingSnafu)?, revision,
                expected.spec.tenant.as_slice(), expected.spec.id, expected.lifecycle],
        ).context(AnalysisDatabaseSnafu { operation: "renew managed authority" })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        self.check_revision_limits(&transaction, expected.spec.tenant)?;
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
        self.change_managed(tenant, id, expected, Change::Running(running), check)
    }

    pub fn stop_managed(
        &self,
        expected: &ManagedInstance,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        self.change_managed(
            expected.spec.tenant,
            &expected.spec.id,
            expected.lifecycle,
            Change::Stop(expected),
            check,
        )
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
            Change::Suspend(expected),
            check,
        )
    }

    /// Join the failed preparation before this call.
    pub fn fail_managed(
        &self,
        expected: &ManagedResume,
        code: Code,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.instance.validate()?;
        self.change_managed(
            expected.instance.spec.tenant,
            &expected.instance.spec.id,
            expected.instance.lifecycle,
            Change::Admission(expected, code),
            check,
        )
    }

    fn change_managed(
        &self,
        tenant: [u8; 16],
        id: &str,
        expected: u64,
        change: Change<'_>,
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
        let admission = match change {
            Change::Admission(expected, code) => Some((expected, code)),
            _ => None,
        };
        let diagnostic = admission.is_some_and(|(_, code)| code != Code::Denied);
        let running = if diagnostic {
            instance.running
        } else {
            matches!(change, Change::Running(true))
        };
        let captured = match change {
            Change::Suspend(expected) => Some(expected),
            Change::Admission(expected, _) => Some(&expected.instance),
            _ => None,
        };
        let stopped = match change {
            Change::Stop(expected) => Some(expected),
            _ => None,
        };
        if instance.removed
            || instance.lifecycle != expected
            || captured.is_some_and(|captured| captured != &instance)
            || stopped.is_some_and(|stopped| {
                stopped.spec != instance.spec
                    || stopped.grant != instance.grant
                    || stopped.generation != instance.generation
            })
        {
            return crate::AnalysisConflictSnafu.fail();
        }
        if let Some((expected, code)) = admission {
            if !instance.running
                || Self::managed_completed_from(&transaction, tenant, id, instance.generation)?
                    != expected.completed
            {
                return crate::AnalysisConflictSnafu.fail();
            }
            Self::check_managed_idle(&transaction, tenant, id)?;
            if diagnostic
                && Self::validate_managed_failure(&transaction, &instance)?.is_some_and(|failure| {
                    failure.origin == super::status::FailureOrigin::Admission
                        && failure.code == code
                        && failure.progress == instance.progress
                })
            {
                check()?;
                return Ok(instance);
            }
        }
        if admission.is_none()
            && instance.running == running
            && (stopped.is_none() || instance.lifecycle != instance.generation)
        {
            check()?;
            return Ok(instance);
        }
        let revision = self.package_next(&transaction)?;
        let failure = captured
            .map(|_| super::status::Failure {
                origin: super::status::FailureOrigin::Admission,
                code: admission.map_or(Code::Denied, |(_, code)| code),
                progress: instance.progress,
                revision,
            })
            .map(|failure| ManagedCodec::encode(&failure).context(crate::ManagedEncodingSnafu))
            .transpose()?;
        let lifecycle = if diagnostic {
            instance.lifecycle
        } else {
            revision
        };
        let changed = transaction.execute(
            "UPDATE managed_instances SET running = ?, lifecycle = ?, failure = CASE WHEN ? THEN ? ELSE failure END WHERE tenant_id = ? AND instance_id = ? AND lifecycle = ?",
            params![running, lifecycle, captured.is_some(), failure, tenant.as_slice(), id, expected],
        ).context(AnalysisDatabaseSnafu { operation: "change managed running state" })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        self.check_revision_limits(&transaction, tenant)?;
        Self::record_revision(&transaction, revision, &["managed_instances"])?;
        check()?;
        self.commit_metadata(transaction, "commit managed lifecycle")?;
        self.revision.send_replace(revision);
        if !diagnostic {
            self.activations.send_replace(revision);
        }
        instance.running = running;
        instance.lifecycle = lifecycle;
        Ok(instance)
    }
}
