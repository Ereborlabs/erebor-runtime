use super::super::{DataView, NativeStore};
use super::{attempts::Attempts, InstanceRecord, Records};
use crate::analysis::managed::{Attempt, Failure};
use crate::{
    AnalysisReadControl, AnalysisSelectionV1, ManagedExit, ManagedResume, ManagedStatus,
    PackageErrorCodeV1 as Code, PackageReadinessV1, Result,
};

impl DataView {
    pub(super) fn outcome_attempt(&self, owner: u64, revision: u64) -> Result<Attempt> {
        let id = Records::read(&Attempts::ended(owner, revision), &self.snapshot)?
            .ok_or_else(|| Code::Missing.error("managed outcome attempt"))?;
        let id = NativeStore::number(&id)?;
        let bytes = Records::payload(&Records::key(b'a', id), |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed outcome attempt"))?;
        Records::decode(&bytes)
    }

    pub fn managed_resume(
        &self,
        tenant: [u8; 16],
        name: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedResume> {
        control.check()?;
        let instance = self
            .managed_instance(tenant, name, control)?
            .ok_or_else(|| Code::Missing.error("managed resume instance"))?;
        if instance.removed {
            return Err(Code::Conflict.error("managed instance removed"));
        }
        let owner = Records::find(&InstanceRecord::identity(tenant, name)?, |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed resume instance"))?;
        self.check_managed_pending(owner, instance.generation)?;
        let completed = self.managed_completed(owner, instance.generation)?;
        if instance.progress != 0 {
            return Err(Code::Unsupported.error("native managed source parent"));
        }
        if completed > instance.progress {
            let attempt = self.outcome_attempt(owner, completed)?;
            let terminal = attempt
                .terminal
                .as_ref()
                .filter(|terminal| {
                    terminal.instance == name
                        && terminal.attempt == attempt.request.id
                        && terminal.revision == completed
                        && attempt.receipt.is_none()
                })
                .ok_or_else(|| Code::Invalid.error("managed terminal frontier"))?;
            if attempt.capture.tenant != tenant
                || attempt.capture.instance != name
                || attempt.capture.generation != instance.generation
            {
                return Err(Code::Invalid.error("managed terminal frontier"));
            }
            if attempt.capture.progress == instance.progress
                && attempt.capture.lifecycle == instance.lifecycle
                && attempt.capture.running == instance.running
                && attempt.request.frontier.is_some()
                && !matches!(
                    terminal.exit,
                    ManagedExit::Cancelled | ManagedExit::Failed(Code::Denied)
                )
            {
                return Ok(ManagedResume {
                    instance,
                    frontier: attempt.request.frontier,
                    completed,
                    source: None,
                });
            }
        }
        control.check()?;
        Ok(ManagedResume {
            instance,
            frontier: None,
            completed,
            source: None,
        })
    }

    pub fn managed_status(
        &self,
        selection: &AnalysisSelectionV1,
        name: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedStatus> {
        control.check()?;
        let instance = self
            .managed_instance(selection.tenant_id, name, control)?
            .ok_or_else(|| Code::Missing.error("managed status instance"))?;
        instance.grant.permitted_by(selection)?;
        let owner = Records::find(
            &InstanceRecord::identity(selection.tenant_id, name)?,
            |key| Records::read(key, &self.snapshot),
        )?
        .ok_or_else(|| Code::Missing.error("managed status instance"))?;
        self.check_managed_pending(owner, instance.generation)?;
        let bytes = Records::payload(&Records::key(b'Y', owner), |key| {
            Records::read(key, &self.snapshot)
        })?;
        let failure = Failure::decode(bytes, &instance, self.metadata_revision)?
            .filter(|failure| failure.progress == instance.progress);
        let readiness = if let Some(failure) = failure {
            PackageReadinessV1::Failed {
                code: failure.code,
                field: "model evaluation".into(),
            }
        } else if instance.running {
            PackageReadinessV1::Ready
        } else {
            PackageReadinessV1::Inactive
        };
        let status_progress = instance.progress;
        Ok(ManagedStatus {
            instance,
            readiness,
            status_progress,
        })
    }

    pub(super) fn check_managed_pending(&self, owner: u64, generation: u64) -> Result<()> {
        use snafu::ResultExt as _;
        if self
            .snapshot
            .prefix(Attempts::pending(owner, generation))
            .next()
            .transpose()
            .context(crate::NativeStorageSnafu {
                operation: "read managed pending attempts",
            })?
            .is_some()
        {
            return Err(Code::Incomplete.error("managed pending attempt"));
        }
        Ok(())
    }
}

impl NativeStore {
    pub fn managed_resume(
        &self,
        tenant: [u8; 16],
        name: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedResume> {
        self.view()?.managed_resume(tenant, name, control)
    }

    pub fn managed_status(
        &self,
        selection: &AnalysisSelectionV1,
        name: &str,
        control: &AnalysisReadControl,
    ) -> Result<ManagedStatus> {
        self.view()?.managed_status(selection, name, control)
    }
}
