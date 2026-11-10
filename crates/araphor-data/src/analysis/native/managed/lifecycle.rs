use std::sync::{atomic::Ordering, Arc};

use snafu::ResultExt as _;

use super::{InstanceRecord, Records};
use crate::analysis::managed::{Failure, FailureOrigin};
use crate::{
    analysis::native::{DataView, DataWrite, NativeStore},
    AnalysisConflictSnafu, AnalysisReadControl, ManagedInstance, ManagedMember, ManagedResume,
    NativeStateSnafu, NativeStorageSnafu, PackageErrorCodeV1 as Code, PackageGrantV1, Result,
};

pub struct ManagedLease(Arc<NativeStore>);

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

impl NativeStore {
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
        let mut tx = self.write()?;
        let instance = tx.change_managed(tenant, id, expected, change)?;
        check()?;
        tx.commit([])?;
        Ok(instance)
    }

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
        let mut tx = self.write()?;
        let mut instance = tx
            .managed_instance(expected.spec.tenant, &expected.spec.id)?
            .ok_or_else(|| Code::Missing.error("managed renewal instance"))?;
        if instance != *expected || instance.running || instance.removed {
            return AnalysisConflictSnafu.fail();
        }
        let owner = Records::find(
            &InstanceRecord::identity(instance.spec.tenant, &instance.spec.id)?,
            |key| Records::staged(key, &tx.transaction),
        )?
        .ok_or_else(|| Code::Missing.error("managed renewal instance"))?;
        tx.check_pending(owner, instance.generation)?;
        if instance.grant != *grant {
            tx.check_managed_images(&instance.spec)?;
            instance.grant = grant.clone();
            instance.lifecycle = tx.revision;
            tx.stage_instance(&instance)?;
        }
        check()?;
        tx.commit([])?;
        Ok(instance)
    }

    pub fn active_managed(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<(u64, Vec<ManagedMember>)> {
        self.view()?.active_managed(control)
    }
}

impl DataWrite<'_> {
    fn change_managed(
        &mut self,
        tenant: [u8; 16],
        id: &str,
        expected: u64,
        change: Change<'_>,
    ) -> Result<ManagedInstance> {
        if tenant == [0; 16] || id.is_empty() || id.chars().any(char::is_control) {
            return Err(Code::Invalid.error("managed lifecycle key"));
        }
        let mut instance = self
            .managed_instance(tenant, id)?
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
            return AnalysisConflictSnafu.fail();
        }
        let owner = Records::find(&InstanceRecord::identity(tenant, id)?, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed lifecycle instance"))?;
        if let Some((expected, code)) = admission {
            if !instance.running
                || self.managed_completed(owner, instance.generation)? != expected.completed
            {
                return AnalysisConflictSnafu.fail();
            }
            self.check_managed_idle(owner)?;
            if diagnostic
                && self
                    .store
                    .view()?
                    .managed_failure(owner, &instance)?
                    .is_some_and(|failure| {
                        failure.origin == FailureOrigin::Admission
                            && failure.code == code
                            && failure.progress == instance.progress
                    })
            {
                return Ok(instance);
            }
        }
        if admission.is_none()
            && instance.running == running
            && (stopped.is_none() || instance.lifecycle != instance.generation)
        {
            return Ok(instance);
        }
        if captured.is_some() {
            Records::stage(
                &mut self.transaction,
                Records::key(b'Y', owner),
                Records::named(&Failure {
                    origin: FailureOrigin::Admission,
                    code: admission.map_or(Code::Denied, |(_, code)| code),
                    progress: instance.progress,
                    revision: self.revision,
                })?,
            );
        }
        instance.running = running;
        if !diagnostic {
            instance.lifecycle = self.revision;
        }
        self.stage_instance(&instance)?;
        Ok(instance)
    }
}

impl DataView {
    pub(in crate::analysis::native) fn input_activation(
        &self,
        key: &[u8],
        revision: u64,
    ) -> Result<bool> {
        let bytes = Records::payload(key, |key| Records::read(key, &self.snapshot))?
            .ok_or_else(|| Code::Missing.error("activation instance"))?;
        let instance: InstanceRecord = Records::decode(&bytes)?;
        Ok(instance.lifecycle == revision)
    }

    pub fn active_managed(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<(u64, Vec<ManagedMember>)> {
        control.check()?;
        let mut active = Vec::new();
        for entry in self.snapshot.prefix(b"\0data/B") {
            control.check()?;
            let (key, value) = entry.context(NativeStorageSnafu {
                operation: "read active managed members",
            })?;
            if key.len() != 15 {
                return NativeStateSnafu {
                    field: "active managed key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[7..])?;
            let bytes = Records::payload(&Records::key(b'J', id), |key| {
                Records::read(key, &self.snapshot)
            })?
            .ok_or_else(|| Code::Missing.error("active managed instance"))?;
            let row: InstanceRecord = Records::decode(&bytes)?;
            if !row.running
                || row.removed
                || row.tenant == [0; 16]
                || row.id.is_empty()
                || row.id.chars().any(char::is_control)
                || row.generation == 0
                || row.lifecycle <= row.generation
                || row.lifecycle > self.metadata_revision
                || NativeStore::number(&value)? != row.lifecycle
            {
                return NativeStateSnafu {
                    field: "active managed member",
                }
                .fail();
            }
            active.push(ManagedMember {
                tenant: row.tenant,
                id: row.id,
                generation: row.generation,
                lifecycle: row.lifecycle,
            });
        }
        active.sort_by(|left, right| (left.tenant, &left.id).cmp(&(right.tenant, &right.id)));
        control.check()?;
        Ok((self.revision, active))
    }
}
