use std::sync::{atomic::Ordering, Arc};

use snafu::ResultExt as _;

use super::{InstanceRecord, Records};
use crate::{
    analysis::native::{DataView, DataWrite, NativeStore},
    AnalysisConflictSnafu, AnalysisReadControl, ManagedInstance, ManagedMember, NativeStateSnafu,
    NativeStorageSnafu, PackageErrorCodeV1 as Code, Result,
};

pub struct ManagedLease(Arc<NativeStore>);

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
        let mut tx = self.write()?;
        let instance = tx.change_managed(tenant, id, expected, running, None)?;
        check()?;
        tx.commit([])?;
        Ok(instance)
    }

    pub fn stop_managed(
        &self,
        expected: &ManagedInstance,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        let mut tx = self.write()?;
        let instance = tx.change_managed(
            expected.spec.tenant,
            &expected.spec.id,
            expected.lifecycle,
            false,
            Some(expected),
        )?;
        check()?;
        tx.commit([])?;
        Ok(instance)
    }
}

impl DataWrite<'_> {
    fn change_managed(
        &mut self,
        tenant: [u8; 16],
        id: &str,
        expected: u64,
        running: bool,
        stopped: Option<&ManagedInstance>,
    ) -> Result<ManagedInstance> {
        if tenant == [0; 16] || id.is_empty() || id.chars().any(char::is_control) {
            return Err(Code::Invalid.error("managed lifecycle key"));
        }
        let mut instance = self
            .managed_instance(tenant, id)?
            .ok_or_else(|| Code::Missing.error("managed lifecycle instance"))?;
        if instance.removed
            || instance.lifecycle != expected
            || stopped.is_some_and(|stopped| {
                stopped.spec != instance.spec
                    || stopped.grant != instance.grant
                    || stopped.generation != instance.generation
            })
        {
            return AnalysisConflictSnafu.fail();
        }
        if instance.running == running
            && (stopped.is_none() || instance.lifecycle != instance.generation)
        {
            return Ok(instance);
        }
        instance.running = running;
        instance.lifecycle = self.revision;
        self.stage_instance(&instance)?;
        Ok(instance)
    }
}

impl DataView {
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
