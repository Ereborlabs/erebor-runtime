use super::{CallHead, InstanceRecord, Records, VersionRecord};
use crate :: { analysis :: native :: NativeStore , AnalysisConflictSnafu , ManagedInstance , ManagedSpec , PackageErrorCodeV1 as Code , PackageGrantV1 , Result } ;

impl NativeStore {
    /// Stop and join the Host worker before this call.
    pub fn remove_managed(
        &self,
        expected: &ManagedInstance,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        let mut tx = self.write()?;
        let mut current = tx
            .managed_instance(expected.spec.tenant, &expected.spec.id)?
            .ok_or_else(|| Code::Missing.error("managed removal instance"))?;
        if current != *expected {
            return AnalysisConflictSnafu.fail();
        }
        let owner = Records::find(
            &InstanceRecord::identity(current.spec.tenant, &current.spec.id)?,
            |key| Records::staged(key, &tx.transaction),
        )?
        .ok_or_else(|| Code::Missing.error("managed removal instance"))?;
        tx.check_managed_idle(owner)?;
        if !current.removed {
            for call in current.spec.manifest.calls.keys() {
                Records::stage(
                    &mut tx.transaction,
                    InstanceRecord::call_key(owner, *call),
                    Records::named(&CallHead {
                        revision: 0,
                        result: None,
                    })?,
                );
            }
            current.running = false;
            current.removed = true;
            current.lifecycle = tx.revision;
            tx.transaction.remove(Records::key(b'Y', owner));
            tx.stage_instance(&current)?;
        }
        check()?;
        tx.commit([])?;
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
        let mut tx = self.write()?;
        let current = tx
            .managed_instance(spec.tenant, &spec.id)?
            .ok_or_else(|| Code::Missing.error("managed recreation instance"))?;
        if current != *expected {
            return AnalysisConflictSnafu.fail();
        }
        let owner = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::staged(key, &tx.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed recreation instance"))?;
        tx.check_managed_idle(owner)?;
        tx.check_managed_images(spec)?;
        tx.check_managed_addressable(spec)?;
        tx.admit_managed_graph(spec, true)?;
        Records::stage(
            &mut tx.transaction,
            VersionRecord::key(owner, tx.revision),
            Records::named(&VersionRecord {
                spec: spec.clone(),
                scope: grant.selection.clone(),
            })?,
        );
        for call in current.spec.manifest.calls.keys() {
            tx.transaction
                .remove(InstanceRecord::call_key(owner, *call));
        }
        for call in spec.manifest.calls.keys() {
            Records::stage(
                &mut tx.transaction,
                InstanceRecord::call_key(owner, *call),
                Records::named(&CallHead {
                    revision: 0,
                    result: None,
                })?,
            );
        }
        let instance = ManagedInstance {
            spec: spec.clone(),
            grant: grant.clone(),
            generation: tx.revision,
            progress: 0,
            running: false,
            removed: false,
            lifecycle: tx.revision,
        };
        tx.transaction.remove(Records::key(b'Y', owner));
        tx.stage_instance(&instance)?;
        check()?;
        tx.commit([])?;
        Ok(instance)
    }
}
