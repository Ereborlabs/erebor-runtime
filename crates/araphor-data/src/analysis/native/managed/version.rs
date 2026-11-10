use snafu::ResultExt as _;

use super::{InstanceRecord, Records, VersionRecord};
use crate :: { analysis :: native :: NativeStore , AnalysisConflictSnafu , ManagedInstance , ManagedSpec , NativeStorageSnafu , PackageErrorCodeV1 as Code , Result } ;

impl NativeStore {
    pub fn prepare_managed_version(
        &self,
        expected: &ManagedInstance,
        spec: &ManagedSpec,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        expected.validate()?;
        spec.validate()?;
        if spec.tenant != expected.spec.tenant || spec.id != expected.spec.id {
            return Err(Code::Conflict.error("managed update identity"));
        }
        let mut tx = self.write()?;
        let current = tx
            .managed_instance(spec.tenant, &spec.id)?
            .ok_or_else(|| Code::Missing.error("managed update instance"))?;
        if current.removed || current != *expected {
            return AnalysisConflictSnafu.fail();
        }
        let owner = Records::find(&InstanceRecord::identity(spec.tenant, &spec.id)?, |key| {
            Records::staged(key, &tx.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed update instance"))?;
        tx.check_pending(owner, current.generation)?;
        tx.check_managed_images(spec)?;
        let prefix = Records::key(b'Z', owner);
        let mut saved = None;
        for row in tx.transaction.prefix(&prefix).rev() {
            let (key, _) = row.context(NativeStorageSnafu {
                operation: "find exact managed version",
            })?;
            if key.len() != prefix.len() + 8 {
                continue;
            }
            let generation = NativeStore::number(&key[prefix.len()..])?;
            let version = VersionRecord::read(
                owner,
                spec.tenant,
                &spec.id,
                generation,
                tx.revision,
                |key| Records::staged(key, &tx.transaction),
            )?;
            if version.spec == *spec && version.scope == current.grant.selection {
                saved = Some(generation);
                break;
            }
        }
        let generation = if let Some(generation) = saved {
            if generation != current.generation {
                tx.check_pending(owner, generation)?;
            }
            tx.admit_managed_graph(spec, false)?;
            generation
        } else {
            tx.check_managed_addressable(spec)?;
            tx.admit_managed_graph(spec, true)?;
            Records::stage(
                &mut tx.transaction,
                VersionRecord::key(owner, tx.revision),
                Records::named(&VersionRecord {
                    spec: spec.clone(),
                    scope: current.grant.selection.clone(),
                })?,
            );
            tx.dirty = true;
            tx.revision
        };
        check()?;
        tx.commit([])?;
        Ok(ManagedInstance {
            spec: spec.clone(),
            generation,
            ..current
        })
    }
}
