use super::{CallHead, InstanceRecord, Records, VersionRecord};
use crate::{
    analysis::native::{DataWrite, NativeStore},
    AnalysisConflictSnafu, ManagedInstance, ManagedSpec, PackageErrorCodeV1 as Code,
    PackageGrantV1, Result,
};

impl NativeStore {
    pub fn admit_managed(
        &self,
        spec: &ManagedSpec,
        grant: &PackageGrantV1,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<ManagedInstance> {
        let mut tx = self.write()?;
        let instance = tx.admit_managed(spec, grant)?;
        check()?;
        tx.commit([])?;
        Ok(instance)
    }
}

impl DataWrite<'_> {
    /// Discard this transaction if staging fails.
    pub fn admit_managed(
        &mut self,
        spec: &ManagedSpec,
        grant: &PackageGrantV1,
    ) -> Result<ManagedInstance> {
        spec.validate()?;
        grant.validate()?;
        if grant.selection.tenant_id != spec.tenant {
            return Err(Code::Invalid.error("managed instance grant"));
        }
        self.check_managed_images(spec)?;
        let saved = self.managed_instance(spec.tenant, &spec.id)?;
        self.admit_managed_graph(spec, saved.is_none())?;
        if let Some(saved) = saved {
            if saved.removed || saved.spec != *spec || saved.grant != *grant {
                return AnalysisConflictSnafu.fail();
            }
            return Ok(saved);
        }
        for pin in &spec.definition.images {
            if !self.installed_image(spec.tenant, pin)? {
                return Err(Code::Missing.error("managed installed image"));
            }
        }
        let id = Records::intern(
            &mut self.transaction,
            &InstanceRecord::identity(spec.tenant, &spec.id)?,
        )?;
        let version = VersionRecord {
            spec: spec.clone(),
            scope: grant.selection.clone(),
        };
        Records::stage(
            &mut self.transaction,
            VersionRecord::key(id, self.revision),
            Records::named(&version)?,
        );
        for call in spec.manifest.calls.keys() {
            Records::stage(
                &mut self.transaction,
                InstanceRecord::call_key(id, *call),
                Records::encode(&CallHead {
                    revision: 0,
                    result: None,
                })?,
            );
        }
        let instance = ManagedInstance {
            spec: spec.clone(),
            grant: grant.clone(),
            generation: self.revision,
            progress: 0,
            running: false,
            removed: false,
            lifecycle: self.revision,
        };
        self.stage_instance(&instance)?;
        Ok(instance)
    }

    fn check_managed_images(&self, spec: &ManagedSpec) -> Result<()> {
        let definition = self
            .definition(
                spec.tenant,
                &spec.definition.definition.name,
                spec.manifest.definition,
            )?
            .map(|definition| definition.encode())
            .transpose()?;
        spec.check_images(definition.as_deref(), |pin| {
            self.retained_package_image(spec.tenant, pin)
        })
    }
}
