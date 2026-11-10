use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{records::Records, DataView, DataWrite};
use crate::{
    AnalysisReadControl, AnalysisSelectionV1, ManagedInstance, ManagedSpec, NativeStateSnafu,
    PackageErrorCodeV1 as Code, PackageGrantV1, Result,
};

mod admission;
mod attempt_recovery;
mod attempts;
mod authority;
mod capture;
mod commit;
mod graph;
mod lifecycle;
mod prepare;
mod priors;
mod read;
mod recovery;
mod references;
mod result_recovery;
mod results;
mod status;
mod terminal;

pub use commit::{ManagedCommit, ManagedReturn};
pub use graph::{GraphPublication, ManagedGraph, ManagedGraphJournal, ManagedGraphTransaction};
pub use lifecycle::ManagedLease;
pub use prepare::PreparedManagedCommit;

#[derive(Deserialize, Serialize)]
struct VersionRecord {
    spec: ManagedSpec,
    scope: AnalysisSelectionV1,
}

#[derive(Deserialize, Serialize)]
struct InstanceRecord {
    tenant: [u8; 16],
    id: String,
    grant: PackageGrantV1,
    generation: u64,
    progress: u64,
    running: bool,
    removed: bool,
    lifecycle: u64,
}

#[derive(Deserialize, Serialize)]
struct CallHead {
    revision: u64,
    result: Option<String>,
}

impl InstanceRecord {
    fn identity(tenant: [u8; 16], id: &str) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b'J', tenant, id)).context(crate::ManagedEncodingSnafu)
    }

    fn read(
        tenant: [u8; 16],
        name: &str,
        head: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<ManagedInstance>> {
        let Some(id) = Records::find(&Self::identity(tenant, name)?, &mut get)? else {
            return Ok(None);
        };
        let Some(bytes) = Records::payload(&Records::key(b'J', id), &mut get)? else {
            return Ok(None);
        };
        let row: Self = Records::decode(&bytes)?;
        let version = VersionRecord::read(id, tenant, name, row.generation, head, get)?;
        let instance = ManagedInstance {
            spec: version.spec,
            grant: row.grant,
            generation: row.generation,
            progress: row.progress,
            running: row.running,
            removed: row.removed,
            lifecycle: row.lifecycle,
        };
        instance.validate()?;
        if row.tenant != tenant
            || row.id != name
            || instance.grant.selection != version.scope
            || instance.progress > head
            || instance.lifecycle < instance.generation
            || instance.lifecycle > head
            || instance.lifecycle == instance.generation && instance.running
        {
            return NativeStateSnafu {
                field: "managed instance record",
            }
            .fail();
        }
        Ok(Some(instance))
    }

    fn call_key(id: u64, call: u64) -> Vec<u8> {
        [Records::key(b'Q', id), call.to_be_bytes().to_vec()].concat()
    }
}

impl From<&ManagedInstance> for InstanceRecord {
    fn from(instance: &ManagedInstance) -> Self {
        Self {
            tenant: instance.spec.tenant,
            id: instance.spec.id.clone(),
            grant: instance.grant.clone(),
            generation: instance.generation,
            progress: instance.progress,
            running: instance.running,
            removed: instance.removed,
            lifecycle: instance.lifecycle,
        }
    }
}

impl VersionRecord {
    fn key(id: u64, generation: u64) -> Vec<u8> {
        [Records::key(b'Z', id), generation.to_be_bytes().to_vec()].concat()
    }

    fn read(
        id: u64,
        tenant: [u8; 16],
        name: &str,
        generation: u64,
        head: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Self> {
        Self::read_charged(id, tenant, name, generation, head, get, &mut |_| Ok(()))
    }

    fn read_charged(
        id: u64,
        tenant: [u8; 16],
        name: &str,
        generation: u64,
        head: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Self> {
        let bytes = Records::charged_payload(&Self::key(id, generation), get, charge)?
            .ok_or_else(|| Code::Missing.error("managed version"))?;
        let row: Self = Records::decode(&bytes)?;
        row.check(tenant, name, generation, head)
    }

    fn check(self, tenant: [u8; 16], name: &str, generation: u64, head: u64) -> Result<Self> {
        self.spec.validate()?;
        if generation == 0
            || generation > head
            || self.spec.tenant != tenant
            || self.spec.id != name
            || !self.scope.valid()
            || self.scope.tenant_id != tenant
        {
            return NativeStateSnafu {
                field: "managed version record",
            }
            .fail();
        }
        Ok(self)
    }
}

impl DataView {
    pub fn managed_instance(
        &self,
        tenant: [u8; 16],
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<Option<ManagedInstance>> {
        control.check()?;
        let instance = InstanceRecord::read(tenant, id, self.metadata_revision, |key| {
            Records::read(key, &self.snapshot)
        })?;
        control.check()?;
        Ok(instance)
    }

    pub fn managed_version(
        &self,
        tenant: [u8; 16],
        name: &str,
        generation: u64,
        control: &AnalysisReadControl,
    ) -> Result<ManagedSpec> {
        control.check()?;
        let id = Records::find(&InstanceRecord::identity(tenant, name)?, |key| {
            Records::read(key, &self.snapshot)
        })?
        .ok_or_else(|| Code::Missing.error("managed version"))?;
        let version = VersionRecord::read(
            id,
            tenant,
            name,
            generation,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
        )?;
        control.check()?;
        Ok(version.spec)
    }
}

impl DataWrite<'_> {
    fn managed_instance(&self, tenant: [u8; 16], id: &str) -> Result<Option<ManagedInstance>> {
        InstanceRecord::read(tenant, id, self.revision, |key| {
            Records::staged(key, &self.transaction)
        })
    }

    fn stage_instance(&mut self, instance: &ManagedInstance) -> Result<()> {
        let id = Records::intern(
            &mut self.transaction,
            &InstanceRecord::identity(instance.spec.tenant, &instance.spec.id)?,
        )?;
        let bytes = Records::encode(&InstanceRecord::from(instance))?;
        Records::stage(&mut self.transaction, Records::key(b'J', id), bytes);
        if instance.running && !instance.removed {
            self.transaction
                .insert(Records::key(b'B', id), instance.lifecycle.to_be_bytes());
        } else {
            self.transaction.remove(Records::key(b'B', id));
        }
        self.dirty = true;
        Ok(())
    }
}
