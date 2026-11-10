use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{attempts::Attempts, InstanceRecord, Records, VersionRecord};
use crate::analysis::managed::{Attempt, Packet, Record, Step};
use crate::analysis::native::{DataView, DataWrite};
use crate::{AnalysisReadControl, ManagedAttempt, ManagedSpec, PackageErrorCodeV1 as Code, Result};

#[derive(Deserialize, Serialize)]
pub(super) enum ResultBody {
    Call(Record),
    Selected(Step),
}

#[derive(Deserialize, Serialize)]
pub(super) struct StoredResult {
    pub tenant: [u8; 16],
    pub id: String,
    pub revision: u64,
    pub body: ResultBody,
}

impl StoredResult {
    pub(super) fn identity(tenant: [u8; 16], id: &str) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b'X', tenant, id)).context(crate::ManagedEncodingSnafu)
    }

    pub(super) fn read(
        tenant: [u8; 16],
        name: &str,
        head: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(u64, Self)>> {
        let Some((id, result)) = Self::load(tenant, name, get, charge)? else {
            return Ok(None);
        };
        result.check_identity(tenant, name, head)?;
        Ok(Some((id, result)))
    }

    pub(super) fn load(
        tenant: [u8; 16],
        name: &str,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(u64, Self)>> {
        let Some(id) = Records::find(&Self::identity(tenant, name)?, &mut get)? else {
            return Ok(None);
        };
        let Some(bytes) = Records::charged_payload(&Records::key(b'X', id), &mut get, charge)?
        else {
            return Ok(None);
        };
        let result: Self = Records::decode(&bytes)?;
        Ok(Some((id, result)))
    }

    pub(super) fn check_identity(&self, tenant: [u8; 16], name: &str, head: u64) -> Result<()> {
        if self.tenant != tenant || self.id != name || self.revision == 0 || self.revision > head {
            return Err(Code::Invalid.error("managed result identity"));
        }
        Ok(())
    }

    pub(super) fn owner(&self) -> (&str, &str) {
        match &self.body {
            ResultBody::Call(record) => (&record.instance, &record.attempt),
            ResultBody::Selected(step) => (&step.instance, &step.attempt),
        }
    }

    pub(super) fn check(&self, attempt: &Attempt, spec: &ManagedSpec) -> Result<()> {
        let (instance, name) = self.owner();
        let receipt = attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("managed result receipt"))?;
        if instance != spec.id
            || attempt.capture.tenant != self.tenant
            || attempt.capture.instance != instance
            || attempt.request.id != name
            || receipt.instance != instance
            || receipt.attempt != name
            || attempt.terminal.is_some()
            || attempt.registered == 0
            || attempt.registered >= self.revision
            || receipt.commit_revision != self.revision
            || receipt.selected.commit_revision != self.revision
            || !receipt.matches_frontier(&attempt.request.frontier)
        {
            return Err(Code::Invalid.error("managed result owner"));
        }
        match &self.body {
            ResultBody::Call(record) => {
                let declaration = spec
                    .manifest
                    .calls
                    .get(&record.call)
                    .ok_or_else(|| Code::Invalid.error("managed result call"))?;
                if receipt.results.get(&record.call).is_none_or(|reference| {
                    reference.result_id != self.id || reference.commit_revision != self.revision
                }) || record.context.target != declaration.target
                    || record.context.artifact != declaration.artifact
                    || record.context.context.id != name
                    || record.context.context.time_utc_ns != attempt.request.time_utc_ns as i64
                    || record.context.context.seed != attempt.request.seed
                {
                    return Err(Code::Invalid.error("managed result call receipt"));
                }
            }
            ResultBody::Selected(_) if receipt.selected.result_id != self.id => {
                return Err(Code::Invalid.error("managed selected receipt"));
            }
            ResultBody::Selected(_) => {}
        }
        Ok(())
    }
}

impl DataView {
    pub(super) fn result_owner(
        &self,
        tenant: [u8; 16],
        name: &str,
        control: &AnalysisReadControl,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<(u64, StoredResult, ManagedAttempt)> {
        control.check()?;
        let (id, result) = StoredResult::read(
            tenant,
            name,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            charge,
        )?
        .ok_or_else(|| Code::Missing.error("managed result"))?;
        let (instance, attempt) = result.owner();
        let owner = self
            .managed_attempt(tenant, instance, attempt, control)?
            .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
        result.check(&owner.0, &owner.1.spec)?;
        control.check()?;
        Ok((id, result, owner))
    }

    pub(super) fn result_checkpoint(
        &self,
        id: u64,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<sdk::wire::Checkpoint>> {
        let bytes = Records::charged_payload(
            &Records::key(b'U', id),
            |key| Records::read(key, &self.snapshot),
            charge,
        )?
        .ok_or_else(|| Code::Missing.error("managed checkpoint"))?;
        Records::decode(&bytes)
    }
}

impl DataWrite<'_> {
    pub(super) fn stage_result(&mut self, result: &StoredResult) -> Result<u64> {
        if result.revision != self.revision {
            return Err(Code::Invalid.error("managed result revision"));
        }
        let (instance, name) = result.owner();
        let (_, attempt) = Attempts::read(result.tenant, instance, name, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed result attempt"))?;
        let owner = Records::find(&InstanceRecord::identity(result.tenant, instance)?, |key| {
            Records::staged(key, &self.transaction)
        })?
        .ok_or_else(|| Code::Missing.error("managed result instance"))?;
        let version = VersionRecord::read(
            owner,
            result.tenant,
            instance,
            attempt.capture.generation,
            self.revision,
            |key| Records::staged(key, &self.transaction),
        )?;
        result.check(&attempt, &version.spec)?;
        let identity = StoredResult::identity(result.tenant, &result.id)?;
        if Records::find(&identity, |key| Records::staged(key, &self.transaction))?.is_some() {
            return Err(Code::Conflict.error("immutable managed result"));
        }
        let id = Records::intern(&mut self.transaction, &identity)?;
        Records::stage(
            &mut self.transaction,
            Records::key(b'X', id),
            Records::named(&result)?,
        );
        self.dirty = true;
        Ok(id)
    }

    pub(super) fn stage_call(&mut self, tenant: [u8; 16], packet: Packet) -> Result<(u64, Record)> {
        let result = StoredResult {
            tenant,
            id: packet.id,
            revision: self.revision,
            body: ResultBody::Call(packet.record),
        };
        let id = self.stage_result(&result)?;
        Records::stage(
            &mut self.transaction,
            Records::key(b'U', id),
            [vec![0], packet.checkpoint].concat(),
        );
        match result.body {
            ResultBody::Call(record) => Ok((id, record)),
            ResultBody::Selected(_) => Err(Code::Invalid.error("managed call body")),
        }
    }
}
