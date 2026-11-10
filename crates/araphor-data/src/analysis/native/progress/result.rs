use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::*;
use crate::{AnalysisProcessorResultV1, AnalysisResultCommitV1};

#[derive(Deserialize, Serialize)]
pub(in crate::analysis::native) struct ResultRecord {
    pub revision: u64,
    pub request: AnalysisResultCommitV1,
    pub producer: Option<PackageResultRefV1>,
    pub header: crate::analysis::progress::ProfileHeader,
    pub body_bytes: u64,
}

impl ResultRecord {
    pub(in crate::analysis::native) const PREFIX: &'static [u8] = b"\0data/@progress/result/";
    pub(in crate::analysis::native) const BODY: &'static [u8] = b"\0data/@progress/body/";

    pub(in crate::analysis::native) fn identity(name: &str) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(b"result".as_slice(), name)).context(crate::ManagedEncodingSnafu)
    }

    pub(in crate::analysis::native) fn read(
        name: &str,
        head: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(u64, Self)>> {
        let Some((id, mut result)) = Self::read_header(name, head, &mut get, charge)? else {
            return Ok(None);
        };
        result.request.body = result.body(id, get, charge)?;
        Ok(Some((id, result)))
    }

    pub(in crate::analysis::native) fn body(
        &self,
        id: u64,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let bytes = Records::charged_payload(&Processor::key(Self::BODY, id), get, charge)?
            .ok_or_else(|| Code::Missing.error("processor result body"))?;
        if bytes.len() as u64 != self.body_bytes {
            return Err(Code::Invalid.error("processor result body length"));
        }
        Ok(bytes)
    }

    pub(in crate::analysis::native) fn read_header(
        name: &str,
        head: u64,
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Option<(u64, Self)>> {
        let Some(id) = Records::find(&Self::identity(name)?, &mut get)? else {
            return Ok(None);
        };
        let Some(bytes) = Records::charged_payload(&Processor::key(Self::PREFIX, id), get, charge)?
        else {
            return Ok(None);
        };
        let result: Self = Records::decode(&bytes)?;
        if result.request.result_id != name
            || result.revision == 0
            || result.revision > head
            || !result.request.body.is_empty()
            || result.body_bytes == 0
            || !result.request.scope.valid()
        {
            return Err(Code::Invalid.error("processor result identity"));
        }
        Ok(Some((id, result)))
    }
}

impl NativeStore {
    pub fn discovery_producer(
        &self,
        selection: &crate::AnalysisSelectionV1,
        profile: &crate::DiscoveryProfileV1,
        control: &AnalysisReadControl,
    ) -> Result<crate::analysis::DiscoveryProducer> {
        control.check()?;
        profile.validate()?;
        let source = &profile.scope.identity;
        if source.tenant_id != selection.tenant_id
            || !selection.sources.is_all() && !selection.sources.as_slice().contains(source)
            || !selection.nodes.is_empty() && !selection.nodes.contains(&source.node_id)
        {
            return Err(Code::Denied.error("discovery producer scope"));
        }
        let view = self.view()?;
        let (_, result) = ResultRecord::read(
            &profile.profile_id,
            view.metadata_revision,
            |key| Records::read(key, &view.snapshot),
            &mut |_| control.check(),
        )?
        .ok_or_else(|| Code::Missing.error("discovery producer profile"))?;
        if crate::DiscoveryProfileV1::try_from(result.request.body.as_slice())? != *profile {
            return Err(Code::Conflict.error("discovery retained profile"));
        }
        let producer =
            view.profile_producer(selection, profile, &result, &mut |_| control.check())?;
        control.check()?;
        Ok(producer)
    }

    pub fn processor_result(
        &self,
        scope: &ProcessorScopeV1,
    ) -> Result<Option<AnalysisProcessorResultV1>> {
        self.view()?.processor_result(scope)
    }

    pub fn read_result(&self, tenant: [u8; 16], name: &str) -> Result<Option<Vec<u8>>> {
        self.view()?.read_result(tenant, name)
    }
}

impl DataView {
    pub(in crate::analysis::native) fn profile_producer(
        &self,
        selection: &crate::AnalysisSelectionV1,
        profile: &crate::DiscoveryProfileV1,
        stored: &ResultRecord,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<crate::analysis::DiscoveryProducer> {
        let source = &profile.scope.identity;
        if source.tenant_id != selection.tenant_id
            || !selection.sources.is_all() && !selection.sources.as_slice().contains(source)
            || !selection.nodes.is_empty() && !selection.nodes.contains(&source.node_id)
        {
            return Err(Code::Denied.error("discovery producer scope"));
        }
        if stored.revision == 0
            || stored.revision > self.metadata_revision
            || stored.request.scope != profile.scope
            || stored.request.result_id != profile.profile_id
        {
            return Err(Code::Conflict.error("discovery retained profile"));
        }
        let reference = stored
            .producer
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("discovery producer edge"))?;
        if reference.commit_revision > stored.revision {
            return Err(Code::Invalid.error("discovery producer revision"));
        }
        let producer = self.profile_call(selection, reference, charge)?;
        if !matches!(&producer.spec.destination, crate::ManagedDestination::DiscoveryProfile { source: owned, call, .. } if owned == source && *call == producer.call)
        {
            return Err(Code::Invalid.error("discovery producer destination"));
        }
        Ok(producer)
    }

    pub fn processor_result(
        &self,
        scope: &ProcessorScopeV1,
    ) -> Result<Option<AnalysisProcessorResultV1>> {
        if !scope.valid() {
            return Err(Code::Invalid.error("processor scope"));
        }
        let Some((_, state)) = Processor::read(
            scope,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            &mut |_| Ok(()),
        )?
        else {
            return Ok(None);
        };
        let Some(head) = state.head else {
            return Ok(None);
        };
        let (_, result) = ResultRecord::read(
            &head.result_id,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            &mut |_| Ok(()),
        )?
        .ok_or_else(|| Code::Missing.error("processor head result"))?;
        if result.revision != head.commit_revision || result.request.scope != *scope {
            return Err(Code::Invalid.error("processor head result"));
        }
        Ok(Some(AnalysisProcessorResultV1 {
            result_id: head.result_id,
            body: result.request.body,
            commit_revision: result.revision,
        }))
    }

    pub fn read_result(&self, tenant: [u8; 16], name: &str) -> Result<Option<Vec<u8>>> {
        if tenant == [0; 16] || name.is_empty() {
            return Err(Code::Invalid.error("processor result identity"));
        }
        let Some((id, result)) = ResultRecord::read_header(
            name,
            self.metadata_revision,
            |key| Records::read(key, &self.snapshot),
            &mut |_| Ok(()),
        )?
        .filter(|(_, result)| result.request.scope.identity.tenant_id == tenant) else {
            return Ok(None);
        };
        Ok(Some(result.body(
            id,
            |key| Records::read(key, &self.snapshot),
            &mut |_| Ok(()),
        )?))
    }
}
