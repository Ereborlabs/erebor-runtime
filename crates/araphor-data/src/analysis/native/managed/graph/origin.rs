use serde::{Deserialize, Serialize};

use super::super::{
    results::{ResultBody, StoredResult},
    Records,
};
use crate::analysis::{
    native::{DataView, DataWrite},
    PackageResultRefV1,
};
use crate::{PackageErrorCodeV1 as Code, PackageGrantV1, Result};

#[derive(Deserialize, PartialEq, Serialize)]
pub(in crate::analysis::native) struct GraphOrigin {
    pub graph: u64,
    pub writer: u64,
    pub layer: u64,
    pub call: u64,
    pub instance: String,
    pub reference: PackageResultRefV1,
    pub grant: PackageGrantV1,
    pub restricted: bool,
    pub reads: Vec<(u64, u64, PackageResultRefV1)>,
    pub(super) rows: Vec<super::transaction::ReadRow>,
    pub pending: std::collections::BTreeMap<u64, PackageResultRefV1>,
}

impl GraphOrigin {
    pub(super) fn key(writer: u64, revision: u64) -> Vec<u8> {
        [Records::key(b'O', writer), revision.to_be_bytes().to_vec()].concat()
    }

    fn check(&self, writer: u64, revision: u64, head: u64) -> Result<()> {
        self.grant.validate()?;
        if self.graph == 0
            || self.writer != writer
            || self.layer == 0
            || self.instance.is_empty()
            || self.reference.result_id.is_empty()
            || self.reference.commit_revision != revision
            || revision == 0
            || revision > head
        {
            return Err(Code::Invalid.error("managed Graph origin"));
        }
        Ok(())
    }
}

impl DataView {
    pub(in crate::analysis::native) fn graph_origin(
        &self,
        writer: u64,
        revision: u64,
    ) -> Result<GraphOrigin> {
        self.graph_origin_charged(writer, revision, &mut |_| Ok(()))
    }

    pub(in crate::analysis::native) fn graph_origin_charged(
        &self,
        writer: u64,
        revision: u64,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<GraphOrigin> {
        let bytes = Records::charged_payload(
            &GraphOrigin::key(writer, revision),
            |key| Records::read(key, &self.snapshot),
            charge,
        )?
        .ok_or_else(|| Code::Missing.error("managed Graph origin"))?;
        let origin: GraphOrigin = Records::decode(&bytes)?;
        origin.check(writer, revision, self.metadata_revision)?;
        Ok(origin)
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native::managed) fn stage_origin(
        &mut self,
        origin: GraphOrigin,
    ) -> Result<()> {
        origin.check(origin.writer, self.revision, self.revision)?;
        let (_, result) = StoredResult::read(
            origin.grant.selection.tenant_id,
            &origin.reference.result_id,
            self.revision,
            |key| Records::staged(key, &self.transaction),
            &mut |_| Ok(()),
        )?
        .ok_or_else(|| Code::Missing.error("managed Graph origin result"))?;
        let ResultBody::Call(record) = &result.body else {
            return Err(Code::Invalid.error("managed Graph origin kind"));
        };
        if record.call != origin.call
            || record.instance != origin.instance
            || result.revision != self.revision
        {
            return Err(Code::Invalid.error("managed Graph origin call"));
        }
        let owner = Records::find(
            &super::super::InstanceRecord::identity(result.tenant, &origin.instance)?,
            |key| Records::staged(key, &self.transaction),
        )?
        .ok_or_else(|| Code::Missing.error("managed Graph origin owner"))?;
        let mapping =
            super::ManagedGraph::read(owner, |key| Records::staged(key, &self.transaction))?
                .ok_or_else(|| Code::Missing.error("managed Graph origin mapping"))?;
        if mapping.graph != origin.graph
            || mapping.writers.get(&origin.call) != Some(&origin.writer)
        {
            return Err(Code::Invalid.error("managed Graph origin writer"));
        }
        let key = GraphOrigin::key(origin.writer, self.revision);
        if Records::staged(&key, &self.transaction)?.is_some() {
            return Err(Code::Conflict.error("immutable Graph origin"));
        }
        Records::stage(&mut self.transaction, key, Records::named(&origin)?);
        self.dirty = true;
        Ok(())
    }
}
