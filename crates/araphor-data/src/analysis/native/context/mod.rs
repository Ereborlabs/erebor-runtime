use super::{records::Records, DataView, DataWrite, NativeStore};
use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, Result};

mod admission;
mod facts;
mod index;
mod pages;
mod record;
mod recovery;

pub(super) type ContextName = ([u8; 16], String, Vec<u8>, Vec<u8>);
pub(super) type ContextNames = rpds::RedBlackTreeMapSync<ContextName, u64>;

pub(in crate::analysis::native) use record::ContextRecord;

impl ContextRecord {
    pub(in crate::analysis::native) fn name(key: &AnalysisContextKeyV1) -> ContextName {
        (
            key.tenant_id,
            key.owner_id.clone(),
            key.entity_key.clone(),
            key.lifetime_key.clone(),
        )
    }
    fn load(id: u64, get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>) -> Result<Self> {
        let bytes = Records::payload(&Records::key(b'C', id), get)?.ok_or_else(|| {
            crate::NativeStateSnafu {
                field: "context index record",
            }
            .build()
        })?;
        let row: Self = Records::decode(&bytes)?;
        Self::check(&row, &row.version.key)?;
        Ok(row)
    }

    pub(in crate::analysis::native) fn id(
        key: &AnalysisContextKeyV1,
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Option<u64>> {
        Records::find(&Self::identity(key, true)?, get)
    }

    fn scope(input: &AnalysisContextVersionV1) -> Result<Vec<u8>> {
        use snafu::ResultExt as _;
        let key = &input.key;
        rmp_serde::to_vec(&(b'V', key.tenant_id, &key.owner_id, &key.lifetime_key))
            .context(crate::ManagedEncodingSnafu)
    }

    fn document(key: &AnalysisContextKeyV1) -> Result<Vec<u8>> {
        use snafu::ResultExt as _;
        rmp_serde::to_vec(&(b'M', key.tenant_id, &key.owner_id, &key.entity_key))
            .context(crate::ManagedEncodingSnafu)
    }
}

impl DataView {
    pub fn context(
        &self,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        if !key.valid() {
            return crate::NativeStateSnafu {
                field: "context lookup key",
            }
            .fail();
        }
        let Some(row) = self.context_row(key)? else {
            return Ok(None);
        };
        self.verify_context(&row.0)?;
        Ok(Some(row))
    }

    pub(in crate::analysis::native) fn verify_context(
        &self,
        input: &AnalysisContextVersionV1,
    ) -> Result<()> {
        crate::analysis::context::VerifiedPackages::default()
            .check_context(input, |tenant, package, revision| {
                self.package_revision(
                    tenant,
                    package,
                    revision,
                    &crate::AnalysisReadControl::default(),
                )
            })
            .map_err(crate::Error::stored_artifact)
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn check_context_ref(
        &mut self,
        reference: &crate::AnalysisContextRefV1,
    ) -> Result<bool> {
        let Some(id) = ContextRecord::id(&reference.key, |key| {
            Records::staged(key, &self.transaction)
        })?
        else {
            return Ok(false);
        };
        let row = ContextRecord::load(id, |key| Records::staged(key, &self.transaction))?;
        ContextRecord::check(&row, &reference.key)?;
        self.verify_context(&row.version)
            .map_err(crate::Error::stored_artifact)?;
        Ok(row.revision == reference.commit_revision)
    }
}
