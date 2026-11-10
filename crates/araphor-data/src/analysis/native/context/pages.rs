use std::ops::Bound::{Excluded, Included, Unbounded};

use super::{ContextRecord, DataView, NativeStore, Records};
use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, NativeStateSnafu, Result};

impl NativeStore {
    pub fn context_version(
        &self,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<AnalysisContextVersionV1>> {
        Ok(self.view()?.context(key)?.map(|(context, _)| context))
    }

    pub fn context_head(
        &self,
        tenant: [u8; 16],
        owner: &str,
        entity: &[u8],
        lifetime: &[u8],
    ) -> Result<Option<AnalysisContextVersionV1>> {
        let key = AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: owner.into(),
            entity_key: entity.into(),
            lifetime_key: lifetime.into(),
            owner_revision: 0,
        };
        if !key.valid() {
            return NativeStateSnafu {
                field: "context head scope",
            }
            .fail();
        }
        let view = self.view()?;
        let name = ContextRecord::name(&key);
        let Some(base) = view.contexts.get(&name) else {
            return Ok(None);
        };
        Ok(view.head_context(&name, *base)?.map(|(context, _)| context))
    }

    pub fn context_heads(
        &self,
        tenant: [u8; 16],
        owner: &str,
        limit: usize,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        self.view()?.context_heads(tenant, owner, limit)
    }

    pub fn context_head_page(
        &self,
        tenant: [u8; 16],
        owner: &str,
        after: Option<&AnalysisContextKeyV1>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        self.view()?.context_head_page(tenant, owner, after)
    }
}

impl DataView {
    pub fn context_heads(
        &self,
        tenant: [u8; 16],
        owner: &str,
        limit: usize,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        self.context_heads_charged(tenant, owner, limit, &mut |_| Ok(()))
    }

    pub(in crate::analysis) fn context_heads_charged(
        &self,
        tenant: [u8; 16],
        owner: &str,
        limit: usize,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        self.head_versions(tenant, owner, None, limit, true, charge)
    }

    pub fn context_head_page(
        &self,
        tenant: [u8; 16],
        owner: &str,
        after: Option<&AnalysisContextKeyV1>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        self.head_versions(
            tenant,
            owner,
            after,
            crate::analysis::MAX_ANALYSIS_PAGE_RECORDS,
            false,
            &mut |_| Ok(()),
        )
    }

    fn head_versions(
        &self,
        tenant: [u8; 16],
        owner: &str,
        after: Option<&AnalysisContextKeyV1>,
        limit: usize,
        reject_excess: bool,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        if tenant == [0; 16]
            || owner.is_empty()
            || limit == 0
            || after
                .is_some_and(|key| !key.valid() || key.tenant_id != tenant || key.owner_id != owner)
        {
            return NativeStateSnafu {
                field: "context head page scope",
            }
            .fail();
        }
        let first = after.map_or_else(
            || Included((tenant, owner.into(), Vec::new(), Vec::new())),
            |key| Excluded(ContextRecord::name(key)),
        );
        let mut versions = Vec::new();
        for (name, base) in self.contexts.range((first, Unbounded)) {
            charge(0)?;
            if name.0 != tenant || name.1 != owner {
                break;
            }
            if versions.len() == limit {
                if !reject_excess {
                    break;
                }
                if Records::read(&Records::key(b'H', *base), &self.snapshot)?.is_some() {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "context heads",
                    }
                    .fail();
                }
                continue;
            }
            if let Some((context, _)) = self.head_context_charged(name, *base, charge)? {
                versions.push(context);
            }
        }
        Ok(versions)
    }
}
