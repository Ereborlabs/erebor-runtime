use std::sync::Arc;



use super::{version_key, AnalysisContextVersionV1};
use crate :: { PackageErrorCodeV1 as Code , Result } ;

pub(in crate::analysis) struct PreparedFact {
    source: Arc<crate::ManagedDerivedSource>,
    ordinal: usize,
    version: Vec<u8>,
    record: super::facts::FactRecord,
    _memory: Box<dyn std::any::Any + Send + Sync>,
}

impl PreparedFact {
    pub(in crate::analysis) fn new(
        source: Arc<crate::ManagedDerivedSource>,
        ordinal: usize,
        reserve: &mut impl FnMut(usize) -> Result<Box<dyn std::any::Any + Send + Sync>>,
    ) -> Result<Self> {
        let value = &source.context_values()[ordinal];
        let _scratch = reserve(
            value
                .body
                .len()
                .checked_mul(8)
                .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<crate::GraphFactV1>()))
                .ok_or_else(|| Code::Limit.error("derived fact decode memory"))?,
        )?;
        let memory = reserve(
            value
                .key
                .allocated_bytes()
                .checked_add(std::mem::size_of_val(&value.key))
                .and_then(|bytes| bytes.checked_mul(16))
                .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<Self>()))
                .ok_or_else(|| Code::Limit.error("derived fact preparation memory"))?,
        )?;
        if !value.valid() {
            return Err(Code::Invalid.error("derived context identity"));
        }
        let record = super::facts::FactRecord::from_context(value)?
            .ok_or_else(|| Code::Invalid.error("derived fact context"))?;
        let version = version_key(&value.key)?;
        Ok(Self {
            source,
            ordinal,
            version,
            record,
            _memory: memory,
        })
    }
    pub(in crate::analysis) fn value(&self) -> &AnalysisContextVersionV1 {
        &self.source.context_values()[self.ordinal]
    }
}


