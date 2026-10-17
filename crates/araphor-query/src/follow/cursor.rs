use std::hash::{Hash, Hasher};

use araphor_data::{
    AnalysisSelectionV1, AnalysisStoreMetaV1, AnalysisTableRequests, StorePositionV1,
};
use datafusion::logical_expr::LogicalPlan;
use serde::{Deserialize, Serialize};

use super::Operation;
use crate::stream::physical::Fingerprint;
use crate::{InvalidSnafu, Result};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    version: u8,
    store: [u8; 16],
    schema: u32,
    epoch: u64,
    operation: Operation,
    binding: [u8; 32],
    position: StorePositionV1,
    revision: u64,
    evaluated: u64,
}

impl Cursor {
    const BYTES: usize = 1024;

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = araphor_analysis_sdk::wire::BoundedBuffer::new(Self::BYTES as u64);
        serde_json::to_writer(&mut buffer, self).map_err(|_| {
            InvalidSnafu {
                field: "cursor encoding",
            }
            .build()
        })?;
        Ok(buffer.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > Self::BYTES {
            return InvalidSnafu {
                field: "cursor size",
            }
            .fail();
        }
        let cursor: Self = serde_json::from_slice(bytes).map_err(|_| {
            InvalidSnafu {
                field: "cursor encoding",
            }
            .build()
        })?;
        if cursor.version != 1 || cursor.position.commit_revision > cursor.revision {
            return InvalidSnafu {
                field: "cursor fields",
            }
            .fail();
        }
        Ok(cursor)
    }

    pub fn position(&self) -> StorePositionV1 {
        self.position
    }
    pub fn read_revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn new(
        meta: &AnalysisStoreMetaV1,
        operation: Operation,
        binding: [u8; 32],
        position: StorePositionV1,
        evaluated: u64,
    ) -> Self {
        Self {
            version: 1,
            store: *meta.store_uuid.as_bytes(),
            schema: meta.schema_version,
            epoch: meta.recovery_epoch,
            operation,
            binding,
            position,
            revision: meta.commit_revision,
            evaluated,
        }
    }

    pub(super) fn check_binding(&self, binding: &[u8; 32], operation: Operation) -> Result<()> {
        if &self.binding != binding || self.operation != operation {
            return InvalidSnafu {
                field: "cursor binding",
            }
            .fail();
        }
        Ok(())
    }

    pub(crate) fn check_store(&self, meta: &AnalysisStoreMetaV1) -> Result<()> {
        if self.store != *meta.store_uuid.as_bytes()
            || self.schema != meta.schema_version
            || self.epoch != meta.recovery_epoch
            || self.revision > meta.commit_revision
        {
            return InvalidSnafu {
                field: "cursor store",
            }
            .fail();
        }
        Ok(())
    }
}

impl Fingerprint {
    pub(super) fn binding(
        plan: &LogicalPlan,
        sources: &AnalysisTableRequests,
        selection: &AnalysisSelectionV1,
        operation: Operation,
        caller: &[u8],
    ) -> Result<[u8; 32]> {
        let mut hash = Self::new();
        Hasher::write(&mut hash, b"araphor-query.follow.v1\0");
        plan.hash(&mut hash);
        sources.len().hash(&mut hash);
        for name in sources.keys() {
            name.hash(&mut hash);
        }
        operation.hash(&mut hash);
        caller.hash(&mut hash);
        serde_json::to_writer(&mut hash, selection).map_err(|_| {
            InvalidSnafu {
                field: "cursor scope",
            }
            .build()
        })?;
        Ok(hash.finish_digest())
    }
}
