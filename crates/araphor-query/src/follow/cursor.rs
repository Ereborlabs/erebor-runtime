use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

use araphor_data::{
    AnalysisSelectionV1, AnalysisStoreMetaV1, AnalysisTableRequests, StorePositionV1,
};
use datafusion::logical_expr::LogicalPlan;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{Operation, Window, WindowRange, WindowSource};
use crate::stream::physical::Fingerprint;
use crate::{InvalidSnafu, Result, SqlSnafu};

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
    pub(crate) windows: Vec<WindowRange>,
    pub(crate) completed_windows: Vec<WindowRange>,
}

impl Cursor {
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| {
            InvalidSnafu {
                field: "cursor encoding",
            }
            .build()
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
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
        cursor.check_fields()?;
        Ok(cursor)
    }

    fn check_fields(&self) -> Result<()> {
        let mut sources = BTreeSet::new();
        let mut completed = BTreeSet::new();
        if self.version != 1
            || self.position.commit_revision > self.revision
            || self.windows.iter().any(|window| {
                !window.active
                    || window.start_utc_ns >= window.end_utc_ns
                    || window.end_utc_ns <= 0
                    || !sources.insert(window.source)
            })
            || self.completed_windows.iter().any(|window| {
                !window.active
                    || !completed.insert(window.source)
                    || self
                        .completed_windows
                        .first()
                        .is_none_or(|first| window.end_utc_ns != first.end_utc_ns)
                    || !self.windows.iter().any(|saved| window.same_interval(saved))
            })
        {
            return InvalidSnafu {
                field: "cursor fields",
            }
            .fail();
        }
        Ok(())
    }

    pub fn position(&self) -> StorePositionV1 {
        self.position
    }
    pub fn read_revision(&self) -> u64 {
        self.revision
    }
    pub(super) fn set_revision(&mut self, revision: u64) {
        self.revision = self.revision.max(revision);
    }
    pub(crate) fn evaluated(&self) -> u64 {
        self.evaluated
    }

    pub(crate) fn new(
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
            windows: Vec::new(),
            completed_windows: Vec::new(),
        }
    }

    pub(crate) fn set_windows(&mut self, windows: &[WindowRange], completed: &[WindowRange]) {
        self.windows = windows
            .iter()
            .filter(|window| window.active)
            .chain(completed)
            .copied()
            .collect();
        self.windows.sort_by_key(|window| window.source);
        self.windows
            .dedup_by(|next, previous| next.same_interval(previous));
        self.completed_windows = completed.to_vec();
    }

    pub(crate) fn check_windows(&self, plan: &LogicalPlan, query: Option<&Window>) -> Result<()> {
        for saved in &self.windows {
            let now = saved
                .end_utc_ns
                .checked_sub(1)
                .and_then(|now| u64::try_from(now).ok())
                .ok_or_else(|| {
                    InvalidSnafu {
                        field: "cursor window",
                    }
                    .build()
                })?;
            let expected = match saved.source {
                WindowSource::Query => query
                    .map(|window| window.fixed_range(now))
                    .transpose()
                    .context(SqlSnafu)?
                    .flatten(),
                WindowSource::Input { call, slot } => {
                    let mut expected = None;
                    crate::definition::PackageCall::any(plan, &mut |candidate| {
                        if candidate.id == call {
                            expected = candidate
                                .input_scope
                                .window(slot)
                                .flatten()
                                .map(|window| window.fixed_range(now))
                                .transpose()?
                                .flatten();
                            return Ok(true);
                        }
                        Ok(false)
                    })
                    .context(SqlSnafu)?;
                    expected
                }
            };
            if expected != Some((saved.start_utc_ns, saved.end_utc_ns)) {
                return InvalidSnafu {
                    field: "cursor window",
                }
                .fail();
            }
        }
        Ok(())
    }

    pub(super) fn check_binding(&self, binding: &[u8; 32], operation: Operation) -> Result<()> {
        self.check_fields()?;
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
