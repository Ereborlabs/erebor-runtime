use fjall::{HistoryPolicy, RetentionId, Revision};
use snafu::ResultExt as _;

use super::{DataView, NativeStore, HISTORY};
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

impl NativeStore {
    fn history_policy(&self, view: &DataView) -> Result<Option<HistoryPolicy>> {
        let Some(bytes) = view.snapshot.get(HISTORY).context(NativeStorageSnafu {
            operation: "read owned history policy",
        })?
        else {
            return Ok(None);
        };
        let id = RetentionId::from_bytes(bytes.as_ref().try_into().map_err(|_| {
            NativeStateSnafu {
                field: "history policy width",
            }
            .build()
        })?);
        let policy = self
            .database
            .history()
            .context(NativeStorageSnafu {
                operation: "read owned history protection",
            })?
            .into_iter()
            .find(|policy| policy.id == id)
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "required history protection",
                }
                .build()
            })?;
        if policy.branch != self.branch.id() || policy.last.to_bytes() != u64::MAX.to_be_bytes() {
            return NativeStateSnafu {
                field: "required history protection",
            }
            .fail();
        }
        Ok(Some(policy))
    }

    fn history_bound(&self, view: &DataView) -> Result<Revision> {
        let mut bound = view.revision;
        if let Some((_, entry)) = view.raw.entries.iter().find(|(_, entry)| {
            view.raw
                .expired
                .get(&entry.reference.id)
                .is_none_or(|expired| expired.revision > view.metadata_revision)
        }) {
            bound = bound.min(entry.commit.revision);
        }
        for prefix in [b"\0data/Z".as_slice(), b"\0data/D"] {
            for row in view.snapshot.prefix(prefix) {
                let (key, _) = row.context(NativeStorageSnafu {
                    operation: "read retained history generations",
                })?;
                if key.len() == 31 {
                    continue;
                }
                if key.len() != 23 {
                    return NativeStateSnafu {
                        field: "history version key",
                    }
                    .fail();
                }
                let revision = Self::number(&key[15..])?;
                if revision == 0 || revision > view.metadata_revision {
                    return NativeStateSnafu {
                        field: "history version revision",
                    }
                    .fail();
                }
                bound = bound.min(revision);
            }
        }
        bound = view.context_bound(bound)?;
        bound = view.package_bound(bound)?;
        bound = self.processor_bound(view, bound)?;
        bound = view.trace_bound(bound)?;
        bound = view.coverage_bound(bound)?;
        bound = view.recovery_bound(bound)?;
        Ok(Self::cut_at(&self.branch, view, bound)?.snapshot.revision())
    }

    pub(super) fn required_history(&self) -> Result<(Revision, Option<HistoryPolicy>)> {
        let view = self.view()?;
        let policy = self.history_policy(&view)?;
        let bound = self.history_bound(&view)?;
        if policy.as_ref().is_some_and(|policy| policy.first > bound) {
            return NativeStateSnafu {
                field: "required history protection",
            }
            .fail();
        }
        Ok((bound, policy))
    }

    pub(super) fn prepare_history(&self) -> Result<Option<RetentionId>> {
        let (bound, policy) = self.required_history()?;
        if policy.is_some() {
            return Ok(None);
        }
        self.branch
            .retain_history(bound..)
            .context(NativeStorageSnafu {
                operation: "retain owned Data history",
            })
            .map(Some)
    }

    pub(super) fn bind_history(&self) -> Result<()> {
        if let Some(id) = self.prepare_history()? {
            let mut tx = self.write()?;
            tx.native().insert(HISTORY, id.to_bytes());
            tx.commit([])?;
        }
        Ok(())
    }
}
