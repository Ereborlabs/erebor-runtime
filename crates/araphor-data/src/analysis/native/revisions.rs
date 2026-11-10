use snafu::ResultExt as _;

use super::{DataWrite, NativeStore};
use crate::{AnalysisReadControl, NativeStateSnafu, NativeStorageSnafu, Result};

impl NativeStore {
    fn relation_key(name: &str) -> Vec<u8> {
        [b"\0data/relation/".as_slice(), name.as_bytes()].concat()
    }

    pub(super) fn relation_revision(snapshot: &fjall::BranchSnapshot, name: &str) -> Result<u64> {
        snapshot
            .get(Self::relation_key(name))
            .context(NativeStorageSnafu {
                operation: "read relation revision",
            })?
            .map(|bytes| Self::number(&bytes))
            .transpose()
            .map(|revision| revision.unwrap_or(0))
    }
}

impl DataWrite<'_> {
    pub(super) fn note_relation(&mut self, name: &str, revision: u64) -> Result<()> {
        if revision > self.revision {
            return NativeStateSnafu {
                field: "relation revision",
            }
            .fail();
        }
        let key = NativeStore::relation_key(name);
        let previous = self
            .transaction
            .get(&key)
            .context(NativeStorageSnafu {
                operation: "read staged relation revision",
            })?
            .map(|bytes| NativeStore::number(&bytes))
            .transpose()?
            .unwrap_or(0);
        if revision > previous {
            self.transaction.insert(key, revision.to_be_bytes());
            self.dirty = true;
        }
        Ok(())
    }

    pub(super) fn sources_current(
        &self,
        sources: &[(String, u64)],
        control: &AnalysisReadControl,
    ) -> Result<bool> {
        for (name, captured) in sources {
            control.check()?;
            let saved = self
                .transaction
                .get(NativeStore::relation_key(name))
                .context(NativeStorageSnafu {
                    operation: "read current relation revision",
                })?
                .map(|bytes| NativeStore::number(&bytes))
                .transpose()?
                .unwrap_or(0);
            if saved > self.revision {
                return NativeStateSnafu {
                    field: "relation revision bound",
                }
                .fail();
            }
            let raw = match name.as_str() {
                "events" | "source_receipts" => self.raw.evidence_revision,
                "source_bindings" => self.raw.binding_revision,
                _ => 0,
            };
            if saved.max(raw) > *captured {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
