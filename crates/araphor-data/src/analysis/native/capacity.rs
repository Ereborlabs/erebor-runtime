use std::collections::BTreeMap;

use snafu::ResultExt as _;

use super::{records::Records, DataWrite, NativeStore};
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

#[derive(Default)]
pub(super) struct RevisionCounts(BTreeMap<[u8; 16], [u64; 3]>);

impl RevisionCounts {
    const PREFIX: &'static [u8] = b"\0data/@capacity/revisions/";

    fn key(tenant: [u8; 16]) -> Vec<u8> {
        [Self::PREFIX, &tenant].concat()
    }

    pub(super) fn add(&mut self, tenant: [u8; 16], kind: usize) -> Result<()> {
        for tenant in [[0; 16], tenant] {
            let counts = self.0.entry(tenant).or_default();
            counts[kind] = counts[kind].checked_add(1).ok_or_else(|| {
                NativeStateSnafu {
                    field: "retained revision count",
                }
                .build()
            })?;
        }
        Ok(())
    }

    fn read(
        tenant: [u8; 16],
        get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<[u64; 3]> {
        Ok(Records::payload(&Self::key(tenant), get)?
            .map(|bytes| Records::decode(&bytes))
            .transpose()?
            .unwrap_or_default())
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn count_revision(
        &mut self,
        tenant: [u8; 16],
        kind: usize,
    ) -> Result<()> {
        for tenant in [[0; 16], tenant] {
            let mut counts =
                RevisionCounts::read(tenant, |key| Records::staged(key, &self.transaction))?;
            counts[kind] = counts[kind].checked_add(1).ok_or_else(|| {
                NativeStateSnafu {
                    field: "retained revision count",
                }
                .build()
            })?;
            Records::stage(
                &mut self.transaction,
                RevisionCounts::key(tenant),
                Records::encode(&counts)?,
            );
        }
        Ok(())
    }
}

impl NativeStore {
    pub(super) fn validate_counts(&self, expected: RevisionCounts) -> Result<()> {
        let view = self.view()?;
        let mut expected = expected.0;
        for entry in view.snapshot.prefix(RevisionCounts::PREFIX) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "validate retained revision counts",
            })?;
            if key.len() != RevisionCounts::PREFIX.len() + 16 {
                return NativeStateSnafu {
                    field: "retained revision count key",
                }
                .fail();
            }
            let tenant = key[RevisionCounts::PREFIX.len()..]
                .try_into()
                .map_err(|_| {
                    NativeStateSnafu {
                        field: "retained revision count tenant",
                    }
                    .build()
                })?;
            let counts = RevisionCounts::read(tenant, |key| Records::read(key, &view.snapshot))?;
            if expected.remove(&tenant) != Some(counts) {
                return NativeStateSnafu {
                    field: "retained revision count",
                }
                .fail();
            }
        }
        if !expected.is_empty() {
            return NativeStateSnafu {
                field: "retained revision count",
            }
            .fail();
        }
        Ok(())
    }
}
