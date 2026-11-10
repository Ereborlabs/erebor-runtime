use std::collections::BTreeSet;

use snafu::ResultExt as _;

use super::{
    context::ContextRecord, managed::References, records::Records, DataWrite, NativeStore,
};
use crate::analysis::raw::{RawIdentity, RawJournal};
use crate::{NativeStateSnafu, NativeStorageSnafu, Result, WitnessUsageV1};

struct Witnesses {
    usage: WitnessUsageV1,
    records: BTreeSet<(u64, u64)>,
}

impl Witnesses {
    fn read(
        raw: &RawJournal,
        tenant: [u8; 16],
        now: u64,
        revision: u64,
        exact: bool,
        references: (fjall::BranchIterator, fjall::BranchIterator),
        mut get: impl FnMut(&[u8]) -> Result<Option<fjall::Slice>>,
    ) -> Result<Self> {
        let mut usage = WitnessUsageV1 {
            read_revision: revision,
            referenced_bytes: 0,
            segment_bytes: 0,
            extra_segment_bytes: 0,
            context_bytes: 0,
            charged_bytes: 0,
        };
        let mut segments = BTreeSet::new();
        let mut records = BTreeSet::new();
        for entry in references.0 {
            let (key, value) = entry.context(NativeStorageSnafu {
                operation: "read witness references",
            })?;
            if key.len() != References::RAW.len() + 16 || value.len() != 24 {
                return NativeStateSnafu {
                    field: "witness reference",
                }
                .fail();
            }
            if NativeStore::number(&value[8..16])? <= now {
                continue;
            }
            let id = NativeStore::number(&value[..8])?;
            let segment = raw.segments.get(&id).ok_or_else(|| {
                NativeStateSnafu {
                    field: "live witness segment",
                }
                .build()
            })?;
            if !RawIdentity::valid_key(&segment.source) {
                return NativeStateSnafu {
                    field: "witness source",
                }
                .fail();
            }
            if segment.source[1..17] != tenant {
                continue;
            }
            if segments.insert(id) {
                usage.segment_bytes =
                    usage
                        .segment_bytes
                        .checked_add(segment.end)
                        .ok_or_else(|| {
                            NativeStateSnafu {
                                field: "witness segment total",
                            }
                            .build()
                        })?;
            }
            if exact {
                records.insert((id, NativeStore::number(&value[16..])?));
            }
        }
        let mut contexts = BTreeSet::new();
        for entry in references.1 {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read referenced contexts",
            })?;
            if key.len() != References::CONTEXT_OWNER.len() + 16 {
                return NativeStateSnafu {
                    field: "referenced context key",
                }
                .fail();
            }
            let id = NativeStore::number(&key[References::CONTEXT_OWNER.len()..key.len() - 8])?;
            if !contexts.insert(id) {
                continue;
            }
            let row = ContextRecord::load(id, &mut get)?;
            if row.version.key.tenant_id != tenant {
                continue;
            }
            usage.context_bytes = [
                row.version.body.len(),
                row.version.key.owner_id.len(),
                row.version.key.entity_key.len(),
                row.version.key.lifetime_key.len(),
            ]
            .into_iter()
            .try_fold(usage.context_bytes, |total, bytes| {
                total.checked_add(bytes as u64)
            })
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "witness context total",
                }
                .build()
            })?;
        }
        usage.charged_bytes = usage
            .segment_bytes
            .checked_add(usage.context_bytes)
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "witness byte total",
                }
                .build()
            })?;
        Ok(Self { usage, records })
    }

    fn exact(mut self, raw: &RawJournal) -> Result<WitnessUsageV1> {
        let mut cached = None;
        for (id, cursor) in self.records {
            let source = &raw.segments[&id].source;
            let (entry, slot) = raw.locate(source, cursor, self.usage.read_revision)?;
            if entry.reference.id != id {
                return NativeStateSnafu {
                    field: "witness segment identity",
                }
                .fail();
            }
            if cached
                .as_ref()
                .is_none_or(|(revision, _)| *revision != entry.commit.revision)
            {
                cached = Some((entry.commit.revision, raw.read_entry(entry)?));
            }
            let span = &cached
                .as_ref()
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "witness original batch",
                    }
                    .build()
                })?
                .1
                .spans[slot];
            let index = (cursor - span.first) as usize;
            let start = index.checked_sub(1).map_or(0, |prior| span.ends[prior]);
            self.usage.referenced_bytes = self
                .usage
                .referenced_bytes
                .checked_add(u64::from(span.ends[index] - start))
                .ok_or_else(|| {
                    NativeStateSnafu {
                        field: "witness record total",
                    }
                    .build()
                })?;
        }
        self.usage.extra_segment_bytes = self
            .usage
            .segment_bytes
            .checked_sub(self.usage.referenced_bytes)
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "witness frame total",
                }
                .build()
            })?;
        Ok(self.usage)
    }
}

impl NativeStore {
    pub(in crate::analysis::native) fn check_append_witnesses(
        &self,
        view: &super::DataView,
        raw: &RawJournal,
        tenant: [u8; 16],
        now: u64,
        id: u64,
        added: u64,
    ) -> Result<()> {
        if self.storage.witness_max_bytes.is_none() {
            return Ok(());
        }
        let prefix = [References::SEGMENT, &id.to_be_bytes()].concat();
        let mut pinned = false;
        for entry in view.snapshot.prefix(prefix) {
            let (_, value) = entry.context(NativeStorageSnafu {
                operation: "read growing segment pins",
            })?;
            if Self::number(&value)? > now {
                pinned = true;
                break;
            }
        }
        if !pinned {
            return Ok(());
        }
        let usage = Witnesses::read(
            raw,
            tenant,
            now,
            view.revision,
            false,
            (
                view.snapshot.prefix(References::RAW),
                view.snapshot.prefix(References::CONTEXT_OWNER),
            ),
            |key| Records::read(key, &view.snapshot),
        )?;
        self.storage
            .check_witness(
                usage
                    .usage
                    .charged_bytes
                    .checked_add(added)
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "growing witness total",
                        }
                        .build()
                    })?,
            )
    }

    pub fn witness_usage(&self, tenant: [u8; 16], now: u64) -> Result<WitnessUsageV1> {
        if tenant == [0; 16] || now == 0 {
            return crate::Error::reject_path(
                &self.root,
                "the witness usage tenant or time is invalid",
            );
        }
        let _writer = self.writer.lock().map_err(|_| {
            NativeStateSnafu {
                field: "writer lock",
            }
            .build()
        })?;
        let view = self.view()?;
        let raw = self.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        Witnesses::read(
            &raw,
            tenant,
            now,
            view.revision,
            true,
            (
                view.snapshot.prefix(References::RAW),
                view.snapshot.prefix(References::CONTEXT_OWNER),
            ),
            |key| Records::read(key, &view.snapshot),
        )?
        .exact(&raw)
    }
}

impl DataWrite<'_> {
    pub(in crate::analysis::native) fn check_witnesses(
        &self,
        tenant: [u8; 16],
        now: u64,
    ) -> Result<()> {
        if self.store.storage.witness_max_bytes.is_none() {
            return Ok(());
        }
        let raw = self.store.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let usage = Witnesses::read(
            &raw,
            tenant,
            now,
            self.revision,
            false,
            (
                self.transaction.prefix(References::RAW),
                self.transaction.prefix(References::CONTEXT_OWNER),
            ),
            |key| Records::staged(key, &self.transaction),
        )?;
        self.store.storage.check_witness(usage.usage.charged_bytes)
    }
}
