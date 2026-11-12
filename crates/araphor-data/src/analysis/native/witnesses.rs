use std::collections::BTreeSet;

use snafu::ResultExt as _;

use super::{
    context::ContextRecord,
    managed::{RawPin, References},
    records::Records,
    NativeStore,
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
            let pin = RawPin::decode(&key, &value)?;
            if pin.expires <= now {
                continue;
            }
            let id = pin.segment;
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
            for (first, last) in pin.ranges {
                let mut cursor = first;
                loop {
                    let (entry, slot) = raw.locate(&segment.source, cursor, revision)?;
                    if entry.reference.id != id {
                        return NativeStateSnafu {
                            field: "witness segment identity",
                        }
                        .fail();
                    }
                    let end = entry.commit.spans[slot].last;
                    if end >= last {
                        break;
                    }
                    cursor = end.checked_add(1).ok_or_else(|| {
                        NativeStateSnafu {
                            field: "witness range bounds",
                        }
                        .build()
                    })?;
                }
                if exact {
                    records.extend((first..=last).map(|cursor| (id, cursor)));
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};

    #[test]
    fn usage_releases_locks() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path().join("analysis"))?;
        store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "p".into(),
                entity_key: vec![1],
                lifetime_key: vec![1],
                owner_revision: 1,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![1],
        })?;
        assert_eq!(store.witness_usage([1; 16], 201)?.charged_bytes, 0);
        assert!(store.writer.try_lock().is_ok());
        assert!(store.raw.try_lock().is_ok());
        assert!(store.maintenance.try_write().is_ok());
        Ok(())
    }
}
