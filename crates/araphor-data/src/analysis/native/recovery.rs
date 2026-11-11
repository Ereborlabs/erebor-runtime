use std::sync::{atomic::Ordering, Arc};

use snafu::ResultExt as _;

use super::{capacity::RevisionCounts, NativeStore};
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

impl NativeStore {
    pub fn recover(&self) -> Result<()> {
        let _writer = self.writer.lock().map_err(|_| {
            NativeStateSnafu {
                field: "writer lock",
            }
            .build()
        })?;
        let _maintenance = self.maintenance.write().map_err(|_| {
            NativeStateSnafu {
                field: "maintenance lock",
            }
            .build()
        })?;
        self.poison();
        self.database
            .persist(fjall::PersistMode::SyncAll)
            .context(NativeStorageSnafu {
                operation: "check recovery engine durability",
            })?;
        let prior = self
            .published
            .read()
            .map(|view| Arc::clone(&view))
            .map_err(|_| {
                NativeStateSnafu {
                    field: "publication lock",
                }
                .build()
            })?;
        let snapshot = self.branch.snapshot().context(NativeStorageSnafu {
            operation: "capture recovery metadata",
        })?;
        let recovered = Self::decode_view(snapshot)?;
        if recovered.store_uuid != prior.store_uuid
            || recovered.schema_version != prior.schema_version
            || recovered.recovery_epoch != prior.recovery_epoch
            || recovered.metadata_revision != prior.metadata_revision
            || recovered.snapshot.revision() != prior.snapshot.revision()
        {
            return NativeStateSnafu {
                field: "changed metadata cut; reopen required",
            }
            .fail();
        }
        let mut live = self.raw.lock().map_err(|_| {
            NativeStateSnafu {
                field: "raw owner lock",
            }
            .build()
        })?;
        let mut raw = Self::recover_raw(
            &self.root,
            &prior.snapshot,
            &mut RevisionCounts::default(),
            Some(&prior.raw),
        )?;
        Self::restore_backlog(&mut raw, &prior.snapshot, self.retention)?;
        for (&revision, entry) in prior.raw.entries.iter() {
            let saved = raw.index.entries.get(&revision).ok_or_else(|| {
                NativeStateSnafu {
                    field: "accepted raw revision lost",
                }
                .build()
            })?;
            if saved.identity != entry.identity
                || saved.commit.kind != entry.commit.kind
                || saved.commit.revision != entry.commit.revision
                || saved.commit.intake != entry.commit.intake
                || saved.commit.spans != entry.commit.spans
                || saved.reference.id != entry.reference.id
                || saved.reference.offset != entry.reference.offset
                || saved.body_start != entry.body_start
                || saved.body_bytes != entry.body_bytes
                || saved.frame_bytes != entry.frame_bytes
            {
                return NativeStateSnafu {
                    field: "accepted raw metadata changed",
                }
                .fail();
            }
        }
        for (key, source) in prior.raw.sources.iter() {
            let saved = raw.index.sources.get(key).ok_or_else(|| {
                NativeStateSnafu {
                    field: "accepted source lost",
                }
                .build()
            })?;
            if saved.receipt.cursor() < source.receipt.cursor()
                || saved.receipt.floor() != source.receipt.floor()
                || saved.receipt.cpu() != source.receipt.cpu()
            {
                return NativeStateSnafu {
                    field: "accepted source progress lost",
                }
                .fail();
            }
        }
        for (id, segment) in &live.segments {
            if let Some(saved) = raw.segments.get_mut(id) {
                if saved.source != segment.source || saved.end < segment.end {
                    return NativeStateSnafu {
                        field: "accepted segment changed",
                    }
                    .fail();
                }
                saved.live = Arc::clone(&segment.live);
            }
        }
        let mut next = (*prior).clone();
        next.revision = prior.revision.max(raw.index.revision);
        next.raw = raw.index.clone();
        let revision = next.revision;
        *live = raw;
        *self.published.write().map_err(|_| {
            NativeStateSnafu {
                field: "publication lock",
            }
            .build()
        })? = Arc::new(next);
        self.ready.store(true, Ordering::Release);
        self.controls.send_replace(());
        self.revision.send_replace(revision);
        Ok(())
    }
}
