use snafu::ResultExt as _;

use super::{Coordinator, InputRecord, Scan};
use crate::analysis::{
    inputs::InputChange,
    native::{DataView, NativeStore},
};
use crate::{NativeStorageSnafu, Result, StorePositionV1};

impl Coordinator {
    pub(super) fn records(
        &self,
        batch: &fjall::cdc::Batch,
        bound: &DataView,
        scan: &mut Scan,
    ) -> Result<()> {
        for item in &batch.items {
            if item.branch == Some(self.branch.id()) && item.key.starts_with(InputRecord::PREFIX) {
                self.refresh(scan, &item.key, bound)?;
            }
            if item.branch == Some(self.branch.id())
                && item.key.starts_with(b"\0data/J")
                && item.key.len() == 15
            {
                let owner = NativeStore::number(&item.key[7..])?;
                let keys = scan
                    .consumers
                    .range((owner, 0)..=(owner, u64::MAX))
                    .map(|(key, _)| *key)
                    .collect::<Vec<_>>();
                for (owner, generation) in keys {
                    self.refresh(scan, &InputRecord::key(owner, generation), bound)?;
                }
            }
        }
        let items = || {
            batch
                .items
                .iter()
                .filter(|item| item.branch == Some(self.branch.id()))
        };
        let coordinator = items().any(|item| item.key.starts_with(InputRecord::PREFIX))
            && items().all(|item| Self::checkpoint_key(&item.key));
        if !coordinator {
            if let Some(head) = items().find(|item| item.key.as_ref() == super::super::HEAD) {
                if let Some(value) = &head.value {
                    scan.last_real = scan.last_real.max(NativeStore::number(value)?);
                }
            }
        }
        let mut candidates = batch
            .items
            .iter()
            .filter(|item| {
                item.branch == Some(self.branch.id())
                    && item.value.is_some()
                    && (DataView::input_context_key(&item.key)
                        || DataView::input_coverage_key(&item.key)
                        || DataView::input_graph_key(&item.key)
                        || DataView::input_progress_key(&item.key)
                        || self.activations.receiver_count() != 0
                            && item.key.starts_with(b"\0data/J")
                            && item.key.len() == 15)
            })
            .peekable();
        if candidates.peek().is_none() {
            return Ok(());
        }
        let Some(head) = batch.items.iter().find(|item| {
            item.branch == Some(self.branch.id()) && item.key.as_ref() == super::super::HEAD
        }) else {
            return Ok(());
        };
        let revision = head
            .value
            .as_deref()
            .map(NativeStore::number)
            .transpose()?
            .ok_or_else(|| {
                crate::NativeStateSnafu {
                    field: "input Data head deletion",
                }
                .build()
            })?;
        if revision > bound.revision {
            return crate::NativeStateSnafu {
                field: "input Data revision bound",
            }
            .fail();
        }
        let snapshot = self
            .branch
            .read_at(batch.revision())
            .context(NativeStorageSnafu {
                operation: "capture input transaction",
            })?;
        let view = NativeStore::decode_view(snapshot)?;
        let position = StorePositionV1 {
            commit_revision: revision,
            ordinal: u32::MAX,
        };
        for item in candidates {
            if item.key.starts_with(b"\0data/J") {
                if view.input_activation(&item.key, revision)? {
                    self.activations.send_if_modified(|current| {
                        if position > *current {
                            *current = position;
                            true
                        } else {
                            false
                        }
                    });
                }
            } else if let Some(reference) = view.input_context(&item.key)? {
                self.readers
                    .publish(position, InputChange::Context(&reference.key));
            } else if let Some(reference) = view.input_coverage(&item.key)? {
                let identity = reference.source.into();
                self.readers.publish(
                    position,
                    InputChange::Raw {
                        identity: &identity,
                        range: None,
                    },
                );
            } else if DataView::input_progress_key(&item.key) {
                view.input_progress(&item.key, &self.readers, position)?;
            } else {
                view.input_graph(&item.key, &self.readers, position)?;
            }
        }
        Ok(())
    }

    fn checkpoint_key(key: &[u8]) -> bool {
        key.starts_with(InputRecord::PREFIX)
            || key == super::super::HEAD
            || key.starts_with(b"\0data/cut/")
            || key.starts_with(b"\0data/source/")
            || key.starts_with(b"\0data/epoch/")
            || key.starts_with(b"\0data/raw/end/")
            || key == b"\0data/raw/next"
            || ["events", "source_receipts", "source_bindings"]
                .iter()
                .any(|name| key == NativeStore::relation_key(name))
    }
}
