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
        let evidence = items()
            .filter(|item| {
                item.key.starts_with(super::super::events::Events::PAYLOAD) && item.value.is_some()
            })
            .collect::<Vec<_>>();
        if !evidence.is_empty() {
            let head = items()
                .find(|item| item.key.as_ref() == super::super::HEAD)
                .and_then(|item| item.value.as_deref())
                .ok_or_else(|| {
                    crate::NativeStateSnafu {
                        field: "evidence input Data head",
                    }
                    .build()
                })?;
            let revision = NativeStore::number(head)?;
            if revision > bound.metadata_revision {
                return crate::NativeStateSnafu {
                    field: "evidence input Data cut",
                }
                .fail();
            }
            let position = super::super::events::Events::position(
                super::super::events::Events::POSITION,
                revision,
            );
            let header = items()
                .find(|item| item.key.as_ref() == position.as_slice())
                .and_then(|item| item.value.as_deref())
                .and_then(|value| value.strip_prefix(&[0]))
                .ok_or_else(|| {
                    crate::NativeStateSnafu {
                        field: "evidence input batch header",
                    }
                    .build()
                })?;
            let header: super::super::events::EventBatch =
                super::super::records::Records::decode(header)?;
            header.check(revision)?;
            for item in evidence {
                if item.key.as_ref()
                    != super::super::events::Events::key(
                        super::super::events::Events::PAYLOAD,
                        &header.source,
                        header.first,
                    )
                    || item
                        .value
                        .as_ref()
                        .is_none_or(|bytes| bytes.len() != header.bytes)
                {
                    return crate::NativeStateSnafu {
                        field: "evidence input payload identity",
                    }
                    .fail();
                }
                self.readers
                    .raw_batch(&header.source.clone().into(), &header.meta);
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
                        || DataView::input_recovery_key(&item.key)
                        || DataView::input_expiry_key(&item.key)
                        || DataView::input_trace_key(&item.key)
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
            } else if let Some((source, gap)) = view.input_recovery(&item.key)? {
                let identity = source.into();
                self.readers.publish(
                    position,
                    InputChange::Removal {
                        identity: &identity,
                        range: Some((gap.first_cursor, gap.last_cursor, None)),
                    },
                );
            } else if DataView::input_expiry_key(&item.key) {
                view.input_expiry(&item.key, &self.readers, position)?;
            } else if DataView::input_trace_key(&item.key) {
                view.input_trace(&item.key, &self.readers, position)?;
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
            || key.starts_with(super::super::notification::NotificationCompletion::PREFIX)
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
