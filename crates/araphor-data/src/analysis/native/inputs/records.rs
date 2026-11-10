use snafu::ResultExt as _;

use super::Coordinator;
use crate::analysis::{
    inputs::InputChange,
    native::{DataView, NativeStore},
};
use crate::{NativeStorageSnafu, Result, StorePositionV1};

impl Coordinator {
    pub(super) fn records(&self, batch: &fjall::cdc::Batch, bound: &DataView) -> Result<()> {
        let mut candidates = batch
            .items
            .iter()
            .filter(|item| {
                item.branch == Some(self.branch.id())
                    && item.value.is_some()
                    && (DataView::input_context_key(&item.key)
                        || DataView::input_coverage_key(&item.key)
                        || DataView::input_graph_key(&item.key))
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
            if let Some(reference) = view.input_context(&item.key)? {
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
            } else {
                view.input_graph(&item.key, &self.readers, position)?;
            }
        }
        Ok(())
    }
}
