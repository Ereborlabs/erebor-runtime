use snafu::ResultExt as _;

use super::super::{DataView, NativeStore};
use crate::analysis::inputs::InputCut;
use crate::{NativeStateSnafu, NativeStorageSnafu, Result, StorePositionV1};

impl InputCut {
    pub(super) fn capture(view: &DataView) -> Result<Self> {
        let native = view
            .snapshot
            .cursor()
            .context(NativeStorageSnafu {
                operation: "capture committed input cursor",
            })?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "input journal cut is not retained",
                }
                .build()
            })?;
        let raw = view
            .raw
            .entries
            .range(..=view.revision)
            .next_back()
            .map(|(revision, entry)| (*revision, entry.reference.id, entry.reference.offset));
        Ok(Self {
            revision: view.revision,
            native: (native.journal, native.offset, native.sequence),
            raw,
        })
    }

    pub(super) fn cursor(&self) -> fjall::Cursor {
        fjall::Cursor {
            journal: self.native.0,
            offset: self.native.1,
            sequence: self.native.2,
        }
    }

    pub(super) fn position(&self) -> StorePositionV1 {
        StorePositionV1 {
            commit_revision: self.revision,
            ordinal: u32::MAX,
        }
    }

    pub(super) fn check(&self, view: &DataView) -> Result<()> {
        if self.revision > view.revision
            || self.native.1 == 0
            || self.native.2.checked_add(1).is_none()
            || self.raw.is_some_and(|(revision, segment, offset)| {
                revision == 0 || revision > self.revision || segment == 0 || offset == 0
            })
        {
            return NativeStateSnafu {
                field: "input cursor bounds",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn read(&self, branch: &fjall::Branch, bound: &DataView) -> Result<DataView> {
        let view = NativeStore::cut_at(branch, bound, self.revision)?;
        if Self::capture(&view)? != *self {
            return NativeStateSnafu {
                field: "saved input cursor identity",
            }
            .fail();
        }
        Ok(view)
    }
}
