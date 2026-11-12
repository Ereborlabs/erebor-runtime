use snafu::ResultExt as _;

use super::{Coordinator, InputRecord};
use crate::analysis::native::records::Records;
use crate::{NativeStateSnafu, NativeStorageSnafu, Result};

impl Coordinator {
    pub(in crate::analysis::native) fn collect_journals(
        &self,
        policy: fjall::HistoryPolicy,
        mut history: fjall::Revision,
        flush: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let mut scan = self.scan.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input journal reader lock",
            }
            .build()
        })?;
        let view = self.view()?;
        self.read(&mut scan, &view)?;
        let mut floor = view
            .snapshot
            .cursor()
            .context(NativeStorageSnafu {
                operation: "capture journal collection cut",
            })?
            .ok_or_else(|| {
                NativeStateSnafu {
                    field: "published input journal cut",
                }
                .build()
            })?;
        if let Some(cursor) = scan.native.cursor() {
            floor = floor.min(cursor);
            history = history.min(cursor.revision());
        }
        for entry in view.snapshot.prefix(InputRecord::PREFIX) {
            let (key, _) = entry.context(NativeStorageSnafu {
                operation: "read journal collection consumers",
            })?;
            let Some((owner, generation)) = InputRecord::identity(&key)? else {
                continue;
            };
            let record =
                InputRecord::read(owner, generation, |key| Records::read(key, &view.snapshot))?
                    .ok_or_else(|| {
                        NativeStateSnafu {
                            field: "journal collection consumer",
                        }
                        .build()
                    })?;
            record.check(&view)?;
            floor = floor.min(record.cut.cursor());
            history = history.min(record.cut.cursor().revision());
        }
        if let Some(after) = self.readers.history_after() {
            history = history.min(
                super::super::NativeStore::cut_at(&self.branch, &view, after)?
                    .snapshot
                    .revision(),
            );
        }
        if history < policy.first {
            return NativeStateSnafu {
                field: "required history protection",
            }
            .fail();
        }
        if scan.retained.is_some_and(|previous| floor < previous) {
            return NativeStateSnafu {
                field: "input journal floor moved backwards",
            }
            .fail();
        }
        self.database
            .inner()
            .retain_after(floor)
            .context(NativeStorageSnafu {
                operation: "advance original journal floor",
            })?;
        scan.retained = Some(floor);
        self.database
            .advance_history(policy.id, history)
            .context(NativeStorageSnafu {
                operation: "advance owned Data history",
            })?;
        flush()?;
        self.database
            .inner()
            .collect_journals()
            .context(NativeStorageSnafu {
                operation: "collect original input journals",
            })
    }
}
