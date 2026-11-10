use std::sync::Arc;

use snafu::ResultExt as _;
use tokio::sync::watch;

use super::Wake;
use crate::analysis::native::NativeStore;
use crate::{NativeStateSnafu, NativeStorageSnafu, Result, StorePositionV1};

pub struct ActivationSubscription {
    wake: Wake,
    changes: watch::Receiver<StorePositionV1>,
    position: u64,
}

impl ActivationSubscription {
    pub fn position(&self) -> u64 {
        self.position
    }

    pub async fn changed(&mut self) -> Result<()> {
        loop {
            self.wake.changed(&mut self.changes).await?;
            let position = self.changes.borrow().commit_revision;
            if position > self.position {
                self.position = position;
                return Ok(());
            }
        }
    }
}

impl NativeStore {
    pub fn subscribe_activations(&self) -> Result<ActivationSubscription> {
        let mut scan = self.inputs.scan.lock().map_err(|_| {
            NativeStateSnafu {
                field: "input journal reader lock",
            }
            .build()
        })?;
        let view = self.inputs.view()?;
        if self.inputs.is_empty() {
            let cursor = view.snapshot.cursor().context(NativeStorageSnafu {
                operation: "capture activation journal cut",
            })?;
            scan.native =
                self.inputs
                    .database
                    .inner()
                    .journal_feed(cursor)
                    .context(NativeStorageSnafu {
                        operation: "open activation journal reader",
                    })?;
            scan.raw = view.revision;
        }
        let changes = self.inputs.activations.subscribe();
        Ok(ActivationSubscription {
            wake: Wake {
                coordinator: Arc::clone(&self.inputs),
                revision: self.revision.subscribe(),
                consumer: None,
                replay: None,
            },
            changes,
            position: view.revision,
        })
    }
}
