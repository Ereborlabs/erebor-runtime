use std::sync::{Arc, Mutex};

use araphor_data::*;

use crate::Result;

mod attempt;
mod attempt_delivery;
mod concern;
mod delivery;
mod obligation;
mod operations;
mod reactive;
mod routing;
mod store;
#[cfg(test)]
pub(crate) mod tests;

pub use reactive::NotificationUpdate;

type Effect<'a> = dyn FnMut(&NotificationDeliveryV1) -> Result<NotificationSinkResultV1> + 'a;

pub struct NotificationRouter {
    store: Arc<AnalysisStore>,
    authority: Arc<dyn NotificationAuthorization>,
    operation: Mutex<()>,
}

impl NotificationRouter {
    pub fn new(
        store: Arc<AnalysisStore>,
        authority: Arc<dyn NotificationAuthorization>,
    ) -> Result<Self> {
        store.enable_notification_owner()?;
        Ok(Self {
            store,
            authority,
            operation: Mutex::new(()),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.operation.lock().map_err(|_| {
            NotificationSnafu {
                code: NotificationErrorCodeV1::Unavailable,
                field: "router lock",
            }
            .build()
            .into()
        })
    }
}

impl Drop for NotificationRouter {
    fn drop(&mut self) {
        self.store.release_notification_owner();
    }
}
