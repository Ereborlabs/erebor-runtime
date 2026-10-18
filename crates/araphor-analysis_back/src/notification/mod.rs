use std::sync::{Arc, Mutex};

use araphor_data::*;
use serde::Serialize;

use crate::{GraphAndFindingOwner, Result};

mod attempt;
mod attempt_delivery;
mod concern;
mod delivery;
mod obligation;
mod operations;
mod routing;
mod store;
#[cfg(test)]
mod tests;

pub struct NotificationRouter {
    store: Arc<AnalysisStore>,
    authority: Arc<dyn NotificationAuthorization>,
    operation: Mutex<WorkCursors>,
}

#[derive(Default)]
struct WorkCursors {
    routing: Option<RoutingCursor>,
    delivery: Option<DeliveryCursor>,
}

struct RoutingCursor {
    tenant: [u8; 16],
    finding_id: Option<String>,
}

struct DeliveryCursor {
    tenant: [u8; 16],
    context: Option<AnalysisContextKeyV1>,
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
            operation: Mutex::new(WorkCursors::default()),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, WorkCursors>> {
        self.operation.lock().map_err(|_| {
            araphor_data::Error::Notification {
                code: NotificationErrorCodeV1::Unavailable,
                field: "router lock",
                location: snafu::location!(),
            }
            .into()
        })
    }
}

impl Drop for NotificationRouter {
    fn drop(&mut self) {
        self.store.release_notification_owner();
    }
}
