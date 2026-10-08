use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisStore, ContextSensitivityV1, FindingV1,
    GraphAndFindingOwner, NotificationEncodingSnafu, Result,
};

mod attempt;
mod attempt_delivery;
mod concern;
mod delivery;
mod model;
mod obligation;
mod operations;
mod routing;
mod store;
pub use model::*;
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
        NotificationErrorCodeV1::Conflict.require(
            store
                .notification_owner
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "router owner",
        )?;
        Ok(Self {
            store,
            authority,
            operation: Mutex::new(WorkCursors::default()),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, WorkCursors>> {
        self.operation.lock().map_err(|_| {
            crate::NotificationSnafu {
                code: NotificationErrorCodeV1::Unavailable,
                field: "router lock",
            }
            .build()
        })
    }
}

impl Drop for NotificationRouter {
    fn drop(&mut self) {
        self.store
            .notification_owner
            .store(false, Ordering::Release);
    }
}
