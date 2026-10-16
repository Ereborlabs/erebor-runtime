use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use crate::{InvalidSnafu, Result};

pub trait Clock: Send + Sync {
    fn now_ns(&self) -> Result<u64>;
    fn changes(&self) -> watch::Receiver<u64>;
}

pub struct SystemClock {
    changes: watch::Sender<u64>,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            changes: watch::channel(0).0,
        }
    }
}

impl Clock for SystemClock {
    fn now_ns(&self) -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|value| u64::try_from(value.as_nanos()).ok())
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "clock time",
                }
                .build()
            })
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}
