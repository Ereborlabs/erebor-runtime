use std::sync::atomic::AtomicU64;

use super::*;

pub(super) struct Clock {
    now: AtomicU64,
    changes: watch::Sender<u64>,
    entered: tokio::sync::Notify,
}

impl Clock {
    pub(super) fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            changes: watch::channel(0).0,
            entered: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn advance(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
        self.changes.send_modify(|revision| *revision += 1);
    }
}

impl araphor_query::follow::Clock for Clock {
    fn now_ns(&self) -> araphor_query::Result<u64> {
        let now = self.now.load(Ordering::SeqCst);
        self.entered.notify_one();
        Ok(now)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}
