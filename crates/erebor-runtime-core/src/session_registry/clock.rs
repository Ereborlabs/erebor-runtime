use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct SessionRegistryClock;

impl SessionRegistryClock {
    pub(super) fn unix_time_ms() -> u64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        u64::try_from(millis).unwrap_or(u64::MAX)
    }
}
