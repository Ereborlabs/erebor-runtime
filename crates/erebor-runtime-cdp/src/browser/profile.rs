use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct BrowserProfilePath;

impl BrowserProfilePath {
    pub(super) fn temporary() -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());

        std::env::temp_dir().join(format!(
            "erebor-runtime-owned-browser-{}-{timestamp}",
            std::process::id()
        ))
    }
}
