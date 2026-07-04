use std::sync::Once;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

static TEST_LOGGING_INIT: Once = Once::new();

pub fn init_test_logging() {
    TEST_LOGGING_INIT.call_once(|| {
        let filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::DEBUG.into())
            .from_env_lossy();

        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}

#[cfg(test)]
mod tests {
    use super::init_test_logging;

    #[test]
    fn init_test_logging_is_idempotent() {
        init_test_logging();
        init_test_logging();

        tracing::debug!("test logging initialized twice");
    }
}
