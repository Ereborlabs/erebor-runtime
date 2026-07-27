use std::sync::Once;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

static TEST_LOGGING_INIT: Once = Once::new();
static STDERR_LOGGING_INIT: Once = Once::new();

pub fn init_stderr_logging() {
    STDERR_LOGGING_INIT.call_once(|| {
        let filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        let _result = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

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
