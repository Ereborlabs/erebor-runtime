use std::sync::Once;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

use crate::{Result, TelemetryError};

static TEST_LOGGING_INIT: Once = Once::new();
static STDERR_LOGGING_INIT: Once = Once::new();

pub fn init_stderr_logging() -> Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .try_from_env()
        .map_err(|source| TelemetryError::InvalidFilter {
            source,
            location: snafu::Location::default(),
        })?;

    STDERR_LOGGING_INIT.call_once(|| {
        let _result = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(std::io::stderr)
            .try_init();
    });
    Ok(())
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
    use std::process::Command;

    use super::{init_stderr_logging, init_test_logging};

    const CHILD_MODE: &str = "EREBOR_TELEMETRY_LOGGING_CHILD";

    #[test]
    fn init_test_logging_is_idempotent() {
        init_test_logging();
        init_test_logging();

        tracing::debug!("test logging initialized twice");
    }

    #[test]
    fn stderr_logging_child() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(mode) = std::env::var(CHILD_MODE) else {
            return Ok(());
        };
        if mode == "invalid" {
            assert!(init_stderr_logging().is_err());
            return Ok(());
        }

        init_stderr_logging()?;
        tracing::info!(sample_count = 7, "telemetry formatter proof");
        tracing::debug!("telemetry target override proof");
        Ok(())
    }

    #[test]
    fn stderr_logging_preserves_format_and_filters() -> Result<(), Box<dyn std::error::Error>> {
        let info = child_output("normal", "info")?;
        let line = info
            .lines()
            .find(|line| line.contains("telemetry formatter proof"))
            .ok_or("the formatter did not emit the INFO event")?;
        assert!(line.contains(" INFO "));
        assert!(line.contains("erebor_telemetry::logging::tests:"));
        assert!(line.contains("sample_count=7"));
        assert!(line
            .split_whitespace()
            .next()
            .is_some_and(|timestamp| { timestamp.contains('T') && timestamp.ends_with('Z') }));
        assert!(!info.contains("telemetry target override proof"));

        let target = child_output("normal", "info,erebor_telemetry::logging::tests=debug")?;
        assert!(target.contains("telemetry target override proof"));
        Ok(())
    }

    #[test]
    fn stderr_logging_rejects_an_invalid_filter() -> Result<(), Box<dyn std::error::Error>> {
        let output = child("invalid", "[")?;
        assert!(output.status.success());
        Ok(())
    }

    fn child_output(mode: &str, filter: &str) -> Result<String, Box<dyn std::error::Error>> {
        let output = child(mode, filter)?;
        if !output.status.success() {
            return Err(format!(
                "logging child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8(output.stderr)?)
    }

    fn child(mode: &str, filter: &str) -> Result<std::process::Output, std::io::Error> {
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "logging::tests::stderr_logging_child",
                "--nocapture",
            ])
            .env(CHILD_MODE, mode)
            .env("RUST_LOG", filter)
            .output()
    }
}
