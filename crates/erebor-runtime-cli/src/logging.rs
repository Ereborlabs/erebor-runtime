use clap::{Args, ValueEnum};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

#[derive(Clone, Debug, Args)]
pub struct LoggingArgs {
    /// Minimum operational log level emitted to stderr.
    #[arg(long, global = true, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    const fn as_filter(self) -> LevelFilter {
        match self {
            Self::Off => LevelFilter::OFF,
            Self::Error => LevelFilter::ERROR,
            Self::Warn => LevelFilter::WARN,
            Self::Info => LevelFilter::INFO,
            Self::Debug => LevelFilter::DEBUG,
            Self::Trace => LevelFilter::TRACE,
        }
    }
}

pub fn init_tracing(args: &LoggingArgs) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(args.log_level.as_filter().into())
        .from_env_lossy();

    let result = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();

    if result.is_err() {
        tracing::debug!("tracing subscriber was already initialized");
    }
}
