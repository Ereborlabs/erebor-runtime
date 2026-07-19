use erebor_runtime_daemon::DaemonControlService;
use erebor_runtime_error::ErrorExt;
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

#[tokio::main]
async fn main() {
    if let Some(exit_code) = command_line_exit_code() {
        std::process::exit(exit_code);
    }
    init_foreground_logging();
    let result = match DaemonControlService::start_system().await {
        Ok(service) => service.serve().await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        erebor_runtime_telemetry::error!(error; "erebord failed");
        eprintln!("{}", error.output_msg());
        std::process::exit(1);
    }
}

fn command_line_exit_code() -> Option<i32> {
    let argument = std::env::args().nth(1)?;
    if argument == "--help" || argument == "-h" {
        println!("Usage: erebord\n\nRun the privileged local Erebor daemon control service.");
        return Some(0);
    }
    eprintln!("erebord does not accept `{argument}`; run `erebord --help`");
    Some(2)
}

fn init_foreground_logging() {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let _result = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}
