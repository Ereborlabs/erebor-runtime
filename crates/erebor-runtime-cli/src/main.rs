mod cli;
mod error;
mod logging;

use clap::Parser;
use cli::Cli;
use erebor_runtime_error::ErrorExt;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = cli.execute() {
        let status_code = error.status_code();
        let retry_hint = error.retry_hint();
        erebor_runtime_telemetry::error!(
            %error;
            "command failed",
            status_code = %status_code,
            retry_hint = %retry_hint
        );
        eprintln!("{}", error.output_msg());
        std::process::exit(1);
    }
}
