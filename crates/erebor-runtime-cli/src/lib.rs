//! Command wiring for the public `erebor` client.

mod cli;
mod error;
mod logging;

use clap::Parser;
use erebor_runtime_error::ErrorExt;

pub fn run() {
    let cli = cli::Cli::parse();
    exit_on_error(cli.execute());
}

fn exit_on_error(result: Result<(), error::CliError>) {
    if let Err(error) = result {
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
