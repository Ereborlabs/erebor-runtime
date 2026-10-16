//! Command wiring for the `araphor` client.

mod cli;
mod error;
mod logging;

use clap::Parser;
use erebor_runtime_error::ErrorExt;

pub fn run() {
    let cli = cli::Cli::parse();
    exit_on_error(cli.execute());
}

#[cfg(test)]
#[test]
#[ignore]
fn araphor_component_compiler() -> std::result::Result<(), Box<dyn std::error::Error>> {
    araphor_analysis::AnalysisPackageOwner::run_compiler_worker()?;
    Ok(())
}

fn exit_on_error(result: Result<(), error::CliError>) {
    if let Err(error) = result {
        let status_code = error.status_code();
        let retry_hint = error.retry_hint();
        erebor_telemetry::error!(
            %error;
            "command failed",
            status_code = %status_code,
            retry_hint = %retry_hint
        );
        eprintln!("{}", error.output_msg());
        std::process::exit(error.exit_code());
    }
}
