mod cli;
mod logging;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = cli.execute() {
        tracing::error!(error = %error, "command failed");
        eprintln!("{error}");
        std::process::exit(1);
    }
}
