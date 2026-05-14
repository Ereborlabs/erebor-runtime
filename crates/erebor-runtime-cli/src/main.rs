mod cli;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = cli.execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
