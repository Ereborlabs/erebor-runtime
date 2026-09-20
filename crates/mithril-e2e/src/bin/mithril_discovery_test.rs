use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Clone, ValueEnum)]
enum Case {
    OfflineExact,
}

#[derive(Parser)]
#[command(about = "Verify recorded Araphor discovery without live services")]
struct Cli {
    #[arg(long, value_enum)]
    case: Case,
    #[arg(long)]
    output_directory: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.case {
        Case::OfflineExact => mithril_e2e::run_discovery_offline(&cli.output_directory),
    };
    match result {
        Ok(()) => {
            println!("Araphor synthetic offline proof passed; no physical action was attempted")
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
