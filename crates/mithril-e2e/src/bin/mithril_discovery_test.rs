use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Clone, ValueEnum)]
enum Case {
    OfflineExact,
    ProfileRestart,
}

#[derive(Parser)]
#[command(about = "Verify Araphor discovery with bounded qualification cases")]
struct Cli {
    #[arg(long, value_enum)]
    case: Case,
    #[arg(long)]
    output_directory: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.case {
        Case::OfflineExact => mithril_e2e::run_discovery_offline(&cli.output_directory)
            .map_err(Box::<dyn std::error::Error>::from),
        Case::ProfileRestart => {
            mithril_e2e::DiscoveryQualificationRunner::new(cli.output_directory)
                .profile_restart()
                .await
        }
    };
    match result {
        Ok(()) => {
            println!("Araphor discovery check passed; see result.json for its proof boundary")
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
