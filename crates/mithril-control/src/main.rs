use std::path::PathBuf;

use clap::Parser;
use mithril_control::{serve, ControlConfig};

#[derive(Parser)]
#[command(about = "Run the private Mithril node control service")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> mithril_control::Result<()> {
    let config = ControlConfig::load(&Cli::parse().config)?;
    let (address, tls, control) = config.into_parts();
    serve(address, &tls, control, async {
        let _result = tokio::signal::ctrl_c().await;
    })
    .await
}
