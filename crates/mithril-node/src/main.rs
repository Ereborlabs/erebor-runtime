use std::path::PathBuf;

use clap::Parser;
use mithril_node::{NodeChassis, NodeConfig};
use tokio::sync::watch;

#[derive(Parser)]
#[command(about = "Run the one-process Mithril node chassis")]
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

async fn run() -> mithril_node::Result<()> {
    let config = NodeConfig::load(&Cli::parse().config)?;
    let node = NodeChassis::start(config)?;
    let (shutdown, receiver) = watch::channel(false);
    tokio::spawn(async move {
        let _result = tokio::signal::ctrl_c().await;
        shutdown.send_replace(true);
    });
    node.run(receiver).await
}
