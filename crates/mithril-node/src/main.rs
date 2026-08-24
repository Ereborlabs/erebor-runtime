use std::path::PathBuf;

use clap::Parser;
use erebor_telemetry::{error, info, init_stderr_logging};
use mithril_node::{NodeChassis, NodeConfig};
use tokio::sync::watch;

#[derive(Parser)]
#[command(about = "Run the one-process Mithril node chassis")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    held_initial_pid: Vec<u32>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = init_stderr_logging() {
        eprintln!("Mithril Node logging initialization failed: {error}");
        std::process::exit(1);
    }
    if let Err(error) = run().await {
        error!(%error; "Mithril Node stopped with an error");
        std::process::exit(1);
    }
    info!("stopped Mithril Node");
}

async fn run() -> mithril_node::Result<()> {
    let cli = Cli::parse();
    let config = match std::env::var("MITHRIL_KUBERNETES_NODE_NAME").ok() {
        // The downward API binds this process before validation that depends on its Node name.
        Some(node_name) => {
            NodeConfig::load_with_kubernetes_runtime_identity(&cli.config, node_name)?
        }
        None => NodeConfig::load(&cli.config)?,
    };
    info!(
        "starting Mithril Node",
        node_id = %config.node_id,
        kubernetes_node = %config.kubernetes_node_name.as_deref().unwrap_or("none")
    );
    let node = NodeChassis::start_with_held_initial_pids(config, &cli.held_initial_pid).await?;
    let (shutdown, receiver) = watch::channel(false);
    tokio::spawn(async move {
        let _result = tokio::signal::ctrl_c().await;
        shutdown.send_replace(true);
    });
    node.run(receiver).await
}
