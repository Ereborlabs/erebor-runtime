use std::path::PathBuf;

use clap::Parser;
use mithril_control::{serve, serve_administrative_http, ControlConfig};

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
    let (address, tls, control, administrative_exec) = config.into_parts()?;
    let policy_owner = control.policy_desired_state();
    let policy_control = control.clone();
    let policy_reconciler = async move {
        if let Some(owner) = policy_owner {
            owner.run_kubernetes(policy_control).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(policy_reconciler);
    if let Some(administrative_exec) = administrative_exec {
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        let control_shutdown = shutdown.clone();
        let administrative_shutdown = shutdown.clone();
        let control_result = serve(address, &tls, control.clone(), async move {
            control_shutdown.notified().await;
        });
        let administrative_result =
            serve_administrative_http(administrative_exec, control, async move {
                administrative_shutdown.notified().await;
            });
        tokio::select! {
            result = control_result => {
                shutdown.notify_waiters();
                result
            },
            result = administrative_result => {
                shutdown.notify_waiters();
                result
            },
            _ = tokio::signal::ctrl_c() => {
                shutdown.notify_waiters();
                Ok(())
            },
            _ = &mut policy_reconciler => {
                shutdown.notify_waiters();
                Ok(())
            },
        }
    } else {
        tokio::select! {
            result = serve(address, &tls, control, async {
                let _result = tokio::signal::ctrl_c().await;
            }) => result,
            _ = &mut policy_reconciler => Ok(()),
        }
    }
}
