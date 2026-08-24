use std::path::PathBuf;

use clap::Parser;
use erebor_telemetry::{error, info, init_stderr_logging};
use mithril_control::{
    serve, serve_administrative_http, ControlConfig, ControlRuntimeParts, KubernetesAdmissionOwner,
};

#[derive(Parser)]
#[command(about = "Run the private Mithril node control service")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = init_stderr_logging() {
        eprintln!("Mithril Control logging initialization failed: {error}");
        std::process::exit(1);
    }
    if let Err(error) = run().await {
        error!(%error; "Mithril Control stopped with an error");
        std::process::exit(1);
    }
    info!("stopped Mithril Control");
}

async fn run() -> mithril_control::Result<()> {
    let config = ControlConfig::load(&Cli::parse().config)?;
    let ControlRuntimeParts {
        listen: address,
        tls,
        control,
        administrative_exec,
        kubernetes_nodes,
        kubernetes_admission,
    } = config.into_parts()?;
    info!(
        "starting Mithril Control",
        listen = %address,
        allowed_nodes = %control.allowed_nodes().len()
    );
    // All optional Kubernetes tasks share the owners created from one validated configuration.
    let policy_owner = control.policy_desired_state();
    let admission_policy_owner = policy_owner.clone();
    let policy_control = control.clone();
    let policy_reconciler = async move {
        if let Some(owner) = policy_owner {
            owner.run_kubernetes(policy_control).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(policy_reconciler);
    let node_control = control.clone();
    let admission_node_owner = kubernetes_nodes.clone();
    let node_reconciler = async move {
        if let Some(owner) = kubernetes_nodes {
            owner.run_kubernetes(node_control).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(node_reconciler);
    let admission_control = control.clone();
    let admission_server = async move {
        if let (Some(config), Some(policies), Some(nodes)) = (
            kubernetes_admission,
            admission_policy_owner,
            admission_node_owner,
        ) {
            KubernetesAdmissionOwner::serve(config, admission_control, policies, nodes, async {
                std::future::pending::<()>().await;
            })
            .await
        } else {
            std::future::pending::<mithril_control::Result<()>>().await
        }
    };
    tokio::pin!(admission_server);
    // Any owner exit stops the process because a partial Control process cannot keep its guarantees.
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
            _ = &mut node_reconciler => {
                shutdown.notify_waiters();
                Ok(())
            },
            result = &mut admission_server => {
                shutdown.notify_waiters();
                result
            },
        }
    } else {
        tokio::select! {
            result = serve(address, &tls, control, async {
                let _result = tokio::signal::ctrl_c().await;
            }) => result,
            _ = &mut policy_reconciler => Ok(()),
            _ = &mut node_reconciler => Ok(()),
            result = &mut admission_server => result,
        }
    }
}
