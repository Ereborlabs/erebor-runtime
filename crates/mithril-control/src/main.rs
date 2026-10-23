use std::path::PathBuf;

use clap::Parser;
use erebor_telemetry::{error, info, init_stderr_logging, warn};
use mithril_control::{
    serve, ClientListener, ControlConfig, ControlRuntimeParts, KubernetesAdmissionOwner,
};

#[derive(Parser)]
#[command(about = "Run the private Mithril node control service")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

fn main() {
    start();
}

#[tokio::main]
async fn start() {
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
        client,
        kubernetes_nodes,
        kubernetes_admission,
        data_error,
        instances,
        discovery,
        graph,
        discovery_error,
    } = config.into_parts()?;
    info!(
        "starting Mithril Control",
        listen = %address,
        allowed_nodes = %control.allowed_nodes().len()
    );
    if let Some(error) = data_error {
        warn!("data intake is unavailable; policy service remains active", error = %error);
    }
    if let Some(error) = discovery_error {
        warn!("discovery startup failed", error = %error);
    }
    let client = match client {
        Some(config) => Some(ClientListener::load(config, control.clone()).await?),
        None => None,
    };
    let (analysis_cancel, analysis_stop) = tokio::sync::watch::channel(false);
    let analysis_task = instances.map(|owner| {
        let cancel = analysis_cancel.clone();
        tokio::spawn(async move {
            let host = owner.serve(analysis_stop.clone(), u64::MAX);
            let sources = async move {
                let discovery_stop = analysis_stop.clone();
                let graph_stop = analysis_stop.clone();
                let discovery = async move {
                    if let Some(owner) = discovery {
                        if let Err(error) = owner.run(discovery_stop).await {
                            warn!("discovery source subscriptions stopped with an error", error = %error);
                        }
                    }
                };
                let graph = async move {
                    if let Some(owner) = graph {
                        if let Err(error) = owner.run(graph_stop).await {
                            warn!("graph source subscriptions stopped with an error", error = %error);
                        }
                    }
                };
                tokio::join!(discovery, graph);
                let mut stop = analysis_stop;
                while !*stop.borrow_and_update() {
                    if stop.changed().await.is_err() {
                        break;
                    }
                }
                Ok(())
            };
            tokio::pin!(host, sources);
            let result = tokio::select! {
                biased;
                result = &mut host => {
                    let _ = cancel.send(true);
                    let joined = sources.await;
                    result.and(joined)
                }
                result = &mut sources => {
                    let _ = cancel.send(true);
                    let joined = host.await;
                    result.and(joined)
                }
            };
            if let Err(error) = result {
                warn!("analysis subscriptions stopped with an error", error = %error);
            }
        })
    });
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
    // Required policy owner exits stop Control.
    let result = if let Some(client) = client {
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        let control_shutdown = shutdown.clone();
        let client_shutdown = shutdown.clone();
        let control_result = serve(address, &tls, control.clone(), async move {
            control_shutdown.notified().await;
        });
        let client_result = async move {
            client
                .serve(async move {
                    client_shutdown.notified().await;
                })
                .await
        };
        tokio::select! {
            result = control_result => {
                shutdown.notify_waiters();
                result
            },
            result = client_result => {
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
    };
    let _ = analysis_cancel.send(true);
    if let Some(task) = analysis_task {
        if let Err(error) = task.await {
            warn!("analysis subscription task failed", error = %error);
        }
    }
    result
}
