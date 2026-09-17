use std::path::PathBuf;

use clap::Parser;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use tokio::io;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    kubeconfig: PathBuf,
    #[arg(long)]
    namespace: String,
    #[arg(long)]
    pod: String,
    #[arg(long)]
    container: String,
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let kubeconfig = Kubeconfig::read_from(&args.kubeconfig)?;
    let config = Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default()).await?;
    let pods = Api::<Pod>::namespaced(Client::try_from(config)?, &args.namespace);
    let params = AttachParams {
        container: Some(args.container),
        stdin: true,
        stdout: true,
        stderr: true,
        ..Default::default()
    };
    let mut process = pods.exec(&args.pod, args.command, &params).await?;
    let input = process.stdin().map(|mut remote| {
        tokio::spawn(async move { io::copy(&mut io::stdin(), &mut remote).await })
    });
    let output = process.stdout().map(|mut remote| {
        tokio::spawn(async move { io::copy(&mut remote, &mut io::stdout()).await })
    });
    let errors = process.stderr().map(|mut remote| {
        tokio::spawn(async move { io::copy(&mut remote, &mut io::stderr()).await })
    });
    let status = process.take_status().map(tokio::spawn);
    process.join().await?;
    if let Some(task) = input {
        task.abort();
    }
    if let Some(task) = output {
        task.await??;
    }
    if let Some(task) = errors {
        task.await??;
    }
    if let Some(status) = match status {
        Some(task) => task.await?,
        None => None,
    } {
        if status.status.as_deref() != Some("Success") {
            return Err(status
                .message
                .unwrap_or_else(|| "remote command failed".into())
                .into());
        }
    }
    Ok(())
}
