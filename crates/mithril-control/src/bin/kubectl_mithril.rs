use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams};
use kube::{Client, Config};
use mithril_control::{
    AdministrativeExecDraftRequestV1, AdministrativeExecDraftResponseV1,
    AdministrativeExecPollResponseV1, NodeDecommissionStateV1, NodeDecommissionStatusV1,
};
use secrecy::SecretString;
use tokio::io;

#[derive(Parser)]
#[command(about = "Operate Mithril through Control HTTPS")]
struct Cli {
    #[arg(long)]
    control_url: String,

    #[arg(long)]
    control_ca: Option<PathBuf>,

    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    Exec(ExecArgs),
    Decommission(DecommissionArgs),
}

#[derive(Args)]
struct DecommissionArgs {
    #[arg(long)]
    artifact: PathBuf,
}

#[derive(Args)]
struct ExecArgs {
    #[arg(short = 'n', long, default_value = "default")]
    namespace: String,

    #[arg(short = 'c', long)]
    container: String,

    #[arg(short = 'i', long)]
    stdin: bool,

    #[arg(short = 't', long)]
    tty: bool,

    pod: String,

    #[arg(required = true, trailing_var_arg = true)]
    argv: Vec<String>,

    #[arg(long, default_value = "runtime-external-administrative")]
    approved_role_id: String,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        CommandKind::Exec(args) => {
            run_exec(&cli.control_url, cli.control_ca.as_deref(), args).await
        }
        CommandKind::Decommission(args) => {
            args.run(&cli.control_url, cli.control_ca.as_deref()).await
        }
    }
}

impl DecommissionArgs {
    async fn run(
        self,
        control_url: &str,
        control_ca: Option<&std::path::Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !control_url.starts_with("https://") || control_url.ends_with('/') {
            return Err("--control-url must be one HTTPS origin without a trailing slash".into());
        }
        let mut client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        if let Some(path) = control_ca {
            client =
                client.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
        }
        let client = client.build()?;
        let response = client
            .post(format!("{control_url}/v1/node-decommissions"))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(std::fs::read(self.artifact)?)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(
                format!("node decommission submission failed with {status}: {body}").into(),
            );
        }
        let mut status: NodeDecommissionStatusV1 = response.json().await?;
        let status_url = format!(
            "{control_url}/v1/node-decommissions/{}",
            status.artifact_sha256
        );
        loop {
            println!("{} {:?}", status.artifact_sha256, status.state);
            match status.state {
                NodeDecommissionStateV1::Completed => return Ok(()),
                NodeDecommissionStateV1::Rejected => {
                    return Err(
                        format!("node rejected decommission: {}", status.reason_code).into(),
                    )
                }
                _ => tokio::time::sleep(Duration::from_millis(250)).await,
            }
            status = client
                .get(&status_url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
        }
    }
}

async fn run_exec(
    control_url: &str,
    control_ca: Option<&std::path::Path>,
    args: ExecArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    if !control_url.starts_with("https://") || control_url.ends_with('/') {
        return Err("--control-url must be one HTTPS origin without a trailing slash".into());
    }
    if args.tty && !args.stdin {
        return Err("--tty requires --stdin".into());
    }
    let mut client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if let Some(path) = control_ca {
        client =
            client.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
    }
    let client = client.build()?;
    let response = client
        .post(format!("{control_url}/v1/administrative-exec/requests"))
        .json(&AdministrativeExecDraftRequestV1 {
            namespace: args.namespace.clone(),
            pod: args.pod.clone(),
            container: args.container.clone(),
            argv: args.argv.clone(),
            stdin: args.stdin,
            stdout: true,
            stderr: !args.tty,
            tty: args.tty,
            approved_role_id: args.approved_role_id,
        })
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("administrative draft request failed with {status}: {body}").into());
    }
    let draft: AdministrativeExecDraftResponseV1 = response.json().await?;
    println!("Approval required for:");
    println!("  namespace: {}", args.namespace);
    println!("  pod:       {}", args.pod);
    println!("  container: {}", args.container);
    println!("  command:   {}", args.argv.join(" "));
    println!("  tty:       {}", args.tty);
    println!();
    println!("Opening {}", draft.activation_url);
    println!("Code: {}", draft.activation_code);
    println!();
    println!("Waiting for approval...");
    open_browser(&draft.activation_url);
    let poll_url = format!(
        "{control_url}/v1/administrative-exec/requests/{}",
        draft.poll_token
    );
    let credential = loop {
        if current_utc_ns()? > draft.expires_at_utc_ns {
            return Err("administrative approval expired".into());
        }
        let response = client.get(&poll_url).send().await?;
        if response.status() == reqwest::StatusCode::ACCEPTED {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let response: AdministrativeExecPollResponseV1 =
            response.error_for_status()?.json().await?;
        let credential = response
            .credential
            .ok_or("approved response contains no credential")?;
        println!(
            "Approved as {}",
            response.approval_id.as_deref().unwrap_or("unknown")
        );
        break credential;
    };
    let mut config = Config::infer().await?;
    config.auth_info = Default::default();
    config.auth_info.token = Some(SecretString::new(credential.into()));
    let kube = Client::try_from(config)?;
    let pods = Api::<Pod>::namespaced(kube, &args.namespace);
    let params = AttachParams {
        container: Some(args.container),
        stdin: args.stdin,
        stdout: true,
        stderr: !args.tty,
        tty: args.tty,
        ..Default::default()
    };
    let mut process = pods.exec(&args.pod, args.argv, &params).await?;
    let _terminal = RawTerminal::new(args.tty)?;
    let stdin_task = process.stdin().map(|mut remote| {
        tokio::spawn(async move { io::copy(&mut io::stdin(), &mut remote).await })
    });
    let stdout_task = process.stdout().map(|mut remote| {
        tokio::spawn(async move { io::copy(&mut remote, &mut io::stdout()).await })
    });
    let stderr_task = process.stderr().map(|mut remote| {
        tokio::spawn(async move { io::copy(&mut remote, &mut io::stderr()).await })
    });
    let status_task = process.take_status().map(tokio::spawn);
    process.join().await?;
    if let Some(task) = stdin_task {
        task.abort();
    }
    if let Some(task) = stdout_task {
        task.await??;
    }
    if let Some(task) = stderr_task {
        task.await??;
    }
    if let Some(status) = match status_task {
        Some(task) => task.await?,
        None => None,
    } {
        if status.status.as_deref() != Some("Success") {
            return Err(format!(
                "remote command failed: {}",
                status.message.unwrap_or_else(|| "unknown error".to_owned())
            )
            .into());
        }
    }
    Ok(())
}

fn open_browser(url: &str) {
    let command = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _result = Command::new(command).arg(url).status();
}

fn current_utc_ns() -> Result<i64, Box<dyn std::error::Error>> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

struct RawTerminal(bool);

impl RawTerminal {
    fn new(enabled: bool) -> Result<Self, Box<dyn std::error::Error>> {
        if enabled {
            enable_raw_mode()?;
        }
        Ok(Self(enabled))
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if self.0 {
            let _result = disable_raw_mode();
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, CommandKind};

    #[test]
    fn decommission_command_requires_one_artifact() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from([
            "kubectl-mithril",
            "--control-url",
            "https://control.example",
            "decommission",
            "--artifact",
            "authorization.cbor",
        ])?;
        assert!(matches!(cli.command, CommandKind::Decommission(_)));
        assert!(Cli::try_parse_from([
            "kubectl-mithril",
            "--control-url",
            "https://control.example",
            "decommission",
        ])
        .is_err());
        Ok(())
    }
}
