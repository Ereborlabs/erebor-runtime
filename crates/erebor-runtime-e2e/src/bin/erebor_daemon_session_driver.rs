use std::{io::Write, path::PathBuf};

use clap::{ArgAction, Args, Parser, Subcommand};
use erebor_runtime_client::DaemonClient;
use erebor_runtime_ipc::v1::{
    AdminSessionKillRequest, AdminSessionSetRetentionHoldRequest, AdminSessionStopRequest,
    SessionAttachRequest, SessionCreateRequest, SessionEnvironmentEntry,
    SessionInputLeaseReleaseRequest, SessionInputLeaseRenewRequest, SessionPruneRequest,
    SessionRecord,
};

#[derive(Parser)]
#[command(name = "erebor-daemon-session-driver")]
struct Driver {
    #[arg(long, default_value = "/run/erebor/daemon.sock")]
    socket: PathBuf,
    #[command(subcommand)]
    command: DriverCommand,
}

#[derive(Subcommand)]
enum DriverCommand {
    Create(CreateArgs),
    Start(SessionMutationArgs),
    Inspect(SessionArgs),
    List,
    Wait(SessionArgs),
    Logs(StreamArgs),
    Events(PageArgs),
    Attach(AttachArgs),
    LeaseRenew(LeaseArgs),
    LeaseRelease(LeaseArgs),
    Stop(StopArgs),
    Kill(KillArgs),
    Remove(RemoveArgs),
    Prune(PruneArgs),
    AdminList(AdminListArgs),
    AdminInspect(AdminSessionArgs),
    AdminStop(AdminStopArgs),
    AdminKill(AdminKillArgs),
    AdminSetRetentionHold(AdminSetRetentionHoldArgs),
}

#[derive(Args)]
struct CreateArgs {
    #[arg(long)]
    runner: String,
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    package_digest: String,
    #[arg(long)]
    installation_digest: String,
    #[arg(long)]
    adapter_digest: String,
    #[arg(long)]
    policy_set_digest: String,
    #[arg(long, default_value = "terminate")]
    failure_mode: String,
    #[arg(long, default_value_t = 2)]
    loss_grace_seconds: u64,
    #[arg(long)]
    image_digest: Option<String>,
    #[arg(long)]
    key: String,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Args)]
struct SessionArgs {
    session_id: String,
}

#[derive(Args)]
struct SessionMutationArgs {
    session_id: String,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct StopArgs {
    session_id: String,
    #[arg(long, default_value_t = 2)]
    grace_seconds: u64,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct KillArgs {
    session_id: String,
    #[arg(long, default_value = "kill")]
    signal: String,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct RemoveArgs {
    session_id: String,
    #[arg(long)]
    force: bool,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct StreamArgs {
    session_id: String,
    #[arg(long, default_value = "stdout")]
    stream: String,
    #[arg(long, default_value_t = 0)]
    after: u64,
    #[arg(long, default_value_t = 100)]
    maximum_records: u32,
}

#[derive(Args)]
struct PageArgs {
    session_id: String,
    #[arg(long, default_value_t = 0)]
    after: u64,
    #[arg(long, default_value_t = 100)]
    maximum_records: u32,
}

#[derive(Args)]
struct AttachArgs {
    session_id: String,
    #[arg(long)]
    input: bool,
    #[arg(long, default_value = "phase-2-driver")]
    client_id: String,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct LeaseArgs {
    session_id: String,
    lease_id: String,
    #[arg(long, default_value = "phase-2-driver")]
    client_id: String,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct PruneArgs {
    #[arg(long)]
    before_unix_ms: u64,
    #[arg(long, default_value_t = 100)]
    maximum_sessions: u32,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct AdminListArgs {
    #[arg(long, default_value_t = 0)]
    uid: u32,
    #[arg(long)]
    all_users: bool,
}

#[derive(Args)]
struct AdminSessionArgs {
    #[arg(long)]
    uid: u32,
    session_id: String,
}

#[derive(Args)]
struct AdminStopArgs {
    #[arg(long)]
    uid: u32,
    session_id: String,
    #[arg(long, default_value_t = 2)]
    grace_seconds: u64,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct AdminKillArgs {
    #[arg(long)]
    uid: u32,
    session_id: String,
    #[arg(long, default_value = "kill")]
    signal: String,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct AdminSetRetentionHoldArgs {
    #[arg(long)]
    uid: u32,
    session_id: String,
    #[arg(long, action = ArgAction::Set)]
    retention_hold: bool,
    #[arg(long)]
    key: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let driver = Driver::parse();
    let client = DaemonClient::at(driver.socket);
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(execute(client, driver.command))
}

async fn execute(
    client: DaemonClient,
    command: DriverCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        DriverCommand::Create(args) => {
            let response = client
                .session_create(
                    SessionCreateRequest {
                        runner_id: args.runner,
                        command: args.command,
                        workspace: args.workspace.display().to_string(),
                        policy_set_digest: args.policy_set_digest,
                        package_digest: args.package_digest,
                        installation_digest: args.installation_digest,
                        adapter_digest: args.adapter_digest,
                        daemon_failure_mode: args.failure_mode,
                        requested_loss_grace_seconds: args.loss_grace_seconds,
                        environment: vec![SessionEnvironmentEntry {
                            key: String::from("LANG"),
                            value: String::from("C"),
                        }],
                        secret_references: Vec::new(),
                        container_image_digest: args.image_digest.unwrap_or_default(),
                        tty: false,
                        detached: true,
                    },
                    &args.key,
                )
                .await?;
            println!(
                "session_id={} state={} generation={} retry_expires_unix_ms={}",
                response.session_id,
                response.state,
                response.generation,
                response.retry_guarantee_expires_unix_ms
            );
        }
        DriverCommand::Start(args) => {
            print_record(&client.session_start(args.session_id, &args.key).await?);
        }
        DriverCommand::Inspect(args) => {
            print_record(&client.session_inspect(args.session_id).await?);
        }
        DriverCommand::List => {
            for record in client.session_list().await?.sessions {
                print_record(&record);
            }
        }
        DriverCommand::Wait(args) => {
            print_record(&client.session_wait(args.session_id, 0).await?);
        }
        DriverCommand::Logs(args) => {
            let page = client
                .session_logs(
                    args.session_id,
                    args.stream,
                    args.after,
                    args.maximum_records,
                )
                .await?;
            let mut stdout = std::io::stdout().lock();
            for record in page.records {
                stdout.write_all(&record.data)?;
            }
            writeln!(
                stdout,
                "\ndurable_cursor={} truncated={}",
                page.end.durable_cursor, page.end.truncated_before_cursor
            )?;
        }
        DriverCommand::Events(args) => {
            let page = client
                .session_events(args.session_id, args.after, args.maximum_records)
                .await?;
            for record in page.records {
                println!(
                    "sequence={} kind={} payload={}",
                    record.sequence,
                    record.event_kind,
                    String::from_utf8_lossy(&record.payload)
                );
            }
            println!(
                "durable_cursor={} truncated={}",
                page.end.durable_cursor, page.end.truncated_before_cursor
            );
        }
        DriverCommand::Attach(args) => {
            let response = client
                .session_attach(
                    SessionAttachRequest {
                        session_id: args.session_id,
                        after_output_sequence: 0,
                        request_input_lease: args.input,
                        client_instance_id: args.client_id,
                    },
                    &args.key,
                )
                .await?;
            println!(
                "session_id={} read_only={} lease_id={} lease_expires_unix_ms={}",
                response.session_id,
                response.read_only,
                response.input_lease_id,
                response.input_lease_expires_unix_ms
            );
        }
        DriverCommand::LeaseRenew(args) => {
            let response = client
                .session_input_lease_renew(
                    SessionInputLeaseRenewRequest {
                        session_id: args.session_id,
                        input_lease_id: args.lease_id,
                        client_instance_id: args.client_id,
                    },
                    &args.key,
                )
                .await?;
            println!(
                "lease_id={} expires_unix_ms={} released={}",
                response.input_lease_id, response.expires_unix_ms, response.released
            );
        }
        DriverCommand::LeaseRelease(args) => {
            let response = client
                .session_input_lease_release(
                    SessionInputLeaseReleaseRequest {
                        session_id: args.session_id,
                        input_lease_id: args.lease_id,
                        client_instance_id: args.client_id,
                    },
                    &args.key,
                )
                .await?;
            println!(
                "lease_id={} expires_unix_ms={} released={}",
                response.input_lease_id, response.expires_unix_ms, response.released
            );
        }
        DriverCommand::Stop(args) => {
            print_record(
                &client
                    .session_stop(args.session_id, args.grace_seconds, &args.key)
                    .await?,
            );
        }
        DriverCommand::Kill(args) => {
            print_record(
                &client
                    .session_kill(args.session_id, args.signal, &args.key)
                    .await?,
            );
        }
        DriverCommand::Remove(args) => {
            print_record(
                &client
                    .session_remove(args.session_id, args.force, &args.key)
                    .await?,
            );
        }
        DriverCommand::Prune(args) => {
            let response = client
                .session_prune(
                    SessionPruneRequest {
                        terminal_before_unix_ms: args.before_unix_ms,
                        maximum_sessions: args.maximum_sessions,
                    },
                    &args.key,
                )
                .await?;
            println!(
                "pruned={} retained={}",
                response.pruned_sessions,
                response.retained_session_ids.join(",")
            );
        }
        DriverCommand::AdminList(args) => {
            for record in client
                .admin_session_list(args.uid, args.all_users)
                .await?
                .sessions
            {
                print_record(&record);
            }
        }
        DriverCommand::AdminInspect(args) => {
            print_record(
                &client
                    .admin_session_inspect(args.uid, args.session_id)
                    .await?,
            );
        }
        DriverCommand::AdminStop(args) => {
            print_record(
                &client
                    .admin_session_stop(
                        AdminSessionStopRequest {
                            target_uid: args.uid,
                            session_id: args.session_id,
                            grace_period_seconds: args.grace_seconds,
                        },
                        &args.key,
                    )
                    .await?,
            );
        }
        DriverCommand::AdminKill(args) => {
            print_record(
                &client
                    .admin_session_kill(
                        AdminSessionKillRequest {
                            target_uid: args.uid,
                            session_id: args.session_id,
                            signal: args.signal,
                        },
                        &args.key,
                    )
                    .await?,
            );
        }
        DriverCommand::AdminSetRetentionHold(args) => {
            print_record(
                &client
                    .admin_session_set_retention_hold(
                        AdminSessionSetRetentionHoldRequest {
                            target_uid: args.uid,
                            session_id: args.session_id,
                            retention_hold: args.retention_hold,
                        },
                        &args.key,
                    )
                    .await?,
            );
        }
    }
    Ok(())
}

fn print_record(record: &SessionRecord) {
    println!(
        "session_id={} state={} generation={} owner_uid={} runner={} runner_recovery={} failure={} retention_hold={} retry_expires_unix_ms={}",
        record.session_id,
        record.state,
        record.generation,
        record.owner_uid,
        record.runner_id,
        record.runner_recovery,
        record.failure,
        record.retention_hold,
        record.retry_guarantee_expires_unix_ms
    );
}
