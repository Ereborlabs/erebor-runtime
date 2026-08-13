use std::path::PathBuf;

use clap::{Parser, Subcommand};
use erebor_runtime_client::MithrilObservationClient;
use mithril_node::{ExactFileObjectResolver, NativeIdentityInspector};

#[derive(Parser)]
#[command(about = "Inspect live Mithril node identity without taking ownership")]
struct Cli {
    #[arg(long)]
    pin_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Task {
        #[arg(long)]
        host_pid: u32,
    },
    Effects {
        #[arg(long)]
        socket_path: PathBuf,
        #[arg(long)]
        cgroup_scope: String,
    },
    FileObject {
        #[arg(long)]
        root_pid: u32,
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        profile_generation: u64,
        #[arg(long)]
        exact_object_key: u64,
        #[arg(long)]
        object_class: String,
        #[arg(long)]
        inode_generation: u32,
        #[arg(long)]
        device_class: Option<String>,
    },
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
        Command::Task { host_pid } => {
            let pin_root = cli
                .pin_root
                .ok_or("--pin-root is required for task inspection")?;
            println!(
                "{}",
                NativeIdentityInspector::new(pin_root).snapshot_json(host_pid)?
            );
        }
        Command::Effects {
            socket_path,
            cgroup_scope,
        } => {
            let snapshot = MithrilObservationClient::new(socket_path, cgroup_scope)
                .snapshot()
                .await?;
            println!(
                "attempted={} emitted={} lost={} unresolved={} decoder_errors={} health_available={}",
                snapshot.attempted_effects,
                snapshot.emitted_effects,
                snapshot.lost_effects,
                snapshot.unresolved_effects,
                snapshot.decoder_errors,
                snapshot.effect_health_available
            );
            for capability in snapshot.capabilities {
                println!(
                    "capability={} state={} reason={}",
                    capability.capability_id, capability.state, capability.reason_code
                );
            }
            for effect in snapshot.recent_effects {
                println!(
                    "task_cookie={} family={} operation={} reason={} result={} object={}:{}:{}:{}:{} exact_object_key_id={} composite_atom_id={} kernel_result={}",
                    effect.task_cookie,
                    effect.effect_family,
                    effect.operation,
                    effect.reason,
                    effect.physical_result,
                    effect.mount_namespace_inode,
                    effect.mount_id_unique,
                    effect.filesystem_device,
                    effect.inode,
                    effect.inode_generation,
                    effect.exact_object_key_id,
                    effect.composite_atom_id,
                    effect.kernel_result,
                );
            }
        }
        Command::FileObject {
            root_pid,
            path,
            profile_generation,
            exact_object_key,
            object_class,
            inode_generation,
            device_class,
        } => println!(
            "{}",
            serde_json::to_string_pretty(&ExactFileObjectResolver::resolve(
                root_pid,
                &path,
                profile_generation,
                exact_object_key,
                object_class,
                inode_generation,
                device_class,
            )?)?
        ),
    }
    Ok(())
}
