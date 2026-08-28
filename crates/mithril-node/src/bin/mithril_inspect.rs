use std::{collections::BTreeSet, path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use erebor_runtime_client::MithrilObservationClient;
use mithril_node::{policy_delivery_status, ExactFileObjectResolver, NativeIdentityInspector};

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
        #[arg(long, default_value_t = 1)]
        samples: u32,
        #[arg(long, default_value_t = 10)]
        sample_interval_ms: u64,
        #[arg(long = "reason")]
        reasons: Vec<String>,
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
        inode_generation: u64,
        #[arg(long)]
        device_class: Option<String>,
    },
    PolicyDelivery {
        #[arg(long)]
        state_directory: PathBuf,
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
            samples,
            sample_interval_ms,
            reasons,
        } => {
            if !(1..=6_000).contains(&samples) || !(1..=1_000).contains(&sample_interval_ms) {
                return Err(
                    "effect samples or sample interval is outside the bounded range".into(),
                );
            }
            if reasons.len() > 16
                || reasons
                    .iter()
                    .any(|reason| reason.is_empty() || reason.len() > 64)
            {
                return Err("effect reason filters are outside the bounded range".into());
            }
            let client = MithrilObservationClient::new(socket_path, cgroup_scope);
            let mut seen = BTreeSet::new();
            for sample in 0..samples {
                let snapshot = client.snapshot().await?;
                if sample == 0 {
                    println!(
                        "attempted={} emitted={} lost={} unresolved={} decoder_errors={} evidence_errors={} wal_capacity_blocked={} wal_rewritten_records={} wal_rewritten_bytes={} reader_settle_timeouts={} health_available={}",
                        snapshot.attempted_effects,
                        snapshot.emitted_effects,
                        snapshot.lost_effects,
                        snapshot.unresolved_effects,
                        snapshot.decoder_errors,
                        snapshot.evidence_errors,
                        snapshot.wal_capacity_blocked,
                        snapshot.wal_rewritten_records,
                        snapshot.wal_rewritten_bytes,
                        snapshot.reader_settle_timeouts,
                        snapshot.effect_health_available
                    );
                    for capability in snapshot.capabilities {
                        println!(
                            "capability={} state={} reason={}",
                            capability.capability_id, capability.state, capability.reason_code
                        );
                    }
                }
                for effect in snapshot.recent_effects {
                    if !effect_reason_selected(&reasons, &effect.reason) {
                        continue;
                    }
                    let line = format!(
                    "observed_boottime_ns={} task_cookie={} target_task_cookie={} admitted_entry_rule_id={} active_role_id={} family={} operation={} operation_argument={} reason={} result={} object={}:{}:{}:{}:{} exact_object_key_id={} composite_atom_id={} kernel_result={}",
                    effect.observed_boottime_ns,
                    effect.task_cookie,
                    effect.target_task_cookie,
                    effect.admitted_entry_rule_id,
                    effect.active_role_id,
                    effect.effect_family,
                    effect.operation,
                    effect.operation_argument,
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
                    if seen.insert(line.clone()) {
                        println!("{line}");
                    }
                }
                if sample + 1 < samples {
                    tokio::time::sleep(Duration::from_millis(sample_interval_ms)).await;
                }
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
        Command::PolicyDelivery { state_directory } => println!(
            "{}",
            serde_json::to_string_pretty(&policy_delivery_status(&state_directory)?)?
        ),
    }
    Ok(())
}

fn effect_reason_selected(reasons: &[String], observed: &str) -> bool {
    reasons.is_empty() || reasons.iter().any(|reason| reason == observed)
}

#[cfg(test)]
mod tests {
    use super::effect_reason_selected;

    #[test]
    fn effect_reason_filter_keeps_only_requested_reasons() {
        assert!(effect_reason_selected(&[], "UNSUPPORTED_OBJECT"));
        assert!(effect_reason_selected(
            &["APPLICATION_DEFAULT_ALLOW".to_owned()],
            "APPLICATION_DEFAULT_ALLOW"
        ));
        assert!(!effect_reason_selected(
            &["APPLICATION_DEFAULT_ALLOW".to_owned()],
            "UNSUPPORTED_OBJECT"
        ));
    }
}
