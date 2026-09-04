use std::fs;
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use containerd_client::services::v1::{
    container::Runtime as ContainerRuntime, containers_client::ContainersClient,
    tasks_client::TasksClient, Container, CreateContainerRequest, CreateTaskRequest,
    DeleteContainerRequest, DeleteProcessRequest, DeleteTaskRequest, ExecProcessRequest,
    KillRequest, StartRequest, WaitRequest,
};
use containerd_client::tonic::Request;
use containerd_client::types::Mount as ContainerdMount;
use containerd_client::with_namespace;
use mithril_e2e::{
    run_effect_child, run_mount_move_child, run_mount_reconfigure_child, run_mount_setattr_child,
    EffectTestRunner,
};
use prost::Message as _;
use prost_types::Any as ProtobufAny;

#[derive(Parser)]
#[command(name = "mithril-effect-test")]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(hide = true)]
    Ctr {
        #[command(subcommand)]
        command: CtrCommand,
    },
    #[command(hide = true)]
    CompileRetainedIdentity {
        #[arg(long)]
        output_directory: PathBuf,
    },
    PhysicalProbe {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        lease_path: PathBuf,
        #[arg(long)]
        cgroup_path: PathBuf,
        #[arg(long, default_value_t = 6_000)]
        measured_opens: u32,
        #[arg(long, default_value_t = 50_000)]
        saturation_opens: u32,
        /// Promote the signed fixture from observation to physical denial.
        #[arg(long)]
        protect: bool,
    },
    ReplacementGenerationExceptionProbe {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        lease_path: PathBuf,
        #[arg(long)]
        cgroup_path: PathBuf,
    },
    RuncEntryRoleRuntimeProbe {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        lease_path: PathBuf,
        #[arg(long)]
        runc_path: PathBuf,
        #[arg(long, default_value = "/usr/bin/sleep")]
        workload_path: PathBuf,
        #[arg(long)]
        retained_bpf_object: PathBuf,
        #[arg(long)]
        containerd_path: Option<PathBuf>,
    },
    RuncRetainedRuntimeGateProbe {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        runc_path: PathBuf,
        #[arg(long)]
        hook_path: PathBuf,
        #[arg(long, default_value = "/usr/local/bin/k3s")]
        k3s_path: PathBuf,
        #[arg(long, default_value = "/usr/bin/nsenter")]
        nsenter_path: PathBuf,
    },
    #[command(hide = true)]
    Child {
        #[arg(long)]
        fixture_root: PathBuf,
        #[arg(long)]
        mailbox_path: PathBuf,
    },
    #[command(hide = true)]
    MountSetattr {
        #[arg(long)]
        namespace: PathBuf,
        #[arg(long)]
        path: PathBuf,
        #[arg(long, action = clap::ArgAction::Set)]
        read_only: bool,
    },
    #[command(hide = true)]
    MountReconfigure {
        #[arg(long)]
        namespace: PathBuf,
        #[arg(long)]
        path: PathBuf,
    },
    #[command(hide = true)]
    MountMove { source: PathBuf, target: PathBuf },
    #[command(hide = true)]
    OciStageFixture {
        #[arg(long)]
        stage: String,
        #[arg(long)]
        request_directory: PathBuf,
    },
    #[command(hide = true)]
    ContainerdStartFixture {
        #[arg(long)]
        socket_path: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        container_id: String,
        #[arg(long)]
        spec_path: PathBuf,
        #[arg(long)]
        rootfs_lower_path: PathBuf,
        #[arg(long)]
        rootfs_upper_path: PathBuf,
        #[arg(long)]
        rootfs_work_path: PathBuf,
        #[arg(long)]
        runc_path: PathBuf,
        #[arg(long)]
        pid_path: PathBuf,
        #[arg(long)]
        stdout_path: PathBuf,
        #[arg(long)]
        stderr_path: PathBuf,
    },
    #[command(hide = true)]
    ContainerdExecFixture {
        #[arg(long)]
        socket_path: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        container_id: String,
        #[arg(long)]
        exec_id: String,
        #[arg(long)]
        process_path: PathBuf,
        #[arg(long)]
        pid_path: PathBuf,
        #[arg(long)]
        stdout_path: PathBuf,
        #[arg(long)]
        stderr_path: PathBuf,
    },
    #[command(hide = true)]
    ContainerdCleanupFixture {
        #[arg(long)]
        socket_path: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        container_id: String,
    },
}

#[derive(Subcommand)]
enum CtrCommand {
    Oci {
        #[command(subcommand)]
        command: OciCommand,
    },
}

#[derive(Subcommand)]
enum OciCommand {
    Spec,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RuncOptions {
    #[prost(string, tag = "6")]
    binary_name: String,
    #[prost(bool, tag = "9")]
    systemd_cgroup: bool,
}

fn containerd_error(action: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("containerd {action} failed: {error}"))
}

struct ContainerdStartFixture {
    socket_path: PathBuf,
    namespace: String,
    container_id: String,
    spec_path: PathBuf,
    rootfs_lower_path: PathBuf,
    rootfs_upper_path: PathBuf,
    rootfs_work_path: PathBuf,
    runc_path: PathBuf,
    pid_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

struct ContainerdExecFixture {
    socket_path: PathBuf,
    namespace: String,
    container_id: String,
    exec_id: String,
    process_path: PathBuf,
    pid_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

async fn run_containerd_start_fixture(
    fixture: ContainerdStartFixture,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let channel = containerd_client::connect(&fixture.socket_path)
        .await
        .map_err(|error| containerd_error("connect", error))?;
    let spec = ProtobufAny {
        type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_owned(),
        value: fs::read(&fixture.spec_path)?,
    };
    let options = RuncOptions {
        binary_name: fixture.runc_path.display().to_string(),
        systemd_cgroup: true,
    };
    let runtime_options = ProtobufAny {
        type_url: "types.containerd.io/containerd.runc.v1.Options".to_owned(),
        value: options.encode_to_vec(),
    };
    let container = Container {
        id: fixture.container_id.clone(),
        runtime: Some(ContainerRuntime {
            name: "io.containerd.runc.v2".to_owned(),
            options: Some(runtime_options),
        }),
        spec: Some(spec),
        ..Default::default()
    };
    let mut containers = ContainersClient::new(channel.clone());
    containers
        .create(with_namespace!(
            CreateContainerRequest {
                container: Some(container),
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("container create", error))?;

    let mut tasks = TasksClient::new(channel);
    tasks
        .create(with_namespace!(
            CreateTaskRequest {
                container_id: fixture.container_id.clone(),
                rootfs: vec![ContainerdMount {
                    r#type: "overlay".to_owned(),
                    source: "overlay".to_owned(),
                    target: String::new(),
                    options: vec![
                        format!("workdir={}", fixture.rootfs_work_path.display()),
                        format!("upperdir={}", fixture.rootfs_upper_path.display()),
                        format!("lowerdir={}", fixture.rootfs_lower_path.display()),
                    ],
                }],
                stdin: "/dev/null".to_owned(),
                stdout: fixture.stdout_path.display().to_string(),
                stderr: fixture.stderr_path.display().to_string(),
                ..Default::default()
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("task create", error))?;
    let response = tasks
        .start(with_namespace!(
            StartRequest {
                container_id: fixture.container_id.clone(),
                exec_id: String::new(),
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("task start", error))?
        .into_inner();
    fs::write(&fixture.pid_path, response.pid.to_string())?;
    let response = tasks
        .wait(with_namespace!(
            WaitRequest {
                container_id: fixture.container_id,
                exec_id: String::new(),
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("task wait", error))?
        .into_inner();
    if response.exit_status != 0 {
        return Err(containerd_error(
            "task process",
            format!("exited with status {}", response.exit_status),
        )
        .into());
    }
    Ok(())
}

async fn run_containerd_exec_fixture(
    fixture: ContainerdExecFixture,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let channel = containerd_client::connect(&fixture.socket_path)
        .await
        .map_err(|error| containerd_error("connect", error))?;
    let mut tasks = TasksClient::new(channel);
    tasks
        .exec(with_namespace!(
            ExecProcessRequest {
                container_id: fixture.container_id.clone(),
                stdin: "/dev/null".to_owned(),
                stdout: fixture.stdout_path.display().to_string(),
                stderr: fixture.stderr_path.display().to_string(),
                terminal: false,
                spec: Some(ProtobufAny {
                    type_url: "types.containerd.io/opencontainers/runtime-spec/1/Process"
                        .to_owned(),
                    value: fs::read(&fixture.process_path)?,
                }),
                exec_id: fixture.exec_id.clone(),
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("exec create", error))?;
    let response = tasks
        .start(with_namespace!(
            StartRequest {
                container_id: fixture.container_id.clone(),
                exec_id: fixture.exec_id.clone(),
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("exec start", error))?
        .into_inner();
    fs::write(&fixture.pid_path, response.pid.to_string())?;
    let response = tasks
        .wait(with_namespace!(
            WaitRequest {
                container_id: fixture.container_id.clone(),
                exec_id: fixture.exec_id.clone(),
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("exec wait", error))?
        .into_inner();
    tasks
        .delete_process(with_namespace!(
            DeleteProcessRequest {
                container_id: fixture.container_id,
                exec_id: fixture.exec_id,
            },
            fixture.namespace
        ))
        .await
        .map_err(|error| containerd_error("exec delete", error))?;
    if response.exit_status != 0 {
        return Err(containerd_error(
            "exec process",
            format!("exited with status {}", response.exit_status),
        )
        .into());
    }
    Ok(())
}

async fn run_containerd_cleanup_fixture(
    socket_path: &Path,
    namespace: &str,
    container_id: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let channel = containerd_client::connect(socket_path)
        .await
        .map_err(|error| containerd_error("connect", error))?;
    let mut tasks = TasksClient::new(channel.clone());
    let kill = tasks
        .kill(with_namespace!(
            KillRequest {
                container_id: container_id.to_owned(),
                exec_id: String::new(),
                signal: libc::SIGKILL as u32,
                all: true,
            },
            namespace
        ))
        .await;
    if let Err(error) = kill {
        if !matches!(
            error.code(),
            containerd_client::tonic::Code::NotFound
                | containerd_client::tonic::Code::FailedPrecondition
        ) {
            return Err(containerd_error("task kill", error).into());
        }
    }
    let wait = tasks
        .wait(with_namespace!(
            WaitRequest {
                container_id: container_id.to_owned(),
                exec_id: String::new(),
            },
            namespace
        ))
        .await;
    if let Err(error) = wait {
        if error.code() != containerd_client::tonic::Code::NotFound {
            return Err(containerd_error("task wait", error).into());
        }
    }
    let delete = tasks
        .delete(with_namespace!(
            DeleteTaskRequest {
                container_id: container_id.to_owned(),
            },
            namespace
        ))
        .await;
    if let Err(error) = delete {
        if error.code() != containerd_client::tonic::Code::NotFound {
            return Err(containerd_error("task delete", error).into());
        }
    }
    let mut containers = ContainersClient::new(channel);
    let delete = containers
        .delete(with_namespace!(
            DeleteContainerRequest {
                id: container_id.to_owned(),
            },
            namespace
        ))
        .await;
    if let Err(error) = delete {
        if error.code() != containerd_client::tonic::Code::NotFound {
            return Err(containerd_error("container delete", error).into());
        }
    }
    Ok(())
}

struct OciStageFixtureOwner;

impl OciStageFixtureOwner {
    const MAXIMUM_STATE_BYTES: u64 = 1_048_576;

    fn invalid(reason: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, reason.into())
    }

    fn runtime_cgroup(pid: u32) -> io::Result<String> {
        let source = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let cgroup = source
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .filter(|path| path.starts_with('/') && path.len() > 1)
            .ok_or_else(|| Self::invalid("the OCI task has no unified cgroup"))?;
        let tasks = fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/cgroup.procs"))?;
        let live = tasks
            .lines()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| Self::invalid(format!("the OCI cgroup is invalid: {error}")))?;
        if live.as_slice() != [pid] {
            return Err(Self::invalid(
                "the createRuntime cgroup does not contain only the OCI task",
            ));
        }
        Ok(cgroup.to_owned())
    }

    fn run(stage: &str, request_directory: &Path) -> io::Result<()> {
        if !matches!(stage, "createRuntime" | "createContainer") {
            return Err(Self::invalid("the OCI fixture stage is invalid"));
        }
        let metadata = fs::symlink_metadata(request_directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(Self::invalid(
                "the OCI request directory is not a root-owned mode-0700 directory",
            ));
        }
        let mut bytes = Vec::new();
        io::stdin()
            .take(Self::MAXIMUM_STATE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > Self::MAXIMUM_STATE_BYTES as usize {
            return Err(Self::invalid("the OCI state exceeds its byte limit"));
        }
        let state: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| Self::invalid(format!("the OCI state is invalid: {error}")))?;
        let pid = state
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(|| Self::invalid("the OCI state has no task PID"))?;
        let container_id = state
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| Self::invalid("the OCI state has no exact container ID"))?;
        let annotations = state
            .get("annotations")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| Self::invalid("the OCI state has no annotations"))?;
        if annotations
            .get("io.kubernetes.cri.container-type")
            .and_then(serde_json::Value::as_str)
            != Some("container")
        {
            return Ok(());
        }
        let cgroup = (stage == "createRuntime")
            .then(|| Self::runtime_cgroup(pid))
            .transpose()?;
        let request = request_directory.join(format!("{container_id}.{stage}.json"));
        let release = request_directory.join(format!("{container_id}.{stage}.release"));
        if request.exists() || release.exists() {
            return Err(Self::invalid("the OCI stage request already exists"));
        }
        let temporary = request_directory.join(format!(
            ".{container_id}.{stage}.{}.tmp",
            std::process::id()
        ));
        fs::write(
            &temporary,
            serde_json::to_vec(&serde_json::json!({
                "stage": stage,
                "pid": pid,
                "cgroup": cgroup,
                "state": state,
                "annotations": annotations,
            }))
            .map_err(|error| Self::invalid(format!("the OCI request is invalid: {error}")))?,
        )?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temporary, &request)?;

        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if release.is_file() {
                let response = fs::read_to_string(&release)?;
                fs::remove_file(&request)?;
                fs::remove_file(&release)?;
                let expected = if stage == "createRuntime" {
                    format!("accepted:{pid}")
                } else {
                    "accepted".to_owned()
                };
                if response != expected {
                    return Err(Self::invalid("the OCI stage was rejected"));
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(Self::invalid("the OCI stage timed out"))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Ctr {
            command: CtrCommand::Oci {
                command: OciCommand::Spec,
            },
        } => {
            println!(r#"{{"ociVersion":"1.2.0"}}"#);
            Ok(())
        }
        Command::CompileRetainedIdentity { output_directory } => {
            let runner = EffectTestRunner::new(cli.repo_root);
            let record = runner.compile_retained_identity_fixture(&output_directory)?;
            runner.write_json(
                &output_directory.join("retained-identity-compile.json"),
                &record,
            )?;
            println!("Mithril retained identity fixture compiled successfully");
            Ok(())
        }
        Command::PhysicalProbe {
            output_directory,
            pin_root,
            lease_path,
            cgroup_path,
            measured_opens,
            saturation_opens,
            protect,
        } => {
            let runner = EffectTestRunner::new(cli.repo_root);
            let bundle = runner.physical_probe(
                &output_directory,
                &pin_root,
                &lease_path,
                &cgroup_path,
                measured_opens,
                saturation_opens,
                protect,
            )?;
            runner.write_json(
                &output_directory.join("effect-physical-probe.json"),
                &bundle,
            )?;
            println!("Mithril effect physical probe passed");
            Ok(())
        }
        Command::ReplacementGenerationExceptionProbe {
            output_directory,
            pin_root,
            lease_path,
            cgroup_path,
        } => {
            let runner = EffectTestRunner::new(cli.repo_root);
            let result = runner.replacement_generation_exception_probe(
                &output_directory,
                &pin_root,
                &lease_path,
                &cgroup_path,
            )?;
            runner.write_json(
                &output_directory.join("replacement-generation-exception-probe.json"),
                &result,
            )?;
            println!("Mithril replacement-generation exception probe passed");
            Ok(())
        }
        Command::RuncEntryRoleRuntimeProbe {
            output_directory,
            pin_root,
            lease_path,
            runc_path,
            workload_path,
            retained_bpf_object,
            containerd_path,
        } => {
            let runner = EffectTestRunner::new(cli.repo_root);
            let result = runner.runc_entry_role_runtime_probe(
                &output_directory,
                &pin_root,
                &lease_path,
                &runc_path,
                &workload_path,
                &retained_bpf_object,
                containerd_path.as_deref(),
            )?;
            runner.write_json(
                &output_directory.join("runc-entry-role-runtime-probe.json"),
                &result,
            )?;
            println!("Mithril direct runc entry-role probe passed");
            Ok(())
        }
        Command::ContainerdStartFixture {
            socket_path,
            namespace,
            container_id,
            spec_path,
            rootfs_lower_path,
            rootfs_upper_path,
            rootfs_work_path,
            runc_path,
            pid_path,
            stdout_path,
            stderr_path,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run_containerd_start_fixture(ContainerdStartFixture {
                socket_path,
                namespace,
                container_id,
                spec_path,
                rootfs_lower_path,
                rootfs_upper_path,
                rootfs_work_path,
                runc_path,
                pid_path,
                stdout_path,
                stderr_path,
            })),
        Command::ContainerdExecFixture {
            socket_path,
            namespace,
            container_id,
            exec_id,
            process_path,
            pid_path,
            stdout_path,
            stderr_path,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run_containerd_exec_fixture(ContainerdExecFixture {
                socket_path,
                namespace,
                container_id,
                exec_id,
                process_path,
                pid_path,
                stdout_path,
                stderr_path,
            })),
        Command::ContainerdCleanupFixture {
            socket_path,
            namespace,
            container_id,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run_containerd_cleanup_fixture(
                &socket_path,
                &namespace,
                &container_id,
            )),
        Command::RuncRetainedRuntimeGateProbe {
            output_directory,
            runc_path,
            hook_path,
            k3s_path,
            nsenter_path,
        } => {
            let runner = EffectTestRunner::new(cli.repo_root);
            let result = runner.runc_retained_runtime_gate_probe(
                &output_directory,
                &runc_path,
                &hook_path,
                &k3s_path,
                &nsenter_path,
            )?;
            runner.write_json(
                &output_directory.join("runc-retained-runtime-gate-probe.json"),
                &result,
            )?;
            println!("Mithril direct runc retained runtime-gate probe passed");
            Ok(())
        }
        Command::Child {
            fixture_root,
            mailbox_path,
        } => Ok(run_effect_child(&fixture_root, &mailbox_path)?),
        Command::MountSetattr {
            namespace,
            path,
            read_only,
        } => Ok(run_mount_setattr_child(&namespace, &path, read_only)?),
        Command::MountReconfigure { namespace, path } => {
            Ok(run_mount_reconfigure_child(&namespace, &path)?)
        }
        Command::MountMove { source, target } => Ok(run_mount_move_child(&source, &target)?),
        Command::OciStageFixture {
            stage,
            request_directory,
        } => Ok(OciStageFixtureOwner::run(&stage, &request_directory)?),
    }
}
