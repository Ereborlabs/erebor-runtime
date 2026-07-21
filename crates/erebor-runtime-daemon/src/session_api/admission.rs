use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{
    DaemonFailureMode, EndpointProjection, EvidenceRequirement, FilesystemProjection,
    ImmutableIdentity, OutputPlan, OutputStreamRequirements, RunRequest, RunnerCapabilityDocument,
    SafePathKind, SessionAdmission, SessionOwner, SessionRunnerKind, SessionSpec,
    WorkloadPrivilegePlan,
};
use erebor_runtime_events::SessionId;
use erebor_runtime_ipc::v1::SessionCreateRequest;

use crate::{
    config::DaemonConfig, error::InvalidRequestSnafu, path_broker::DescriptorBroker, Result,
};

pub(super) struct AdmissionContext<'a> {
    pub(super) owner_uid: u32,
    pub(super) owner_gid: u32,
    pub(super) session_id: &'a str,
    pub(super) root_configuration_generation: u64,
    pub(super) state_root: &'a Path,
    pub(super) runtime_root: &'a Path,
    pub(super) capability: RunnerCapabilityDocument,
    pub(super) config: &'a DaemonConfig,
    pub(super) descriptor_broker: &'a DescriptorBroker,
}

pub(super) fn admit(
    request: SessionCreateRequest,
    context: AdmissionContext<'_>,
) -> Result<SessionSpec> {
    let runner = parse_runner(&request.runner_id)?;
    let failure_mode = parse_failure_mode(&request.daemon_failure_mode)?;
    let package_digest = optional(request.package_digest);
    let installation_digest = optional(request.installation_digest);
    let adapter_digest = optional(request.adapter_digest);
    let image_digest = optional(request.container_image_digest);
    let environment = request
        .environment
        .into_iter()
        .map(|entry| (entry.key, entry.value))
        .collect::<Vec<_>>();
    let run_request = RunRequest::new(
        runner,
        request.command,
        PathBuf::from(request.workspace),
        request.policy_set_digest,
        package_digest,
        installation_digest,
        adapter_digest,
        image_digest,
        environment,
        request.secret_references,
        request.tty,
        request.detached,
        failure_mode,
        request.requested_loss_grace_seconds,
    )
    .map_err(invalid_spec)?;
    let fixture = context
        .config
        .phase_two_fixture(
            run_request.package_sha256(),
            run_request.installation_sha256(),
            run_request.adapter_sha256(),
            run_request.policy_set_sha256(),
        )
        .ok_or_else(|| {
            InvalidRequestSnafu {
            reason: String::from(
                    "package, installation, adapter, and policy identities do not match an operator-admitted Phase 2 validated fixture",
            ),
        }
            .build()
        })?;
    if run_request.runner() != context.capability.runner() {
        return InvalidRequestSnafu {
            reason: String::from("selected runner does not match its capability document"),
        }
        .fail();
    }
    let workspace = context
        .descriptor_broker
        .resolve(
            context.owner_uid,
            context.owner_gid,
            run_request.workspace(),
            SafePathKind::Directory,
        )?
        .binding()
        .clone();
    let executable = if runner == SessionRunnerKind::LinuxHost {
        let program = run_request.command().first().ok_or_else(|| {
            InvalidRequestSnafu {
                reason: String::from("Linux-host session requires an executable"),
            }
            .build()
        })?;
        Some(
            context
                .descriptor_broker
                .resolve(
                    context.owner_uid,
                    context.owner_gid,
                    Path::new(program),
                    SafePathKind::Executable,
                )?
                .binding()
                .clone(),
        )
    } else {
        None
    };
    let loss_grace_seconds = run_request
        .requested_loss_grace_seconds()
        .min(context.config.max_daemon_loss_grace_seconds);
    let output_root = context
        .state_root
        .join("users")
        .join(context.owner_uid.to_string())
        .join("sessions")
        .join(context.session_id)
        .join("output");
    let runtime_guard_host_path = context
        .runtime_root
        .join(context.owner_uid.to_string())
        .join(context.session_id)
        .join("runtime-interception.sock");
    let endpoint_projections = (runner == SessionRunnerKind::LinuxHost)
        .then(|| {
            EndpointProjection::new(
                "runtime-guard",
                runtime_guard_host_path,
                PathBuf::from("/run/erebor/runtime-interception.sock"),
            )
            .map_err(invalid_spec)
        })
        .transpose()?
        .into_iter()
        .collect();
    let filesystem_projections =
        vec![
            FilesystemProjection::new(workspace.clone(), PathBuf::from("/workspace"), false)
                .map_err(invalid_spec)?,
        ];
    SessionSpec::new(SessionAdmission {
        session_id: SessionId::new(context.session_id),
        owner: SessionOwner::new(context.owner_uid, context.owner_gid),
        workload_privileges: WorkloadPrivilegePlan::new(
            Vec::new(),
            if runner == SessionRunnerKind::Docker {
                0o022
            } else {
                0o077
            },
            1024,
            512,
            0,
        )
        .map_err(invalid_spec)?,
        command: run_request.command().to_vec(),
        package: identity("agent-package", run_request.package_sha256())?,
        installation: identity("installation", run_request.installation_sha256())?,
        adapter: identity("adapter", run_request.adapter_sha256())?,
        policy_inputs: fixture
            .policy_input_digests()
            .iter()
            .map(|digest| ImmutableIdentity::new("policy-input", digest).map_err(invalid_spec))
            .collect::<Result<Vec<_>>>()?,
        policy_set: ImmutableIdentity::new("policy-set", run_request.policy_set_sha256())
            .map_err(invalid_spec)?,
        runner_capability: context.capability,
        workspace,
        executable,
        container_image: identity("container-image", run_request.container_image_sha256())?,
        environment: run_request.environment().to_vec(),
        secret_references: run_request.secret_references().to_vec(),
        filesystem_projections,
        endpoint_projections,
        output: OutputPlan::new(
            output_root,
            context.config.max_session_output_bytes,
            context.config.session_output_rotation_bytes,
            256,
            OutputStreamRequirements::required(),
        )
        .map_err(invalid_spec)?,
        evidence_requirements: vec![
            EvidenceRequirement::new("governance-audit", true).map_err(invalid_spec)?
        ],
        tty: run_request.tty(),
        detached: run_request.detached(),
        daemon_failure_mode: run_request.daemon_failure_mode(),
        loss_grace_seconds,
        root_configuration_generation: context.root_configuration_generation,
        created_at_unix_ms: unix_time_ms(),
    })
    .map_err(invalid_spec)
}

fn parse_runner(value: &str) -> Result<SessionRunnerKind> {
    match value {
        "linux-host" | "linux_host" => Ok(SessionRunnerKind::LinuxHost),
        "docker" => Ok(SessionRunnerKind::Docker),
        _ => InvalidRequestSnafu {
            reason: format!("unknown runner `{value}`"),
        }
        .fail(),
    }
}

fn parse_failure_mode(value: &str) -> Result<DaemonFailureMode> {
    match value {
        "terminate" => Ok(DaemonFailureMode::Terminate),
        "continue" => Ok(DaemonFailureMode::Continue),
        "continue_if_enforced" => Ok(DaemonFailureMode::ContinueIfEnforced),
        _ => InvalidRequestSnafu {
            reason: format!("unknown daemon failure mode `{value}`"),
        }
        .fail(),
    }
}

fn identity(kind: &str, digest: Option<&str>) -> Result<Option<ImmutableIdentity>> {
    digest
        .map(|digest| ImmutableIdentity::new(kind, digest).map_err(invalid_spec))
        .transpose()
}

fn optional(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn invalid_spec(source: erebor_runtime_core::SessionSpecError) -> crate::DaemonError {
    InvalidRequestSnafu {
        reason: source.to_string(),
    }
    .build()
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}
