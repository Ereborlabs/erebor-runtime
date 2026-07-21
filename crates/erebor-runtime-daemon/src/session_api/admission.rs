use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::{
    DaemonFailureMode, EvidenceRequirement, ImmutableIdentity, OutputPlan,
    OutputStreamRequirements, RunRequest, RunnerCapabilityDocument, RunnerId, SessionAdmission,
    SessionOwner, SessionSpec,
};
use erebor_runtime_events::SessionId;
use erebor_runtime_ipc::v1::SessionCreateRequest;

use crate::{
    config::DaemonConfig, error::InvalidRequestSnafu, local_store::DaemonLocalStore, Result,
};
use erebor_runtime_session::RunnerExecutionAdmission;

pub(super) struct AdmissionContext<'a> {
    pub(super) owner: SessionOwner,
    pub(super) session_id: &'a str,
    pub(super) root_configuration_generation: u64,
    pub(super) state_root: &'a Path,
    pub(super) capability: RunnerCapabilityDocument,
    pub(super) runner_admission: RunnerExecutionAdmission,
    pub(super) local_store: &'a DaemonLocalStore,
    pub(super) config: &'a DaemonConfig,
}

pub(super) fn parse_request(request: SessionCreateRequest) -> Result<RunRequest> {
    let runner = RunnerId::new(request.runner_id).map_err(invalid_spec)?;
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
    RunRequest::new(
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
    .map_err(invalid_spec)
}

pub(super) fn admit(run_request: RunRequest, context: AdmissionContext<'_>) -> Result<SessionSpec> {
    let package_digest = required_identity(run_request.package_sha256(), "package")?;
    let installation_digest = required_identity(run_request.installation_sha256(), "installation")?;
    let adapter_digest = required_identity(run_request.adapter_sha256(), "adapter")?;
    let admission = context.local_store.resolve_admission(
        context.owner.uid(),
        package_digest,
        installation_digest,
        adapter_digest,
        run_request.policy_set_sha256(),
    )?;
    if run_request.runner() != context.capability.runner() {
        return InvalidRequestSnafu {
            reason: String::from("selected runner does not match its capability document"),
        }
        .fail();
    }
    let loss_grace_seconds = run_request
        .requested_loss_grace_seconds()
        .min(context.config.max_daemon_loss_grace_seconds);
    let output_root = context
        .state_root
        .join("users")
        .join(context.owner.uid().to_string())
        .join("sessions")
        .join(context.session_id)
        .join("output");
    let RunnerExecutionAdmission {
        workspace,
        workload_privileges,
        executable,
        container_image,
        filesystem_projections,
        endpoint_projections,
    } = context.runner_admission;
    SessionSpec::new(SessionAdmission {
        session_id: SessionId::new(context.session_id),
        owner: context.owner,
        workload_privileges,
        command: run_request.command().to_vec(),
        package: identity("agent-package", Some(admission.package_digest()))?,
        installation: identity("installation", Some(admission.installation_digest()))?,
        adapter: identity("adapter", Some(admission.adapter_digest()))?,
        policy_inputs: admission
            .policy_input_digests()
            .iter()
            .map(|digest| ImmutableIdentity::new("policy-input", digest).map_err(invalid_spec))
            .collect::<Result<Vec<_>>>()?,
        policy_set: ImmutableIdentity::new("policy-set", admission.policy_set_digest())
            .map_err(invalid_spec)?,
        runner_capability: context.capability,
        workspace,
        executable,
        container_image,
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

fn required_identity<'a>(digest: Option<&'a str>, kind: &str) -> Result<&'a str> {
    digest.ok_or_else(|| {
        InvalidRequestSnafu {
            reason: format!("generic session admission requires an exact {kind} digest"),
        }
        .build()
    })
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
