use std::net::SocketAddr;

use erebor_runtime_cdp::BrowserCdpSurface;
use erebor_runtime_core::{
    RuntimeConfig, SessionAdoptPlan, SessionRunPlan, SessionRunnerKind, SessionSurfaceDefinition,
    SessionSurfaceKind, SessionSurfaceLaunchPlan, SessionSurfaceLauncher,
};
use erebor_runtime_filesystem::LinuxOverlaySessionView;
use snafu::ResultExt;

use crate::{
    error::{FilesystemSurfaceSnafu, InvalidAdoptTargetSnafu, InvalidConfigSnafu, RuntimeSnafu},
    policies::read_policy_set,
    registry_lifecycle::PreparedSession,
    session_context::{CdpSessionContexts, SessionPlanContext},
    session_resources::{SessionResourceLifetime, SessionSideResources},
    SessionExecutionError,
};

pub(crate) fn start_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionRunPlan,
    prepared_session: Option<&PreparedSession>,
) -> Result<SessionSideResources, SessionExecutionError> {
    let start_plan = config
        .surface_start_plan_for_session(plan)
        .context(InvalidConfigSnafu)?;
    start_session_side_resources_from_start_plan(plan, start_plan, prepared_session)
}

pub(crate) fn start_adopt_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionAdoptPlan,
) -> Result<SessionSideResources, SessionExecutionError> {
    if plan.runner().kind() == SessionRunnerKind::LinuxHost {
        return InvalidAdoptTargetSnafu {
            reason: String::from(
                "linux-host adoption is unavailable because its removed interception backend has no replacement",
            ),
        }
        .fail();
    }
    let start_plan = config
        .surface_start_plan_for_runner_kind(plan.runner().kind())
        .context(InvalidConfigSnafu)?;
    start_session_side_resources_from_start_plan(plan, start_plan, None)
}

fn start_session_side_resources_from_start_plan(
    plan: &impl SessionPlanContext,
    start_plan: erebor_runtime_core::SessionSurfaceStartPlan,
    prepared_session: Option<&PreparedSession>,
) -> Result<SessionSideResources, SessionExecutionError> {
    if start_plan.surfaces().is_empty() {
        return Ok(SessionSideResources::default());
    }
    let launch_plan = SessionSurfaceLaunchPlan::from_start_plan(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &start_plan,
    )
    .context(RuntimeSnafu)?;
    let mut launcher = SessionSurfaceLauncher::new(launch_plan.control_listen());
    let mut environment = Vec::new();
    let mut filesystem_overlay_wrapper = None;

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                let policy_set = read_policy_set(config.policies())?;
                let mut surface = BrowserCdpSurface::new(
                    config.clone(),
                    policy_set,
                    CdpSessionContexts::from_plan(plan),
                )
                .with_audit_config(plan.audit().clone());
                if let Some(audit_jsonl) =
                    prepared_session.map(|session| session.storage().audit_path())
                {
                    surface = surface.with_audit_jsonl(audit_jsonl.to_path_buf());
                }
                launcher.add_surface(surface);
            }
            SessionSurfaceDefinition::Terminal(config) => {
                environment.push((
                    String::from("EREBOR_TERMINAL_SURFACE"),
                    String::from("terminal"),
                ));
                environment.push((
                    String::from("EREBOR_TERMINAL_TTY"),
                    config.tty().to_string(),
                ));
            }
            SessionSurfaceDefinition::Filesystem(_config) => {
                environment.push((
                    String::from("EREBOR_FILESYSTEM_SURFACE"),
                    String::from("filesystem"),
                ));
                if let Some(storage) = prepared_session
                    .map(PreparedSession::storage)
                    .and_then(|storage| storage.filesystem())
                {
                    environment.push((
                        String::from("EREBOR_FILESYSTEM_SESSION_DIR"),
                        storage.root().display().to_string(),
                    ));
                    environment.push((
                        String::from("EREBOR_FILESYSTEM_REPO"),
                        storage.repo_path().display().to_string(),
                    ));
                    if plan.runner_kind() == SessionRunnerKind::LinuxHost {
                        let overlay_view = LinuxOverlaySessionView::prepare(storage)
                            .context(FilesystemSurfaceSnafu)?;
                        let wrapper_path = overlay_view.wrapper_path().to_path_buf();
                        environment.push((
                            String::from("EREBOR_FILESYSTEM_OVERLAY_WRAPPER"),
                            wrapper_path.display().to_string(),
                        ));
                        filesystem_overlay_wrapper = Some(wrapper_path);
                    }
                }
            }
        }
    }

    let supervisor = if launcher.is_empty() {
        None
    } else {
        let supervisor = launcher.start().context(RuntimeSnafu)?;
        for runtime in supervisor.running() {
            if runtime.surface() == SessionSurfaceKind::BrowserCdp {
                environment.push((
                    String::from("EREBOR_BROWSER_CDP_URL"),
                    runtime.endpoint().to_owned(),
                ));
                environment.push((
                    String::from("EREBOR_OPENCLAW_BROWSER_PROFILE"),
                    String::from("erebor"),
                ));
            }
        }
        Some(supervisor)
    };
    let mut resources = SessionSideResources::new(
        environment,
        Default::default(),
        Default::default(),
        SessionResourceLifetime::new(supervisor),
    );
    if let Some(wrapper) = filesystem_overlay_wrapper {
        resources.add_linux_host_outer_wrapper(wrapper);
    }
    Ok(resources)
}
