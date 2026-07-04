use std::net::SocketAddr;

use erebor_runtime_cdp::BrowserCdpSurface;
use erebor_runtime_core::{
    RuntimeConfig, SessionAdoptPlan, SessionInterceptionOperation, SessionRunPlan,
    SessionRunnerKind, SessionSurfaceDefinition, SessionSurfaceKind, SessionSurfaceLaunchPlan,
    SessionSurfaceLauncher,
};
use snafu::ResultExt;

use crate::{
    error::{GuardConfigSnafu, InvalidConfigSnafu, RuntimeSnafu},
    interception_backend::{FileOperationInterceptionInput, SessionInterceptionBackendBundle},
    interception_setup::SessionInterceptionSetup,
    policies::read_policy_set,
    registry_lifecycle::PreparedSession,
    session_context::{CdpSessionContexts, SessionPlanContext},
    session_resources::SessionSideResources,
    surfaces::{
        filesystem::{FilesystemFileOperationHandler, FilesystemSessionContext},
        terminal::{LazyBrowserCdpProcessMediation, TerminalProcessSurface},
    },
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
    start_session_side_resources_from_start_plan(config, plan, start_plan, prepared_session)
}

pub(crate) fn start_adopt_session_side_resources(
    config: &RuntimeConfig,
    plan: &SessionAdoptPlan,
) -> Result<SessionSideResources, SessionExecutionError> {
    let process_exec_interception = config
        .session_interception_capabilities()
        .operations()
        .iter()
        .any(|operation| {
            operation.operation() == SessionInterceptionOperation::ProcessExec
                && operation.effective()
        });
    if plan.runner().kind() == SessionRunnerKind::LinuxHost && !process_exec_interception {
        return GuardConfigSnafu {
            reason: String::from(
                "linux-host adoption requires session.interception process_exec support",
            ),
        }
        .fail();
    }

    let start_plan = config
        .surface_start_plan_for_runner_kind(plan.runner().kind())
        .context(InvalidConfigSnafu)?;
    start_session_side_resources_from_start_plan(config, plan, start_plan, None)
}

fn start_session_side_resources_from_start_plan(
    _config: &RuntimeConfig,
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
    let mut terminal_surface_present = false;
    let mut terminal_process_surface = TerminalProcessSurface::absent();
    let mut filesystem_handler = None;
    let mut process_exec_interception = None;
    let process_exec_supported = start_plan
        .interception()
        .operation_supported(SessionInterceptionOperation::ProcessExec);
    let mut lazy_browser_cdp = None;
    let uses_lazy_browser_cdp = start_plan
        .terminal()
        .is_some_and(TerminalProcessSurface::uses_managed_browser_cdp_mediation);

    for definition in launch_plan.definitions() {
        match definition {
            SessionSurfaceDefinition::BrowserCdp(config) => {
                let policy_set = read_policy_set(config.policies())?;
                if uses_lazy_browser_cdp {
                    lazy_browser_cdp = Some(LazyBrowserCdpProcessMediation::new(
                        config.clone(),
                        policy_set,
                        CdpSessionContexts::from_plan(plan),
                        prepared_session
                            .map(|session| session.storage().audit_path().to_path_buf()),
                        plan.audit().clone(),
                    ));
                } else {
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
            }
            SessionSurfaceDefinition::Terminal(config) => {
                terminal_surface_present = true;
                environment.push((
                    String::from("EREBOR_TERMINAL_SURFACE"),
                    String::from("terminal"),
                ));
                environment.push((
                    String::from("EREBOR_TERMINAL_TTY"),
                    config.tty().to_string(),
                ));

                if process_exec_supported {
                    terminal_process_surface = TerminalProcessSurface::present(config);
                    process_exec_interception = terminal_process_surface.backend_input(plan)?;
                }
            }
            SessionSurfaceDefinition::Filesystem(config) => {
                let policy_set = read_policy_set(config.policies())?;
                let mut handler = FilesystemFileOperationHandler::new(
                    policy_set,
                    FilesystemSessionContext::from_plan(plan),
                );
                if let Some(audit_jsonl) =
                    prepared_session.map(|session| session.storage().audit_path())
                {
                    handler =
                        handler.with_audit_jsonl(audit_jsonl.to_path_buf(), plan.audit().clone());
                }
                filesystem_handler = Some(handler);
                environment.push((
                    String::from("EREBOR_FILESYSTEM_SURFACE"),
                    String::from("filesystem"),
                ));
            }
        }
    }

    let interception_setup =
        SessionInterceptionSetup::new(SessionInterceptionBackendBundle::prepare(
            start_plan.interception(),
            process_exec_interception,
            file_operation_interception_input(start_plan.interception(), &filesystem_handler),
            plan,
            prepared_session.map(PreparedSession::storage),
        )?);
    if terminal_surface_present {
        environment.push((
            String::from("EREBOR_TERMINAL_PROCESS_GUARD"),
            interception_setup
                .backend_kind()
                .unwrap_or("disabled")
                .to_owned(),
        ));
    }

    if launcher.is_empty() {
        let uses_lazy_browser_cdp = lazy_browser_cdp.is_some();
        let interception_router = session_interception_router(
            terminal_process_surface,
            None,
            lazy_browser_cdp,
            filesystem_handler,
        )?;
        let interception_registration =
            interception_setup.register(interception_router, plan, uses_lazy_browser_cdp)?;
        return interception_setup.into_side_resources(
            environment,
            None,
            interception_registration,
            None,
        );
    }

    let supervisor = launcher.start().context(RuntimeSnafu)?;
    let mut browser_cdp_endpoint = None;
    for runtime in supervisor.running() {
        match runtime.surface() {
            SessionSurfaceKind::BrowserCdp => {
                browser_cdp_endpoint = Some(runtime.endpoint().to_owned());
                environment.push((
                    String::from("EREBOR_BROWSER_CDP_URL"),
                    runtime.endpoint().to_owned(),
                ));
                environment.push((
                    String::from("EREBOR_OPENCLAW_BROWSER_PROFILE"),
                    String::from("erebor"),
                ));
            }
            SessionSurfaceKind::Terminal => {}
            SessionSurfaceKind::Filesystem => {}
            SessionSurfaceKind::Mcp
            | SessionSurfaceKind::Network
            | SessionSurfaceKind::Saas
            | SessionSurfaceKind::Desktop
            | SessionSurfaceKind::InternalSystem => {}
        }
    }

    let interception_router = session_interception_router(
        terminal_process_surface,
        browser_cdp_endpoint.as_deref(),
        lazy_browser_cdp,
        filesystem_handler,
    )?;
    let interception_registration =
        interception_setup.register(interception_router, plan, uses_lazy_browser_cdp)?;

    interception_setup.into_side_resources(
        environment,
        browser_cdp_endpoint,
        interception_registration,
        Some(supervisor),
    )
}

fn file_operation_interception_input(
    interception: &erebor_runtime_core::SessionInterceptionConfig,
    filesystem_handler: &Option<FilesystemFileOperationHandler>,
) -> FileOperationInterceptionInput {
    let filesystem_registered = filesystem_handler.is_some();
    FileOperationInterceptionInput::new(
        filesystem_registered
            && interception.operation_supported(SessionInterceptionOperation::FileOpen),
        filesystem_registered
            && interception.operation_supported(SessionInterceptionOperation::FileRead),
        filesystem_registered
            && interception.operation_supported(SessionInterceptionOperation::FileMutation),
    )
}

fn session_interception_router(
    terminal_process_surface: TerminalProcessSurface<'_>,
    browser_cdp_endpoint: Option<&str>,
    lazy_browser_cdp: Option<LazyBrowserCdpProcessMediation>,
    filesystem_handler: Option<FilesystemFileOperationHandler>,
) -> Result<crate::runtime_interception_broker::SessionInterceptionRouter, SessionExecutionError> {
    let router = terminal_process_surface.router(browser_cdp_endpoint, lazy_browser_cdp)?;
    Ok(match filesystem_handler {
        Some(handler) => router.with_file_operation_handler(handler),
        None => router,
    })
}
