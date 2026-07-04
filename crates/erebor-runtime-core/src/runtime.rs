use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
};

use erebor_runtime_telemetry::{debug, info};
use snafu::ResultExt;
use tokio::runtime::Runtime;

use crate::error::{
    BuildAsyncRuntimeSnafu, NoSessionSurfaceServicesSnafu, SurfaceExitedSnafu,
    UnsupportedSessionSurfaceSnafu,
};
use crate::{
    BrowserCdpSurfaceConfig, RuntimeAuditConfig, RuntimeError, SessionSurfaceKind,
    SessionSurfaceStartPlan, TerminalSurfaceConfig,
};

pub type SessionSurfaceFailureSender = Sender<SessionSurfaceFailure>;

pub trait SessionSurfaceService: Send {
    fn surface(&self) -> SessionSurfaceKind;

    fn start(
        self: Box<Self>,
        runtime: &Runtime,
        failures: SessionSurfaceFailureSender,
    ) -> Result<RunningSessionSurface, RuntimeError>;
}

pub struct SessionSurfaceLauncher {
    control_listen: SocketAddr,
    surfaces: Vec<Box<dyn SessionSurfaceService>>,
}

impl SessionSurfaceLauncher {
    #[must_use]
    pub fn new(control_listen: SocketAddr) -> Self {
        Self {
            control_listen,
            surfaces: Vec::new(),
        }
    }

    pub fn add_surface<S>(&mut self, surface: S)
    where
        S: SessionSurfaceService + 'static,
    {
        debug!(
            surface = surface.surface().as_str(),
            "registered session surface service"
        );
        self.surfaces.push(Box::new(surface));
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.surfaces.is_empty()
    }

    pub fn start(self) -> Result<SessionSurfaceSupervisor, RuntimeError> {
        if self.surfaces.is_empty() {
            return NoSessionSurfaceServicesSnafu.fail();
        }

        info!(
            control = %self.control_listen,
            surface_count = self.surfaces.len(),
            "starting session surface supervisor"
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context(BuildAsyncRuntimeSnafu)?;
        let (failures, failure_rx) = mpsc::channel();
        let mut running = Vec::new();

        for session_surface in self.surfaces {
            let surface = session_surface.surface();
            debug!("starting session surface", surface = %surface.as_str());
            let surface_status = session_surface.start(&runtime, failures.clone())?;
            info!(
                surface = surface_status.surface().as_str(),
                endpoint = surface_status.endpoint(),
                "session surface is listening"
            );
            running.push(surface_status);
        }
        drop(failures);

        Ok(SessionSurfaceSupervisor {
            control_listen: self.control_listen,
            running,
            failure_rx,
            _runtime: runtime,
        })
    }
}

pub struct SessionSurfaceSupervisor {
    control_listen: SocketAddr,
    running: Vec<RunningSessionSurface>,
    failure_rx: Receiver<SessionSurfaceFailure>,
    _runtime: Runtime,
}

impl SessionSurfaceSupervisor {
    #[must_use]
    pub fn control_listen(&self) -> SocketAddr {
        self.control_listen
    }

    #[must_use]
    pub fn running(&self) -> &[RunningSessionSurface] {
        &self.running
    }

    pub fn wait(self) -> Result<(), RuntimeError> {
        let failure = match self.failure_rx.recv() {
            Ok(failure) => failure,
            Err(_error) => return NoSessionSurfaceServicesSnafu.fail(),
        };

        SurfaceExitedSnafu {
            surface: failure.surface.as_str().to_owned(),
            reason: failure.reason,
        }
        .fail()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSurfaceLaunchPlan {
    control_listen: SocketAddr,
    policy_paths: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    definitions: Vec<SessionSurfaceDefinition>,
}

impl SessionSurfaceLaunchPlan {
    pub fn from_start_plan(
        control_listen: SocketAddr,
        plan: &SessionSurfaceStartPlan,
    ) -> Result<Self, RuntimeError> {
        let mut definitions = Vec::new();

        for surface in plan.surfaces() {
            match surface {
                SessionSurfaceKind::BrowserCdp => {
                    let Some(browser_cdp) = plan.browser_cdp().cloned() else {
                        return UnsupportedSessionSurfaceSnafu {
                            surface: surface.as_str().to_owned(),
                        }
                        .fail();
                    };
                    definitions.push(SessionSurfaceDefinition::BrowserCdp(browser_cdp));
                }
                SessionSurfaceKind::Terminal => {
                    let Some(terminal) = plan.terminal().cloned() else {
                        return UnsupportedSessionSurfaceSnafu {
                            surface: surface.as_str().to_owned(),
                        }
                        .fail();
                    };
                    definitions.push(SessionSurfaceDefinition::Terminal(terminal));
                }
                SessionSurfaceKind::Mcp
                | SessionSurfaceKind::Network
                | SessionSurfaceKind::Saas
                | SessionSurfaceKind::Desktop
                | SessionSurfaceKind::InternalSystem => {
                    return UnsupportedSessionSurfaceSnafu {
                        surface: surface.as_str().to_owned(),
                    }
                    .fail();
                }
            }
        }

        Ok(Self {
            control_listen,
            policy_paths: plan.policies().to_vec(),
            audit: plan.audit().clone(),
            definitions,
        })
    }

    #[must_use]
    pub fn control_listen(&self) -> SocketAddr {
        self.control_listen
    }

    #[must_use]
    pub fn policy_paths(&self) -> &[PathBuf] {
        &self.policy_paths
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub fn definitions(&self) -> &[SessionSurfaceDefinition] {
        &self.definitions
    }

    #[must_use]
    pub fn surfaces(&self) -> Vec<SessionSurfaceKind> {
        self.definitions
            .iter()
            .map(SessionSurfaceDefinition::surface)
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionSurfaceDefinition {
    BrowserCdp(BrowserCdpSurfaceConfig),
    Terminal(TerminalSurfaceConfig),
}

impl SessionSurfaceDefinition {
    #[must_use]
    pub fn surface(&self) -> SessionSurfaceKind {
        match self {
            Self::BrowserCdp(_) => SessionSurfaceKind::BrowserCdp,
            Self::Terminal(_) => SessionSurfaceKind::Terminal,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSurfaceFailure {
    surface: SessionSurfaceKind,
    reason: String,
}

impl SessionSurfaceFailure {
    #[must_use]
    pub fn new(surface: SessionSurfaceKind, reason: impl Into<String>) -> Self {
        Self {
            surface,
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningSessionSurface {
    surface: SessionSurfaceKind,
    endpoint: String,
}

impl RunningSessionSurface {
    #[must_use]
    pub fn new(surface: SessionSurfaceKind, endpoint: impl Into<String>) -> Self {
        Self {
            surface,
            endpoint: endpoint.into(),
        }
    }

    #[must_use]
    pub fn surface(&self) -> SessionSurfaceKind {
        self.surface
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}
